package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/sandbox"
)

// Driver implements SandboxDriver for Self-Hosted BYOC Kubernetes clusters using
// gVisor (`runsc`) or Kata Containers RuntimeClass with CSI VolumeSnapshot / PVC clones.
type Driver struct {
	APIServer        string
	Namespace        string
	BearerToken      string
	RuntimeClassName string // "gvisor" or "kata"
	StorageClass     string
	SnapshotClass    string
	HTTPClient       *http.Client
}

func NewDriver(apiServer, namespace, runtimeClass, token string) *Driver {
	if namespace == "" {
		namespace = "agentbox"
	}
	if runtimeClass == "" {
		runtimeClass = "gvisor"
	}
	return &Driver{
		APIServer:        strings.TrimRight(apiServer, "/"),
		Namespace:        namespace,
		BearerToken:      token,
		RuntimeClassName: runtimeClass,
		HTTPClient:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *Driver) Name() string {
	return "k8s-" + d.RuntimeClassName
}

// BuildPodManifest constructs a hardened Kubernetes Pod specification enforcing
// RuntimeClass isolation, readOnlyRootFilesystem, dropped Linux capabilities, and cgroup quotas.
func (d *Driver) BuildPodManifest(podName, pvcName string, spec sandbox.SandboxSpec) map[string]any {
	vcpu := spec.VCPU
	if vcpu <= 0 {
		vcpu = 2
	}
	memMB := spec.MemoryMB
	if memMB <= 0 {
		memMB = 4096
	}
	image := spec.Image
	if image == "" {
		image = "ghcr.io/agentbox/swe-node22-py312:v1"
	}
	envList := []map[string]any{
		{"name": "AGENTBOX_SESSION_ID", "value": spec.SessionID},
		{"name": "AGENTBOX_SESSION_NONCE", "value": spec.SessionNonce},
		{"name": "AGENTBOX_PROXY_URL", "value": spec.ProxyAddr},
	}
	if spec.EgressProxy != "" {
		envList = append(envList,
			map[string]any{"name": "HTTP_PROXY", "value": spec.EgressProxy},
			map[string]any{"name": "HTTPS_PROXY", "value": spec.EgressProxy},
		)
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      podName,
			"namespace": d.Namespace,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "agentbox-runner",
				"agentbox.dev/session-id":      spec.SessionID,
				"agentbox.dev/customer-id":     spec.CustomerID,
			},
		},
		"spec": map[string]any{
			"runtimeClassName":             d.RuntimeClassName,
			"restartPolicy":                "Never",
			"automountServiceAccountToken": false,
			"securityContext": map[string]any{
				"runAsNonRoot": true,
				"runAsUser":    1000,
				"fsGroup":      1000,
				"seccompProfile": map[string]any{
					"type": "RuntimeDefault",
				},
			},
			"containers": []map[string]any{
				{
					"name":       "sandbox",
					"image":      image,
					"workingDir": "/workspace",
					"command":    []string{"/opt/agentbox/agentd"},
					"env":        envList,
					"securityContext": map[string]any{
						"readOnlyRootFilesystem":   true,
						"allowPrivilegeEscalation": false,
						"capabilities": map[string]any{
							"drop": []string{"ALL"},
						},
					},
					"resources": map[string]any{
						"requests": map[string]any{
							"cpu":    fmt.Sprintf("%d", vcpu),
							"memory": fmt.Sprintf("%dMi", memMB),
						},
						"limits": map[string]any{
							"cpu":    fmt.Sprintf("%d", vcpu),
							"memory": fmt.Sprintf("%dMi", memMB),
						},
					},
					"volumeMounts": []map[string]any{
						{"name": "workspace", "mountPath": "/workspace"},
						{"name": "tmp", "mountPath": "/tmp"},
					},
				},
			},
			"volumes": []map[string]any{
				{
					"name": "workspace",
					"persistentVolumeClaim": map[string]any{
						"claimName": pvcName,
					},
				},
				{
					"name":     "tmp",
					"emptyDir": map[string]any{"sizeLimit": "512Mi"},
				},
			},
		},
	}
}

// BuildVolumeSnapshotManifest builds a CSI VolumeSnapshot manifest for warm workspaces / hibernation.
func (d *Driver) BuildVolumeSnapshotManifest(snapName, pvcName string) map[string]any {
	spec := map[string]any{
		"source": map[string]any{
			"persistentVolumeClaimName": pvcName,
		},
	}
	if d.SnapshotClass != "" {
		spec["volumeSnapshotClassName"] = d.SnapshotClass
	}
	return map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind":       "VolumeSnapshot",
		"metadata": map[string]any{
			"name":      snapName,
			"namespace": d.Namespace,
		},
		"spec": spec,
	}
}

func (d *Driver) Create(ctx context.Context, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := strings.ToLower(strings.ReplaceAll(protocol.NewID("abx-"), "_", "-"))
	pvcName := id + "-ws"
	diskGB := spec.DiskGB
	if diskGB <= 0 {
		diskGB = 20
	}

	pvc := map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   map[string]any{"name": pvcName, "namespace": d.Namespace},
		"spec": map[string]any{
			"accessModes": []string{"ReadWriteOnce"},
			"resources": map[string]any{
				"requests": map[string]any{"storage": fmt.Sprintf("%dGi", diskGB)},
			},
		},
	}
	if err := d.k8sRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/persistentvolumeclaims", d.Namespace), pvc); err != nil {
		return nil, err
	}

	pod := d.BuildPodManifest(id, pvcName, spec)
	if err := d.k8sRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/pods", d.Namespace), pod); err != nil {
		return nil, err
	}

	return &sandbox.SandboxHandle{
		ID:          id,
		Driver:      d.Name(),
		SessionID:   spec.SessionID,
		WorkspaceID: spec.WorkspaceID,
		PodName:     id,
		ProxyAddr:   spec.ProxyAddr,
		CreatedAt:   time.Now().UTC(),
		Meta:        map[string]string{"pvc_name": pvcName},
	}, nil
}

func (d *Driver) Start(_ context.Context, _ *sandbox.SandboxHandle) error {
	// Kubernetes schedules and starts the Pod automatically upon creation.
	return nil
}

func (d *Driver) AttachProxy(_ context.Context, handle *sandbox.SandboxHandle, proxyAddr string) error {
	handle.ProxyAddr = proxyAddr
	return nil
}

func (d *Driver) Snapshot(ctx context.Context, handle *sandbox.SandboxHandle, workspaceID string) (*sandbox.SnapshotRef, error) {
	snapName := strings.ToLower(strings.ReplaceAll(protocol.NewID("abx-snap-"), "_", "-"))
	pvcName := handle.Meta["pvc_name"]
	manifest := d.BuildVolumeSnapshotManifest(snapName, pvcName)
	if err := d.k8sRequest(ctx, http.MethodPost, fmt.Sprintf("/apis/snapshot.storage.k8s.io/v1/namespaces/%s/volumesnapshots", d.Namespace), manifest); err != nil {
		return nil, err
	}
	return &sandbox.SnapshotRef{
		ID:          snapName,
		Driver:      d.Name(),
		WorkspaceID: workspaceID,
		SessionID:   handle.SessionID,
		Path:        snapName,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func (d *Driver) Restore(ctx context.Context, snap *sandbox.SnapshotRef, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := strings.ToLower(strings.ReplaceAll(protocol.NewID("abx-"), "_", "-"))
	pvcName := id + "-ws"
	diskGB := spec.DiskGB
	if diskGB <= 0 {
		diskGB = 20
	}
	pvc := map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   map[string]any{"name": pvcName, "namespace": d.Namespace},
		"spec": map[string]any{
			"accessModes": []string{"ReadWriteOnce"},
			"dataSource": map[string]any{
				"apiGroup": "snapshot.storage.k8s.io",
				"kind":     "VolumeSnapshot",
				"name":     snap.Path,
			},
			"resources": map[string]any{
				"requests": map[string]any{"storage": fmt.Sprintf("%dGi", diskGB)},
			},
		},
	}
	if err := d.k8sRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/persistentvolumeclaims", d.Namespace), pvc); err != nil {
		return nil, err
	}
	pod := d.BuildPodManifest(id, pvcName, spec)
	if err := d.k8sRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/pods", d.Namespace), pod); err != nil {
		return nil, err
	}
	return &sandbox.SandboxHandle{
		ID:          id,
		Driver:      d.Name(),
		SessionID:   spec.SessionID,
		WorkspaceID: spec.WorkspaceID,
		PodName:     id,
		ProxyAddr:   spec.ProxyAddr,
		CreatedAt:   time.Now().UTC(),
		Meta:        map[string]string{"pvc_name": pvcName},
	}, nil
}

func (d *Driver) Hibernate(ctx context.Context, handle *sandbox.SandboxHandle) (*sandbox.SnapshotRef, error) {
	snap, err := d.Snapshot(ctx, handle, handle.WorkspaceID)
	if err != nil {
		return nil, err
	}
	snap.Hibernated = true
	_ = d.Destroy(ctx, handle)
	return snap, nil
}

func (d *Driver) Destroy(ctx context.Context, handle *sandbox.SandboxHandle) error {
	if handle == nil || handle.PodName == "" {
		return nil
	}
	return d.k8sRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", d.Namespace, handle.PodName), nil)
}

func (d *Driver) k8sRequest(ctx context.Context, method, path string, payload any) error {
	if d.APIServer == "" {
		return fmt.Errorf("kubernetes API server URL not configured")
	}
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.APIServer+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.BearerToken)
	}
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("k8s %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s %s %s failed (%d): %s", method, path, resp.StatusCode, string(msg))
	}
	return nil
}
