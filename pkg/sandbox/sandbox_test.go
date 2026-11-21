package sandbox_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/parkiyong/agentbox/pkg/sandbox"
	"github.com/parkiyong/agentbox/pkg/sandbox/docker"
	"github.com/parkiyong/agentbox/pkg/sandbox/k8s"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

func TestLocalDriverLifecycleSnapshotHibernateRestore(t *testing.T) {
	ctx := context.Background()
	drv, err := local.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	wsID := sandbox.WorkspaceKey("org_1", "cust_1", "https://github.com/acme/repo", "hash123")
	spec := sandbox.SandboxSpec{
		SessionID:    "ses_1",
		OrgID:        "org_1",
		CustomerID:   "cust_1",
		WorkspaceID:  wsID,
		SessionNonce: "abx_nonce_test",
	}

	h, err := drv.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := drv.Start(ctx, h); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.WorkspacePath, "cached_dep.txt"), []byte("warm-cache"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := drv.Hibernate(ctx, h)
	if err != nil || !snap.Hibernated {
		t.Fatalf("Hibernate failed: snap=%+v err=%v", snap, err)
	}
	// Workspace should be cleaned after hibernate
	if _, err := os.Stat(h.WorkspacePath); !os.IsNotExist(err) {
		t.Fatalf("expected original workspace to be destroyed on hibernate")
	}

	restored, err := drv.Restore(ctx, snap, spec)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	defer drv.Destroy(ctx, restored)

	data, err := os.ReadFile(filepath.Join(restored.WorkspacePath, "cached_dep.txt"))
	if err != nil || string(data) != "warm-cache" {
		t.Fatalf("expected restored warm cache file, got %q err=%v", string(data), err)
	}
}

func TestDockerDriverSecurityFlags(t *testing.T) {
	drv, err := docker.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	args := drv.BuildCreateArgs("sbx_123", "/tmp/ws", sandbox.SandboxSpec{
		SessionID:    "ses_1",
		VCPU:         2,
		MemoryMB:     2048,
		AgentDBinary: "/usr/local/bin/agentd",
		SessionNonce: "abx_nonce_xyz",
		ProxyAddr:    "unix:///tmp/proxy.sock",
		EgressProxy:  "http://127.0.0.1:9001",
	})

	for _, required := range []string{
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=256",
		"/usr/local/bin/agentd:/opt/agentbox/agentd:ro",
		"/tmp/proxy.sock:/run/agentbox/proxy.sock:rw",
	} {
		if !slices.Contains(args, required) {
			t.Errorf("docker create args missing required hardening flag %q: %v", required, args)
		}
	}
}

func TestK8sDriverPodHardeningAndAPICalls(t *testing.T) {
	var paths []string
	k8sAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer k8sAPI.Close()

	drv := k8s.NewDriver(k8sAPI.URL, "agentbox-byoc", "gvisor", "tok")
	if drv.Name() != "k8s-gvisor" {
		t.Fatalf("unexpected driver name: %s", drv.Name())
	}

	spec := sandbox.SandboxSpec{
		SessionID:    "ses_k8s",
		CustomerID:   "cust_42",
		WorkspaceID:  "wksp_1",
		SessionNonce: "abx_nonce_k8s",
		ProxyAddr:    "http://agentbox-proxy.agentbox-byoc.svc:8081",
	}
	h, err := drv.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("k8s Create failed: %v", err)
	}
	snap, err := drv.Snapshot(context.Background(), h, spec.WorkspaceID)
	if err != nil {
		t.Fatalf("k8s Snapshot failed: %v", err)
	}
	if _, err := drv.Restore(context.Background(), snap, spec); err != nil {
		t.Fatalf("k8s Restore failed: %v", err)
	}
	if err := drv.Destroy(context.Background(), h); err != nil {
		t.Fatalf("k8s Destroy failed: %v", err)
	}

	joined := strings.Join(paths, "\n")
	for _, want := range []string{
		"POST /api/v1/namespaces/agentbox-byoc/persistentvolumeclaims",
		"POST /api/v1/namespaces/agentbox-byoc/pods",
		"POST /apis/snapshot.storage.k8s.io/v1/namespaces/agentbox-byoc/volumesnapshots",
		"DELETE /api/v1/namespaces/agentbox-byoc/pods/",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected k8s API call %q, got:\n%s", want, joined)
		}
	}
}
