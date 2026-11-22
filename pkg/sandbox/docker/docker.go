package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/sandbox"
)

// Driver implements SandboxDriver using hardened rootless Docker containers:
// read-only rootfs, dropped capabilities (--cap-drop=ALL), no-new-privileges, cgroup CPU/RAM/PID quotas,
// read-only /opt/agentbox/agentd mount, and host-side proxy socket mounting.
type Driver struct {
	DockerBinary string
	BaseDir      string
	NetworkName  string
}

func NewDriver(baseDir string) (*Driver, error) {
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "agentbox-docker")
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "workspaces"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "snapshots"), 0o755); err != nil {
		return nil, err
	}
	return &Driver{
		DockerBinary: "docker",
		BaseDir:      baseDir,
		NetworkName:  "agentbox-isolated",
	}, nil
}

func (d *Driver) Name() string { return "docker" }

// BuildCreateArgs constructs the hardened `docker create` argument slice for a SandboxSpec.
// Exported for unit testing security flags without requiring a running Docker daemon.
func (d *Driver) BuildCreateArgs(id, wsPath string, spec sandbox.SandboxSpec) []string {
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

	args := []string{
		"create",
		"--name", id,
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=256",
		"--cpus", strconv.Itoa(vcpu),
		"--memory", fmt.Sprintf("%dm", memMB),
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
		"-v", wsPath + ":/workspace:rw",
		"-w", "/workspace",
		"-e", "AGENTBOX_SESSION_ID=" + spec.SessionID,
		"-e", "AGENTBOX_SESSION_NONCE=" + spec.SessionNonce,
	}

	if d.NetworkName != "" {
		args = append(args, "--network", d.NetworkName)
	}
	if spec.AgentDBinary != "" {
		args = append(args, "-v", spec.AgentDBinary+":/opt/agentbox/agentd:ro")
	}
	if strings.HasPrefix(spec.ProxyAddr, "unix://") {
		hostSock := strings.TrimPrefix(spec.ProxyAddr, "unix://")
		args = append(args,
			"-v", hostSock+":/run/agentbox/proxy.sock:rw",
			"-e", "AGENTBOX_PROXY_URL=unix:///run/agentbox/proxy.sock",
		)
	} else if spec.ProxyAddr != "" {
		args = append(args, "-e", "AGENTBOX_PROXY_URL="+spec.ProxyAddr)
	}
	if spec.EgressProxy != "" {
		args = append(args,
			"-e", "HTTP_PROXY="+spec.EgressProxy,
			"-e", "HTTPS_PROXY="+spec.EgressProxy,
		)
	}
	for k, v := range spec.Env {
		args = append(args, "-e", k+"="+v)
	}

	args = append(args, image, "sleep", "infinity")
	return args
}

func (d *Driver) Create(ctx context.Context, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := protocol.NewID("sbx_")
	wsPath := filepath.Join(d.BaseDir, "workspaces", id)
	if err := os.MkdirAll(wsPath, 0o755); err != nil {
		return nil, err
	}

	// Ensure isolated internal docker network exists (ignore error if already exists).
	if d.NetworkName != "" {
		_, _ = d.runDocker(ctx, "network", "create", "--internal", d.NetworkName)
	}

	args := d.BuildCreateArgs(id, wsPath, spec)
	out, err := d.runDocker(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("docker create sandbox: %w", err)
	}
	return &sandbox.SandboxHandle{
		ID:            id,
		Driver:        d.Name(),
		SessionID:     spec.SessionID,
		WorkspaceID:   spec.WorkspaceID,
		WorkspacePath: wsPath,
		ProxyAddr:     spec.ProxyAddr,
		ContainerID:   strings.TrimSpace(out),
		CreatedAt:     time.Now().UTC(),
	}, nil
}

func (d *Driver) Start(ctx context.Context, handle *sandbox.SandboxHandle) error {
	_, err := d.runDocker(ctx, "start", handle.ContainerID)
	return err
}

func (d *Driver) AttachProxy(_ context.Context, handle *sandbox.SandboxHandle, proxyAddr string) error {
	handle.ProxyAddr = proxyAddr
	return nil
}

func (d *Driver) Snapshot(_ context.Context, handle *sandbox.SandboxHandle, workspaceID string) (*sandbox.SnapshotRef, error) {
	snapID := protocol.NewID("snap_")
	snapPath := filepath.Join(d.BaseDir, "snapshots", snapID+".tar.gz")
	if err := sandbox.ArchiveDirectory(handle.WorkspacePath, snapPath); err != nil {
		return nil, fmt.Errorf("docker workspace snapshot: %w", err)
	}
	return &sandbox.SnapshotRef{
		ID:          snapID,
		Driver:      d.Name(),
		WorkspaceID: workspaceID,
		SessionID:   handle.SessionID,
		Path:        snapPath,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func (d *Driver) Restore(ctx context.Context, snap *sandbox.SnapshotRef, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	handle, err := d.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := sandbox.ExtractArchive(snap.Path, handle.WorkspacePath); err != nil {
		_ = d.Destroy(ctx, handle)
		return nil, fmt.Errorf("restore docker workspace snapshot: %w", err)
	}
	return handle, nil
}

func (d *Driver) Hibernate(ctx context.Context, handle *sandbox.SandboxHandle) (*sandbox.SnapshotRef, error) {
	_, _ = d.runDocker(ctx, "pause", handle.ContainerID)
	snap, err := d.Snapshot(ctx, handle, handle.WorkspaceID)
	if err != nil {
		return nil, err
	}
	snap.Hibernated = true
	_ = d.Destroy(ctx, handle)
	return snap, nil
}

func (d *Driver) Destroy(ctx context.Context, handle *sandbox.SandboxHandle) error {
	if handle == nil {
		return nil
	}
	if handle.ContainerID != "" {
		_, _ = d.runDocker(ctx, "rm", "-f", handle.ContainerID)
	}
	if handle.WorkspacePath != "" {
		_ = os.RemoveAll(handle.WorkspacePath)
	}
	return nil
}

// BuildExecArgs constructs the `docker exec -i` command arguments to run /opt/agentbox/agentd
// inside the hardened container with zero raw secrets.
func (d *Driver) BuildExecArgs(containerID string, req sandbox.AgentRunRequest, containerBPPath, limitsJSON string) []string {
	args := []string{
		"exec", "-i",
		"-w", "/workspace",
		"-e", "AGENTBOX_SESSION_ID=" + req.SessionID,
		"-e", "AGENTBOX_CUSTOMER_ID=" + req.CustomerID,
		"-e", "AGENTBOX_WORKSPACE=/workspace",
		"-e", "AGENTBOX_SESSION_NONCE=" + req.SessionNonce,
		"-e", "AGENTBOX_TASK=" + req.Task,
	}
	if containerBPPath != "" {
		args = append(args, "-e", "AGENTBOX_BLUEPRINT_PATH="+containerBPPath)
	}
	if limitsJSON != "" {
		args = append(args, "-e", "AGENTBOX_LIMITS_JSON="+limitsJSON)
	}
	args = append(args, containerID, "/opt/agentbox/agentd")
	return args
}

// StartAgent runs /opt/agentbox/agentd inside the hardened Docker container over `docker exec -i`.
func (d *Driver) StartAgent(ctx context.Context, handle *sandbox.SandboxHandle, req sandbox.AgentRunRequest, onEvent func(protocol.Event)) (sandbox.AgentProcess, error) {
	if handle == nil || handle.ContainerID == "" {
		return nil, fmt.Errorf("docker sandbox handle missing container ID")
	}

	var containerBPPath string
	var cleanupFn func()
	if req.Blueprint != nil {
		metaDir, err := os.MkdirTemp(d.BaseDir, "docker-bp-*")
		if err != nil {
			return nil, err
		}
		hostBP, err := sandbox.WriteRuntimeBlueprintFile(metaDir, req.Blueprint)
		if err != nil {
			_ = os.RemoveAll(metaDir)
			return nil, err
		}
		containerBPPath = "/tmp/.agentbox-blueprint.json"
		if _, err := d.runDocker(ctx, "cp", hostBP, handle.ContainerID+":"+containerBPPath); err != nil {
			_ = os.RemoveAll(metaDir)
			return nil, fmt.Errorf("copy blueprint into container: %w", err)
		}
		cleanupFn = func() { _ = os.RemoveAll(metaDir) }
	}

	limitsBytes, _ := json.Marshal(req.Limits)
	execArgs := d.BuildExecArgs(handle.ContainerID, req, containerBPPath, string(limitsBytes))
	cmd := exec.CommandContext(ctx, d.DockerBinary, execArgs...)
	return sandbox.StartCmdAgent(cmd, onEvent, cleanupFn)
}

func (d *Driver) runDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, d.DockerBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %s (%w)", strings.Join(args, " "), strings.TrimSpace(stderr.String()), err)
	}
	return stdout.String(), nil
}
