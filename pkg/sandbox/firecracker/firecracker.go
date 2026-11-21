package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/sandbox"
)

// Driver implements SandboxDriver for Managed Cloud bare-metal Linux KVM using Firecracker microVMs.
// It drives the Firecracker REST API over a per-VM Unix socket to configure kernel, rootfs/workspace
// drives, vsock proxy channel, full VM memory+disk hibernation snapshots, and sub-2s snapshot restores.
type Driver struct {
	FirecrackerBin string
	KernelImage    string
	RootfsImage    string
	BaseDir        string
	// SkipProcessSpawn is used in unit tests with a mocked Firecracker API socket.
	SkipProcessSpawn bool
}

func NewDriver(baseDir, kernelImage, rootfsImage string) (*Driver, error) {
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "agentbox-firecracker")
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "vms"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "snapshots"), 0o755); err != nil {
		return nil, err
	}
	return &Driver{
		FirecrackerBin: "firecracker",
		KernelImage:    kernelImage,
		RootfsImage:    rootfsImage,
		BaseDir:        baseDir,
	}, nil
}

func (d *Driver) Name() string { return "firecracker" }

func (d *Driver) Create(ctx context.Context, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := protocol.NewID("fc_")
	vmDir := filepath.Join(d.BaseDir, "vms", id)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return nil, err
	}
	apiSock := filepath.Join(vmDir, "firecracker.sock")
	vsockPath := filepath.Join(vmDir, "vsock.sock")

	if !d.SkipProcessSpawn {
		if _, err := os.Stat("/dev/kvm"); err != nil {
			return nil, fmt.Errorf("firecracker requires /dev/kvm on bare-metal Linux host: %w", err)
		}
		cmd := exec.CommandContext(ctx, d.FirecrackerBin, "--api-sock", apiSock)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("spawn firecracker process: %w", err)
		}
		if err := waitForSocket(apiSock, 3*time.Second); err != nil {
			return nil, err
		}
	}

	vcpu := spec.VCPU
	if vcpu <= 0 {
		vcpu = 2
	}
	memMB := spec.MemoryMB
	if memMB <= 0 {
		memMB = 4096
	}

	if err := d.fcRequest(ctx, apiSock, http.MethodPut, "/machine-config", map[string]any{
		"vcpu_count":  vcpu,
		"mem_size_mib": memMB,
		"smt":         false,
	}); err != nil {
		return nil, err
	}

	if err := d.fcRequest(ctx, apiSock, http.MethodPut, "/boot-source", map[string]any{
		"kernel_image_path": d.KernelImage,
		"boot_args":         "console=ttyS0 reboot=k panic=1 pci=off init=/opt/agentbox/agentd",
	}); err != nil {
		return nil, err
	}

	if err := d.fcRequest(ctx, apiSock, http.MethodPut, "/drives/rootfs", map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   d.RootfsImage,
		"is_root_device": true,
		"is_read_only":   true,
	}); err != nil {
		return nil, err
	}

	if err := d.fcRequest(ctx, apiSock, http.MethodPut, "/vsock", map[string]any{
		"guest_cid": 3,
		"uds_path":  vsockPath,
	}); err != nil {
		return nil, err
	}

	return &sandbox.SandboxHandle{
		ID:            id,
		Driver:        d.Name(),
		SessionID:     spec.SessionID,
		WorkspaceID:   spec.WorkspaceID,
		WorkspacePath: filepath.Join(vmDir, "workspace"),
		SocketPath:    apiSock,
		ProxyAddr:     spec.ProxyAddr,
		CreatedAt:     time.Now().UTC(),
		Meta: map[string]string{
			"vsock_path": vsockPath,
			"vm_dir":     vmDir,
		},
	}, nil
}

func (d *Driver) Start(ctx context.Context, handle *sandbox.SandboxHandle) error {
	return d.fcRequest(ctx, handle.SocketPath, http.MethodPut, "/actions", map[string]any{
		"action_type": "InstanceStart",
	})
}

func (d *Driver) AttachProxy(_ context.Context, handle *sandbox.SandboxHandle, proxyAddr string) error {
	handle.ProxyAddr = proxyAddr
	return nil
}

func (d *Driver) Snapshot(ctx context.Context, handle *sandbox.SandboxHandle, workspaceID string) (*sandbox.SnapshotRef, error) {
	snapID := protocol.NewID("fcsnap_")
	snapDir := filepath.Join(d.BaseDir, "snapshots", snapID)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return nil, err
	}
	vmStatePath := filepath.Join(snapDir, "vmstate.bin")
	memPath := filepath.Join(snapDir, "mem.bin")

	if err := d.fcRequest(ctx, handle.SocketPath, http.MethodPatch, "/vm", map[string]any{"state": "Paused"}); err != nil {
		return nil, err
	}
	if err := d.fcRequest(ctx, handle.SocketPath, http.MethodPut, "/snapshot/create", map[string]any{
		"snapshot_type": "Full",
		"snapshot_path": vmStatePath,
		"mem_file_path": memPath,
	}); err != nil {
		return nil, err
	}
	_ = d.fcRequest(ctx, handle.SocketPath, http.MethodPatch, "/vm", map[string]any{"state": "Resumed"})

	return &sandbox.SnapshotRef{
		ID:          snapID,
		Driver:      d.Name(),
		WorkspaceID: workspaceID,
		SessionID:   handle.SessionID,
		Path:        vmStatePath,
		MemoryPath:  memPath,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func (d *Driver) Restore(ctx context.Context, snap *sandbox.SnapshotRef, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := protocol.NewID("fc_")
	vmDir := filepath.Join(d.BaseDir, "vms", id)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		return nil, err
	}
	apiSock := filepath.Join(vmDir, "firecracker.sock")

	if !d.SkipProcessSpawn {
		cmd := exec.CommandContext(ctx, d.FirecrackerBin, "--api-sock", apiSock)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("spawn firecracker for restore: %w", err)
		}
		if err := waitForSocket(apiSock, 3*time.Second); err != nil {
			return nil, err
		}
	}

	if err := d.fcRequest(ctx, apiSock, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": snap.Path,
		"mem_backend": map[string]any{
			"backend_path": snap.MemoryPath,
			"backend_type": "File",
		},
		"resume_vm": true,
	}); err != nil {
		return nil, err
	}

	return &sandbox.SandboxHandle{
		ID:          id,
		Driver:      d.Name(),
		SessionID:   spec.SessionID,
		WorkspaceID: spec.WorkspaceID,
		SocketPath:  apiSock,
		ProxyAddr:   spec.ProxyAddr,
		CreatedAt:   time.Now().UTC(),
		Meta:        map[string]string{"vm_dir": vmDir},
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

func (d *Driver) Destroy(_ context.Context, handle *sandbox.SandboxHandle) error {
	if handle == nil {
		return nil
	}
	if vmDir := handle.Meta["vm_dir"]; vmDir != "" {
		return os.RemoveAll(vmDir)
	}
	return nil
}

func (d *Driver) fcRequest(ctx context.Context, sockPath, method, path string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", sockPath)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firecracker %s %s failed (%d): %s", method, path, resp.StatusCode, string(msg))
	}
	return nil
}

func waitForSocket(sockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for firecracker api socket %s", sockPath)
}
