package local

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/sandbox"
)

// Driver provides a rootless process/directory-isolated SandboxDriver for local development
// and CI environments where Docker or KVM are unavailable.
type Driver struct {
	BaseDir string
}

func NewDriver(baseDir string) (*Driver, error) {
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "agentbox-local")
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "workspaces"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "snapshots"), 0o755); err != nil {
		return nil, err
	}
	return &Driver{BaseDir: baseDir}, nil
}

func (d *Driver) Name() string { return "local" }

func (d *Driver) Create(ctx context.Context, spec sandbox.SandboxSpec) (*sandbox.SandboxHandle, error) {
	id := protocol.NewID("sbx_")
	wsPath := filepath.Join(d.BaseDir, "workspaces", id)
	if err := os.MkdirAll(wsPath, 0o755); err != nil {
		return nil, fmt.Errorf("create local workspace: %w", err)
	}

	if spec.Repo.LocalPath != "" {
		if err := copyDirectory(spec.Repo.LocalPath, wsPath); err != nil {
			return nil, fmt.Errorf("seed workspace from local path: %w", err)
		}
	}

	return &sandbox.SandboxHandle{
		ID:            id,
		Driver:        d.Name(),
		SessionID:     spec.SessionID,
		WorkspaceID:   spec.WorkspaceID,
		WorkspacePath: wsPath,
		ProxyAddr:     spec.ProxyAddr,
		CreatedAt:     time.Now().UTC(),
		Meta: map[string]string{
			"egress_proxy": spec.EgressProxy,
		},
	}, nil
}

func (d *Driver) Start(ctx context.Context, handle *sandbox.SandboxHandle) error {
	if handle == nil || handle.WorkspacePath == "" {
		return fmt.Errorf("invalid sandbox handle")
	}
	if _, err := os.Stat(handle.WorkspacePath); err != nil {
		return fmt.Errorf("workspace missing: %w", err)
	}
	return nil
}

func (d *Driver) AttachProxy(_ context.Context, handle *sandbox.SandboxHandle, proxyAddr string) error {
	handle.ProxyAddr = proxyAddr
	return nil
}

func (d *Driver) Snapshot(_ context.Context, handle *sandbox.SandboxHandle, workspaceID string) (*sandbox.SnapshotRef, error) {
	snapID := protocol.NewID("snap_")
	snapPath := filepath.Join(d.BaseDir, "snapshots", snapID+".tar.gz")
	if err := sandbox.ArchiveDirectory(handle.WorkspacePath, snapPath); err != nil {
		return nil, fmt.Errorf("snapshot local workspace: %w", err)
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
	id := protocol.NewID("sbx_")
	wsPath := filepath.Join(d.BaseDir, "workspaces", id)
	if err := sandbox.ExtractArchive(snap.Path, wsPath); err != nil {
		return nil, fmt.Errorf("restore local snapshot: %w", err)
	}
	return &sandbox.SandboxHandle{
		ID:            id,
		Driver:        d.Name(),
		SessionID:     spec.SessionID,
		WorkspaceID:   spec.WorkspaceID,
		WorkspacePath: wsPath,
		ProxyAddr:     spec.ProxyAddr,
		CreatedAt:     time.Now().UTC(),
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
	if handle == nil || handle.WorkspacePath == "" {
		return nil
	}
	return os.RemoveAll(handle.WorkspacePath)
}

// RunSetupCommands executes Blueprint setup commands inside the isolated workspace.
func RunSetupCommands(ctx context.Context, workspace string, commands []string, extraEnv []string) error {
	for _, cmdStr := range commands {
		cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
		cmd.Dir = workspace
		cmd.Env = append(os.Environ(), extraEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("setup command %q failed: %s (%w)", cmdStr, string(out), err)
		}
	}
	return nil
}

func copyDirectory(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}
