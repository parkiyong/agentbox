package sandbox

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// SandboxSpec defines the isolated runtime parameters for a session sandbox.
type SandboxSpec struct {
	SessionID     string
	OrgID         string
	CustomerID    string
	WorkspaceID   string
	Image         string
	VCPU          int
	MemoryMB      int
	DiskGB        int
	AgentDBinary  string // Path to static Go agentd binary mounted read-only at /opt/agentbox/agentd
	SessionNonce  string // Ephemeral nonce ONLY — zero raw secrets ever passed in SandboxSpec
	ProxyAddr     string // Host-Side Security Proxy UDS or loopback address
	EgressProxy   string // Host-Side Egress Firewall HTTP/CONNECT proxy address
	Repo          protocol.RepoSpec
	SetupCommands []string
	Env           map[string]string
}

// SandboxHandle references a provisioned sandbox instance managed by a SandboxDriver.
type SandboxHandle struct {
	ID            string
	Driver        string
	SessionID     string
	WorkspaceID   string
	WorkspacePath string // Host-side or mounted workspace directory
	ProxyAddr     string
	ContainerID   string
	PodName       string
	SocketPath    string
	CreatedAt     time.Time
	Meta          map[string]string
}

// SnapshotRef identifies a persisted warm workspace or hibernated VM snapshot.
type SnapshotRef struct {
	ID           string    `json:"id"`
	Driver       string    `json:"driver"`
	WorkspaceID  string    `json:"workspace_id"`
	SessionID    string    `json:"session_id,omitempty"`
	Path         string    `json:"path"`          // Local path, thin-LVM ref, or CSI VolumeSnapshot name
	MemoryPath   string    `json:"memory_path,omitempty"` // Firecracker VM RAM snapshot file
	Hibernated   bool      `json:"hibernated"`
	CreatedAt    time.Time `json:"created_at"`
}

// SandboxDriver is the pluggable isolation runtime interface implemented by
// firecracker (Managed Cloud), k8s-gvisor / k8s-kata (BYOC K8s), docker, and local dev drivers.
type SandboxDriver interface {
	Name() string
	Create(ctx context.Context, spec SandboxSpec) (*SandboxHandle, error)
	Start(ctx context.Context, handle *SandboxHandle) error
	AttachProxy(ctx context.Context, handle *SandboxHandle, proxyAddr string) error
	Snapshot(ctx context.Context, handle *SandboxHandle, workspaceID string) (*SnapshotRef, error)
	Restore(ctx context.Context, snap *SnapshotRef, spec SandboxSpec) (*SandboxHandle, error)
	Hibernate(ctx context.Context, handle *SandboxHandle) (*SnapshotRef, error)
	Destroy(ctx context.Context, handle *SandboxHandle) error
}

// WorkspaceKey computes the deterministic workspace_id keyed by
// (org_id, customer_id, repo_url, blueprint_hash) for warm dependency caching.
func WorkspaceKey(orgID, customerID, repoURL, blueprintHash string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", orgID, customerID, strings.TrimSpace(repoURL), blueprintHash)
	sum := sha256.Sum256([]byte(raw))
	return "wksp_" + hex.EncodeToString(sum[:10])
}

// ArchiveDirectory writes a gzip-compressed tar snapshot of srcDir to dstFile.
func ArchiveDirectory(srcDir, dstFile string) error {
	if err := os.MkdirAll(filepath.Dir(dstFile), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil || rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rf, err := os.Open(path)
		if err != nil {
			return err
		}
		defer rf.Close()
		_, err = io.Copy(tw, rf)
		return err
	})
}

// ExtractArchive restores a gzip-compressed tar snapshot into dstDir safely (preventing ZipSlip).
func ExtractArchive(srcFile, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	f, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	absDst, err := filepath.Abs(dstDir)
	if err != nil {
		return err
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Clean(filepath.Join(absDst, hdr.Name))
		rel, err := filepath.Rel(absDst, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("archive entry %q escapes target directory", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
}
