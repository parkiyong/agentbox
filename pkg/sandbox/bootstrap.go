package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// BootstrapConfig configures workspace Git clone/fetch (via Host-Side Git Proxy) and
// Blueprint runtime.setup.commands execution.
type BootstrapConfig struct {
	WorkspacePath string
	SessionID     string
	Repo          protocol.RepoSpec
	Blueprint     *protocol.Blueprint
	ProxyBaseURL  string
	EgressProxy   string
	SessionNonce  string
	IsWarmRestore bool
}

// BootstrapResult summarizes the prepared workspace state.
type BootstrapResult struct {
	Branch        string
	ColdBootstrap bool
	SetupRan      bool
}

// ProxyGitURL constructs the zero-trust Host-Side Git Proxy URL embedding only the ephemeral
// session nonce as Basic Auth password (never a raw GitHub/GitLab token).
func ProxyGitURL(proxyBaseURL, sessionNonce, repoURL string) (string, error) {
	if strings.TrimSpace(proxyBaseURL) == "" {
		return "", fmt.Errorf("proxy base URL is required for remote git bootstrap")
	}
	if strings.HasPrefix(proxyBaseURL, "unix://") {
		return "", fmt.Errorf("git smart-http proxy requires an http:// host proxy endpoint")
	}
	u, err := url.Parse(proxyBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse proxy url: %w", err)
	}
	slug := normalizeGitRepoSlug(repoURL)
	if slug == "" {
		return "", fmt.Errorf("invalid repo url %q", repoURL)
	}
	u.User = url.UserPassword("agentbox", sessionNonce)
	u.Path = strings.TrimRight(u.Path, "/") + "/git/" + slug + ".git"
	return u.String(), nil
}

// BootstrapWorkspace prepares a sandbox workspace for a session:
//   - Remote Git (cold): clones via Host-Side Git Proxy, runs Blueprint setup.commands, creates working branch.
//   - Remote Git (warm snapshot hit): updates origin URL to fresh nonce, runs git fetch, resets/branches cleanly, skips setup.commands.
//   - Local/Greenfield: initializes git if needed, creates working branch, runs setup.commands on cold start.
func BootstrapWorkspace(ctx context.Context, cfg BootstrapConfig) (BootstrapResult, error) {
	if cfg.Blueprint == nil {
		cfg.Blueprint = protocol.DefaultBlueprint("default")
	}
	ws := cfg.WorkspacePath
	if err := os.MkdirAll(ws, 0o755); err != nil {
		return BootstrapResult{}, err
	}

	branchPrefix := cfg.Blueprint.Harness.Git.BranchPrefix
	if branchPrefix == "" {
		branchPrefix = "agentbox/fix-"
	}
	shortID := strings.TrimPrefix(cfg.SessionID, "ses_")
	if len(shortID) > 8 {
		shortID = strings.ToLower(shortID[:8])
	}
	if shortID == "" {
		shortID = "work"
	}
	workBranch := branchPrefix + shortID
	baseBranch := cfg.Repo.BaseBranch

	hasGitDir := false
	if st, err := os.Stat(filepath.Join(ws, ".git")); err == nil && st.IsDir() {
		hasGitDir = true
	}

	result := BootstrapResult{
		Branch:        workBranch,
		ColdBootstrap: !cfg.IsWarmRestore,
	}

	// Sanitized environment for git & setup commands (zero host secrets!).
	cleanEnv := BuildSandboxEnv(AgentRunRequest{
		SessionID:    cfg.SessionID,
		SessionNonce: cfg.SessionNonce,
		ProxyAddr:    cfg.ProxyBaseURL,
		EgressProxy:  cfg.EgressProxy,
	}, ws, "", "")

	if strings.TrimSpace(cfg.Repo.URL) != "" {
		proxyGitURL, err := ProxyGitURL(cfg.ProxyBaseURL, cfg.SessionNonce, cfg.Repo.URL)
		if err != nil {
			return BootstrapResult{}, err
		}

		if !hasGitDir {
			// Cold clone into workspace via Host-Side Git Proxy.
			cloneArgs := []string{"clone"}
			if baseBranch != "" {
				cloneArgs = append(cloneArgs, "--branch", baseBranch)
			}
			cloneArgs = append(cloneArgs, proxyGitURL, ".")
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "git", cloneArgs...); err != nil {
				return BootstrapResult{}, fmt.Errorf("git clone via host proxy: %w", err)
			}
			result.ColdBootstrap = true
		} else {
			// Warm snapshot hit: point origin to fresh session nonce and fetch latest base branch!
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "git", "remote", "set-url", "origin", proxyGitURL); err != nil {
				return BootstrapResult{}, fmt.Errorf("update origin proxy url: %w", err)
			}
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "git", "fetch", "origin"); err != nil {
				return BootstrapResult{}, fmt.Errorf("git fetch via host proxy: %w", err)
			}
			if baseBranch != "" {
				_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "checkout", "-B", workBranch, "origin/"+baseBranch)
			} else {
				_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "checkout", "-B", workBranch)
			}
		}

		_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.name", "AgentBox SWE")
		_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.email", "agentd@agentbox.dev")
		if !hasGitDir {
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "git", "checkout", "-B", workBranch); err != nil {
				return BootstrapResult{}, fmt.Errorf("create working branch %s: %w", workBranch, err)
			}
		}
	} else {
		// Local repo or greenfield fallback.
		if !hasGitDir {
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "git", "init", "-b", "main"); err != nil {
				_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "init")
			}
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.name", "AgentBox SWE")
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.email", "agentd@agentbox.dev")
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "add", "-A")
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "commit", "--allow-empty", "-m", "agentbox: initial workspace state")
		} else {
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.name", "AgentBox SWE")
			_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "config", "user.email", "agentd@agentbox.dev")
		}
		_ = runBootstrapCmd(ctx, ws, cleanEnv, "git", "checkout", "-B", workBranch)
	}

	// Execute Blueprint runtime.setup.commands ONLY on cold bootstrap (warm snapshots already have cached deps).
	if result.ColdBootstrap && len(cfg.Blueprint.Runtime.Setup.Commands) > 0 {
		for _, cmdStr := range cfg.Blueprint.Runtime.Setup.Commands {
			if strings.TrimSpace(cmdStr) == "" {
				continue
			}
			if err := runBootstrapCmd(ctx, ws, cleanEnv, "bash", "-c", cmdStr); err != nil {
				return result, fmt.Errorf("blueprint setup command %q failed: %w", cmdStr, err)
			}
		}
		result.SetupRan = true
	}

	return result, nil
}

func runBootstrapCmd(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), msg, err)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func normalizeGitRepoSlug(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = strings.TrimPrefix(u.Path, "/")
	}
	raw = strings.TrimSuffix(raw, ".git")
	return strings.Trim(raw, "/")
}
