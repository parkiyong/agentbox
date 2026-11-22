package sandbox_test

import (
	"context"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox"
	"github.com/parkiyong/agentbox/pkg/sandbox/docker"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

func TestDockerDriverBuildExecArgs(t *testing.T) {
	drv, err := docker.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	args := drv.BuildExecArgs("cid_123", sandbox.AgentRunRequest{
		SessionID:    "ses_1",
		CustomerID:   "cust_1",
		Task:         "fix bug",
		SessionNonce: "abx_nonce_1",
	}, "/tmp/.agentbox-blueprint.json", `{"max_turns":10}`)

	for _, want := range []string{
		"exec", "-i",
		"AGENTBOX_SESSION_NONCE=abx_nonce_1",
		"AGENTBOX_BLUEPRINT_PATH=/tmp/.agentbox-blueprint.json",
		"cid_123",
		"/opt/agentbox/agentd",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("docker exec args missing %q: %v", want, args)
		}
	}
}

func TestBootstrapWorkspaceRealSmartHTTPGitProxyAndWarmCache(t *testing.T) {
	gitExecPathBytes, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git not available")
	}
	backendBin := filepath.Join(strings.TrimSpace(string(gitExecPathBytes)), "git-http-backend")
	if _, err := os.Stat(backendBin); err != nil {
		t.Skip("git-http-backend not installed")
	}

	// 1. Create a real bare git repository on disk with an initial commit on main.
	gitRoot := t.TempDir()
	bareRepo := filepath.Join(gitRoot, "acme", "webapp.git")
	if err := os.MkdirAll(filepath.Dir(bareRepo), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(dir string, name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v failed: %s (%v)", name, args, string(out), err)
		}
	}

	run(gitRoot, "git", "init", "--bare", "-b", "main", bareRepo)
	seedDir := t.TempDir()
	run(seedDir, "git", "init", "-b", "main")
	run(seedDir, "git", "config", "user.name", "Seed")
	run(seedDir, "git", "config", "user.email", "seed@example.com")
	_ = os.WriteFile(filepath.Join(seedDir, "README.md"), []byte("# Acme Webapp\n"), 0o644)
	run(seedDir, "git", "add", ".")
	run(seedDir, "git", "commit", "-m", "initial commit")
	run(seedDir, "git", "remote", "add", "origin", bareRepo)
	run(seedDir, "git", "push", "-u", "origin", "main")
	run(bareRepo, "git", "config", "http.receivepack", "true")

	// 2. Serve the bare repo over Smart HTTP requiring host-only Basic Auth credentials!
	var sawHostAuth bool
	upstreamGit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "x-access-token" || pass != "ghs_real_host_only_token" {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sawHostAuth = true
		h := &cgi.Handler{
			Path: backendBin,
			Env: []string{
				"GIT_PROJECT_ROOT=" + gitRoot,
				"GIT_HTTP_EXPORT_ALL=1",
				"REMOTE_USER=" + user,
			},
		}
		h.ServeHTTP(w, r)
	}))
	defer upstreamGit.Close()

	// 3. Start Host-Side Security Proxy pointing acme/webapp -> upstreamGit.
	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		GitBroker: &proxy.StaticGitTokenBroker{
			Username: "x-access-token",
			Token:    "ghs_real_host_only_token",
		},
	})
	hostProxy.Git.UpstreamMap["acme/webapp"] = upstreamGit.URL + "/acme/webapp.git"
	if err := hostProxy.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer hostProxy.Close(context.Background())

	bp := protocol.DefaultBlueprint("git-test-bp")
	bp.Runtime.Setup.Commands = []string{
		"echo warm-dep-ready > .cached-deps",
	}

	nonce1, _ := protocol.NewNonce()
	hostProxy.Registry.Register(&proxy.SessionBinding{
		Nonce:      nonce1,
		SessionID:  "ses_cold1",
		OrgID:      "org_1",
		CustomerID: "cust_1",
		RepoURL:    "https://github.com/acme/webapp.git",
		Blueprint:  bp,
	})

	// 4. Cold Bootstrap: clones via Host Proxy (zero raw tokens!), runs setup.commands, creates feature branch.
	drv, err := local.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h1, err := drv.Create(ctx, sandbox.SandboxSpec{SessionID: "ses_cold1", WorkspaceID: "wksp_acme"})
	if err != nil {
		t.Fatal(err)
	}

	res1, err := sandbox.BootstrapWorkspace(ctx, sandbox.BootstrapConfig{
		WorkspacePath: h1.WorkspacePath,
		SessionID:     "ses_cold1",
		Repo:          protocol.RepoSpec{URL: "https://github.com/acme/webapp.git", BaseBranch: "main"},
		Blueprint:     bp,
		ProxyBaseURL:  hostProxy.APIBaseURL(),
		SessionNonce:  nonce1,
		IsWarmRestore: false,
	})
	if err != nil {
		t.Fatalf("cold BootstrapWorkspace failed: %v", err)
	}
	if !res1.ColdBootstrap || !res1.SetupRan {
		t.Fatalf("expected cold bootstrap with setup run, got %+v", res1)
	}
	if !sawHostAuth {
		t.Fatalf("expected upstream git to receive host-injected credentials")
	}
	if _, err := os.Stat(filepath.Join(h1.WorkspacePath, "README.md")); err != nil {
		t.Fatalf("cloned README.md missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h1.WorkspacePath, ".cached-deps")); err != nil {
		t.Fatalf("setup.commands artifact .cached-deps missing: %v", err)
	}

	// Verify origin URL inside workspace contains ONLY ephemeral nonce, NEVER the host token!
	originURLBytes, _ := exec.Command("git", "-C", h1.WorkspacePath, "remote", "get-url", "origin").Output()
	if strings.Contains(string(originURLBytes), "ghs_real_host_only_token") {
		t.Fatalf("SECURITY VIOLATION: raw host git token found in workspace .git/config!")
	}

	// Verify real `git push` to feature branch succeeds through Host-Side Git Broker!
	_ = os.WriteFile(filepath.Join(h1.WorkspacePath, "fix.txt"), []byte("fixed\n"), 0o644)
	run(h1.WorkspacePath, "git", "add", "fix.txt")
	run(h1.WorkspacePath, "git", "commit", "-m", "apply fix")
	run(h1.WorkspacePath, "git", "push", "-u", "origin", res1.Branch)

	// Verify pushing directly to protected branch `main` is BLOCKED by Host-Side Git Broker!
	pushMain := exec.Command("git", "-C", h1.WorkspacePath, "push", "origin", "HEAD:refs/heads/main")
	if out, err := pushMain.CombinedOutput(); err == nil {
		t.Fatalf("expected push to protected branch main to fail, succeeded: %s", string(out))
	}

	// 5. Take warm workspace snapshot and restore into session 2 (warm hit skips setup.commands!).
	snap, err := drv.Snapshot(ctx, h1, "wksp_acme")
	if err != nil {
		t.Fatal(err)
	}
	nonce2, _ := protocol.NewNonce()
	hostProxy.Registry.Register(&proxy.SessionBinding{
		Nonce:      nonce2,
		SessionID:  "ses_warm2",
		OrgID:      "org_1",
		CustomerID: "cust_1",
		RepoURL:    "https://github.com/acme/webapp.git",
		Blueprint:  bp,
	})
	h2, err := drv.Restore(ctx, snap, sandbox.SandboxSpec{SessionID: "ses_warm2", WorkspaceID: "wksp_acme"})
	if err != nil {
		t.Fatal(err)
	}
	res2, err := sandbox.BootstrapWorkspace(ctx, sandbox.BootstrapConfig{
		WorkspacePath: h2.WorkspacePath,
		SessionID:     "ses_warm2",
		Repo:          protocol.RepoSpec{URL: "https://github.com/acme/webapp.git", BaseBranch: "main"},
		Blueprint:     bp,
		ProxyBaseURL:  hostProxy.APIBaseURL(),
		SessionNonce:  nonce2,
		IsWarmRestore: true,
	})
	if err != nil {
		t.Fatalf("warm BootstrapWorkspace failed: %v", err)
	}
	if res2.ColdBootstrap || res2.SetupRan {
		t.Fatalf("expected warm snapshot hit to skip setup.commands, got %+v", res2)
	}
	if _, err := os.Stat(filepath.Join(h2.WorkspacePath, ".cached-deps")); err != nil {
		t.Fatalf("expected warm cached deps to survive restore: %v", err)
	}
}
