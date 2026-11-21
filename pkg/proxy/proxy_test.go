package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

func TestAntiSSRFAndDomainAllowlist(t *testing.T) {
	blockedIPs := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.5.4",
		"192.168.1.10",
		"169.254.169.254", // AWS/GCP/Azure metadata endpoint
		"100.64.0.1",
		"::1",
		"fe80::1",
	}
	for _, s := range blockedIPs {
		ip := net.ParseIP(s)
		if !IsBlockedSSRFIP(ip, false) {
			t.Errorf("expected IP %s to be blocked by anti-SSRF", s)
		}
	}
	if IsBlockedSSRFIP(net.ParseIP("1.1.1.1"), false) {
		t.Errorf("did not expect public IP 1.1.1.1 to be blocked")
	}

	cfg := protocol.EgressConfig{
		Default:      "deny",
		AllowDomains: []string{"registry.npmjs.org", "*.pythonhosted.org"},
	}
	if !IsDomainAllowed("registry.npmjs.org", cfg) {
		t.Errorf("expected exact allowed domain to pass")
	}
	if !IsDomainAllowed("files.pythonhosted.org", cfg) {
		t.Errorf("expected wildcard allowed domain to pass")
	}
	if IsDomainAllowed("evil-exfil.example.com", cfg) {
		t.Errorf("expected unlisted domain to be denied")
	}
}

type fakeBudget struct {
	exceeded bool
	recorded []protocol.UsageReportedPayload
}

func (f *fakeBudget) CheckCredits(_ context.Context, _, _, _ string) error {
	if f.exceeded {
		return errors.New("credit limit exceeded")
	}
	return nil
}

func (f *fakeBudget) RecordUsage(_ context.Context, _, _, _ string, p protocol.UsageReportedPayload) error {
	f.recorded = append(f.recorded, p)
	return nil
}

func TestHostProxySecurityBoundaries(t *testing.T) {
	// Fake upstream MCP server that checks Authorization header injected ONLY by Host Proxy.
	var receivedMCPAuth string
	mcpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMCPAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"issue":"ERR-412"}}`))
	}))
	defer mcpUpstream.Close()

	// Fake upstream Git server checking injected Basic Auth token.
	var receivedGitUser, receivedGitPass string
	gitUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedGitUser, receivedGitPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("git-ok"))
	}))
	defer gitUpstream.Close()

	bp := protocol.DefaultBlueprint("test-bp")
	bp.MCPServers = []protocol.MCPServerConfig{
		{
			Name:          "sentry",
			Transport:     "streamable-http",
			URL:           mcpUpstream.URL,
			AuthSecretRef: "acme_sentry_token",
			AllowedTools:  []string{"get_issue"},
		},
	}

	secrets := NewMapSecretStore(map[string]string{
		"acme_sentry_token": "super-secret-host-only-token",
	})
	srv := NewHostProxyServer(Config{
		LLMProvider: NewMockSWEProvider(),
		GitBroker:   &StaticGitTokenBroker{Username: "x-access-token", Token: "ghs_host_only_git_token"},
		Secrets:     secrets,
	})
	srv.Git.UpstreamMap["acme/webapp"] = gitUpstream.URL

	if err := srv.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatalf("start host proxy: %v", err)
	}
	defer srv.Close(context.Background())

	nonce, _ := protocol.NewNonce()
	budget := &fakeBudget{}
	srv.Registry.Register(&SessionBinding{
		Nonce:      nonce,
		SessionID:  "ses_test1",
		OrgID:      "org_1",
		CustomerID: "cust_1",
		RepoURL:    "https://github.com/acme/webapp.git",
		Blueprint:  bp,
		Budget:     budget,
	})

	// 1. Missing nonce rejected on LLM proxy
	resp, err := http.Post(srv.APIBaseURL()+"/llm/v1/complete", "application/json", strings.NewReader(`{}`))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without nonce, got %v / %v", resp, err)
	}

	// 2. Valid nonce succeeds on LLM proxy and records credit usage
	llmBody, _ := json.Marshal(protocol.LLMCompleteRequest{
		Profile:  "swe-balanced",
		Messages: []protocol.LLMMessage{{Role: "user", Content: "fix bug"}},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/llm/v1/complete", bytes.NewReader(llmBody))
	req.Header.Set("X-AgentBox-Nonce", nonce)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on LLM proxy, got status=%d err=%v", resp.StatusCode, err)
	}
	if len(budget.recorded) != 1 || budget.recorded[0].CreditsDelta <= 0 {
		t.Fatalf("expected usage recorded in ledger, got %+v", budget.recorded)
	}

	// 3. Budget exceeded blocks LLM call with 402
	budget.exceeded = true
	req, _ = http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/llm/v1/complete", bytes.NewReader(llmBody))
	req.Header.Set("X-AgentBox-Nonce", nonce)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 when budget exceeded, got %d", resp.StatusCode)
	}
	budget.exceeded = false

	// 4. MCP bridge allows allowlisted tool and injects secret ONLY on host side
	mcpReq, _ := http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/mcp/sentry", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_issue"}}`))
	mcpReq.Header.Set("X-AgentBox-Nonce", nonce)
	resp, err = http.DefaultClient.Do(mcpReq)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on allowed MCP tool, got %d / %v", resp.StatusCode, err)
	}
	if receivedMCPAuth != "Bearer super-secret-host-only-token" {
		t.Fatalf("expected host-injected MCP auth header, got %q", receivedMCPAuth)
	}

	// 5. MCP bridge blocks non-allowlisted tool
	mcpDenied, _ := http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/mcp/sentry", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_project"}}`))
	mcpDenied.Header.Set("X-AgentBox-Nonce", nonce)
	resp, _ = http.DefaultClient.Do(mcpDenied)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed MCP tool, got %d", resp.StatusCode)
	}

	// 6. Git proxy blocks repo pivot to another repo
	gitPivot, _ := http.NewRequest(http.MethodGet, srv.APIBaseURL()+"/git/otherorg/secret-repo.git/info/refs", nil)
	gitPivot.Header.Set("X-AgentBox-Nonce", nonce)
	resp, _ = http.DefaultClient.Do(gitPivot)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong repo pivot, got %d", resp.StatusCode)
	}

	// 7. Git proxy blocks push to protected branch "main"
	gitProtected, _ := http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/git/acme/webapp.git/git-receive-pack", strings.NewReader("0000old new refs/heads/main\x00report-status"))
	gitProtected.Header.Set("X-AgentBox-Nonce", nonce)
	resp, _ = http.DefaultClient.Do(gitProtected)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 pushing to protected branch main, got %d", resp.StatusCode)
	}

	// 8. Git proxy allows push to feature branch and injects short-lived host token
	gitAllowed, _ := http.NewRequest(http.MethodPost, srv.APIBaseURL()+"/git/acme/webapp.git/git-receive-pack", strings.NewReader("0000old new refs/heads/agentbox/fix-42\x00report-status"))
	gitAllowed.Header.Set("X-AgentBox-Nonce", nonce)
	resp, err = http.DefaultClient.Do(gitAllowed)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on feature branch push, got %d / %v", resp.StatusCode, err)
	}
	if receivedGitUser != "x-access-token" || receivedGitPass != "ghs_host_only_git_token" {
		t.Fatalf("expected host-injected git credentials, got %q / %q", receivedGitUser, receivedGitPass)
	}
}
