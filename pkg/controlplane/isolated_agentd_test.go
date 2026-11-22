package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

type isolatedScriptedLLM struct {
	mu   sync.Mutex
	turn int
}

func (l *isolatedScriptedLLM) Complete(_ context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	l.mu.Lock()
	t := l.turn
	l.turn++
	l.mu.Unlock()

	usage := protocol.LLMTokenUsage{PromptTokens: 200, CompletionTokens: 60, TotalTokens: 260, CreditsUsed: 1}
	switch t {
	case 0:
		return protocol.LLMCompleteResponse{
			Model:        "scripted-isolated",
			FinishReason: "tool_calls",
			Usage:        usage,
			Message: protocol.LLMMessage{
				Role: "assistant",
				ToolCalls: []protocol.LLMToolCall{
					{
						ID:        "call_env_probe",
						Name:      "shell_exec",
						Arguments: json.RawMessage(`{"command":"env"}`),
					},
					{
						ID:   "call_ci_edit",
						Name: "fs_edit_patch",
						Arguments: json.RawMessage(`{
							"path": ".github/workflows/ci.yml",
							"create": true,
							"content": "name: AgentBox Verified CI\n"
						}`),
					},
				},
			},
		}, nil
	default:
		return protocol.LLMCompleteResponse{
			Model:        "scripted-isolated",
			FinishReason: "stop",
			Usage:        usage,
			Message: protocol.LLMMessage{
				Role:    "assistant",
				Content: "Isolated agentd completed after HITL approval and budget top-up.",
			},
		}, nil
	}
}

func TestIsolatedOutOfProcessAgentDZeroSecretsHITLAndBudgetResume(t *testing.T) {
	// 1. Compile the real static cmd/agentd binary for this test run.
	binPath := filepath.Join(t.TempDir(), "agentd")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/agentd")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/agentd failed: %s (%v)", string(out), err)
	}

	// 2. Plant canary secrets in the host process environment that MUST NOT leak into agentd.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-canary-MUST-NOT-LEAK")
	t.Setenv("AGENTBOX_GIT_TOKEN", "ghp_canary_MUST_NOT_LEAK")

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := NewCreditLedger()
	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: &isolatedScriptedLLM{},
	})
	if err := hostProxy.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer hostProxy.Close(context.Background())

	drv, err := local.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orch := NewOrchestrator(store, ledger, hostProxy, drv)
	orch.AgentDBinary = binPath // Enable real out-of-process isolated agentd execution!

	auth := NewAuthManager("isolated-test-secret", map[string]string{
		"abx_live_iso": "org_iso",
	})
	apiSrv := httptest.NewServer(NewServer(orch, auth))
	defer apiSrv.Close()

	doJSON := func(method, path, token string, body any) *http.Response {
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, apiSrv.URL+path, r)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 3. Register Blueprint requiring HITL approval on .github/workflows/** and max_turns=1 (to trigger budget_paused).
	bpYAML := `
apiVersion: agentbox.dev/v1
kind: Blueprint
metadata:
  name: isolated-bp
  version: "1.0.0"
runtime:
  image: ghcr.io/agentbox/swe-node22-py312:v1
model:
  profile: swe-balanced
policies:
  approvals:
    - action: fs.edit
      match_globs: [".github/workflows/**"]
      mode: require_approval
limits:
  max_credits: 100
  max_turns: 1
`
	putReq, _ := http.NewRequest(http.MethodPut, apiSrv.URL+"/v1/blueprints/isolated-bp", strings.NewReader(bpYAML))
	putReq.Header.Set("Authorization", "Bearer abx_live_iso")
	putReq.Header.Set("Content-Type", "application/yaml")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil || putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT blueprint failed: %v / %v", err, putResp)
	}
	putResp.Body.Close()

	// 4. Create session and mint a scoped Browser Client Token.
	createResp := doJSON(http.MethodPost, "/v1/sessions", "abx_live_iso", protocol.CreateSessionRequest{
		CustomerID: "cust_iso_1",
		Blueprint:  "isolated-bp",
		Task:       "Check env and create CI workflow",
	})
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("POST session failed (%d): %s", createResp.StatusCode, string(b))
	}
	var sess protocol.Session
	_ = json.NewDecoder(createResp.Body).Decode(&sess)
	createResp.Body.Close()

	tokResp := doJSON(http.MethodPost, "/v1/sessions/"+sess.ID+"/client-token", "abx_live_iso", map[string]any{
		"scopes": []string{"read", "steer", "approve"},
	})
	var clientTok protocol.CreateClientTokenResponse
	_ = json.NewDecoder(tokResp.Body).Decode(&clientTok)
	tokResp.Body.Close()

	// 5. Stream SSE events while interactively approving HITL and topping up budget_paused across OS process boundary!
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sseReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiSrv.URL+"/v1/sessions/"+sess.ID+"/events", nil)
	sseReq.Header.Set("Authorization", "Bearer "+clientTok.Token)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil || sseResp.StatusCode != http.StatusOK {
		t.Fatalf("SSE failed: %v / %v", err, sseResp)
	}
	defer sseResp.Body.Close()

	var envOutput strings.Builder
	var sawApproval, sawBudgetPaused, sawCompleted bool

	scanner := bufio.NewScanner(sseResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var evt protocol.Event
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt) != nil {
			continue
		}
		switch evt.Type {
		case protocol.EventTerminalChunk:
			var p protocol.TerminalChunkPayload
			if json.Unmarshal(evt.Payload, &p) == nil {
				envOutput.WriteString(p.Data)
			}
		case protocol.EventApprovalRequired:
			sawApproval = true
			var p protocol.ApprovalRequiredPayload
			_ = json.Unmarshal(evt.Payload, &p)
			go func(aprID string) {
				resp := doJSON(http.MethodPost, "/v1/sessions/"+sess.ID+"/approvals/"+aprID, clientTok.Token, protocol.ResolveApprovalRequest{
					Decision: "approved",
					Feedback: "Approved from test browser client",
				})
				resp.Body.Close()
			}(p.ApprovalID)
		case protocol.EventBudgetExceeded:
			sawBudgetPaused = true
			go func() {
				resp := doJSON(http.MethodPost, "/v1/sessions/"+sess.ID+"/resume", clientTok.Token, protocol.ResumeSessionRequest{
					AddTurns: 5,
				})
				resp.Body.Close()
			}()
		case protocol.EventSessionCompleted:
			sawCompleted = true
		}
	}

	if !sawApproval {
		t.Fatalf("expected HITL approval.required across agentd process boundary")
	}
	if !sawBudgetPaused {
		t.Fatalf("expected graceful budget.exceeded across agentd process boundary")
	}
	if !sawCompleted {
		t.Fatalf("expected session.completed after approval + resume")
	}

	// Verify ZERO-TRUST SECURITY INVARIANT: canary host secrets NEVER entered agentd!
	envDump := envOutput.String()
	if !strings.Contains(envDump, "AGENTBOX_SESSION_NONCE=abx_nonce_") {
		t.Fatalf("expected ephemeral AGENTBOX_SESSION_NONCE inside agentd, got env:\n%s", envDump)
	}
	if strings.Contains(envDump, "sk-ant-canary-MUST-NOT-LEAK") || strings.Contains(envDump, "ghp_canary_MUST_NOT_LEAK") {
		t.Fatalf("SECURITY VIOLATION: host secret leaked into isolated agentd process!\n%s", envDump)
	}

	// Verify unified diff contains the approved .github/workflows/ci.yml file!
	diffResp := doJSON(http.MethodGet, "/v1/sessions/"+sess.ID+"/diff", clientTok.Token, nil)
	var diff protocol.SessionDiffResponse
	_ = json.NewDecoder(diffResp.Body).Decode(&diff)
	diffResp.Body.Close()
	if diff.Stats.FilesChanged < 1 || !strings.Contains(diff.Unified, "AgentBox Verified CI") {
		t.Fatalf("expected diff with .github/workflows/ci.yml, got %+v", diff)
	}
}
