package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
)

func TestEngineFullSWELoopViaHostProxy(t *testing.T) {
	ws := t.TempDir()
	srv := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: proxy.NewMockSWEProvider(),
	})
	if err := srv.Start("127.0.0.1:0", ""); err != nil {
		t.Fatalf("start host proxy: %v", err)
	}
	defer srv.Close(context.Background())

	bp := protocol.DefaultBlueprint("test-swe")
	nonce, _ := protocol.NewNonce()
	srv.Registry.Register(&proxy.SessionBinding{
		Nonce:      nonce,
		SessionID:  "ses_harness1",
		OrgID:      "org_1",
		CustomerID: "cust_1",
		Blueprint:  bp,
	})

	var mu sync.Mutex
	seenTypes := make(map[protocol.EventType]int)

	engine := NewEngine(EngineConfig{
		SessionID:    "ses_harness1",
		CustomerID:   "cust_1",
		Workspace:    ws,
		Task:         "Create a verification document and check workspace status",
		Blueprint:    bp,
		ProxyAddr:    srv.APIBaseURL(),
		SessionNonce: nonce,
		LLM:          NewProxyLLMClient(srv.APIBaseURL(), nonce),
		OnEvent: func(evt protocol.Event) {
			mu.Lock()
			seenTypes[evt.Type]++
			mu.Unlock()
		},
	})

	summary, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if summary == "" {
		t.Fatalf("expected non-empty completion summary")
	}
	if _, err := os.Stat(filepath.Join(ws, "AGENTBOX_FIX.md")); err != nil {
		t.Fatalf("expected AGENTBOX_FIX.md to be created: %v", err)
	}

	for _, required := range []protocol.EventType{
		protocol.EventSessionRunning,
		protocol.EventPlanUpdated,
		protocol.EventCheckpointCreated,
		protocol.EventFileDiff,
		protocol.EventTerminalChunk,
		protocol.EventUsageReported,
		protocol.EventSessionCompleted,
	} {
		if seenTypes[required] == 0 {
			t.Errorf("expected event %q to be emitted, got map=%v", required, seenTypes)
		}
	}
}

type scriptedLLM struct {
	mu        sync.Mutex
	responses []protocol.LLMCompleteResponse
	idx       int
}

func (s *scriptedLLM) Complete(_ context.Context, _ protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx >= len(s.responses) {
		return protocol.LLMCompleteResponse{
			Model:        "scripted",
			FinishReason: "stop",
			Message:      protocol.LLMMessage{Role: "assistant", Content: "Done."},
			Usage:        protocol.LLMTokenUsage{TotalTokens: 100, CreditsUsed: 1},
		}, nil
	}
	r := s.responses[s.idx]
	s.idx++
	return r, nil
}

func TestEngineHITLApprovalAndBudgetPauseResume(t *testing.T) {
	ws := t.TempDir()
	bp := protocol.DefaultBlueprint("policy-test")
	bp.Policies.Approvals = []protocol.ApprovalRule{
		{
			Action:     "fs.edit",
			MatchGlobs: []string{".github/workflows/**"},
			Mode:       protocol.PolicyRequireApproval,
		},
	}
	bp.Limits.MaxTurns = 1 // Force graceful budget_paused after turn 1

	llm := &scriptedLLM{
		responses: []protocol.LLMCompleteResponse{
			{
				Model:        "scripted",
				FinishReason: "tool_calls",
				Usage:        protocol.LLMTokenUsage{TotalTokens: 200, CreditsUsed: 2},
				Message: protocol.LLMMessage{
					Role: "assistant",
					ToolCalls: []protocol.LLMToolCall{
						{
							ID:   "call_ci_edit",
							Name: "fs_edit_patch",
							Arguments: json.RawMessage(`{
								"path": ".github/workflows/ci.yml",
								"create": true,
								"content": "name: CI\n"
							}`),
						},
					},
				},
			},
			{
				Model:        "scripted",
				FinishReason: "stop",
				Usage:        protocol.LLMTokenUsage{TotalTokens: 100, CreditsUsed: 1},
				Message:      protocol.LLMMessage{Role: "assistant", Content: "CI workflow updated after approval and budget top-up."},
			},
		},
	}

	var engine *Engine
	approvalSeen := make(chan string, 1)
	budgetPausedSeen := make(chan struct{}, 1)

	engine = NewEngine(EngineConfig{
		SessionID:  "ses_hitl",
		CustomerID: "cust_1",
		Workspace:  ws,
		Task:       "Create CI workflow",
		Blueprint:  bp,
		Limits:     bp.Limits,
		LLM:        llm,
		OnEvent: func(evt protocol.Event) {
			if evt.Type == protocol.EventApprovalRequired {
				var p protocol.ApprovalRequiredPayload
				_ = json.Unmarshal(evt.Payload, &p)
				approvalSeen <- p.ApprovalID
			}
			if evt.Type == protocol.EventBudgetExceeded {
				budgetPausedSeen <- struct{}{}
			}
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := engine.Run(ctx)
		done <- err
	}()

	// 1. Wait for HITL approval required on .github/workflows/ci.yml and approve it
	select {
	case aprID := <-approvalSeen:
		engine.SendControl(ControlMessage{Kind: "approval", ApprovalID: aprID, Approved: true})
	case <-ctx.Done():
		t.Fatalf("timed out waiting for approval.required event")
	}

	// 2. Wait for graceful budget_paused on max_turns=1 and top-up + resume
	select {
	case <-budgetPausedSeen:
		engine.SendControl(ControlMessage{Kind: "resume", AddTurns: 5})
	case <-ctx.Done():
		t.Fatalf("timed out waiting for budget.exceeded event")
	}

	if err := <-done; err != nil {
		t.Fatalf("engine failed after approval & resume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ws, ".github", "workflows", "ci.yml")); err != nil {
		t.Fatalf("expected .github/workflows/ci.yml to exist: %v", err)
	}
}
