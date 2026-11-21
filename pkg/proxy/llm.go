package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// LLMProvider abstracts upstream model inference (Managed Cloud tiers or BYOC BYOK/vLLM).
type LLMProvider interface {
	Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error)
}

// LLMProxy serves POST /llm/v1/complete on the host side, enforcing ephemeral nonce auth,
// credit budget checks, model profile routing, and per-customer token usage metering.
type LLMProxy struct {
	Registry      *SessionRegistry
	DefaultModel  LLMProvider
	BYOCProviders map[string]LLMProvider
	CreditPer1K   map[string]float64 // profile -> credits per 1K tokens
}

func NewLLMProxy(reg *SessionRegistry, defaultProvider LLMProvider) *LLMProxy {
	return &LLMProxy{
		Registry:      reg,
		DefaultModel:  defaultProvider,
		BYOCProviders: make(map[string]LLMProvider),
		CreditPer1K: map[string]float64{
			"swe-fast":     0.5,
			"swe-balanced": 1.5,
			"swe-max":      4.0,
		},
	}
}

func (p *LLMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	binding, ok := p.Registry.Authenticate(r)
	if !ok {
		http.Error(w, "unauthorized session nonce", http.StatusUnauthorized)
		return
	}

	if binding.Budget != nil {
		if err := binding.Budget.CheckCredits(r.Context(), binding.OrgID, binding.CustomerID, binding.SessionID); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "code": "budget_exceeded"})
			return
		}
	}

	var req protocol.LLMCompleteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024*1024)).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid llm request: %v", err), http.StatusBadRequest)
		return
	}
	if req.Profile == "" && binding.Blueprint != nil {
		req.Profile = binding.Blueprint.Model.Profile
	}

	provider := p.DefaultModel
	if binding.Blueprint != nil && binding.Blueprint.Model.BYOCProvider != nil && *binding.Blueprint.Model.BYOCProvider != "" {
		if custom, exists := p.BYOCProviders[*binding.Blueprint.Model.BYOCProvider]; exists {
			provider = custom
		}
	}
	if provider == nil {
		http.Error(w, "no LLM provider configured on host proxy", http.StatusServiceUnavailable)
		return
	}

	resp, err := provider.Complete(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream llm error: %v", err), http.StatusBadGateway)
		return
	}

	// Calculate unified credit cost based on model tier.
	rate := p.CreditPer1K[req.Profile]
	if rate <= 0 {
		rate = 1.5
	}
	if resp.Usage.TotalTokens == 0 {
		resp.Usage.TotalTokens = resp.Usage.PromptTokens + resp.Usage.CompletionTokens
	}
	if resp.Usage.CreditsUsed == 0 {
		resp.Usage.CreditsUsed = (float64(resp.Usage.TotalTokens) / 1000.0) * rate
		if resp.Usage.CreditsUsed < 0.1 {
			resp.Usage.CreditsUsed = 0.1
		}
	}

	if binding.Budget != nil {
		_ = binding.Budget.RecordUsage(r.Context(), binding.OrgID, binding.CustomerID, binding.SessionID, protocol.UsageReportedPayload{
			Model:            resp.Model,
			Profile:          req.Profile,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
			CreditsDelta:     resp.Usage.CreditsUsed,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// OpenAICompatProvider connects to OpenAI, OpenRouter, or self-hosted BYOC vLLM/Ollama endpoints.
type OpenAICompatProvider struct {
	BaseURL      string
	APIKey       string
	ProfileModel map[string]string
	HTTPClient   *http.Client
}

func NewOpenAICompatProviderFromEnv() *OpenAICompatProvider {
	baseURL := os.Getenv("AGENTBOX_LLM_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	apiKey := os.Getenv("AGENTBOX_LLM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	defaultModel := os.Getenv("AGENTBOX_LLM_MODEL")
	if defaultModel == "" {
		defaultModel = "gpt-4o"
	}
	return &OpenAICompatProvider{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		ProfileModel: map[string]string{
			"swe-fast":     "gpt-4o-mini",
			"swe-balanced": defaultModel,
			"swe-max":      defaultModel,
		},
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *OpenAICompatProvider) Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	model := o.ProfileModel[req.Profile]
	if model == "" {
		model = "gpt-4o"
	}

	msgs := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		entry := map[string]any{"role": m.Role, "content": m.Content}
		if m.ToolCallID != "" {
			entry["tool_call_id"] = m.ToolCallID
		}
		if len(m.ToolCalls) > 0 {
			tcs := make([]map[string]any, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				tcs = append(tcs, map[string]any{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]any{
						"name":      tc.Name,
						"arguments": string(tc.Arguments),
					},
				})
			}
			entry["tool_calls"] = tcs
		}
		msgs = append(msgs, entry)
	}

	tools := make([]map[string]any, 0, len(req.Tools))
	for _, t := range req.Tools {
		tools = append(tools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.Parameters,
			},
		})
	}

	payload := map[string]any{
		"model":    model,
		"messages": msgs,
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	bodyBytes, _ := json.Marshal(payload)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)
	}

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("openai-compat status %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("decode llm response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("llm returned zero choices")
	}
	ch := parsed.Choices[0]
	outMsg := protocol.LLMMessage{
		Role:    "assistant",
		Content: ch.Message.Content,
	}
	for _, tc := range ch.Message.ToolCalls {
		outMsg.ToolCalls = append(outMsg.ToolCalls, protocol.LLMToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: json.RawMessage(tc.Function.Arguments),
		})
	}
	return protocol.LLMCompleteResponse{
		Model:        parsed.Model,
		Message:      outMsg,
		FinishReason: ch.FinishReason,
		Usage: protocol.LLMTokenUsage{
			PromptTokens:     parsed.Usage.PromptTokens,
			CompletionTokens: parsed.Usage.CompletionTokens,
			TotalTokens:      parsed.Usage.TotalTokens,
		},
	}, nil
}

// MockSWEProvider provides a deterministic SWE execution loop for local dev, demos, and tests
// without requiring external API keys.
type MockSWEProvider struct {
	mu    sync.Mutex
	steps map[string]int
}

func NewMockSWEProvider() *MockSWEProvider {
	return &MockSWEProvider{steps: make(map[string]int)}
}

func (m *MockSWEProvider) Complete(_ context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	// Derive turn number from assistant messages already present in conversation.
	turn := 0
	for _, msg := range req.Messages {
		if msg.Role == "assistant" {
			turn++
		}
	}

	usage := protocol.LLMTokenUsage{
		PromptTokens:     350 + int64(turn*120),
		CompletionTokens: 110,
		TotalTokens:      460 + int64(turn*120),
		CreditsUsed:      1.0,
	}

	switch turn {
	case 0:
		// Step 1: Emit structured plan + inspect workspace status
		return protocol.LLMCompleteResponse{
			Model:        "agentbox-mock-swe-v1",
			FinishReason: "tool_calls",
			Usage:        usage,
			Message: protocol.LLMMessage{
				Role: "assistant",
				ToolCalls: []protocol.LLMToolCall{
					{
						ID:   "call_plan_1",
						Name: "plan_update",
						Arguments: json.RawMessage(`{
							"summary": "Explore workspace, apply requested change, and verify with tests",
							"steps": [
								{"id":"1","title":"Inspect repository layout and git status","status":"in_progress"},
								{"id":"2","title":"Implement minimal fix and record checkpoint","status":"pending"},
								{"id":"3","title":"Verify changes and summarize diff","status":"pending"}
							]
						}`),
					},
					{
						ID:        "call_git_status",
						Name:      "git_ops",
						Arguments: json.RawMessage(`{"op":"status"}`),
					},
				},
			},
		}, nil
	case 1:
		// Step 2: Create/update an example report/fix file and advance plan
		return protocol.LLMCompleteResponse{
			Model:        "agentbox-mock-swe-v1",
			FinishReason: "tool_calls",
			Usage:        usage,
			Message: protocol.LLMMessage{
				Role: "assistant",
				ToolCalls: []protocol.LLMToolCall{
					{
						ID:   "call_edit_1",
						Name: "fs_edit_patch",
						Arguments: json.RawMessage(`{
							"path": "AGENTBOX_FIX.md",
							"create": true,
							"content": "# AgentBox Automated Fix\n\nVerified autonomous SWE session execution with zero-trust host proxy.\n"
						}`),
					},
					{
						ID:        "call_shell_1",
						Name:      "shell_exec",
						Arguments: json.RawMessage(`{"command":"ls -la"}`),
					},
				},
			},
		}, nil
	default:
		// Step 3: Mark plan complete and finish
		if turn == 2 {
			return protocol.LLMCompleteResponse{
				Model:        "agentbox-mock-swe-v1",
				FinishReason: "tool_calls",
				Usage:        usage,
				Message: protocol.LLMMessage{
					Role: "assistant",
					ToolCalls: []protocol.LLMToolCall{
						{
							ID:   "call_plan_done",
							Name: "plan_update",
							Arguments: json.RawMessage(`{
								"summary": "Completed autonomous SWE task",
								"steps": [
									{"id":"1","title":"Inspect repository layout and git status","status":"completed"},
									{"id":"2","title":"Implement minimal fix and record checkpoint","status":"completed"},
									{"id":"3","title":"Verify changes and summarize diff","status":"completed"}
								]
							}`),
						},
					},
				},
			}, nil
		}
		return protocol.LLMCompleteResponse{
			Model:        "agentbox-mock-swe-v1",
			FinishReason: "stop",
			Usage:        usage,
			Message: protocol.LLMMessage{
				Role:    "assistant",
				Content: "Task completed and verified. Created `AGENTBOX_FIX.md` and recorded shadow git checkpoints.",
			},
		}, nil
	}
}
