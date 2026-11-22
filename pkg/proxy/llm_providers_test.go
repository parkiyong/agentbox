package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

func TestAnthropicProviderToolCallRoundTrip(t *testing.T) {
	var gotAPIKey, gotVersion string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "claude-sonnet-4-5",
			"stop_reason": "tool_use",
			"content": [
				{"type": "text", "text": "Checking file first."},
				{"type": "tool_use", "id": "toolu_1", "name": "fs_read", "input": {"path": "main.go"}}
			],
			"usage": {"input_tokens": 500, "output_tokens": 120}
		}`))
	}))
	defer srv.Close()

	provider := &AnthropicProvider{
		BaseURL:      srv.URL,
		APIKey:       "sk-ant-host-only",
		APIVersion:   "2023-06-01",
		ProfileModel: map[string]string{"swe-balanced": "claude-sonnet-4-5"},
	}

	resp, err := provider.Complete(context.Background(), protocol.LLMCompleteRequest{
		Profile: "swe-balanced",
		Messages: []protocol.LLMMessage{
			{Role: "system", Content: "You are an SWE agent."},
			{Role: "user", Content: "Fix bug in main.go"},
		},
		Tools: []protocol.LLMToolDefinition{
			{Name: "fs_read", Description: "Read file", Parameters: map[string]any{"type": "object"}},
		},
	})
	if err != nil {
		t.Fatalf("AnthropicProvider.Complete failed: %v", err)
	}
	if gotAPIKey != "sk-ant-host-only" || gotVersion != "2023-06-01" {
		t.Fatalf("unexpected headers: key=%q ver=%q", gotAPIKey, gotVersion)
	}
	if gotBody["system"] != "You are an SWE agent." {
		t.Fatalf("expected system prompt extracted, got %v", gotBody["system"])
	}
	if resp.FinishReason != "tool_calls" || len(resp.Message.ToolCalls) != 1 || resp.Message.ToolCalls[0].Name != "fs_read" {
		t.Fatalf("unexpected tool calls: %+v", resp)
	}
	if resp.Usage.PromptTokens != 500 || resp.Usage.CompletionTokens != 120 || resp.Usage.TotalTokens != 620 {
		t.Fatalf("unexpected token usage: %+v", resp.Usage)
	}
}

func TestGeminiProviderToolCallRoundTrip(t *testing.T) {
	var gotAPIKey, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-goog-api-key")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"finishReason": "STOP",
				"content": {
					"parts": [
						{"functionCall": {"name": "fs_search", "args": {"query": "TODO"}}}
					]
				}
			}],
			"usageMetadata": {
				"promptTokenCount": 400,
				"candidatesTokenCount": 80,
				"totalTokenCount": 480
			}
		}`))
	}))
	defer srv.Close()

	provider := &GeminiProvider{
		BaseURL:      srv.URL,
		APIKey:       "gemini-host-only-key",
		ProfileModel: map[string]string{"swe-fast": "gemini-2.5-flash"},
	}

	resp, err := provider.Complete(context.Background(), protocol.LLMCompleteRequest{
		Profile: "swe-fast",
		Messages: []protocol.LLMMessage{
			{Role: "system", Content: "SWE system prompt"},
			{Role: "user", Content: "Find TODOs"},
		},
		Tools: []protocol.LLMToolDefinition{
			{
				Name:        "fs_search",
				Description: "Search workspace",
				Parameters:  map[string]any{"type": "object", "additionalProperties": false},
			},
		},
	})
	if err != nil {
		t.Fatalf("GeminiProvider.Complete failed: %v", err)
	}
	if gotAPIKey != "gemini-host-only-key" {
		t.Fatalf("expected x-goog-api-key header, got %q", gotAPIKey)
	}
	if gotPath != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("unexpected gemini path: %q", gotPath)
	}
	if resp.FinishReason != "tool_calls" || len(resp.Message.ToolCalls) != 1 || resp.Message.ToolCalls[0].Name != "fs_search" {
		t.Fatalf("unexpected gemini tool calls: %+v", resp)
	}
	if resp.Usage.TotalTokens != 480 {
		t.Fatalf("unexpected gemini usage: %+v", resp.Usage)
	}
}
