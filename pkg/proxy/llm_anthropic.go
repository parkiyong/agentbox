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
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// AnthropicProvider connects to the Anthropic Messages API (/v1/messages) strictly from the
// host-side LLM Proxy so ANTHROPIC_API_KEY never enters the sandbox.
type AnthropicProvider struct {
	BaseURL      string
	APIKey       string
	APIVersion   string
	ProfileModel map[string]string
	HTTPClient   *http.Client
}

func NewAnthropicProviderFromEnv() *AnthropicProvider {
	baseURL := os.Getenv("ANTHROPIC_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	defaultModel := os.Getenv("AGENTBOX_ANTHROPIC_MODEL")
	if defaultModel == "" {
		defaultModel = "claude-sonnet-4-5"
	}
	return &AnthropicProvider{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     os.Getenv("ANTHROPIC_API_KEY"),
		APIVersion: "2023-06-01",
		ProfileModel: map[string]string{
			"swe-fast":     "claude-haiku-4-5",
			"swe-balanced": defaultModel,
			"swe-max":      "claude-opus-4-5",
		},
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (a *AnthropicProvider) Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	model := a.ProfileModel[req.Profile]
	if model == "" {
		model = "claude-sonnet-4-5"
	}

	var systemParts []string
	var messages []map[string]any

	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if strings.TrimSpace(m.Content) != "" {
				systemParts = append(systemParts, m.Content)
			}
		case "user":
			messages = append(messages, map[string]any{
				"role":    "user",
				"content": m.Content,
			})
		case "assistant":
			var blocks []map[string]any
			if strings.TrimSpace(m.Content) != "" {
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				var inputObj any = map[string]any{}
				if len(tc.Arguments) > 0 {
					_ = json.Unmarshal(tc.Arguments, &inputObj)
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": inputObj,
				})
			}
			if len(blocks) > 0 {
				messages = append(messages, map[string]any{
					"role":    "assistant",
					"content": blocks,
				})
			}
		case "tool":
			toolBlock := map[string]any{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}
			// Merge consecutive tool results into a single user message per Anthropic Messages API spec.
			if len(messages) > 0 && messages[len(messages)-1]["role"] == "user" {
				if existing, ok := messages[len(messages)-1]["content"].([]map[string]any); ok {
					messages[len(messages)-1]["content"] = append(existing, toolBlock)
					continue
				}
			}
			messages = append(messages, map[string]any{
				"role":    "user",
				"content": []map[string]any{toolBlock},
			})
		}
	}

	var tools []map[string]any
	for _, t := range req.Tools {
		schema := t.Parameters
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		tools = append(tools, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": schema,
		})
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 8192
	}
	payload := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}
	if len(systemParts) > 0 {
		payload["system"] = strings.Join(systemParts, "\n\n")
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if req.Temperature > 0 {
		payload["temperature"] = req.Temperature
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	apiVer := a.APIVersion
	if apiVer == "" {
		apiVer = "2023-06-01"
	}
	httpReq.Header.Set("anthropic-version", apiVer)
	if a.APIKey != "" {
		httpReq.Header.Set("x-api-key", a.APIKey)
	}

	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("anthropic status %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("decode anthropic response: %w", err)
	}

	var textParts []string
	var toolCalls []protocol.LLMToolCall
	for _, block := range parsed.Content {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "tool_use":
			args := block.Input
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			toolCalls = append(toolCalls, protocol.LLMToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: args,
			})
		}
	}

	finish := "stop"
	if parsed.StopReason == "tool_use" || len(toolCalls) > 0 {
		finish = "tool_calls"
	} else if parsed.StopReason == "max_tokens" {
		finish = "length"
	}

	return protocol.LLMCompleteResponse{
		Model: parsed.Model,
		Message: protocol.LLMMessage{
			Role:      "assistant",
			Content:   strings.Join(textParts, "\n"),
			ToolCalls: toolCalls,
		},
		FinishReason: finish,
		Usage: protocol.LLMTokenUsage{
			PromptTokens:     parsed.Usage.InputTokens,
			CompletionTokens: parsed.Usage.OutputTokens,
			TotalTokens:      parsed.Usage.InputTokens + parsed.Usage.OutputTokens,
		},
	}, nil
}
