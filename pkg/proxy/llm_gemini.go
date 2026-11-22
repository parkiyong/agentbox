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

// GeminiProvider connects to the Google Gemini generateContent REST API strictly from the
// host-side LLM Proxy so GEMINI_API_KEY never enters the sandbox.
type GeminiProvider struct {
	BaseURL      string
	APIKey       string
	ProfileModel map[string]string
	HTTPClient   *http.Client
}

func NewGeminiProviderFromEnv() *GeminiProvider {
	baseURL := os.Getenv("GEMINI_BASE_URL")
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com"
	}
	defaultModel := os.Getenv("AGENTBOX_GEMINI_MODEL")
	if defaultModel == "" {
		defaultModel = "gemini-2.5-pro"
	}
	return &GeminiProvider{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  os.Getenv("GEMINI_API_KEY"),
		ProfileModel: map[string]string{
			"swe-fast":     "gemini-2.5-flash",
			"swe-balanced": defaultModel,
			"swe-max":      defaultModel,
		},
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *GeminiProvider) Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	model := g.ProfileModel[req.Profile]
	if model == "" {
		model = "gemini-2.5-pro"
	}

	var systemParts []string
	var contents []map[string]any

	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if strings.TrimSpace(m.Content) != "" {
				systemParts = append(systemParts, m.Content)
			}
		case "user":
			contents = append(contents, map[string]any{
				"role":  "user",
				"parts": []map[string]any{{"text": m.Content}},
			})
		case "assistant":
			var parts []map[string]any
			if strings.TrimSpace(m.Content) != "" {
				parts = append(parts, map[string]any{"text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var argsObj any = map[string]any{}
				if len(tc.Arguments) > 0 {
					_ = json.Unmarshal(tc.Arguments, &argsObj)
				}
				parts = append(parts, map[string]any{
					"functionCall": map[string]any{
						"name": tc.Name,
						"args": argsObj,
					},
				})
			}
			if len(parts) > 0 {
				contents = append(contents, map[string]any{
					"role":  "model",
					"parts": parts,
				})
			}
		case "tool":
			fnPart := map[string]any{
				"functionResponse": map[string]any{
					"name": m.Name,
					"response": map[string]any{
						"output": m.Content,
					},
				},
			}
			if len(contents) > 0 && contents[len(contents)-1]["role"] == "user" {
				if existing, ok := contents[len(contents)-1]["parts"].([]map[string]any); ok {
					contents[len(contents)-1]["parts"] = append(existing, fnPart)
					continue
				}
			}
			contents = append(contents, map[string]any{
				"role":  "user",
				"parts": []map[string]any{fnPart},
			})
		}
	}

	payload := map[string]any{
		"contents": contents,
	}
	if len(systemParts) > 0 {
		payload["systemInstruction"] = map[string]any{
			"parts": []map[string]any{{"text": strings.Join(systemParts, "\n\n")}},
		}
	}
	if len(req.Tools) > 0 {
		decls := make([]map[string]any, 0, len(req.Tools))
		for _, t := range req.Tools {
			decl := map[string]any{
				"name":        t.Name,
				"description": t.Description,
			}
			if len(t.Parameters) > 0 {
				decl["parameters"] = sanitizeGeminiSchema(t.Parameters)
			}
			decls = append(decls, decl)
		}
		payload["tools"] = []map[string]any{{"functionDeclarations": decls}}
	}
	genCfg := map[string]any{}
	if req.MaxTokens > 0 {
		genCfg["maxOutputTokens"] = req.MaxTokens
	}
	if req.Temperature > 0 {
		genCfg["temperature"] = req.Temperature
	}
	if len(genCfg) > 0 {
		payload["generationConfig"] = genCfg
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent", g.BaseURL, model)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if g.APIKey != "" {
		httpReq.Header.Set("x-goog-api-key", g.APIKey)
	}

	client := g.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("gemini status %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Candidates []struct {
			FinishReason string `json:"finishReason"`
			Content      struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int64 `json:"promptTokenCount"`
			CandidatesTokenCount int64 `json:"candidatesTokenCount"`
			TotalTokenCount      int64 `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("decode gemini response: %w", err)
	}
	if len(parsed.Candidates) == 0 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("gemini returned zero candidates")
	}

	cand := parsed.Candidates[0]
	var textParts []string
	var toolCalls []protocol.LLMToolCall
	for idx, p := range cand.Content.Parts {
		if p.Text != "" {
			textParts = append(textParts, p.Text)
		}
		if p.FunctionCall != nil {
			args := p.FunctionCall.Args
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			toolCalls = append(toolCalls, protocol.LLMToolCall{
				ID:        fmt.Sprintf("gem_call_%d_%s", idx+1, p.FunctionCall.Name),
				Name:      p.FunctionCall.Name,
				Arguments: args,
			})
		}
	}

	finish := "stop"
	if len(toolCalls) > 0 {
		finish = "tool_calls"
	} else if cand.FinishReason == "MAX_TOKENS" {
		finish = "length"
	}
	totalTokens := parsed.UsageMetadata.TotalTokenCount
	if totalTokens == 0 {
		totalTokens = parsed.UsageMetadata.PromptTokenCount + parsed.UsageMetadata.CandidatesTokenCount
	}

	return protocol.LLMCompleteResponse{
		Model: model,
		Message: protocol.LLMMessage{
			Role:      "assistant",
			Content:   strings.Join(textParts, "\n"),
			ToolCalls: toolCalls,
		},
		FinishReason: finish,
		Usage: protocol.LLMTokenUsage{
			PromptTokens:     parsed.UsageMetadata.PromptTokenCount,
			CompletionTokens: parsed.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      totalTokens,
		},
	}, nil
}

// sanitizeGeminiSchema strips JSON Schema fields rejected by Gemini's OpenAPI subset (e.g. additionalProperties).
func sanitizeGeminiSchema(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if k == "additionalProperties" {
			continue
		}
		switch typed := v.(type) {
		case map[string]any:
			out[k] = sanitizeGeminiSchema(typed)
		default:
			out[k] = v
		}
	}
	return out
}
