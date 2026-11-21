package protocol

import "encoding/json"

// LLMMessage represents a single turn message exchanged with the Host-Side LLM Proxy.
type LLMMessage struct {
	Role       string        `json:"role"` // system | user | assistant | tool
	Content    string        `json:"content,omitempty"`
	ToolCalls  []LLMToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}

// LLMToolDefinition describes a tool exposed to the model.
type LLMToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// LLMToolCall represents a tool invocation requested by the model.
type LLMToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// LLMCompleteRequest is sent from agentd inside the sandbox to the Host-Side LLM Proxy.
// Note: No API keys are ever present in this payload; auth uses the ephemeral session nonce.
type LLMCompleteRequest struct {
	Profile     string              `json:"profile"`
	Messages    []LLMMessage        `json:"messages"`
	Tools       []LLMToolDefinition `json:"tools,omitempty"`
	Temperature float64             `json:"temperature,omitempty"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
}

// LLMTokenUsage reports exact token usage and billed credits from the proxy.
type LLMTokenUsage struct {
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CreditsUsed      float64 `json:"credits_used"`
}

// LLMCompleteResponse is returned by the Host-Side LLM Proxy to agentd.
type LLMCompleteResponse struct {
	Model        string        `json:"model"`
	Message      LLMMessage    `json:"message"`
	FinishReason string        `json:"finish_reason"` // stop | tool_calls | length
	Usage        LLMTokenUsage `json:"usage"`
}
