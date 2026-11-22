package proxy

import "os"

// NewAutoProviderFromEnv selects the appropriate host-side LLMProvider based on configured
// host environment credentials, falling back to MockSWEProvider when forceMock is true or no
// provider keys are configured.
func NewAutoProviderFromEnv(forceMock bool) (LLMProvider, string) {
	if forceMock {
		return NewMockSWEProvider(), "mock (MockSWEProvider)"
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return NewAnthropicProviderFromEnv(), "anthropic (/v1/messages)"
	}
	if os.Getenv("GEMINI_API_KEY") != "" {
		return NewGeminiProviderFromEnv(), "gemini (generateContent)"
	}
	if os.Getenv("AGENTBOX_LLM_API_KEY") != "" || os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("AGENTBOX_LLM_BASE_URL") != "" {
		p := NewOpenAICompatProviderFromEnv()
		return p, "openai-compat (" + p.BaseURL + ")"
	}
	return NewMockSWEProvider(), "mock (no host LLM key configured)"
}

// RegisterBYOCProvidersFromEnv wires named BYOC providers ("anthropic-byok", "gemini-byok",
// "openai-byok", "local-vllm") onto an LLMProxy when their host env vars are present.
func RegisterBYOCProvidersFromEnv(p *LLMProxy) {
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		p.BYOCProviders["anthropic-byok"] = NewAnthropicProviderFromEnv()
	}
	if os.Getenv("GEMINI_API_KEY") != "" {
		p.BYOCProviders["gemini-byok"] = NewGeminiProviderFromEnv()
	}
	if os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("AGENTBOX_LLM_API_KEY") != "" {
		p.BYOCProviders["openai-byok"] = NewOpenAICompatProviderFromEnv()
	}
	if vllmURL := os.Getenv("AGENTBOX_VLLM_BASE_URL"); vllmURL != "" {
		p.BYOCProviders["local-vllm"] = &OpenAICompatProvider{
			BaseURL: vllmURL,
			APIKey:  os.Getenv("AGENTBOX_VLLM_API_KEY"),
			ProfileModel: map[string]string{
				"swe-fast":     os.Getenv("AGENTBOX_VLLM_MODEL"),
				"swe-balanced": os.Getenv("AGENTBOX_VLLM_MODEL"),
				"swe-max":      os.Getenv("AGENTBOX_VLLM_MODEL"),
			},
		}
	}
}
