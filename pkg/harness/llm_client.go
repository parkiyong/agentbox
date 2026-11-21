package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// ErrBudgetExceeded is returned by the Host-Side LLM Proxy (HTTP 402) when session or
// customer credit limits are reached.
var ErrBudgetExceeded = errors.New("session credit budget exceeded")

// LLMClient calls the Host-Side LLM Proxy (or an in-process provider in tests).
type LLMClient interface {
	Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error)
}

// ProxyLLMClient communicates with the Host-Side Security Proxy over HTTP or Unix Domain Socket.
// Only the ephemeral AGENTBOX_SESSION_NONCE is transmitted; zero API keys exist in the sandbox.
type ProxyLLMClient struct {
	BaseURL      string
	SessionNonce string
	HTTPClient   *http.Client
}

// NewProxyHTTPClient creates an *http.Client that transparently supports unix:// UDS URLs
// as well as standard http:// URLs.
func NewProxyHTTPClient(proxyAddr string, timeout time.Duration) (*http.Client, string) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if strings.HasPrefix(proxyAddr, "unix://") {
		sockPath := strings.TrimPrefix(proxyAddr, "unix://")
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		}
		return &http.Client{Transport: tr, Timeout: timeout}, "http://agentbox-proxy.internal"
	}
	return &http.Client{Timeout: timeout}, strings.TrimRight(proxyAddr, "/")
}

func NewProxyLLMClient(proxyAddr, sessionNonce string) *ProxyLLMClient {
	client, baseURL := NewProxyHTTPClient(proxyAddr, 120*time.Second)
	return &ProxyLLMClient{
		BaseURL:      baseURL,
		SessionNonce: sessionNonce,
		HTTPClient:   client,
	}
}

func (c *ProxyLLMClient) Complete(ctx context.Context, req protocol.LLMCompleteRequest) (protocol.LLMCompleteResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/llm/v1/complete", bytes.NewReader(bodyBytes))
	if err != nil {
		return protocol.LLMCompleteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-AgentBox-Nonce", c.SessionNonce)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("llm proxy request failed: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusPaymentRequired {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("%w: %s", ErrBudgetExceeded, strings.TrimSpace(string(respBytes)))
	}
	if resp.StatusCode >= 300 {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("llm proxy status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var out protocol.LLMCompleteResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return protocol.LLMCompleteResponse{}, fmt.Errorf("decode llm proxy response: %w", err)
	}
	return out, nil
}
