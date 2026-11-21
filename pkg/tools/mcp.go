package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MCPTool proxies a Blueprint-registered MCP tool call through the Host-Side MCP Bridge.
// Zero raw MCP credentials ever enter the sandbox; only the ephemeral session nonce is sent.
type MCPTool struct {
	ServerName   string
	ToolName     string
	ToolDesc     string
	ToolSchema   map[string]any
	ProxyBaseURL string
	SessionNonce string
	HTTPClient   *http.Client
}

func (t *MCPTool) Name() string {
	return fmt.Sprintf("mcp.%s.%s", t.ServerName, t.ToolName)
}

func (t *MCPTool) Description() string {
	if t.ToolDesc != "" {
		return t.ToolDesc
	}
	return fmt.Sprintf("Call MCP tool %q on server %q via Host-Side MCP Bridge.", t.ToolName, t.ServerName)
}

func (t *MCPTool) Parameters() map[string]any {
	if len(t.ToolSchema) > 0 {
		return t.ToolSchema
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": true,
	}
}

func (t *MCPTool) Execute(ctx context.Context, raw json.RawMessage) (Result, error) {
	if t.ProxyBaseURL == "" {
		return Result{}, fmt.Errorf("MCP proxy base URL not configured")
	}
	var argsMap map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &argsMap)
	}
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      t.ToolName,
			"arguments": argsMap,
		},
	}
	bodyBytes, _ := json.Marshal(reqPayload)
	endpoint := fmt.Sprintf("%s/mcp/%s", strings.TrimRight(t.ProxyBaseURL, "/"), t.ServerName)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AgentBox-Nonce", t.SessionNonce)

	client := t.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("mcp call %s: %w", t.Name(), err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("mcp proxy error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &rpcResp); err == nil {
		if rpcResp.Error != nil {
			return Result{}, fmt.Errorf("mcp tool error (%d): %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		if len(rpcResp.Result) > 0 {
			return Result{Output: string(rpcResp.Result)}, nil
		}
	}
	return Result{Output: string(respBytes)}, nil
}
