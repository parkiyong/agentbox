package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// MCPBridge mediates sandbox calls to company-provided MCP endpoints.
// It enforces Blueprint server/tool allowlists and injects auth_secret_ref on the host side.
type MCPBridge struct {
	Registry   *SessionRegistry
	Secrets    SecretStore
	HTTPClient *http.Client
}

func NewMCPBridge(reg *SessionRegistry, secrets SecretStore) *MCPBridge {
	return &MCPBridge{
		Registry:   reg,
		Secrets:    secrets,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *MCPBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	binding, ok := m.Registry.Authenticate(r)
	if !ok {
		http.Error(w, "unauthorized session nonce", http.StatusUnauthorized)
		return
	}

	serverName := strings.TrimPrefix(r.URL.Path, "/mcp/")
	serverName = strings.Trim(serverName, "/")
	if serverName == "" || binding.Blueprint == nil {
		http.Error(w, "mcp server not specified", http.StatusBadRequest)
		return
	}

	var srvCfg *protocol.MCPServerConfig
	for i := range binding.Blueprint.MCPServers {
		if binding.Blueprint.MCPServers[i].Name == serverName {
			srvCfg = &binding.Blueprint.MCPServers[i]
			break
		}
	}
	if srvCfg == nil {
		http.Error(w, fmt.Sprintf("mcp server %q not registered in Blueprint", serverName), http.StatusForbidden)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, "failed to read mcp payload", http.StatusBadRequest)
		return
	}

	var rpcReq struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(bodyBytes, &rpcReq); err != nil {
		http.Error(w, "invalid mcp json-rpc body", http.StatusBadRequest)
		return
	}

	if rpcReq.Method == "tools/call" {
		if !isMCPToolAllowed(rpcReq.Params.Name, srvCfg.AllowedTools) {
			http.Error(w, fmt.Sprintf("mcp tool %q is not in allowed_tools for server %q", rpcReq.Params.Name, serverName), http.StatusForbidden)
			return
		}
		// Check Blueprint policy for mcp.<server>.<tool>
		action := fmt.Sprintf("mcp.%s.%s", serverName, rpcReq.Params.Name)
		mode, _ := binding.Blueprint.EvaluatePolicy(action, rpcReq.Params.Name)
		if mode == protocol.PolicyDeny {
			http.Error(w, fmt.Sprintf("mcp action %q denied by policy", action), http.StatusForbidden)
			return
		}
		if mode == protocol.PolicyRequireApproval && binding.ApprovalGate != nil {
			approved, feedback, err := binding.ApprovalGate.RequestApproval(
				r.Context(),
				binding.SessionID,
				action,
				fmt.Sprintf("Invoke MCP tool %s on %s", rpcReq.Params.Name, serverName),
				map[string]any{"server": serverName, "tool": rpcReq.Params.Name},
			)
			if err != nil {
				http.Error(w, "approval gate error", http.StatusInternalServerError)
				return
			}
			if !approved {
				http.Error(w, fmt.Sprintf("mcp call rejected: %s", feedback), http.StatusForbidden)
				return
			}
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, srvCfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "invalid upstream mcp url", http.StatusBadGateway)
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	if srvCfg.AuthSecretRef != "" && m.Secrets != nil {
		secret, err := m.Secrets.GetSecret(r.Context(), srvCfg.AuthSecretRef)
		if err != nil {
			http.Error(w, "failed to resolve mcp secret on host", http.StatusInternalServerError)
			return
		}
		if secret != "" {
			outReq.Header.Set("Authorization", "Bearer "+secret)
		}
	}

	resp, err := m.HTTPClient.Do(outReq)
	if err != nil {
		http.Error(w, "upstream mcp request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Sanitize: copy only Content-Type and body, never leaking upstream auth/set-cookie headers.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 8*1024*1024))
}

func isMCPToolAllowed(tool string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	for _, a := range allowlist {
		if a == "*" || a == tool {
			return true
		}
	}
	return false
}
