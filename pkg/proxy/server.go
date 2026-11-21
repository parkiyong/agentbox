package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// HostProxyServer hosts the four zero-trust host-side boundary proxies outside the sandbox:
// 1. LLM Proxy (/llm/v1/complete)
// 2. Git & Secret Broker (/git/...)
// 3. MCP Tool Bridge (/mcp/...)
// 4. Egress Firewall (HTTP/CONNECT proxy on a dedicated listener)
type HostProxyServer struct {
	Registry *SessionRegistry
	LLM      *LLMProxy
	Git      *GitBrokerProxy
	MCP      *MCPBridge
	Egress   *EgressFirewall

	apiServer    *http.Server
	egressServer *http.Server
	apiAddr      string
	egressAddr   string
	udsPath      string
}

type Config struct {
	ListenAddr       string // e.g., "127.0.0.1:0" or "unix:///tmp/agentbox-proxy.sock"
	EgressListenAddr string // e.g., "127.0.0.1:0"
	LLMProvider      LLMProvider
	GitBroker        GitTokenBroker
	Secrets          SecretStore
}

func NewHostProxyServer(cfg Config) *HostProxyServer {
	reg := NewSessionRegistry()
	llmProvider := cfg.LLMProvider
	if llmProvider == nil {
		llmProvider = NewMockSWEProvider()
	}
	secrets := cfg.Secrets
	if secrets == nil {
		secrets = NewMapSecretStore(nil)
	}
	s := &HostProxyServer{
		Registry: reg,
		LLM:      NewLLMProxy(reg, llmProvider),
		Git:      NewGitBrokerProxy(reg, cfg.GitBroker),
		MCP:      NewMCPBridge(reg, secrets),
		Egress:   NewEgressFirewall(reg),
	}

	mux := http.NewServeMux()
	mux.Handle("/llm/v1/complete", s.LLM)
	mux.Handle("/git/", s.Git)
	mux.Handle("/mcp/", s.MCP)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	s.apiServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	s.egressServer = &http.Server{
		Handler:           s.Egress,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return s
}

func (s *HostProxyServer) Start(listenAddr, egressListenAddr string) error {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	var apiLn net.Listener
	var err error
	if strings.HasPrefix(listenAddr, "unix://") {
		sockPath := strings.TrimPrefix(listenAddr, "unix://")
		_ = os.Remove(sockPath)
		apiLn, err = net.Listen("unix", sockPath)
		if err != nil {
			return fmt.Errorf("listen proxy uds %s: %w", sockPath, err)
		}
		_ = os.Chmod(sockPath, 0o660)
		s.udsPath = sockPath
		s.apiAddr = listenAddr
	} else {
		apiLn, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("listen proxy api %s: %w", listenAddr, err)
		}
		s.apiAddr = "http://" + apiLn.Addr().String()
	}

	go func() {
		_ = s.apiServer.Serve(apiLn)
	}()

	if egressListenAddr != "" {
		egressLn, err := net.Listen("tcp", egressListenAddr)
		if err != nil {
			_ = s.apiServer.Close()
			return fmt.Errorf("listen egress firewall %s: %w", egressListenAddr, err)
		}
		s.egressAddr = "http://" + egressLn.Addr().String()
		go func() {
			_ = s.egressServer.Serve(egressLn)
		}()
	}
	return nil
}

func (s *HostProxyServer) APIBaseURL() string    { return s.apiAddr }
func (s *HostProxyServer) EgressProxyURL() string { return s.egressAddr }

func (s *HostProxyServer) Close(ctx context.Context) error {
	_ = s.apiServer.Shutdown(ctx)
	_ = s.egressServer.Shutdown(ctx)
	if s.udsPath != "" {
		_ = os.Remove(s.udsPath)
	}
	return nil
}
