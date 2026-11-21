package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// EgressFirewall is a host-side HTTP/HTTPS CONNECT proxy enforcing per-Blueprint domain
// allowlists and strict Anti-SSRF IP filtering (blocking RFC1918, loopback, and cloud metadata IPs).
type EgressFirewall struct {
	Registry       *SessionRegistry
	DefaultEgress  protocol.EgressConfig
	AllowLoopback  bool // Only true in explicit local unit tests; always false in production
	DialTimeout    time.Duration
}

func NewEgressFirewall(reg *SessionRegistry) *EgressFirewall {
	return &EgressFirewall{
		Registry:      reg,
		DefaultEgress: protocol.EgressConfig{Default: "deny"},
		DialTimeout:   15 * time.Second,
	}
}

func (fw *EgressFirewall) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	egressCfg := fw.resolveEgressConfig(r)

	if r.Method == http.MethodConnect {
		fw.handleConnect(w, r, egressCfg)
		return
	}
	fw.handleHTTP(w, r, egressCfg)
}

func (fw *EgressFirewall) resolveEgressConfig(r *http.Request) protocol.EgressConfig {
	// Support Proxy-Authorization: Basic base64("agentbox:<nonce>") or X-AgentBox-Nonce.
	if b, ok := fw.Registry.Authenticate(r); ok && b.Blueprint != nil {
		return b.Blueprint.Network.Egress
	}
	if proxyAuth := r.Header.Get("Proxy-Authorization"); strings.HasPrefix(proxyAuth, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(raw), ":", 2)
			if len(parts) == 2 {
				reqCopy := r.Clone(r.Context())
				reqCopy.Header.Set("X-AgentBox-Nonce", parts[1])
				if b, ok := fw.Registry.Authenticate(reqCopy); ok && b.Blueprint != nil {
					return b.Blueprint.Network.Egress
				}
			}
		}
	}
	return fw.DefaultEgress
}

func (fw *EgressFirewall) handleConnect(w http.ResponseWriter, r *http.Request, cfg protocol.EgressConfig) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}
	if !IsDomainAllowed(host, cfg) {
		http.Error(w, fmt.Sprintf("egress denied by Blueprint policy for host %q", host), http.StatusForbidden)
		return
	}
	targetConn, err := fw.safeDialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, fmt.Sprintf("egress dial blocked or failed: %v", err), http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(clientConn, targetConn)
	}()
}

func (fw *EgressFirewall) handleHTTP(w http.ResponseWriter, r *http.Request, cfg protocol.EgressConfig) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if !IsDomainAllowed(host, cfg) {
		http.Error(w, fmt.Sprintf("egress denied by Blueprint policy for host %q", host), http.StatusForbidden)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("X-AgentBox-Nonce")

	transport := &http.Transport{
		DialContext: fw.safeDialContext,
	}
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("egress request blocked or failed: %v", err), http.StatusForbidden)
		return
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// IsDomainAllowed enforces Blueprint egress allowlists (default deny).
func IsDomainAllowed(host string, cfg protocol.EgressConfig) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Never allow raw IP literals when default is deny unless explicitly listed.
	for _, allowed := range cfg.AllowDomains {
		pattern := strings.ToLower(strings.TrimSpace(allowed))
		if pattern == "" {
			continue
		}
		if pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return strings.EqualFold(cfg.Default, "allow")
}

// safeDialContext resolves DNS and verifies every target IP against Anti-SSRF blocks
// BEFORE opening the TCP connection (defeating DNS rebinding and metadata IP attacks).
func (fw *EgressFirewall) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []net.IP{parsed}
	} else {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("dns lookup %q: %w", host, err)
		}
		for _, r := range resolved {
			ips = append(ips, r.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses resolved for %q", host)
	}

	var allowedIP net.IP
	for _, ip := range ips {
		if IsBlockedSSRFIP(ip, fw.AllowLoopback) {
			return nil, fmt.Errorf("anti-SSRF blocked destination IP %s for host %q", ip.String(), host)
		}
		if allowedIP == nil {
			allowedIP = ip
		}
	}
	dialer := &net.Dialer{Timeout: fw.DialTimeout}
	return dialer.DialContext(ctx, network, net.JoinHostPort(allowedIP.String(), port))
}

// IsBlockedSSRFIP returns true for loopback, RFC1918 private, link-local / cloud metadata
// (169.254.169.254), CGNAT (100.64.0.0/10), multicast, and unspecified IP addresses.
func IsBlockedSSRFIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Explicitly block 169.254.0.0/16 (AWS/GCP/Azure metadata) and 100.64.0.0/10 (CGNAT) and 0.0.0.0/8.
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 0 {
			return true
		}
	}
	return false
}
