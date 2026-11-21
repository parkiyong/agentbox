package proxy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// GitTokenBroker mints short-lived, single-repo-scoped Git credentials ONLY on the host side.
type GitTokenBroker interface {
	MintRepoToken(ctx context.Context, orgID, repoURL string) (username string, token string, err error)
}

// StaticGitTokenBroker supplies a configured PAT/token for local dev (never exposed to sandbox).
type StaticGitTokenBroker struct {
	Username string
	Token    string
}

func (b *StaticGitTokenBroker) MintRepoToken(_ context.Context, _, _ string) (string, string, error) {
	u := b.Username
	if u == "" {
		u = "x-access-token"
	}
	return u, b.Token, nil
}

// GitHubAppTokenBroker signs RS256 GitHub App JWTs on the host and exchanges them for
// single-repository installation access tokens.
type GitHubAppTokenBroker struct {
	AppID          string
	InstallationID string
	PrivateKeyPEM  []byte
	APIBaseURL     string
	HTTPClient     *http.Client
}

func (b *GitHubAppTokenBroker) MintRepoToken(ctx context.Context, _, repoURL string) (string, string, error) {
	jwtToken, err := signRS256AppJWT(b.AppID, b.PrivateKeyPEM, time.Now().UTC())
	if err != nil {
		return "", "", fmt.Errorf("sign github app jwt: %w", err)
	}
	_, repoName := parseOwnerRepo(repoURL)
	apiBase := b.APIBaseURL
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	bodyMap := map[string]any{}
	if repoName != "" {
		bodyMap["repositories"] = []string{repoName}
	}
	bodyBytes, _ := json.Marshal(bodyMap)
	endpoint := fmt.Sprintf("%s/app/installations/%s/access_tokens", strings.TrimRight(apiBase, "/"), b.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	client := b.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("github installation token error (%d): %s", resp.StatusCode, string(respBytes))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBytes, &out); err != nil || out.Token == "" {
		return "", "", fmt.Errorf("decode github installation token: %w", err)
	}
	return "x-access-token", out.Token, nil
}

func signRS256AppJWT(appID string, keyPEM []byte, now time.Time) (string, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("invalid PEM private key")
	}
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if kAny, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
		var ok bool
		priv, ok = kAny.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("private key is not RSA")
		}
	} else {
		return "", fmt.Errorf("parse RSA private key: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	claims := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// GitBrokerProxy proxies Smart HTTP Git requests and PR creation on the host side.
// It enforces: (1) valid session nonce, (2) repo == session.repo, (3) protected branch blocks,
// (4) HITL approval gates on git.push, and (5) host-side token injection only.
type GitBrokerProxy struct {
	Registry    *SessionRegistry
	Broker      GitTokenBroker
	HTTPClient  *http.Client
	UpstreamMap map[string]string // Optional test override mapping normalized repo -> upstream URL
}

func NewGitBrokerProxy(reg *SessionRegistry, broker GitTokenBroker) *GitBrokerProxy {
	return &GitBrokerProxy{
		Registry:    reg,
		Broker:      broker,
		HTTPClient:  &http.Client{Timeout: 60 * time.Second},
		UpstreamMap: make(map[string]string),
	}
}

func (g *GitBrokerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	binding, ok := g.Registry.Authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="agentbox-git-proxy"`)
		http.Error(w, "unauthorized session nonce", http.StatusUnauthorized)
		return
	}

	if r.URL.Path == "/git/pr" && r.Method == http.MethodPost {
		g.handleOpenPR(w, r, binding)
		return
	}

	// Path format: /git/<owner>/<repo>.git/<git-smart-http-tail>
	trimmed := strings.TrimPrefix(r.URL.Path, "/git/")
	idx := strings.Index(trimmed, ".git")
	if idx < 0 {
		http.Error(w, "invalid git proxy path", http.StatusBadRequest)
		return
	}
	reqRepoSlug := normalizeRepoSlug(trimmed[:idx])
	tail := trimmed[idx+4:]

	allowedSlug := normalizeRepoSlug(binding.RepoURL)
	if allowedSlug == "" || !strings.EqualFold(reqRepoSlug, allowedSlug) {
		http.Error(w, fmt.Sprintf("forbidden: repo %q does not match session authorized repo %q", reqRepoSlug, allowedSlug), http.StatusForbidden)
		return
	}

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, 64*1024*1024))
		if err != nil {
			http.Error(w, "failed to read git request body", http.StatusBadRequest)
			return
		}
	}

	isPush := strings.Contains(tail, "git-receive-pack") || r.URL.Query().Get("service") == "git-receive-pack"
	if isPush {
		refs := extractReceivePackRefs(bodyBytes)
		for _, ref := range refs {
			if binding.Blueprint != nil && binding.Blueprint.IsProtectedBranch(ref) {
				http.Error(w, fmt.Sprintf("forbidden: pushing directly to protected branch %q is blocked", ref), http.StatusForbidden)
				return
			}
		}
		// Enforce Blueprint HITL policy on actual push payload (git-receive-pack POST).
		if strings.Contains(tail, "git-receive-pack") && r.Method == http.MethodPost && binding.Blueprint != nil {
			targetRef := strings.Join(refs, ",")
			mode, _ := binding.Blueprint.EvaluatePolicy("git.push", targetRef)
			if mode == protocol.PolicyDeny {
				http.Error(w, "git.push denied by Blueprint policy", http.StatusForbidden)
				return
			}
			if mode == protocol.PolicyRequireApproval && binding.ApprovalGate != nil {
				approved, feedback, err := binding.ApprovalGate.RequestApproval(
					r.Context(),
					binding.SessionID,
					"git.push",
					fmt.Sprintf("Push changes to %s (%s)", allowedSlug, targetRef),
					map[string]any{"repo": allowedSlug, "refs": refs},
				)
				if err != nil {
					http.Error(w, fmt.Sprintf("approval error: %v", err), http.StatusInternalServerError)
					return
				}
				if !approved {
					http.Error(w, fmt.Sprintf("git.push rejected by approver: %s", feedback), http.StatusForbidden)
					return
				}
			}
		}
	}

	upstreamBase := binding.RepoURL
	if override, exists := g.UpstreamMap[strings.ToLower(allowedSlug)]; exists {
		upstreamBase = strings.TrimRight(override, "/")
	} else if !strings.HasSuffix(upstreamBase, ".git") {
		upstreamBase += ".git"
	}
	upstreamURL := upstreamBase + tail
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("build upstream git request: %v", err), http.StatusInternalServerError)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		outReq.Header.Set("Content-Type", ct)
	}
	if acc := r.Header.Get("Accept"); acc != "" {
		outReq.Header.Set("Accept", acc)
	}
	if g.Broker != nil {
		user, token, err := g.Broker.MintRepoToken(r.Context(), binding.OrgID, binding.RepoURL)
		if err != nil {
			http.Error(w, fmt.Sprintf("mint scoped git token: %v", err), http.StatusBadGateway)
			return
		}
		if token != "" {
			outReq.SetBasicAuth(user, token)
		}
	}

	resp, err := g.HTTPClient.Do(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream git error: %v", err), http.StatusBadGateway)
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

func (g *GitBrokerProxy) handleOpenPR(w http.ResponseWriter, r *http.Request, binding *SessionBinding) {
	var req struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid open_pr request", http.StatusBadRequest)
		return
	}
	if req.Base == "" {
		req.Base = "main"
	}
	owner, repo := parseOwnerRepo(binding.RepoURL)
	if owner == "" || repo == "" {
		http.Error(w, "session repo does not support remote PR creation", http.StatusBadRequest)
		return
	}

	// If no token broker or empty token, return a simulated local PR URL in dev mode.
	var token string
	if g.Broker != nil {
		_, tok, err := g.Broker.MintRepoToken(r.Context(), binding.OrgID, binding.RepoURL)
		if err == nil {
			token = tok
		}
	}
	if token == "" {
		pr := protocol.PRCreatedPayload{
			URL:        fmt.Sprintf("https://github.com/%s/%s/pull/1", owner, repo),
			Number:     1,
			Title:      req.Title,
			Branch:     req.Head,
			BaseBranch: req.Base,
		}
		if binding.OnPRCreated != nil {
			binding.OnPRCreated(pr)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pr)
		return
	}

	ghBody, _ := json.Marshal(map[string]string{
		"title": req.Title,
		"body":  req.Body,
		"head":  req.Head,
		"base":  req.Base,
	})
	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", owner, repo), bytes.NewReader(ghBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	apiReq.Header.Set("Authorization", "Bearer "+token)
	apiReq.Header.Set("Accept", "application/vnd.github+json")
	apiReq.Header.Set("Content-Type", "application/json")

	resp, err := g.HTTPClient.Do(apiReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("github open_pr request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		http.Error(w, fmt.Sprintf("github open_pr failed (%d): %s", resp.StatusCode, string(respBytes)), http.StatusBadGateway)
		return
	}
	var ghResp struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
		Title   string `json:"title"`
	}
	_ = json.Unmarshal(respBytes, &ghResp)
	pr := protocol.PRCreatedPayload{
		URL:        ghResp.HTMLURL,
		Number:     ghResp.Number,
		Title:      ghResp.Title,
		Branch:     req.Head,
		BaseBranch: req.Base,
	}
	if binding.OnPRCreated != nil {
		binding.OnPRCreated(pr)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pr)
}

func normalizeRepoSlug(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = strings.TrimPrefix(u.Path, "/")
	}
	raw = strings.TrimSuffix(raw, ".git")
	return strings.Trim(raw, "/")
}

func parseOwnerRepo(raw string) (string, string) {
	slug := normalizeRepoSlug(raw)
	parts := strings.Split(slug, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

var refPattern = regexp.MustCompile(`refs/heads/[A-Za-z0-9._/\-]+`)

// extractReceivePackRefs inspects git-receive-pack pkt-line command headers for target branch refs.
func extractReceivePackRefs(body []byte) []string {
	// Pkt-line command headers appear before the PACK binary header.
	headerRegion := body
	if idx := bytes.Index(body, []byte("PACK")); idx >= 0 {
		headerRegion = body[:idx]
	}
	if len(headerRegion) > 64*1024 {
		headerRegion = headerRegion[:64*1024]
	}
	matches := refPattern.FindAllString(string(headerRegion), -1)
	seen := make(map[string]bool)
	var refs []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			refs = append(refs, m)
		}
	}
	return refs
}
