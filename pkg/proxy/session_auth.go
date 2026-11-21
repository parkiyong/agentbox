package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// ApprovalGate allows host-side proxy actions (like git.push) to pause and request
// human-in-the-loop approval via the Control Plane before executing privileged operations.
type ApprovalGate interface {
	RequestApproval(ctx context.Context, sessionID, action, summary string, details map[string]any) (approved bool, feedback string, err error)
}

// BudgetChecker verifies whether a session/customer still has remaining credit quota.
type BudgetChecker interface {
	CheckCredits(ctx context.Context, orgID, customerID, sessionID string) error
	RecordUsage(ctx context.Context, orgID, customerID, sessionID string, payload protocol.UsageReportedPayload) error
}

// SecretStore resolves host-side secret references (e.g., MCP auth tokens, GitHub App keys).
// Secrets are resolved ONLY on the host and never sent into sandboxes.
type SecretStore interface {
	GetSecret(ctx context.Context, ref string) (string, error)
}

// MapSecretStore is an in-memory SecretStore suitable for local dev and testing.
type MapSecretStore struct {
	mu      sync.RWMutex
	secrets map[string]string
}

func NewMapSecretStore(initial map[string]string) *MapSecretStore {
	cp := make(map[string]string, len(initial))
	for k, v := range initial {
		cp[k] = v
	}
	return &MapSecretStore{secrets: cp}
}

func (s *MapSecretStore) Set(ref, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[ref] = val
}

func (s *MapSecretStore) GetSecret(_ context.Context, ref string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secrets[ref], nil
}

// SessionBinding binds an ephemeral sandbox session nonce to its zero-trust policy context.
type SessionBinding struct {
	Nonce         string
	SessionID     string
	OrgID         string
	CustomerID    string
	RepoURL       string
	Blueprint     *protocol.Blueprint
	Budget        BudgetChecker
	ApprovalGate  ApprovalGate
	OnPRCreated   func(protocol.PRCreatedPayload)
}

// SessionRegistry tracks active session nonces authorized to use this Host Proxy.
type SessionRegistry struct {
	mu       sync.RWMutex
	bindings map[string]*SessionBinding
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		bindings: make(map[string]*SessionBinding),
	}
}

func (r *SessionRegistry) Register(b *SessionBinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings[b.Nonce] = b
}

func (r *SessionRegistry) Unregister(nonce string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bindings, nonce)
}

func (r *SessionRegistry) Authenticate(req *http.Request) (*SessionBinding, bool) {
	nonce := strings.TrimSpace(req.Header.Get("X-AgentBox-Nonce"))
	if nonce == "" {
		if _, pass, ok := req.BasicAuth(); ok && strings.HasPrefix(pass, "abx_nonce_") {
			nonce = pass
		}
	}
	if nonce == "" {
		if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer abx_nonce_") {
			nonce = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if nonce == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bindings[nonce]
	return b, ok
}
