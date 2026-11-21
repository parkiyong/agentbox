package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// ClientTokenClaims represents a short-lived browser JWT scoped to a single customer session.
type ClientTokenClaims struct {
	OrgID      string   `json:"org_id"`
	CustomerID string   `json:"customer_id"`
	SessionID  string   `json:"session_id"`
	Scopes     []string `json:"scopes"`
	IssuedAt   int64    `json:"iat"`
	ExpiresAt  int64    `json:"exp"`
}

func (c ClientTokenClaims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// AuthManager manages Org API Keys and short-lived HS256 JWT Browser Client Tokens.
type AuthManager struct {
	SigningSecret []byte
	OrgAPIKeys    map[string]string // apiKey -> orgID; if empty, local dev mode allows default org_dev
}

func NewAuthManager(secret string, orgKeys map[string]string) *AuthManager {
	if secret == "" {
		secret = "agentbox-local-dev-jwt-secret"
	}
	return &AuthManager{
		SigningSecret: []byte(secret),
		OrgAPIKeys:    orgKeys,
	}
}

// MintClientToken issues an HS256 JWT scoped strictly to (orgID, customerID, sessionID, scopes).
func (a *AuthManager) MintClientToken(orgID, customerID, sessionID string, scopes []string, ttl time.Duration) (string, time.Time, error) {
	if len(scopes) == 0 {
		scopes = []string{"read", "steer", "approve"}
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, err := json.Marshal(ClientTokenClaims{
		OrgID:      orgID,
		CustomerID: customerID,
		SessionID:  sessionID,
		Scopes:     scopes,
		IssuedAt:   now.Unix(),
		ExpiresAt:  exp.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := header + "." + payload
	sig := a.signHS256(signingInput)
	return signingInput + "." + sig, exp, nil
}

// VerifyClientToken validates signature & expiration of a browser client token.
func (a *AuthManager) VerifyClientToken(token string) (*ClientTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt")
	}
	expectedSig := a.signHS256(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt claims: %w", err)
	}
	var claims ClientTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("client token expired")
	}
	return &claims, nil
}

func (a *AuthManager) signHS256(input string) string {
	mac := hmac.New(sha256.New, a.SigningSecret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// AuthPrincipal represents the authenticated caller (either Company Backend Org Key or Scoped Browser Client Token).
type AuthPrincipal struct {
	IsOrgKey     bool
	OrgID        string
	ClientClaims *ClientTokenClaims
}

// AuthenticateRequest resolves the caller from Authorization: Bearer <token> or ?token=<jwt> (for SSE EventSource).
func (a *AuthManager) AuthenticateRequest(r *http.Request) (*AuthPrincipal, error) {
	rawToken := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		rawToken = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if rawToken == "" {
		rawToken = strings.TrimSpace(r.URL.Query().Get("token"))
	}

	if rawToken == "" {
		// In local dev mode (no OrgAPIKeys configured), allow unauthenticated calls as org_dev.
		if len(a.OrgAPIKeys) == 0 {
			return &AuthPrincipal{IsOrgKey: true, OrgID: "org_dev"}, nil
		}
		return nil, fmt.Errorf("missing Authorization bearer token")
	}

	// Check if token is a registered Org API key.
	if orgID, ok := a.OrgAPIKeys[rawToken]; ok {
		return &AuthPrincipal{IsOrgKey: true, OrgID: orgID}, nil
	}

	// Otherwise check if it's a signed Browser Client Token JWT.
	if strings.Count(rawToken, ".") == 2 {
		claims, err := a.VerifyClientToken(rawToken)
		if err != nil {
			return nil, err
		}
		return &AuthPrincipal{
			IsOrgKey:     false,
			OrgID:        claims.OrgID,
			ClientClaims: claims,
		}, nil
	}

	// In local dev mode with no configured keys, accept any abx_dev_* key as org_dev.
	if len(a.OrgAPIKeys) == 0 && strings.HasPrefix(rawToken, "abx_") {
		return &AuthPrincipal{IsOrgKey: true, OrgID: "org_dev"}, nil
	}

	return nil, fmt.Errorf("invalid credentials")
}

// AuthorizeSession verifies the caller may access sessionID with the required scope.
func (p *AuthPrincipal) AuthorizeSession(sessionID, requiredScope string) error {
	if p.IsOrgKey {
		return nil
	}
	if p.ClientClaims == nil {
		return fmt.Errorf("unauthorized")
	}
	if p.ClientClaims.SessionID != sessionID {
		return fmt.Errorf("client token not authorized for session %s", sessionID)
	}
	if requiredScope != "" && !p.ClientClaims.HasScope(requiredScope) {
		return fmt.Errorf("client token missing required scope %q", requiredScope)
	}
	return nil
}
