package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// Server exposes the AgentBox Control Plane REST & SSE HTTP API (Section 7 of spec).
type Server struct {
	Orch *Orchestrator
	Auth *AuthManager
	mux  *http.ServeMux
}

func NewServer(orch *Orchestrator, auth *AuthManager) *Server {
	if auth == nil {
		auth = NewAuthManager("", nil)
	}
	s := &Server{
		Orch: orch,
		Auth: auth,
		mux:  http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Permissive CORS headers for white-label @agentbox/react browser integrations.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Last-Event-ID")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("/v1/blueprints", s.handleBlueprintsCollection)
	s.mux.HandleFunc("/v1/blueprints/", s.handleBlueprintItem)
	s.mux.HandleFunc("/v1/sessions", s.handleSessionsCollection)
	s.mux.HandleFunc("/v1/sessions/", s.handleSessionRoutes)
	s.mux.HandleFunc("/v1/customers/", s.handleCustomerUsage)
}

func (s *Server) handleBlueprintsCollection(w http.ResponseWriter, r *http.Request) {
	principal, err := s.Auth.AuthenticateRequest(r)
	if err != nil || !principal.IsOrgKey {
		writeError(w, http.StatusUnauthorized, "org api key required")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	list := s.Orch.Store.ListBlueprints(principal.OrgID)
	writeJSON(w, http.StatusOK, map[string]any{"blueprints": list})
}

func (s *Server) handleBlueprintItem(w http.ResponseWriter, r *http.Request) {
	principal, err := s.Auth.AuthenticateRequest(r)
	if err != nil || !principal.IsOrgKey {
		writeError(w, http.StatusUnauthorized, "org api key required")
		return
	}
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/blueprints/"), "/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "blueprint name is required")
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		var bp *protocol.Blueprint
		// Accept either YAML (application/yaml, text/yaml, raw YAML) or JSON.
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") && len(body) > 0 && body[0] == '{' {
			var parsed protocol.Blueprint
			if err := json.Unmarshal(body, &parsed); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid blueprint json: %v", err))
				return
			}
			if parsed.Metadata.Name == "" {
				parsed.Metadata.Name = name
			}
			parsed.ApplyDefaults()
			if err := parsed.Validate(); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			bp = &parsed
		} else {
			parsed, err := protocol.ParseBlueprintYAML(body)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if parsed.Metadata.Name == "" {
				parsed.Metadata.Name = name
			}
			bp = parsed
		}
		bp.Metadata.Name = name
		s.Orch.Store.PutBlueprint(principal.OrgID, bp)
		writeJSON(w, http.StatusOK, map[string]any{
			"blueprint": bp,
			"hash":      bp.Hash(),
		})

	case http.MethodGet:
		bp, ok := s.Orch.Store.GetBlueprint(principal.OrgID, name)
		if !ok {
			writeError(w, http.StatusNotFound, "blueprint not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"blueprint": bp,
			"hash":      bp.Hash(),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSessionsCollection(w http.ResponseWriter, r *http.Request) {
	principal, err := s.Auth.AuthenticateRequest(r)
	if err != nil || !principal.IsOrgKey {
		writeError(w, http.StatusUnauthorized, "org api key required")
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req protocol.CreateSessionRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1*1024*1024)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}
		sess, err := s.Orch.CreateSession(r.Context(), principal.OrgID, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, sess)

	case http.MethodGet:
		customerID := r.URL.Query().Get("customer_id")
		sessions := s.Orch.Store.ListSessions(principal.OrgID, customerID)
		writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSessionRoutes(w http.ResponseWriter, r *http.Request) {
	principal, err := s.Auth.AuthenticateRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "session id required")
		return
	}
	sessionID := parts[0]

	// Verify session exists and belongs to caller's org.
	sess, ok := s.Orch.Store.GetSession(sessionID)
	if !ok || sess.OrgID != principal.OrgID {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	// GET /v1/sessions/{id}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "read"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, sess)
		return
	}

	sub := parts[1]
	switch sub {
	case "events":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "read"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		s.handleSSEStream(w, r, sessionID)

	case "client-token":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !principal.IsOrgKey {
			writeError(w, http.StatusForbidden, "org api key required to mint client token")
			return
		}
		var req protocol.CreateClientTokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		scopes := req.Scopes
		if len(scopes) == 0 {
			scopes = []string{"read", "steer", "approve"}
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = time.Hour
		}
		tok, exp, err := s.Auth.MintClientToken(sess.OrgID, sess.CustomerID, sess.ID, scopes, ttl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, protocol.CreateClientTokenResponse{
			Token:      tok,
			SessionID:  sess.ID,
			CustomerID: sess.CustomerID,
			Scopes:     scopes,
			ExpiresAt:  exp,
		})

	case "messages":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "steer"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		var req protocol.SendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid message payload")
			return
		}
		if err := s.Orch.SendMessage(sessionID, req); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})

	case "approvals":
		if len(parts) < 3 || r.Method != http.MethodPost {
			writeError(w, http.StatusBadRequest, "POST /v1/sessions/{id}/approvals/{aid} required")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "approve"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		approvalID := parts[2]
		var req protocol.ResolveApprovalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid approval resolution payload")
			return
		}
		if req.Decision != "approved" && req.Decision != "rejected" {
			writeError(w, http.StatusBadRequest, "decision must be 'approved' or 'rejected'")
			return
		}
		if err := s.Orch.ResolveApproval(sessionID, approvalID, req); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "resolved", "decision": req.Decision})

	case "resume":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "approve"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		var req protocol.ResumeSessionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		updated, err := s.Orch.ResumeSession(sessionID, req)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)

	case "fork":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !principal.IsOrgKey {
			writeError(w, http.StatusForbidden, "org api key required to fork session")
			return
		}
		var req protocol.ForkSessionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		child, err := s.Orch.ForkSession(r.Context(), principal.OrgID, sessionID, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, child)

	case "diff":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "read"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if r.URL.Query().Get("format") == "tar" {
			tarPath, err := s.Orch.ArchiveSessionWorkspace(sessionID)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			defer os.Remove(tarPath)
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", sessionID+".tar.gz"))
			http.ServeFile(w, r, tarPath)
			return
		}
		diffResp, err := s.Orch.GetSessionDiff(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, diffResp)

	case "cancel":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := principal.AuthorizeSession(sessionID, "approve"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		updated, err := s.Orch.CancelSession(sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)

	default:
		writeError(w, http.StatusNotFound, "unknown session endpoint")
	}
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request, sessionID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	lastEventID := r.Header.Get("Last-Event-ID")
	if lastEventID == "" {
		lastEventID = r.URL.Query().Get("last_event_id")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	replay, ch, unsub := s.Orch.Store.Subscribe(sessionID, lastEventID)
	defer unsub()

	sendEvent := func(evt protocol.Event) bool {
		data, err := json.Marshal(evt)
		if err != nil {
			return true
		}
		_, _ = fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", evt.ID, evt.Type, string(data))
		flusher.Flush()
		return !isTerminalEvent(evt.Type)
	}

	var lastSeq int64
	for _, evt := range replay {
		lastSeq = evt.Seq
		if !sendEvent(evt) {
			return
		}
	}

	// If session already finished before subscribing, close cleanly.
	if sess, ok := s.Orch.Store.GetSession(sessionID); ok && sess.Status.IsTerminal() {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case evt := <-ch:
			if evt.Seq <= lastSeq {
				continue
			}
			lastSeq = evt.Seq
			if !sendEvent(evt) {
				return
			}
		}
	}
}

func (s *Server) handleCustomerUsage(w http.ResponseWriter, r *http.Request) {
	principal, err := s.Auth.AuthenticateRequest(r)
	if err != nil || !principal.IsOrgKey {
		writeError(w, http.StatusUnauthorized, "org api key required")
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/v1/customers/")
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) < 2 || parts[1] != "usage" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	usage := s.Orch.Ledger.GetCustomerUsage(principal.OrgID, parts[0])
	writeJSON(w, http.StatusOK, usage)
}

func isTerminalEvent(t protocol.EventType) bool {
	return t == protocol.EventSessionCompleted || t == protocol.EventSessionFailed || t == protocol.EventSessionCancelled
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
