package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

func TestControlPlaneEndToEnd(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := NewCreditLedger()
	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: proxy.NewMockSWEProvider(),
	})
	if err := hostProxy.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer hostProxy.Close(context.Background())

	drv, err := local.NewDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orch := NewOrchestrator(store, ledger, hostProxy, drv)
	auth := NewAuthManager("test-jwt-secret", map[string]string{
		"abx_live_acme": "org_acme",
	})
	apiSrv := httptest.NewServer(NewServer(orch, auth))
	defer apiSrv.Close()

	// Webhook receiver verifying HMAC-SHA256 signatures
	var whMu sync.Mutex
	var webhookEvents []string
	whSecret := "whsec_test_123"
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotSig := r.Header.Get("X-AgentBox-Signature")
		wantSig := SignWebhookPayload(whSecret, body)
		if gotSig != wantSig {
			t.Errorf("invalid webhook signature: got %s want %s", gotSig, wantSig)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		whMu.Lock()
		webhookEvents = append(webhookEvents, r.Header.Get("X-AgentBox-Event-Type"))
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	doReq := func(method, path, token string, body []byte, contentType string) *http.Response {
		req, err := http.NewRequest(method, apiSrv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 1. Register Blueprint YAML via PUT /v1/blueprints/{name}
	bpYAML := `
apiVersion: agentbox.dev/v1
kind: Blueprint
metadata:
  name: acme-swe
  version: "1.0.0"
runtime:
  image: ghcr.io/agentbox/swe-node22-py312:v1
model:
  profile: swe-balanced
limits:
  max_credits: 200
  max_turns: 20
`
	resp := doReq(http.MethodPut, "/v1/blueprints/acme-swe", "abx_live_acme", []byte(bpYAML), "application/yaml")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT blueprint failed (%d): %s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// 2. Create Session via POST /v1/sessions
	createBody, _ := json.Marshal(protocol.CreateSessionRequest{
		CustomerID:    "cust_acme_42",
		Blueprint:     "acme-swe",
		Task:          "Create AGENTBOX_FIX.md and verify repo status",
		WebhookURL:    whSrv.URL,
		WebhookSecret: whSecret,
	})
	resp = doReq(http.MethodPost, "/v1/sessions", "abx_live_acme", createBody, "application/json")
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST session failed (%d): %s", resp.StatusCode, string(b))
	}
	var sess protocol.Session
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()

	// 3. Mint short-lived Browser Client Token
	resp = doReq(http.MethodPost, "/v1/sessions/"+sess.ID+"/client-token", "abx_live_acme", []byte(`{"scopes":["read","steer","approve"]}`), "application/json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client-token failed (%d)", resp.StatusCode)
	}
	var tokResp protocol.CreateClientTokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&tokResp)
	resp.Body.Close()
	if tokResp.Token == "" || tokResp.SessionID != sess.ID {
		t.Fatalf("unexpected client token response: %+v", tokResp)
	}

	// 4. Stream SSE events using Browser Client Token until session completes
	sseReq, _ := http.NewRequest(http.MethodGet, apiSrv.URL+"/v1/sessions/"+sess.ID+"/events?token="+tokResp.Token, nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil || sseResp.StatusCode != http.StatusOK {
		t.Fatalf("SSE stream failed: %v / %d", err, sseResp.StatusCode)
	}
	var events []protocol.Event
	scanner := bufio.NewScanner(sseResp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var evt protocol.Event
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt) == nil {
				events = append(events, evt)
			}
		}
	}
	sseResp.Body.Close()
	if len(events) < 5 {
		t.Fatalf("expected >=5 SSE events, got %d", len(events))
	}
	if events[len(events)-1].Type != protocol.EventSessionCompleted {
		t.Fatalf("expected final event session.completed, got %s", events[len(events)-1].Type)
	}

	// 5. Verify Last-Event-ID lossless replay skips earlier events
	midEventID := events[len(events)/2].ID
	replayReq, _ := http.NewRequest(http.MethodGet, apiSrv.URL+"/v1/sessions/"+sess.ID+"/events", nil)
	replayReq.Header.Set("Authorization", "Bearer "+tokResp.Token)
	replayReq.Header.Set("Last-Event-ID", midEventID)
	replayResp, err := http.DefaultClient.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	var replayed []protocol.Event
	rScan := bufio.NewScanner(replayResp.Body)
	for rScan.Scan() {
		line := rScan.Text()
		if strings.HasPrefix(line, "data: ") {
			var evt protocol.Event
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt) == nil {
				replayed = append(replayed, evt)
			}
		}
	}
	replayResp.Body.Close()
	if len(replayed) != len(events)-(len(events)/2)-1 {
		t.Fatalf("expected %d replayed events after %s, got %d", len(events)-(len(events)/2)-1, midEventID, len(replayed))
	}

	// 6. Verify per-customer credit metering
	resp = doReq(http.MethodGet, "/v1/customers/cust_acme_42/usage", "abx_live_acme", nil, "")
	var cu CustomerUsage
	_ = json.NewDecoder(resp.Body).Decode(&cu)
	resp.Body.Close()
	if cu.CreditsUsed <= 0 || cu.SessionsCount != 1 {
		t.Fatalf("unexpected customer usage: %+v", cu)
	}

	// 7. Verify Fork creates a child session and Client Token for parent CANNOT read child!
	resp = doReq(http.MethodPost, "/v1/sessions/"+sess.ID+"/fork", "abx_live_acme", []byte(`{"task":"Explore alternative approach"}`), "application/json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("fork failed (%d)", resp.StatusCode)
	}
	var child protocol.Session
	_ = json.NewDecoder(resp.Body).Decode(&child)
	resp.Body.Close()

	crossResp := doReq(http.MethodGet, "/v1/sessions/"+child.ID, tokResp.Token, nil, "")
	if crossResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when parent client token accesses child session, got %d", crossResp.StatusCode)
	}
	crossResp.Body.Close()

	// 8. Verify signed webhooks arrived
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		whMu.Lock()
		n := len(webhookEvents)
		whMu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	whMu.Lock()
	if len(webhookEvents) == 0 {
		t.Errorf("expected signed webhooks to be delivered")
	}
	whMu.Unlock()
}
