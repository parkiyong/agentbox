package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// WebhookDispatcher delivers HMAC-SHA256 signed canonical events to company webhook endpoints.
type WebhookDispatcher struct {
	HTTPClient *http.Client
	MaxRetries int
}

func NewWebhookDispatcher() *WebhookDispatcher {
	return &WebhookDispatcher{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		MaxRetries: 3,
	}
}

// SignWebhookPayload computes the canonical "sha256=<hex>" HMAC signature header.
func SignWebhookPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (d *WebhookDispatcher) DispatchAsync(webhookURL, secret string, evt protocol.Event) {
	if webhookURL == "" {
		return
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	go func() {
		retries := d.MaxRetries
		if retries <= 0 {
			retries = 1
		}
		for attempt := 0; attempt < retries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
			if err != nil {
				cancel()
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-AgentBox-Event-ID", evt.ID)
			req.Header.Set("X-AgentBox-Event-Type", string(evt.Type))
			req.Header.Set("X-AgentBox-Session-ID", evt.SessionID)
			if secret != "" {
				req.Header.Set("X-AgentBox-Signature", SignWebhookPayload(secret, body))
			}

			resp, err := d.HTTPClient.Do(req)
			cancel()
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return
				}
			}
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		}
	}()
}
