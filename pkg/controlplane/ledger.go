package controlplane

import (
	"context"
	"fmt"
	"sync"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// CustomerUsage aggregates compute & LLM credit metering per end-customer (`customer_id`).
type CustomerUsage struct {
	OrgID            string  `json:"org_id"`
	CustomerID       string  `json:"customer_id"`
	CreditsUsed      float64 `json:"credits_used"`
	CreditsCap       float64 `json:"credits_cap,omitempty"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	SessionsCount    int     `json:"sessions_count"`
}

// CreditLedger enforces unified credits and per-session / per-customer hard caps.
// Implements proxy.BudgetChecker directly.
type CreditLedger struct {
	mu             sync.RWMutex
	customerUsage  map[string]*CustomerUsage // key: orgID + ":" + customerID
	sessionCredits map[string]float64        // key: sessionID
	sessionCaps    map[string]float64        // key: sessionID
}

func NewCreditLedger() *CreditLedger {
	return &CreditLedger{
		customerUsage:  make(map[string]*CustomerUsage),
		sessionCredits: make(map[string]float64),
		sessionCaps:    make(map[string]float64),
	}
}

func (l *CreditLedger) SetCustomerCap(orgID, customerID string, capCredits float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cu := l.getOrCreateCustomerLocked(orgID, customerID)
	cu.CreditsCap = capCredits
}

func (l *CreditLedger) RegisterSession(orgID, customerID, sessionID string, maxCredits float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cu := l.getOrCreateCustomerLocked(orgID, customerID)
	cu.SessionsCount++
	l.sessionCaps[sessionID] = maxCredits
}

func (l *CreditLedger) ExtendSessionCredits(sessionID string, addCredits float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessionCaps[sessionID] += addCredits
}

func (l *CreditLedger) CheckCredits(_ context.Context, orgID, customerID, sessionID string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if capVal := l.sessionCaps[sessionID]; capVal > 0 && l.sessionCredits[sessionID] >= capVal {
		return fmt.Errorf("session %s reached hard credit cap (%.2f / %.2f)", sessionID, l.sessionCredits[sessionID], capVal)
	}
	if cu, ok := l.customerUsage[orgID+":"+customerID]; ok {
		if cu.CreditsCap > 0 && cu.CreditsUsed >= cu.CreditsCap {
			return fmt.Errorf("customer %s reached hard credit cap (%.2f / %.2f)", customerID, cu.CreditsUsed, cu.CreditsCap)
		}
	}
	return nil
}

func (l *CreditLedger) RecordUsage(_ context.Context, orgID, customerID, sessionID string, payload protocol.UsageReportedPayload) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessionCredits[sessionID] += payload.CreditsDelta
	cu := l.getOrCreateCustomerLocked(orgID, customerID)
	cu.CreditsUsed += payload.CreditsDelta
	cu.PromptTokens += payload.PromptTokens
	cu.CompletionTokens += payload.CompletionTokens
	return nil
}

func (l *CreditLedger) GetCustomerUsage(orgID, customerID string) CustomerUsage {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if cu, ok := l.customerUsage[orgID+":"+customerID]; ok {
		return *cu
	}
	return CustomerUsage{OrgID: orgID, CustomerID: customerID}
}

func (l *CreditLedger) getOrCreateCustomerLocked(orgID, customerID string) *CustomerUsage {
	key := orgID + ":" + customerID
	cu, ok := l.customerUsage[key]
	if !ok {
		cu = &CustomerUsage{OrgID: orgID, CustomerID: customerID}
		l.customerUsage[key] = cu
	}
	return cu
}
