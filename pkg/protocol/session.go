package protocol

import (
	"fmt"
	"time"
)

// SessionStatus represents the durable lifecycle state of an autonomous SWE session.
type SessionStatus string

const (
	SessionQueued          SessionStatus = "queued"
	SessionProvisioning    SessionStatus = "provisioning"
	SessionRunning         SessionStatus = "running"
	SessionWaitingApproval SessionStatus = "waiting_approval"
	SessionWaitingInput    SessionStatus = "waiting_input"
	SessionBudgetPaused    SessionStatus = "budget_paused"
	SessionHibernated      SessionStatus = "hibernated"
	SessionCompleted       SessionStatus = "completed"
	SessionFailed          SessionStatus = "failed"
	SessionCancelled       SessionStatus = "cancelled"
)

// IsTerminal reports whether the session has reached a terminal state.
func (s SessionStatus) IsTerminal() bool {
	return s == SessionCompleted || s == SessionFailed || s == SessionCancelled
}

var allowedTransitions = map[SessionStatus]map[SessionStatus]bool{
	SessionQueued: {
		SessionProvisioning: true,
		SessionCancelled:    true,
		SessionFailed:       true,
	},
	SessionProvisioning: {
		SessionRunning:   true,
		SessionFailed:    true,
		SessionCancelled: true,
	},
	SessionRunning: {
		SessionWaitingApproval: true,
		SessionWaitingInput:    true,
		SessionBudgetPaused:    true,
		SessionHibernated:      true,
		SessionCompleted:       true,
		SessionFailed:          true,
		SessionCancelled:       true,
	},
	SessionWaitingApproval: {
		SessionRunning:    true,
		SessionHibernated: true,
		SessionCancelled:  true,
		SessionFailed:     true,
	},
	SessionWaitingInput: {
		SessionRunning:    true,
		SessionHibernated: true,
		SessionCancelled:  true,
		SessionCompleted:  true,
		SessionFailed:     true,
	},
	SessionBudgetPaused: {
		SessionRunning:    true,
		SessionHibernated: true,
		SessionCancelled:  true,
		SessionFailed:     true,
	},
	SessionHibernated: {
		SessionProvisioning: true,
		SessionRunning:      true,
		SessionCancelled:    true,
	},
}

// CanTransition validates whether transitioning from current status to next is permitted
// by the AgentBox session state machine.
func (s SessionStatus) CanTransition(next SessionStatus) bool {
	if s == next {
		return true
	}
	allowed, ok := allowedTransitions[s]
	if !ok {
		return false
	}
	return allowed[next]
}

// ValidateTransition returns an error if the status transition is invalid.
func (s SessionStatus) ValidateTransition(next SessionStatus) error {
	if !s.CanTransition(next) {
		return fmt.Errorf("invalid session state transition: %s -> %s", s, next)
	}
	return nil
}

// RepoSpec identifies the target git repository and base branch for a session.
// If URL is empty, the session starts in greenfield fallback mode.
type RepoSpec struct {
	URL        string `json:"url,omitempty" yaml:"url,omitempty"`
	BaseBranch string `json:"base_branch,omitempty" yaml:"base_branch,omitempty"`
	LocalPath  string `json:"local_path,omitempty" yaml:"local_path,omitempty"`
}

// UsageStats tracks cumulative credit, token, turn, and compute usage for a session.
type UsageStats struct {
	CreditsUsed      float64 `json:"credits_used"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TurnsUsed        int     `json:"turns_used"`
	WallClockSeconds float64 `json:"wall_clock_seconds"`
}

// ApprovalStatus represents the resolution state of an HITL approval.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

// Approval represents a human-in-the-loop gate awaiting customer resolution.
type Approval struct {
	ID         string         `json:"id"`
	SessionID  string         `json:"session_id"`
	Action     string         `json:"action"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details,omitempty"`
	DiffStats  *DiffStats     `json:"diff_stats,omitempty"`
	Status     ApprovalStatus `json:"status"`
	Feedback   string         `json:"feedback,omitempty"`
	ResolvedBy string         `json:"resolved_by,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
}

// Checkpoint records a lightweight shadow git commit created by agentd.
type Checkpoint struct {
	ID        string    `json:"id"`
	Ref       string    `json:"ref"`
	CommitSHA string    `json:"commit_sha"`
	Step      int       `json:"step"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// Session represents a multi-tenant autonomous SWE agent session.
type Session struct {
	ID               string            `json:"id"`
	OrgID            string            `json:"org_id"`
	CustomerID       string            `json:"customer_id"`
	WorkspaceID      string            `json:"workspace_id"`
	BlueprintName    string            `json:"blueprint_name"`
	BlueprintVersion string            `json:"blueprint_version,omitempty"`
	BlueprintHash    string            `json:"blueprint_hash,omitempty"`
	Repo             RepoSpec          `json:"repo"`
	Task             string            `json:"task"`
	Status           SessionStatus     `json:"status"`
	Limits           LimitsConfig      `json:"limits"`
	Usage            UsageStats        `json:"usage"`
	WebhookURL       string            `json:"webhook_url,omitempty"`
	WebhookSecret    string            `json:"-"`
	ParentSessionID  string            `json:"parent_session_id,omitempty"`
	ForkCheckpointID string            `json:"fork_checkpoint_id,omitempty"`
	Branch           string            `json:"branch,omitempty"`
	PRURL            string            `json:"pr_url,omitempty"`
	LatestCheckpoint string            `json:"latest_checkpoint,omitempty"`
	Checkpoints      []Checkpoint      `json:"checkpoints,omitempty"`
	PendingApproval  *Approval         `json:"pending_approval,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Error            string            `json:"error,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
}

// --- REST API Request / Response Types ---

type CreateSessionRequest struct {
	CustomerID    string            `json:"customer_id"`
	Blueprint     string            `json:"blueprint"`
	Repo          RepoSpec          `json:"repo,omitempty"`
	Task          string            `json:"task"`
	Limits        *LimitsConfig     `json:"limits,omitempty"`
	WebhookURL    string            `json:"webhook_url,omitempty"`
	WebhookSecret string            `json:"webhook_secret,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type CreateClientTokenRequest struct {
	Scopes     []string `json:"scopes,omitempty"`      // default: ["read", "steer", "approve"]
	TTLSeconds int      `json:"ttl_seconds,omitempty"` // default: 3600
}

type CreateClientTokenResponse struct {
	Token      string    `json:"token"`
	SessionID  string    `json:"session_id"`
	CustomerID string    `json:"customer_id"`
	Scopes     []string  `json:"scopes"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SendMessageRequest struct {
	Content string `json:"content"`
	Sender  string `json:"sender,omitempty"`
}

type ResolveApprovalRequest struct {
	Decision   string `json:"decision"` // approved | rejected
	Feedback   string `json:"feedback,omitempty"`
	ResolvedBy string `json:"resolved_by,omitempty"`
}

type ResumeSessionRequest struct {
	AddCredits          float64 `json:"add_credits,omitempty"`
	AddTurns            int     `json:"add_turns,omitempty"`
	AddWallClockSeconds int     `json:"add_wall_clock_seconds,omitempty"`
	Message             string  `json:"message,omitempty"`
}

type ForkSessionRequest struct {
	CheckpointID string `json:"checkpoint_id,omitempty"`
	Task         string `json:"task,omitempty"`
}

type SessionDiffResponse struct {
	SessionID string    `json:"session_id"`
	Branch    string    `json:"branch,omitempty"`
	Unified   string    `json:"unified"`
	Stats     DiffStats `json:"stats"`
}
