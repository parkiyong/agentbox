package protocol

import (
	"encoding/json"
	"time"
)

// EventType identifies a canonical AgentBox event in SSE streams and webhooks.
type EventType string

const (
	// Lifecycle events
	EventSessionQueued     EventType = "session.queued"
	EventSessionBooting    EventType = "session.booting"
	EventSessionRunning    EventType = "session.running"
	EventSessionHibernated EventType = "session.hibernated"
	EventSessionCompleted  EventType = "session.completed"
	EventSessionFailed     EventType = "session.failed"
	EventSessionCancelled  EventType = "session.cancelled"

	// Progress & Code events
	EventPlanUpdated       EventType = "plan.updated"
	EventToolStarted       EventType = "tool.started"
	EventToolCompleted     EventType = "tool.completed"
	EventTerminalChunk     EventType = "terminal.chunk"
	EventFileDiff          EventType = "file.diff"
	EventCheckpointCreated EventType = "checkpoint.created"
	EventPRCreated         EventType = "pr.created"
	EventAgentMessage      EventType = "agent.message"

	// Interactive & Limits events
	EventInputRequested    EventType = "input.requested"
	EventApprovalRequired  EventType = "approval.required"
	EventApprovalResolved  EventType = "approval.resolved"
	EventBudgetExceeded    EventType = "budget.exceeded"
	EventUsageReported     EventType = "usage.reported"
)

// Event is the canonical versioned event envelope emitted over SSE and webhooks.
type Event struct {
	ID         string          `json:"id"`
	Seq        int64           `json:"seq"`
	Timestamp  time.Time       `json:"timestamp"`
	SessionID  string          `json:"session_id"`
	CustomerID string          `json:"customer_id"`
	Type       EventType       `json:"type"`
	Payload    json.RawMessage `json:"payload"`
}

// NewEvent constructs a canonical Event with a JSON-marshaled payload.
func NewEvent(sessionID, customerID string, seq int64, eventType EventType, payload any) (Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, err
	}
	return Event{
		ID:         NewID("evt_"),
		Seq:        seq,
		Timestamp:  time.Now().UTC(),
		SessionID:  sessionID,
		CustomerID: customerID,
		Type:       eventType,
		Payload:    raw,
	}, nil
}

// PlanStep represents a milestone step in the SWE agent's execution plan.
type PlanStep struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // pending | in_progress | completed | failed
}

type PlanUpdatedPayload struct {
	Summary string     `json:"summary,omitempty"`
	Steps   []PlanStep `json:"steps"`
}

type ToolStartedPayload struct {
	CallID string         `json:"call_id"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args,omitempty"`
}

type ToolCompletedPayload struct {
	CallID     string `json:"call_id"`
	Tool       string `json:"tool"`
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
}

type TerminalChunkPayload struct {
	CallID   string `json:"call_id,omitempty"`
	Command  string `json:"command,omitempty"`
	Stream   string `json:"stream"` // stdout | stderr
	Data     string `json:"data"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

type DiffStats struct {
	FilesChanged int `json:"files_changed"`
	Insertions   int `json:"insertions"`
	Deletions    int `json:"deletions"`
}

type FileDiffPayload struct {
	Path       string `json:"path"`
	Operation  string `json:"operation"` // create | modify | delete
	Unified    string `json:"unified"`
	Insertions int    `json:"insertions"`
	Deletions  int    `json:"deletions"`
}

type CheckpointCreatedPayload struct {
	CheckpointID string `json:"checkpoint_id"`
	Ref          string `json:"ref"`
	CommitSHA    string `json:"commit_sha"`
	Step         int    `json:"step"`
	Message      string `json:"message"`
}

type PRCreatedPayload struct {
	URL        string `json:"url"`
	Number     int    `json:"number,omitempty"`
	Title      string `json:"title"`
	Branch     string `json:"branch"`
	BaseBranch string `json:"base_branch"`
}

type AgentMessagePayload struct {
	Role    string `json:"role"` // assistant | user | system
	Content string `json:"content"`
}

type InputRequestedPayload struct {
	Prompt  string   `json:"prompt"`
	Options []string `json:"options,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

type ApprovalRequiredPayload struct {
	ApprovalID string         `json:"approval_id"`
	Action     string         `json:"action"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details,omitempty"`
	DiffStats  *DiffStats     `json:"diff_stats,omitempty"`
}

type ApprovalResolvedPayload struct {
	ApprovalID string `json:"approval_id"`
	Action     string `json:"action"`
	Decision   string `json:"decision"` // approved | rejected
	Feedback   string `json:"feedback,omitempty"`
	ResolvedBy string `json:"resolved_by,omitempty"`
}

type BudgetExceededPayload struct {
	LimitType    string  `json:"limit_type"` // credits | turns | wall_clock
	Current      float64 `json:"current"`
	Limit        float64 `json:"limit"`
	CheckpointID string  `json:"checkpoint_id,omitempty"`
	Message      string  `json:"message"`
}

type UsageReportedPayload struct {
	Model            string  `json:"model"`
	Profile          string  `json:"profile,omitempty"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CreditsDelta     float64 `json:"credits_delta"`
	TotalCredits     float64 `json:"total_credits"`
	ComputeSeconds   float64 `json:"compute_seconds,omitempty"`
}

type SessionLifecyclePayload struct {
	Status       SessionStatus `json:"status"`
	Reason       string        `json:"reason,omitempty"`
	Summary      string        `json:"summary,omitempty"`
	Error        string        `json:"error,omitempty"`
	CheckpointID string        `json:"checkpoint_id,omitempty"`
	PRURL        string        `json:"pr_url,omitempty"`
	DiffStats    *DiffStats    `json:"diff_stats,omitempty"`
}
