package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/tools"
)

// ControlMessage represents an interactive control signal sent from the Control Plane / user
// to a live or paused agentd session.
type ControlMessage struct {
	Kind       string // steer | approval | resume | cancel
	Content    string
	ApprovalID string
	Approved   bool
	Feedback   string
	AddCredits float64
	AddTurns   int
	AddWallSec int
}

// EngineConfig configures an autonomous SWE Engine run inside the sandbox.
type EngineConfig struct {
	SessionID    string
	CustomerID   string
	Workspace    string
	Task         string
	Blueprint    *protocol.Blueprint
	Limits       protocol.LimitsConfig
	ProxyAddr    string
	SessionNonce string
	LLM          LLMClient
	OnEvent      func(protocol.Event)
	OnStatus     func(protocol.SessionStatus)
	ExtraEnv     []string
}

// Engine implements the opinionated AgentBox SWE execution loop:
// Ingest & Ground -> Plan -> Explore -> Edit -> Verify -> Self-Heal -> Checkpoints -> HITL / Budget Pause.
type Engine struct {
	cfg         EngineConfig
	registry    *tools.Registry
	checkpoints *tools.CheckpointManager
	seq         atomic.Int64

	mu              sync.Mutex
	limits          protocol.LimitsConfig
	usage           protocol.UsageStats
	status          protocol.SessionStatus
	startedAt       time.Time
	controlCh       chan ControlMessage
	pendingApproval map[string]chan ControlMessage
	failureCounts   map[string]int
}

func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Blueprint == nil {
		cfg.Blueprint = protocol.DefaultBlueprint("default-swe")
	}
	limits := cfg.Limits
	if limits.MaxCredits <= 0 && limits.MaxTurns <= 0 && limits.MaxWallClockSeconds <= 0 {
		limits = cfg.Blueprint.Limits
	}
	e := &Engine{
		cfg:             cfg,
		registry:        tools.NewRegistry(),
		limits:          limits,
		status:          protocol.SessionRunning,
		controlCh:       make(chan ControlMessage, 32),
		pendingApproval: make(map[string]chan ControlMessage),
		failureCounts:   make(map[string]int),
	}
	e.checkpoints = tools.NewCheckpointManager(cfg.Workspace, func(p protocol.CheckpointCreatedPayload) {
		e.emit(protocol.EventCheckpointCreated, p)
	})
	e.registerCoreTools()
	return e
}

// SendControl delivers a live steering, approval resolution, resume, or cancel signal to the engine.
func (e *Engine) SendControl(msg ControlMessage) {
	if msg.Kind == "approval" {
		e.mu.Lock()
		ch, ok := e.pendingApproval[msg.ApprovalID]
		e.mu.Unlock()
		if ok {
			select {
			case ch <- msg:
			default:
			}
			return
		}
	}
	select {
	case e.controlCh <- msg:
	default:
	}
}

func (e *Engine) Usage() protocol.UsageStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	u := e.usage
	if !e.startedAt.IsZero() {
		u.WallClockSeconds = time.Since(e.startedAt).Seconds()
	}
	return u
}

func (e *Engine) registerCoreTools() {
	httpClient, proxyBaseURL := NewProxyHTTPClient(e.cfg.ProxyAddr, 30*time.Second)

	e.registry.Register(&tools.FSReadTool{Workspace: e.cfg.Workspace})
	e.registry.Register(&tools.FSEditPatchTool{
		Workspace: e.cfg.Workspace,
		OnDiff: func(p protocol.FileDiffPayload) {
			e.emit(protocol.EventFileDiff, p)
		},
	})
	e.registry.Register(&tools.FSSearchTool{Workspace: e.cfg.Workspace})
	e.registry.Register(&tools.CodeOutlineTool{Workspace: e.cfg.Workspace})
	e.registry.Register(tools.NewShellExecTool(e.cfg.Workspace, e.cfg.ExtraEnv, func(c protocol.TerminalChunkPayload) {
		e.emit(protocol.EventTerminalChunk, c)
	}))
	e.registry.Register(&tools.GitOpsTool{
		Workspace:         e.cfg.Workspace,
		ProxyBaseURL:      proxyBaseURL,
		SessionNonce:      e.cfg.SessionNonce,
		HTTPClient:        httpClient,
		Checkpoints:       e.checkpoints,
		ProtectedBranches: e.cfg.Blueprint.Harness.Git.ProtectedBranches,
		OnPRCreated: func(pr protocol.PRCreatedPayload) {
			e.emit(protocol.EventPRCreated, pr)
		},
	})

	// Harness-native structured planning & clarification tools
	e.registry.Register(&planUpdateTool{onPlan: func(p protocol.PlanUpdatedPayload) {
		e.emit(protocol.EventPlanUpdated, p)
	}})
	e.registry.Register(&askUserTool{engine: e})

	// Dynamically register Blueprint MCP server tools routed through Host-Side MCP Bridge
	for _, srv := range e.cfg.Blueprint.MCPServers {
		for _, toolName := range srv.AllowedTools {
			e.registry.Register(&tools.MCPTool{
				ServerName:   srv.Name,
				ToolName:     toolName,
				ProxyBaseURL: proxyBaseURL,
				SessionNonce: e.cfg.SessionNonce,
				HTTPClient:   httpClient,
			})
		}
	}
}

func (e *Engine) emit(eventType protocol.EventType, payload any) {
	if e.cfg.OnEvent == nil {
		return
	}
	seq := e.seq.Add(1)
	evt, err := protocol.NewEvent(e.cfg.SessionID, e.cfg.CustomerID, seq, eventType, payload)
	if err != nil {
		return
	}
	e.cfg.OnEvent(evt)
}

func (e *Engine) setStatus(status protocol.SessionStatus) {
	e.mu.Lock()
	e.status = status
	e.mu.Unlock()
	if e.cfg.OnStatus != nil {
		e.cfg.OnStatus(status)
	}
}

// Run executes the autonomous SWE loop until completion, cancellation, or unrecoverable error.
func (e *Engine) Run(ctx context.Context) (string, error) {
	e.startedAt = time.Now().UTC()
	e.setStatus(protocol.SessionRunning)
	e.emit(protocol.EventSessionRunning, protocol.SessionLifecyclePayload{Status: protocol.SessionRunning})

	// Ensure git repository + initial baseline checkpoint (handles both git-first & greenfield fallback).
	if err := e.checkpoints.EnsureGitRepo(ctx); err != nil {
		return "", fmt.Errorf("init workspace git: %w", err)
	}
	if _, err := e.checkpoints.Create(ctx, "initial workspace baseline"); err != nil {
		return "", fmt.Errorf("initial checkpoint: %w", err)
	}

	systemPrompt := e.buildSystemPrompt()
	grounding := e.buildWorkspaceGrounding()

	messages := []protocol.LLMMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: fmt.Sprintf("Task:\n%s\n\nWorkspace Grounding:\n%s", e.cfg.Task, grounding)},
	}

	for {
		if ctx.Err() != nil {
			e.setStatus(protocol.SessionCancelled)
			e.emit(protocol.EventSessionCancelled, protocol.SessionLifecyclePayload{
				Status: protocol.SessionCancelled,
				Reason: "context cancelled",
			})
			return "", ctx.Err()
		}

		// Drain any pending live steering or cancel signals before starting the next turn.
		if cancelled, steered := e.drainControls(); cancelled {
			e.setStatus(protocol.SessionCancelled)
			e.emit(protocol.EventSessionCancelled, protocol.SessionLifecyclePayload{
				Status: protocol.SessionCancelled,
				Reason: "cancelled by caller",
			})
			return "", context.Canceled
		} else {
			for _, s := range steered {
				messages = append(messages, protocol.LLMMessage{
					Role:    "user",
					Content: fmt.Sprintf("[User Steering Message]: %s", s),
				})
				e.emit(protocol.EventAgentMessage, protocol.AgentMessagePayload{
					Role:    "user",
					Content: s,
				})
			}
		}

		// Check hard limits (credits / turns / wall-clock) -> graceful budget_paused + checkpoint
		if limitType, cur, lim, hit := e.checkLimits(); hit {
			if err := e.handleBudgetPause(ctx, limitType, cur, lim); err != nil {
				return "", err
			}
			continue
		}

		messages = CompactMessages(messages, 120_000)

		resp, err := e.cfg.LLM.Complete(ctx, protocol.LLMCompleteRequest{
			Profile:  e.cfg.Blueprint.Model.Profile,
			Messages: messages,
			Tools:    e.registry.Definitions(),
		})
		if err != nil {
			if errors.Is(err, ErrBudgetExceeded) {
				e.mu.Lock()
				cur := e.usage.CreditsUsed
				lim := e.limits.MaxCredits
				e.mu.Unlock()
				if pauseErr := e.handleBudgetPause(ctx, "credits", cur, lim); pauseErr != nil {
					return "", pauseErr
				}
				continue
			}
			e.setStatus(protocol.SessionFailed)
			e.emit(protocol.EventSessionFailed, protocol.SessionLifecyclePayload{
				Status: protocol.SessionFailed,
				Error:  err.Error(),
			})
			return "", err
		}

		e.mu.Lock()
		e.usage.TurnsUsed++
		e.usage.PromptTokens += resp.Usage.PromptTokens
		e.usage.CompletionTokens += resp.Usage.CompletionTokens
		e.usage.CreditsUsed += resp.Usage.CreditsUsed
		totalCredits := e.usage.CreditsUsed
		e.mu.Unlock()

		e.emit(protocol.EventUsageReported, protocol.UsageReportedPayload{
			Model:            resp.Model,
			Profile:          e.cfg.Blueprint.Model.Profile,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
			CreditsDelta:     resp.Usage.CreditsUsed,
			TotalCredits:     totalCredits,
			ComputeSeconds:   time.Since(e.startedAt).Seconds(),
		})

		messages = append(messages, resp.Message)
		if strings.TrimSpace(resp.Message.Content) != "" {
			e.emit(protocol.EventAgentMessage, protocol.AgentMessagePayload{
				Role:    "assistant",
				Content: resp.Message.Content,
			})
		}

		// If the model emitted no tool calls, the SWE task is complete!
		if len(resp.Message.ToolCalls) == 0 {
			cp, _ := e.checkpoints.Create(ctx, "final verified state")
			_, stats, _ := tools.ComputeWorkspaceDiff(ctx, e.cfg.Workspace)
			e.setStatus(protocol.SessionCompleted)
			e.emit(protocol.EventSessionCompleted, protocol.SessionLifecyclePayload{
				Status:       protocol.SessionCompleted,
				Summary:      resp.Message.Content,
				CheckpointID: cp.ID,
				DiffStats:    &stats,
			})
			return resp.Message.Content, nil
		}

		// Create a shadow git checkpoint before an edit batch so rewind is always zero-cost.
		hasEdit := false
		for _, tc := range resp.Message.ToolCalls {
			if tc.Name == "fs_edit_patch" {
				hasEdit = true
				break
			}
		}
		if hasEdit {
			_, _ = e.checkpoints.Create(ctx, fmt.Sprintf("pre-edit turn %d", e.usage.TurnsUsed))
		}

		// Execute requested tool calls sequentially with policy enforcement and self-heal loop detection.
		for _, tc := range resp.Message.ToolCalls {
			toolOut := e.executeToolCall(ctx, tc)
			messages = append(messages, protocol.LLMMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Name:       tc.Name,
				Content:    toolOut,
			})
		}
	}
}

func (e *Engine) executeToolCall(ctx context.Context, tc protocol.LLMToolCall) string {
	var argsMap map[string]any
	_ = json.Unmarshal(tc.Arguments, &argsMap)

	// Evaluate Blueprint policy before executing sensitive tools.
	if policyAction, target, summary := classifyToolForPolicy(tc.Name, argsMap); policyAction != "" {
		mode, _ := e.cfg.Blueprint.EvaluatePolicy(policyAction, target)
		if mode == protocol.PolicyDeny {
			return fmt.Sprintf("Policy denied action %q on %q. Choose a different approach.", policyAction, target)
		}
		if mode == protocol.PolicyRequireApproval {
			approved, feedback, err := e.requestApproval(ctx, policyAction, summary, argsMap)
			if err != nil {
				return fmt.Sprintf("Approval wait failed: %v", err)
			}
			if !approved {
				if feedback == "" {
					feedback = "User rejected this action."
				}
				return fmt.Sprintf("Action %q was REJECTED by the approver. Feedback: %s", policyAction, feedback)
			}
		}
	}

	tool, ok := e.registry.Get(tc.Name)
	if !ok {
		return fmt.Sprintf("Error: unknown tool %q", tc.Name)
	}

	e.emit(protocol.EventToolStarted, protocol.ToolStartedPayload{
		CallID: tc.ID,
		Tool:   tc.Name,
		Args:   argsMap,
	})

	start := time.Now()
	res, err := tool.Execute(ctx, tc.Arguments)
	dur := time.Since(start).Milliseconds()

	if err != nil {
		e.emit(protocol.EventToolCompleted, protocol.ToolCompletedPayload{
			CallID:     tc.ID,
			Tool:       tc.Name,
			Success:    false,
			DurationMs: dur,
			Output:     res.Output,
			Error:      err.Error(),
		})

		// Self-heal loop detector: track repeating identical failures.
		sig := tc.Name + "::" + err.Error()
		e.mu.Lock()
		e.failureCounts[sig]++
		count := e.failureCounts[sig]
		e.mu.Unlock()

		var msg strings.Builder
		fmt.Fprintf(&msg, "Tool %s failed: %v", tc.Name, err)
		if res.Output != "" {
			fmt.Fprintf(&msg, "\nOutput:\n%s", res.Output)
		}
		if count >= 3 {
			msg.WriteString("\n[Self-Heal Hint]: This exact failure has repeated 3+ times. Switch strategy, inspect assumptions with fs_search/code_outline, rewind to a checkpoint, or use ask_user to request clarification.")
		}
		return msg.String()
	}

	e.emit(protocol.EventToolCompleted, protocol.ToolCompletedPayload{
		CallID:     tc.ID,
		Tool:       tc.Name,
		Success:    true,
		DurationMs: dur,
		Output:     truncateForEvent(res.Output, 4096),
	})
	return res.Output
}

func (e *Engine) requestApproval(ctx context.Context, action, summary string, details map[string]any) (bool, string, error) {
	aprID := protocol.NewID("apr_")
	ch := make(chan ControlMessage, 1)
	e.mu.Lock()
	e.pendingApproval[aprID] = ch
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.pendingApproval, aprID)
		e.mu.Unlock()
	}()

	_, stats, _ := tools.ComputeWorkspaceDiff(ctx, e.cfg.Workspace)
	e.setStatus(protocol.SessionWaitingApproval)
	e.emit(protocol.EventApprovalRequired, protocol.ApprovalRequiredPayload{
		ApprovalID: aprID,
		Action:     action,
		Summary:    summary,
		Details:    details,
		DiffStats:  &stats,
	})

	select {
	case <-ctx.Done():
		return false, "", ctx.Err()
	case msg := <-ch:
		decision := "rejected"
		if msg.Approved {
			decision = "approved"
		}
		e.emit(protocol.EventApprovalResolved, protocol.ApprovalResolvedPayload{
			ApprovalID: aprID,
			Action:     action,
			Decision:   decision,
			Feedback:   msg.Feedback,
		})
		e.setStatus(protocol.SessionRunning)
		return msg.Approved, msg.Feedback, nil
	}
}

func (e *Engine) waitForUserInput(ctx context.Context, prompt string, options []string) (string, error) {
	e.setStatus(protocol.SessionWaitingInput)
	e.emit(protocol.EventInputRequested, protocol.InputRequestedPayload{
		Prompt:  prompt,
		Options: options,
	})

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case msg := <-e.controlCh:
			if msg.Kind == "cancel" {
				return "", context.Canceled
			}
			if msg.Kind == "steer" || msg.Kind == "resume" {
				e.setStatus(protocol.SessionRunning)
				return msg.Content, nil
			}
		}
	}
}

func (e *Engine) checkLimits() (string, float64, float64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.limits.MaxCredits > 0 && e.usage.CreditsUsed >= e.limits.MaxCredits {
		return "credits", e.usage.CreditsUsed, e.limits.MaxCredits, true
	}
	if e.limits.MaxTurns > 0 && e.usage.TurnsUsed >= e.limits.MaxTurns {
		return "turns", float64(e.usage.TurnsUsed), float64(e.limits.MaxTurns), true
	}
	elapsed := time.Since(e.startedAt).Seconds()
	if e.limits.MaxWallClockSeconds > 0 && elapsed >= float64(e.limits.MaxWallClockSeconds) {
		return "wall_clock", elapsed, float64(e.limits.MaxWallClockSeconds), true
	}
	return "", 0, 0, false
}

func (e *Engine) handleBudgetPause(ctx context.Context, limitType string, current, limit float64) error {
	cp, _ := e.checkpoints.Create(ctx, fmt.Sprintf("budget_paused (%s)", limitType))
	e.setStatus(protocol.SessionBudgetPaused)
	e.emit(protocol.EventBudgetExceeded, protocol.BudgetExceededPayload{
		LimitType:    limitType,
		Current:      current,
		Limit:        limit,
		CheckpointID: cp.ID,
		Message:      fmt.Sprintf("Session paused: %s limit reached (%.2f / %.2f). Resume with extended budget to continue without losing progress.", limitType, current, limit),
	})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-e.controlCh:
			if msg.Kind == "cancel" {
				e.setStatus(protocol.SessionCancelled)
				e.emit(protocol.EventSessionCancelled, protocol.SessionLifecyclePayload{
					Status: protocol.SessionCancelled,
					Reason: "cancelled while budget_paused",
				})
				return context.Canceled
			}
			if msg.Kind == "resume" {
				e.mu.Lock()
				if msg.AddCredits > 0 {
					e.limits.MaxCredits += msg.AddCredits
				} else if limitType == "credits" {
					e.limits.MaxCredits += 100
				}
				if msg.AddTurns > 0 {
					e.limits.MaxTurns += msg.AddTurns
				} else if limitType == "turns" {
					e.limits.MaxTurns += 10
				}
				if msg.AddWallSec > 0 {
					e.limits.MaxWallClockSeconds += msg.AddWallSec
				} else if limitType == "wall_clock" {
					e.limits.MaxWallClockSeconds += 600
				}
				e.mu.Unlock()
				e.setStatus(protocol.SessionRunning)
				e.emit(protocol.EventSessionRunning, protocol.SessionLifecyclePayload{
					Status: protocol.SessionRunning,
					Reason: "resumed after budget top-up",
				})
				return nil
			}
		}
	}
}

func (e *Engine) drainControls() (bool, []string) {
	var steered []string
	for {
		select {
		case msg := <-e.controlCh:
			if msg.Kind == "cancel" {
				return true, steered
			}
			if msg.Kind == "steer" && strings.TrimSpace(msg.Content) != "" {
				steered = append(steered, msg.Content)
			}
		default:
			return false, steered
		}
	}
}

func (e *Engine) buildSystemPrompt() string {
	var b strings.Builder
	b.WriteString("You are AgentBox, an autonomous Software Engineering agent running inside an isolated sandbox.\n")
	b.WriteString("Workflow: 1) Update your plan with plan_update. 2) Explore with fs_search, code_outline, and fs_read. 3) Make minimal, surgical edits with fs_edit_patch. 4) Verify with shell_exec tests/builds. 5) Summarize your verified diff.\n")
	if strings.TrimSpace(e.cfg.Blueprint.Harness.SystemInstructions) != "" {
		b.WriteString("\nBlueprint Instructions:\n")
		b.WriteString(strings.TrimSpace(e.cfg.Blueprint.Harness.SystemInstructions))
		b.WriteString("\n")
	}
	for _, skill := range e.cfg.Blueprint.Harness.Skills {
		content := skill.Content
		if content == "" && skill.Path != "" {
			if abs, _, err := tools.SafeWorkspacePath(e.cfg.Workspace, skill.Path); err == nil {
				if data, err := os.ReadFile(abs); err == nil {
					content = string(data)
				}
			}
		}
		if strings.TrimSpace(content) != "" {
			fmt.Fprintf(&b, "\nSkill (%s):\n%s\n", skill.Path, strings.TrimSpace(content))
		}
	}
	return b.String()
}

func (e *Engine) buildWorkspaceGrounding() string {
	entries, err := os.ReadDir(e.cfg.Workspace)
	if err != nil {
		return "(unable to list workspace)"
	}
	var names []string
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		n := entry.Name()
		if entry.IsDir() {
			n += "/"
		}
		names = append(names, n)
		if len(names) >= 50 {
			names = append(names, "...")
			break
		}
	}
	return "Top-level files: " + strings.Join(names, ", ")
}

func classifyToolForPolicy(toolName string, args map[string]any) (string, string, string) {
	switch toolName {
	case "shell_exec":
		cmd, _ := args["command"].(string)
		return "shell.exec", cmd, fmt.Sprintf("Run shell command: %s", cmd)
	case "fs_edit_patch":
		p, _ := args["path"].(string)
		return "fs.edit", p, fmt.Sprintf("Edit sensitive file: %s", p)
	case "git_ops":
		op, _ := args["op"].(string)
		if op == "push" {
			branch, _ := args["branch"].(string)
			return "git.push", branch, fmt.Sprintf("Push commits to branch %s", branch)
		}
	}
	return "", "", ""
}

func truncateForEvent(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

// --- Built-in Harness Coordination Tools ---

type planUpdateTool struct {
	onPlan func(protocol.PlanUpdatedPayload)
}

func (t *planUpdateTool) Name() string { return "plan_update" }
func (t *planUpdateTool) Description() string {
	return "Update the structured execution plan visible to the end-customer UI."
}
func (t *planUpdateTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"summary": map[string]any{"type": "string"},
			"steps": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":     map[string]any{"type": "string"},
						"title":  map[string]any{"type": "string"},
						"status": map[string]any{"type": "string", "enum": []string{"pending", "in_progress", "completed", "failed"}},
					},
					"required": []string{"id", "title", "status"},
				},
			},
		},
		"required": []string{"steps"},
	}
}
func (t *planUpdateTool) Execute(_ context.Context, raw json.RawMessage) (tools.Result, error) {
	var p protocol.PlanUpdatedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return tools.Result{}, err
	}
	if t.onPlan != nil {
		t.onPlan(p)
	}
	return tools.Result{Output: fmt.Sprintf("Plan updated (%d steps)", len(p.Steps))}, nil
}

type askUserTool struct {
	engine *Engine
}

func (t *askUserTool) Name() string { return "ask_user" }
func (t *askUserTool) Description() string {
	return "Pause and ask the end-customer a clarification question when requirements are ambiguous."
}
func (t *askUserTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"prompt":  map[string]any{"type": "string"},
			"options": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
		"required": []string{"prompt"},
	}
}
func (t *askUserTool) Execute(ctx context.Context, raw json.RawMessage) (tools.Result, error) {
	var args struct {
		Prompt  string   `json:"prompt"`
		Options []string `json:"options"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return tools.Result{}, err
	}
	reply, err := t.engine.waitForUserInput(ctx, args.Prompt, args.Options)
	if err != nil {
		return tools.Result{}, err
	}
	return tools.Result{Output: "User response: " + reply}, nil
}

// Helper to ensure unused import doesn't trigger if filepath is needed later.
var _ = filepath.Clean
