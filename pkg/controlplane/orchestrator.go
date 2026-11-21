package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/parkiyong/agentbox/pkg/harness"
	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox"
	"github.com/parkiyong/agentbox/pkg/tools"
)

type runningSession struct {
	engine  *harness.Engine
	handle  *sandbox.SandboxHandle
	nonce   string
	cancel  context.CancelFunc
	wsPath  string
}

// Orchestrator coordinates session lifecycle, sandbox provisioning, warm workspace snapshots,
// host-side zero-trust proxy binding, credit metering, HITL approvals, forking, and webhooks.
type Orchestrator struct {
	Store    *Store
	Ledger   *CreditLedger
	Proxy    *proxy.HostProxyServer
	Driver   sandbox.SandboxDriver
	Webhooks *WebhookDispatcher

	mu     sync.RWMutex
	active map[string]*runningSession
}

func NewOrchestrator(store *Store, ledger *CreditLedger, hostProxy *proxy.HostProxyServer, driver sandbox.SandboxDriver) *Orchestrator {
	return &Orchestrator{
		Store:    store,
		Ledger:   ledger,
		Proxy:    hostProxy,
		Driver:   driver,
		Webhooks: NewWebhookDispatcher(),
		active:   make(map[string]*runningSession),
	}
}

func (o *Orchestrator) CreateSession(ctx context.Context, orgID string, req protocol.CreateSessionRequest) (*protocol.Session, error) {
	if req.CustomerID == "" {
		return nil, fmt.Errorf("customer_id is required")
	}
	if req.Task == "" {
		return nil, fmt.Errorf("task is required")
	}

	bp, ok := o.Store.GetBlueprint(orgID, req.Blueprint)
	if !ok {
		// Fall back to default blueprint in local dev when blueprint name is "default" or omitted.
		if req.Blueprint == "" || req.Blueprint == "default" {
			bp = protocol.DefaultBlueprint("default")
			o.Store.PutBlueprint(orgID, bp)
		} else {
			return nil, fmt.Errorf("blueprint %q not found", req.Blueprint)
		}
	}

	now := time.Now().UTC()
	limits := protocol.MergeLimits(bp.Limits, req.Limits)
	wsID := sandbox.WorkspaceKey(orgID, req.CustomerID, req.Repo.URL+req.Repo.LocalPath, bp.Hash())

	sess := &protocol.Session{
		ID:               protocol.NewID("ses_"),
		OrgID:            orgID,
		CustomerID:       req.CustomerID,
		WorkspaceID:      wsID,
		BlueprintName:    bp.Metadata.Name,
		BlueprintVersion: bp.Metadata.Version,
		BlueprintHash:    bp.Hash(),
		Repo:             req.Repo,
		Task:             req.Task,
		Status:           protocol.SessionQueued,
		Limits:           limits,
		WebhookURL:       req.WebhookURL,
		WebhookSecret:    req.WebhookSecret,
		Metadata:         req.Metadata,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	o.Store.PutSession(sess)
	o.Ledger.RegisterSession(orgID, req.CustomerID, sess.ID, limits.MaxCredits)
	o.emitAndDispatch(sess, protocol.EventSessionQueued, protocol.SessionLifecyclePayload{Status: protocol.SessionQueued})

	go o.runSession(sess.ID, bp, "")
	return sess, nil
}

func (o *Orchestrator) runSession(sessionID string, bp *protocol.Blueprint, forkFromWorkspace string) {
	sess, ok := o.Store.GetSession(sessionID)
	if !ok {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	now := time.Now().UTC()
	_, _ = o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
		s.Status = protocol.SessionProvisioning
		s.StartedAt = &now
		s.UpdatedAt = now
		return nil
	})
	o.emitAndDispatch(sess, protocol.EventSessionBooting, protocol.SessionLifecyclePayload{Status: protocol.SessionProvisioning})

	nonce, err := protocol.NewNonce()
	if err != nil {
		o.failSession(sessionID, err)
		cancel()
		return
	}

	spec := sandbox.SandboxSpec{
		SessionID:     sess.ID,
		OrgID:         sess.OrgID,
		CustomerID:    sess.CustomerID,
		WorkspaceID:   sess.WorkspaceID,
		Image:         bp.Runtime.Image,
		VCPU:          bp.Runtime.Resources.VCPU,
		MemoryMB:      bp.Runtime.Resources.MemoryMB,
		DiskGB:        bp.Runtime.Resources.DiskGB,
		SessionNonce:  nonce,
		ProxyAddr:     o.Proxy.APIBaseURL(),
		EgressProxy:   o.Proxy.EgressProxyURL(),
		Repo:          sess.Repo,
		SetupCommands: bp.Runtime.Setup.Commands,
	}

	var handle *sandbox.SandboxHandle
	if forkFromWorkspace != "" {
		spec.Repo.LocalPath = forkFromWorkspace
		handle, err = o.Driver.Create(ctx, spec)
	} else if snap, hasWarm := o.Store.GetWorkspaceSnapshot(sess.WorkspaceID); hasWarm {
		handle, err = o.Driver.Restore(ctx, snap, spec)
	} else {
		handle, err = o.Driver.Create(ctx, spec)
	}
	if err != nil {
		o.failSession(sessionID, fmt.Errorf("provision sandbox: %w", err))
		cancel()
		return
	}
	if err := o.Driver.Start(ctx, handle); err != nil {
		o.failSession(sessionID, fmt.Errorf("start sandbox: %w", err))
		cancel()
		return
	}

	// Bind ephemeral nonce to Host-Side Security Proxy (ZERO raw secrets ever enter the sandbox).
	o.Proxy.Registry.Register(&proxy.SessionBinding{
		Nonce:      nonce,
		SessionID:  sess.ID,
		OrgID:      sess.OrgID,
		CustomerID: sess.CustomerID,
		RepoURL:    sess.Repo.URL,
		Blueprint:  bp,
		Budget:     o.Ledger,
		OnPRCreated: func(pr protocol.PRCreatedPayload) {
			_, _ = o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
				s.PRURL = pr.URL
				s.Branch = pr.Branch
				s.UpdatedAt = time.Now().UTC()
				return nil
			})
		},
	})

	engine := harness.NewEngine(harness.EngineConfig{
		SessionID:    sess.ID,
		CustomerID:   sess.CustomerID,
		Workspace:    handle.WorkspacePath,
		Task:         sess.Task,
		Blueprint:    bp,
		Limits:       sess.Limits,
		ProxyAddr:    o.Proxy.APIBaseURL(),
		SessionNonce: nonce,
		LLM:          harness.NewProxyLLMClient(o.Proxy.APIBaseURL(), nonce),
		OnEvent: func(evt protocol.Event) {
			o.handleEngineEvent(sess, evt)
		},
		OnStatus: func(st protocol.SessionStatus) {
			_, _ = o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
				s.Status = st
				s.UpdatedAt = time.Now().UTC()
				if st.IsTerminal() {
					t := time.Now().UTC()
					s.CompletedAt = &t
				}
				return nil
			})
		},
	})

	o.mu.Lock()
	o.active[sessionID] = &runningSession{
		engine: engine,
		handle: handle,
		nonce:  nonce,
		cancel: cancel,
		wsPath: handle.WorkspacePath,
	}
	o.mu.Unlock()

	// If this session was forked at a specific checkpoint, rewind the cloned workspace before running.
	if sess.ForkCheckpointID != "" {
		cm := tools.NewCheckpointManager(handle.WorkspacePath, nil)
		_ = cm.Rewind(ctx, sess.ForkCheckpointID)
	}

	summary, runErr := engine.Run(ctx)

	// Persist warm workspace snapshot for fast 2-5s subsequent boots!
	if snap, snapErr := o.Driver.Snapshot(context.Background(), handle, sess.WorkspaceID); snapErr == nil {
		o.Store.PutWorkspaceSnapshot(sess.WorkspaceID, snap)
	}

	o.Proxy.Registry.Unregister(nonce)
	_, _ = o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
		s.Usage = engine.Usage()
		s.UpdatedAt = time.Now().UTC()
		if runErr != nil && s.Status != protocol.SessionCancelled {
			s.Status = protocol.SessionFailed
			s.Error = runErr.Error()
		} else if summary != "" {
			s.Summary = summary
		}
		return nil
	})
}

func (o *Orchestrator) handleEngineEvent(sess *protocol.Session, evt protocol.Event) {
	stored := o.Store.AppendEvent(evt)

	// Keep session metadata synchronized with key progress & interactive events.
	switch stored.Type {
	case protocol.EventCheckpointCreated:
		var p protocol.CheckpointCreatedPayload
		if json.Unmarshal(stored.Payload, &p) == nil {
			_, _ = o.Store.UpdateSession(sess.ID, func(s *protocol.Session) error {
				s.LatestCheckpoint = p.CheckpointID
				s.Checkpoints = append(s.Checkpoints, protocol.Checkpoint{
					ID:        p.CheckpointID,
					Ref:       p.Ref,
					CommitSHA: p.CommitSHA,
					Step:      p.Step,
					Message:   p.Message,
					CreatedAt: stored.Timestamp,
				})
				return nil
			})
		}
	case protocol.EventApprovalRequired:
		var p protocol.ApprovalRequiredPayload
		if json.Unmarshal(stored.Payload, &p) == nil {
			_, _ = o.Store.UpdateSession(sess.ID, func(s *protocol.Session) error {
				s.PendingApproval = &protocol.Approval{
					ID:        p.ApprovalID,
					SessionID: sess.ID,
					Action:    p.Action,
					Summary:   p.Summary,
					Details:   p.Details,
					DiffStats: p.DiffStats,
					Status:    protocol.ApprovalPending,
					CreatedAt: stored.Timestamp,
				}
				return nil
			})
		}
	case protocol.EventApprovalResolved:
		_, _ = o.Store.UpdateSession(sess.ID, func(s *protocol.Session) error {
			s.PendingApproval = nil
			return nil
		})
	case protocol.EventUsageReported:
		var p protocol.UsageReportedPayload
		if json.Unmarshal(stored.Payload, &p) == nil {
			_, _ = o.Store.UpdateSession(sess.ID, func(s *protocol.Session) error {
				s.Usage.CreditsUsed = p.TotalCredits
				s.Usage.PromptTokens += p.PromptTokens
				s.Usage.CompletionTokens += p.CompletionTokens
				s.Usage.TurnsUsed++
				return nil
			})
		}
	}

	o.Webhooks.DispatchAsync(sess.WebhookURL, sess.WebhookSecret, stored)
}

func (o *Orchestrator) emitAndDispatch(sess *protocol.Session, eventType protocol.EventType, payload any) {
	evt, err := protocol.NewEvent(sess.ID, sess.CustomerID, 0, eventType, payload)
	if err != nil {
		return
	}
	stored := o.Store.AppendEvent(evt)
	o.Webhooks.DispatchAsync(sess.WebhookURL, sess.WebhookSecret, stored)
}

func (o *Orchestrator) failSession(sessionID string, err error) {
	now := time.Now().UTC()
	sess, updateErr := o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
		s.Status = protocol.SessionFailed
		s.Error = err.Error()
		s.UpdatedAt = now
		s.CompletedAt = &now
		return nil
	})
	if updateErr == nil {
		o.emitAndDispatch(sess, protocol.EventSessionFailed, protocol.SessionLifecyclePayload{
			Status: protocol.SessionFailed,
			Error:  err.Error(),
		})
	}
}

func (o *Orchestrator) SendMessage(sessionID string, req protocol.SendMessageRequest) error {
	o.mu.RLock()
	rs, ok := o.active[sessionID]
	o.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %q is not currently active", sessionID)
	}
	rs.engine.SendControl(harness.ControlMessage{
		Kind:    "steer",
		Content: req.Content,
	})
	return nil
}

func (o *Orchestrator) ResolveApproval(sessionID, approvalID string, req protocol.ResolveApprovalRequest) error {
	o.mu.RLock()
	rs, ok := o.active[sessionID]
	o.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %q is not currently active", sessionID)
	}
	approved := req.Decision == "approved"
	rs.engine.SendControl(harness.ControlMessage{
		Kind:       "approval",
		ApprovalID: approvalID,
		Approved:   approved,
		Feedback:   req.Feedback,
	})
	return nil
}

func (o *Orchestrator) ResumeSession(sessionID string, req protocol.ResumeSessionRequest) (*protocol.Session, error) {
	if req.AddCredits > 0 {
		o.Ledger.ExtendSessionCredits(sessionID, req.AddCredits)
	}
	sess, err := o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
		if req.AddCredits > 0 {
			s.Limits.MaxCredits += req.AddCredits
		}
		if req.AddTurns > 0 {
			s.Limits.MaxTurns += req.AddTurns
		}
		if req.AddWallClockSeconds > 0 {
			s.Limits.MaxWallClockSeconds += req.AddWallClockSeconds
		}
		s.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		return nil, err
	}

	o.mu.RLock()
	rs, ok := o.active[sessionID]
	o.mu.RUnlock()
	if ok {
		rs.engine.SendControl(harness.ControlMessage{
			Kind:       "resume",
			Content:    req.Message,
			AddCredits: req.AddCredits,
			AddTurns:   req.AddTurns,
			AddWallSec: req.AddWallClockSeconds,
		})
	}
	return sess, nil
}

func (o *Orchestrator) CancelSession(sessionID string) (*protocol.Session, error) {
	o.mu.RLock()
	rs, ok := o.active[sessionID]
	o.mu.RUnlock()
	if ok {
		rs.engine.SendControl(harness.ControlMessage{Kind: "cancel"})
		rs.cancel()
	}
	return o.Store.UpdateSession(sessionID, func(s *protocol.Session) error {
		if !s.Status.IsTerminal() {
			s.Status = protocol.SessionCancelled
			now := time.Now().UTC()
			s.UpdatedAt = now
			s.CompletedAt = &now
		}
		return nil
	})
}

// ForkSession clones an existing session's workspace (optionally rewound to checkpoint_id)
// into a brand-new parallel session!
func (o *Orchestrator) ForkSession(ctx context.Context, orgID, parentSessionID string, req protocol.ForkSessionRequest) (*protocol.Session, error) {
	parent, ok := o.Store.GetSession(parentSessionID)
	if !ok {
		return nil, fmt.Errorf("parent session %q not found", parentSessionID)
	}
	o.mu.RLock()
	rs, hasActive := o.active[parentSessionID]
	o.mu.RUnlock()

	forkWS := ""
	if hasActive && rs.wsPath != "" {
		forkWS = rs.wsPath
	}

	bp, ok := o.Store.GetBlueprint(orgID, parent.BlueprintName)
	if !ok {
		bp = protocol.DefaultBlueprint(parent.BlueprintName)
	}

	task := req.Task
	if task == "" {
		task = parent.Task
	}
	now := time.Now().UTC()
	child := &protocol.Session{
		ID:               protocol.NewID("ses_"),
		OrgID:            parent.OrgID,
		CustomerID:       parent.CustomerID,
		WorkspaceID:      parent.WorkspaceID,
		BlueprintName:    parent.BlueprintName,
		BlueprintVersion: parent.BlueprintVersion,
		BlueprintHash:    parent.BlueprintHash,
		Repo:             parent.Repo,
		Task:             task,
		Status:           protocol.SessionQueued,
		Limits:           parent.Limits,
		WebhookURL:       parent.WebhookURL,
		WebhookSecret:    parent.WebhookSecret,
		ParentSessionID:  parent.ID,
		ForkCheckpointID: req.CheckpointID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	o.Store.PutSession(child)
	o.Ledger.RegisterSession(child.OrgID, child.CustomerID, child.ID, child.Limits.MaxCredits)
	o.emitAndDispatch(child, protocol.EventSessionQueued, protocol.SessionLifecyclePayload{Status: protocol.SessionQueued})

	go o.runSession(child.ID, bp, forkWS)
	return child, nil
}

// GetSessionDiff returns the clean unified git diff and stats for a session's workspace.
func (o *Orchestrator) GetSessionDiff(ctx context.Context, sessionID string) (*protocol.SessionDiffResponse, error) {
	sess, ok := o.Store.GetSession(sessionID)
	if !ok {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}
	o.mu.RLock()
	rs, hasActive := o.active[sessionID]
	o.mu.RUnlock()
	if !hasActive || rs.wsPath == "" {
		return &protocol.SessionDiffResponse{SessionID: sessionID, Branch: sess.Branch}, nil
	}
	diffText, stats, err := tools.ComputeWorkspaceDiff(ctx, rs.wsPath)
	if err != nil {
		return nil, err
	}
	return &protocol.SessionDiffResponse{
		SessionID: sessionID,
		Branch:    sess.Branch,
		Unified:   diffText,
		Stats:     stats,
	}, nil
}

// ArchiveSessionWorkspace writes a downloadable .tar.gz of the session workspace (greenfield export).
func (o *Orchestrator) ArchiveSessionWorkspace(sessionID string) (string, error) {
	o.mu.RLock()
	rs, hasActive := o.active[sessionID]
	o.mu.RUnlock()
	if !hasActive || rs.wsPath == "" {
		return "", fmt.Errorf("workspace not available for session %s", sessionID)
	}
	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("agentbox-export-%s.tar.gz", sessionID))
	if err := sandbox.ArchiveDirectory(rs.wsPath, tmpPath); err != nil {
		return "", err
	}
	return tmpPath, nil
}
