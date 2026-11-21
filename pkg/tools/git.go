package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// CheckpointManager maintains lightweight shadow git commits on refs/agentbox/checkpoints/<step>
// so agentd can rewind zero-cost, fork parallel sessions, and emit clean diffs.
type CheckpointManager struct {
	Workspace    string
	OnCheckpoint func(protocol.CheckpointCreatedPayload)

	mu          sync.Mutex
	step        int
	checkpoints []protocol.Checkpoint
}

func NewCheckpointManager(workspace string, onCheckpoint func(protocol.CheckpointCreatedPayload)) *CheckpointManager {
	return &CheckpointManager{
		Workspace:    workspace,
		OnCheckpoint: onCheckpoint,
	}
}

// EnsureGitRepo initializes a git repo if the workspace is greenfield (no .git directory).
func (cm *CheckpointManager) EnsureGitRepo(ctx context.Context) error {
	if _, err := runGit(ctx, cm.Workspace, "rev-parse", "--git-dir"); err == nil {
		return nil
	}
	if _, err := runGit(ctx, cm.Workspace, "init", "-b", "main"); err != nil {
		if _, err2 := runGit(ctx, cm.Workspace, "init"); err2 != nil {
			return err2
		}
	}
	_, _ = runGit(ctx, cm.Workspace, "config", "user.name", "AgentBox SWE")
	_, _ = runGit(ctx, cm.Workspace, "config", "user.email", "agentd@agentbox.dev")
	// Create an initial commit so refs/diffs always have a valid base.
	_, _ = runGit(ctx, cm.Workspace, "add", "-A")
	_, _ = runGit(ctx, cm.Workspace, "commit", "--allow-empty", "-m", "agentbox: initial workspace state")
	return nil
}

// Create records a shadow git commit under refs/agentbox/checkpoints/<step> without mutating HEAD's commit history.
func (cm *CheckpointManager) Create(ctx context.Context, message string) (protocol.Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if err := cm.EnsureGitRepo(ctx); err != nil {
		return protocol.Checkpoint{}, err
	}

	cm.step++
	stepNum := cm.step
	ref := fmt.Sprintf("refs/agentbox/checkpoints/%d", stepNum)

	// Build a temporary index copy so we capture untracked + modified files cleanly without altering HEAD.
	tmpIdx := filepath.Join(cm.Workspace, ".git", fmt.Sprintf("agentbox-idx-%d", time.Now().UnixNano()))
	env := []string{"GIT_INDEX_FILE=" + tmpIdx}
	defer func() {
		_ = exec.Command("rm", "-f", tmpIdx).Run()
	}()

	// Seed temp index from HEAD if it exists.
	_, _ = runGitEnv(ctx, cm.Workspace, env, "read-tree", "HEAD")
	if _, err := runGitEnv(ctx, cm.Workspace, env, "add", "-A"); err != nil {
		return protocol.Checkpoint{}, fmt.Errorf("stage checkpoint tree: %w", err)
	}
	treeSHA, err := runGitEnv(ctx, cm.Workspace, env, "write-tree")
	if err != nil {
		return protocol.Checkpoint{}, fmt.Errorf("write checkpoint tree: %w", err)
	}
	treeSHA = strings.TrimSpace(treeSHA)

	commitArgs := []string{"commit-tree", treeSHA, "-m", fmt.Sprintf("checkpoint %d: %s", stepNum, message)}
	if parent, err := runGit(ctx, cm.Workspace, "rev-parse", "--verify", "HEAD"); err == nil && strings.TrimSpace(parent) != "" {
		commitArgs = append(commitArgs, "-p", strings.TrimSpace(parent))
	}
	commitSHA, err := runGit(ctx, cm.Workspace, commitArgs...)
	if err != nil {
		return protocol.Checkpoint{}, fmt.Errorf("create checkpoint commit: %w", err)
	}
	commitSHA = strings.TrimSpace(commitSHA)

	if _, err := runGit(ctx, cm.Workspace, "update-ref", ref, commitSHA); err != nil {
		return protocol.Checkpoint{}, fmt.Errorf("update checkpoint ref: %w", err)
	}

	cp := protocol.Checkpoint{
		ID:        protocol.NewID("chk_"),
		Ref:       ref,
		CommitSHA: commitSHA,
		Step:      stepNum,
		Message:   message,
		CreatedAt: time.Now().UTC(),
	}
	cm.checkpoints = append(cm.checkpoints, cp)
	if cm.OnCheckpoint != nil {
		cm.OnCheckpoint(protocol.CheckpointCreatedPayload{
			CheckpointID: cp.ID,
			Ref:          cp.Ref,
			CommitSHA:    cp.CommitSHA,
			Step:         cp.Step,
			Message:      cp.Message,
		})
	}
	return cp, nil
}

// Rewind restores the working tree to a previously captured checkpoint ref or ID.
func (cm *CheckpointManager) Rewind(ctx context.Context, checkpointIDOrRef string) error {
	cm.mu.Lock()
	target := checkpointIDOrRef
	for _, cp := range cm.checkpoints {
		if cp.ID == checkpointIDOrRef || cp.Ref == checkpointIDOrRef {
			target = cp.CommitSHA
			break
		}
	}
	cm.mu.Unlock()

	if _, err := runGit(ctx, cm.Workspace, "read-tree", "--reset", "-u", target); err != nil {
		return fmt.Errorf("rewind workspace to %s: %w", target, err)
	}
	_, _ = runGit(ctx, cm.Workspace, "clean", "-fd")
	return nil
}

func (cm *CheckpointManager) List() []protocol.Checkpoint {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	out := make([]protocol.Checkpoint, len(cm.checkpoints))
	copy(out, cm.checkpoints)
	return out
}

// GitOpsTool exposes git status, diff, log, branch, commit, push, rewind, and open_pr.
// All remote operations route strictly through the Host-Side Git Proxy (zero raw tokens in sandbox).
type GitOpsTool struct {
	Workspace         string
	ProxyBaseURL      string
	SessionNonce      string
	HTTPClient        *http.Client
	Checkpoints       *CheckpointManager
	ProtectedBranches []string
	OnPRCreated       func(protocol.PRCreatedPayload)
}

func (t *GitOpsTool) Name() string { return "git_ops" }
func (t *GitOpsTool) Description() string {
	return "Perform git operations: status, diff, log, branch, commit, push, open_pr, checkpoint_list, rewind."
}
func (t *GitOpsTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"op":            map[string]any{"type": "string", "enum": []string{"status", "diff", "log", "branch", "commit", "push", "open_pr", "checkpoint_list", "rewind"}},
			"branch":        map[string]any{"type": "string", "description": "Branch name for branch/push/open_pr"},
			"base_branch":   map[string]any{"type": "string", "description": "Base branch for open_pr"},
			"message":       map[string]any{"type": "string", "description": "Commit message or PR body"},
			"title":         map[string]any{"type": "string", "description": "Pull request title for open_pr"},
			"checkpoint_id": map[string]any{"type": "string", "description": "Checkpoint ID or ref for rewind"},
		},
		"required": []string{"op"},
	}
}

func (t *GitOpsTool) Execute(ctx context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Op           string `json:"op"`
		Branch       string `json:"branch"`
		BaseBranch   string `json:"base_branch"`
		Message      string `json:"message"`
		Title        string `json:"title"`
		CheckpointID string `json:"checkpoint_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid git_ops args: %w", err)
	}

	switch args.Op {
	case "status":
		out, err := runGit(ctx, t.Workspace, "status", "--short", "--branch")
		return Result{Output: out}, err
	case "diff":
		out, err := runGit(ctx, t.Workspace, "diff", "HEAD")
		if err != nil {
			out, err = runGit(ctx, t.Workspace, "diff")
		}
		if strings.TrimSpace(out) == "" {
			out = "(no unstaged or staged diff)"
		}
		return Result{Output: out}, err
	case "log":
		out, err := runGit(ctx, t.Workspace, "log", "-n", "10", "--oneline")
		return Result{Output: out}, err
	case "branch":
		if args.Branch == "" {
			out, err := runGit(ctx, t.Workspace, "branch", "--show-current")
			return Result{Output: strings.TrimSpace(out)}, err
		}
		out, err := runGit(ctx, t.Workspace, "checkout", "-B", args.Branch)
		return Result{Output: out}, err
	case "commit":
		msg := strings.TrimSpace(args.Message)
		if msg == "" {
			msg = "agentbox: apply automated fix"
		}
		if _, err := runGit(ctx, t.Workspace, "add", "-A"); err != nil {
			return Result{}, err
		}
		out, err := runGit(ctx, t.Workspace, "commit", "-m", msg)
		return Result{Output: out}, err
	case "checkpoint_list":
		if t.Checkpoints == nil {
			return Result{Output: "No checkpoints recorded"}, nil
		}
		list := t.Checkpoints.List()
		data, _ := json.MarshalIndent(list, "", "  ")
		return Result{Output: string(data)}, nil
	case "rewind":
		if t.Checkpoints == nil {
			return Result{}, fmt.Errorf("checkpoint manager not configured")
		}
		if err := t.Checkpoints.Rewind(ctx, args.CheckpointID); err != nil {
			return Result{}, err
		}
		return Result{Output: fmt.Sprintf("Rewound workspace to checkpoint %s", args.CheckpointID)}, nil
	case "push":
		branch := args.Branch
		if branch == "" {
			cur, err := runGit(ctx, t.Workspace, "branch", "--show-current")
			if err != nil {
				return Result{}, err
			}
			branch = strings.TrimSpace(cur)
		}
		for _, pb := range t.ProtectedBranches {
			if strings.EqualFold(pb, branch) {
				return Result{}, fmt.Errorf("refusing to push directly to protected branch %q", branch)
			}
		}
		out, err := runGit(ctx, t.Workspace, "push", "-u", "origin", branch)
		return Result{Output: out}, err
	case "open_pr":
		return t.openPR(ctx, args.Title, args.Message, args.Branch, args.BaseBranch)
	default:
		return Result{}, fmt.Errorf("unsupported git_ops operation %q", args.Op)
	}
}

func (t *GitOpsTool) openPR(ctx context.Context, title, body, branch, baseBranch string) (Result, error) {
	if t.ProxyBaseURL == "" {
		return Result{}, fmt.Errorf("host git proxy URL not configured; cannot open PR")
	}
	if branch == "" {
		cur, _ := runGit(ctx, t.Workspace, "branch", "--show-current")
		branch = strings.TrimSpace(cur)
	}
	if baseBranch == "" {
		baseBranch = "main"
	}
	reqBody, _ := json.Marshal(map[string]string{
		"title":       title,
		"body":        body,
		"head":        branch,
		"base":        baseBranch,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.ProxyBaseURL, "/")+"/git/pr", bytes.NewReader(reqBody))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AgentBox-Nonce", t.SessionNonce)

	client := t.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("proxy open_pr request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("proxy open_pr failed (%d): %s", resp.StatusCode, string(respBytes))
	}
	var pr protocol.PRCreatedPayload
	if err := json.Unmarshal(respBytes, &pr); err != nil {
		return Result{}, fmt.Errorf("decode pr response: %w", err)
	}
	if t.OnPRCreated != nil {
		t.OnPRCreated(pr)
	}
	return Result{
		Output: fmt.Sprintf("Opened PR #%d: %s (%s -> %s)", pr.Number, pr.URL, pr.Branch, pr.BaseBranch),
		Metadata: map[string]any{
			"url":    pr.URL,
			"number": pr.Number,
		},
	}, nil
}

// ComputeWorkspaceDiff returns the unified git diff and diff stats for a workspace directory,
// including newly created untracked files without mutating the repository's working index.
func ComputeWorkspaceDiff(ctx context.Context, workspace string) (string, protocol.DiffStats, error) {
	tmpIdx := filepath.Join(workspace, ".git", fmt.Sprintf("agentbox-diff-idx-%d", time.Now().UnixNano()))
	env := []string{"GIT_INDEX_FILE=" + tmpIdx}
	defer func() {
		_ = exec.Command("rm", "-f", tmpIdx).Run()
	}()

	var diffOut string
	var err error
	if _, rErr := runGitEnv(ctx, workspace, env, "read-tree", "HEAD"); rErr == nil {
		if _, aErr := runGitEnv(ctx, workspace, env, "add", "-A"); aErr == nil {
			diffOut, err = runGitEnv(ctx, workspace, env, "diff", "--cached", "HEAD")
		}
	}
	if err != nil || diffOut == "" {
		if fallback, fErr := runGit(ctx, workspace, "diff", "HEAD"); fErr == nil && fallback != "" {
			diffOut = fallback
		}
	}

	var stats protocol.DiffStats
	seenFiles := make(map[string]bool)
	for _, line := range strings.Split(diffOut, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			seenFiles[strings.TrimPrefix(line, "+++ b/")] = true
		} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			stats.Insertions++
		} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			stats.Deletions++
		}
	}
	stats.FilesChanged = len(seenFiles)
	return diffOut, stats, nil
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	return runGitEnv(ctx, dir, nil, args...)
}

func runGitEnv(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	if len(extraEnv) > 0 {
		cmd.Env = append(cmd.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.String(), fmt.Errorf("git %s: %s (%w)", strings.Join(args, " "), msg, err)
	}
	return stdout.String(), nil
}
