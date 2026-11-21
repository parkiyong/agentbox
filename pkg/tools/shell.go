package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

const (
	defaultShellTimeoutSec = 120
	maxShellTimeoutSec     = 600
	maxOutputBytes         = 16 * 1024
)

// ShellExecTool executes shell commands with persistent working directory & environment,
// live terminal.chunk streaming, configurable timeout, and smart head+tail summarization.
type ShellExecTool struct {
	Workspace string
	ExtraEnv  []string
	OnChunk   func(protocol.TerminalChunkPayload)

	mu  sync.Mutex
	cwd string
	env map[string]string
}

func NewShellExecTool(workspace string, extraEnv []string, onChunk func(protocol.TerminalChunkPayload)) *ShellExecTool {
	abs, _ := filepath.Abs(workspace)
	return &ShellExecTool{
		Workspace: abs,
		ExtraEnv:  extraEnv,
		OnChunk:   onChunk,
		cwd:       abs,
		env:       make(map[string]string),
	}
}

func (t *ShellExecTool) Name() string { return "shell_exec" }
func (t *ShellExecTool) Description() string {
	return "Run shell commands (builds, tests, linters, CLI tools) with persistent cwd, streaming output, and timeout."
}
func (t *ShellExecTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command":         map[string]any{"type": "string", "description": "Bash command to execute"},
			"workdir":         map[string]any{"type": "string", "description": "Optional working directory relative to workspace"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "Command timeout in seconds (default 120, max 600)"},
		},
		"required": []string{"command"},
	}
}

func (t *ShellExecTool) Execute(ctx context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Command        string `json:"command"`
		Workdir        string `json:"workdir"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid shell_exec args: %w", err)
	}
	if strings.TrimSpace(args.Command) == "" {
		return Result{}, fmt.Errorf("command is required")
	}

	timeout := args.TimeoutSeconds
	if timeout <= 0 {
		timeout = defaultShellTimeoutSec
	}
	if timeout > maxShellTimeoutSec {
		timeout = maxShellTimeoutSec
	}

	t.mu.Lock()
	runDir := t.cwd
	if args.Workdir != "" {
		resolved, _, err := SafeWorkspacePath(t.Workspace, args.Workdir)
		if err != nil {
			t.mu.Unlock()
			return Result{}, err
		}
		runDir = resolved
	}
	baseEnv := os.Environ()
	for _, kv := range t.ExtraEnv {
		baseEnv = append(baseEnv, kv)
	}
	for k, v := range t.env {
		baseEnv = append(baseEnv, k+"="+v)
	}
	t.mu.Unlock()

	// Wrap command so we capture final pwd for stateful directory persistence across calls.
	sentinel := "__AGENTBOX_PWD_SENTINEL__"
	wrapped := fmt.Sprintf("%s\n__abx_rc=$?\nprintf '\\n%s%%s\\n' \"$PWD\" >&2\nexit $__abx_rc", args.Command, sentinel)

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "bash", "-c", wrapped)
	cmd.Dir = runDir
	cmd.Env = baseEnv

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return Result{}, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start shell command: %w", err)
	}

	var outMu sync.Mutex
	var combined strings.Builder
	var newCWD string

	var wg sync.WaitGroup
	streamReader := func(streamName string, r io.Reader) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if streamName == "stderr" && strings.HasPrefix(line, sentinel) {
				candidate := strings.TrimPrefix(line, sentinel)
				if _, _, err := SafeWorkspacePath(t.Workspace, candidate); err == nil {
					newCWD = candidate
				}
				continue
			}
			outMu.Lock()
			combined.WriteString(line)
			combined.WriteByte('\n')
			if t.OnChunk != nil {
				t.OnChunk(protocol.TerminalChunkPayload{
					Command: args.Command,
					Stream:  streamName,
					Data:    line + "\n",
				})
			}
			outMu.Unlock()
		}
	}

	wg.Add(2)
	go streamReader("stdout", stdoutPipe)
	go streamReader("stderr", stderrPipe)
	wg.Wait()

	waitErr := cmd.Wait()
	exitCode := 0
	if waitErr != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			exitCode = 124
		} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	if newCWD != "" {
		t.mu.Lock()
		t.cwd = newCWD
		t.mu.Unlock()
	}

	if t.OnChunk != nil {
		t.OnChunk(protocol.TerminalChunkPayload{
			Command:  args.Command,
			Stream:   "stdout",
			Data:     "",
			ExitCode: &exitCode,
		})
	}

	summary := smartTruncateTerminalOutput(combined.String(), maxOutputBytes)
	output := fmt.Sprintf("$ %s\n(exit code %d)\n%s", args.Command, exitCode, summary)
	meta := map[string]any{
		"exit_code": exitCode,
		"cwd":       runDir,
	}
	if exitCode != 0 {
		return Result{Output: output, Metadata: meta}, fmt.Errorf("command exited with status %d", exitCode)
	}
	return Result{Output: output, Metadata: meta}, nil
}

// smartTruncateTerminalOutput preserves the beginning and end of verbose build/test logs
// while surfacing error/failure lines from the middle if truncated.
func smartTruncateTerminalOutput(out string, maxBytes int) string {
	if len(out) <= maxBytes {
		return out
	}
	headBytes := maxBytes / 3
	tailBytes := maxBytes / 2
	head := out[:headBytes]
	tail := out[len(out)-tailBytes:]
	middle := out[headBytes : len(out)-tailBytes]

	// Extract up to 20 error-related lines from the omitted middle section.
	var highlights []string
	for _, line := range strings.Split(middle, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "fail") || strings.Contains(lower, "panic") || strings.Contains(lower, "exception") {
			highlights = append(highlights, line)
			if len(highlights) >= 20 {
				break
			}
		}
	}

	var b strings.Builder
	b.WriteString(head)
	fmt.Fprintf(&b, "\n... [%d bytes omitted", len(middle))
	if len(highlights) > 0 {
		fmt.Fprintf(&b, "; %d error/failure lines highlighted below]\n", len(highlights))
		for _, h := range highlights {
			b.WriteString("  ! ")
			b.WriteString(h)
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("]\n")
	}
	b.WriteString(tail)
	return b.String()
}
