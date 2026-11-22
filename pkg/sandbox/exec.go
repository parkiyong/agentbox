package sandbox

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

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// AgentRunRequest configures an out-of-process agentd invocation inside a sandbox.
// ZERO raw credentials are included — only the ephemeral SessionNonce and Host Proxy URLs.
type AgentRunRequest struct {
	SessionID    string
	CustomerID   string
	Task         string
	Blueprint    *protocol.Blueprint
	Limits       protocol.LimitsConfig
	SessionNonce string
	ProxyAddr    string
	EgressProxy  string
	AgentDBinary string
}

// AgentProcess represents a running isolated agentd process communicating via JSONL
// (stdout = canonical protocol.Event stream; stdin = harness.ControlMessage commands).
type AgentProcess interface {
	SendControl(msg any) error
	Wait() error
	Kill() error
}

// AgentExecutor is an optional capability interface implemented by SandboxDrivers
// that execute the static Go agentd binary out-of-process inside the sandbox boundary.
type AgentExecutor interface {
	StartAgent(ctx context.Context, handle *SandboxHandle, req AgentRunRequest, onEvent func(protocol.Event)) (AgentProcess, error)
}

// BuildSandboxEnv returns a strictly sanitized environment slice for sandboxed execution.
// Host environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY,
// AGENTBOX_GIT_TOKEN, AWS_*, etc.) are NEVER inherited.
func BuildSandboxEnv(req AgentRunRequest, workspaceDir, blueprintPath, limitsJSON string) []string {
	pathVal := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if hostPath := os.Getenv("PATH"); hostPath != "" {
		// Preserve toolchain PATH entries (e.g. go/node/uv) while keeping zero secrets.
		pathVal = hostPath
	}

	env := []string{
		"PATH=" + pathVal,
		"HOME=" + workspaceDir,
		"TMPDIR=" + os.TempDir(),
		"LANG=C.UTF-8",
		"GIT_TERMINAL_PROMPT=0",
		"AGENTBOX_SESSION_ID=" + req.SessionID,
		"AGENTBOX_CUSTOMER_ID=" + req.CustomerID,
		"AGENTBOX_WORKSPACE=" + workspaceDir,
		"AGENTBOX_PROXY_URL=" + req.ProxyAddr,
		"AGENTBOX_SESSION_NONCE=" + req.SessionNonce,
		"AGENTBOX_TASK=" + req.Task,
	}
	if blueprintPath != "" {
		env = append(env, "AGENTBOX_BLUEPRINT_PATH="+blueprintPath)
	}
	if limitsJSON != "" {
		env = append(env, "AGENTBOX_LIMITS_JSON="+limitsJSON)
	}
	if req.EgressProxy != "" {
		env = append(env,
			"HTTP_PROXY="+req.EgressProxy,
			"HTTPS_PROXY="+req.EgressProxy,
			"NO_PROXY=127.0.0.1,localhost",
		)
	}
	return env
}

// WriteRuntimeBlueprintFile writes the Blueprint YAML/JSON to a temporary host file
// mounted or passed read-only to agentd.
func WriteRuntimeBlueprintFile(dir string, bp *protocol.Blueprint) (string, error) {
	if bp == nil {
		return "", nil
	}
	data, err := json.Marshal(bp)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, ".agentbox-blueprint.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// ExecAgentProcess wraps an *exec.Cmd running agentd with JSONL stdin/stdout streaming.
type ExecAgentProcess struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdinMu    sync.Mutex
	stderrBuf  strings.Builder
	stderrMu   sync.Mutex
	doneCh     chan error
	cleanupFns []func()
}

// StartCmdAgent launches a configured *exec.Cmd (local subprocess or `docker exec -i`)
// and wires stdout JSONL events to onEvent and stdin to SendControl.
func StartCmdAgent(cmd *exec.Cmd, onEvent func(protocol.Event), cleanupFns ...func()) (*ExecAgentProcess, error) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("agentd stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("agentd stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("agentd stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start agentd process: %w", err)
	}

	proc := &ExecAgentProcess{
		cmd:        cmd,
		stdin:      stdinPipe,
		doneCh:     make(chan error, 1),
		cleanupFns: cleanupFns,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream canonical JSONL protocol.Event records from agentd stdout.
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var evt protocol.Event
			if err := json.Unmarshal([]byte(line), &evt); err == nil && evt.Type != "" {
				if onEvent != nil {
					onEvent(evt)
				}
			}
		}
	}()

	// Capture stderr diagnostics for failure reporting.
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 0, 32*1024), 512*1024)
		for scanner.Scan() {
			proc.stderrMu.Lock()
			if proc.stderrBuf.Len() < 16*1024 {
				proc.stderrBuf.WriteString(scanner.Text())
				proc.stderrBuf.WriteByte('\n')
			}
			proc.stderrMu.Unlock()
		}
	}()

	go func() {
		wg.Wait()
		waitErr := cmd.Wait()
		for _, fn := range proc.cleanupFns {
			if fn != nil {
				fn()
			}
		}
		if waitErr != nil {
			proc.stderrMu.Lock()
			diag := strings.TrimSpace(proc.stderrBuf.String())
			proc.stderrMu.Unlock()
			if diag != "" {
				waitErr = fmt.Errorf("%w: %s", waitErr, diag)
			}
		}
		proc.doneCh <- waitErr
		close(proc.doneCh)
	}()

	return proc, nil
}

func (p *ExecAgentProcess) SendControl(msg any) error {
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = p.stdin.Write(append(data, '\n'))
	return err
}

func (p *ExecAgentProcess) Wait() error {
	err := <-p.doneCh
	return err
}

func (p *ExecAgentProcess) Kill() error {
	p.stdinMu.Lock()
	_ = p.stdin.Close()
	p.stdinMu.Unlock()
	if p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

// FindAgentDBinary locates a prebuilt static agentd binary on the host (explicit path,
// AGENTBOX_AGENTD_BIN env var, ./bin/agentd, or sibling of current executable).
func FindAgentDBinary(explicit string) string {
	candidates := []string{
		explicit,
		os.Getenv("AGENTBOX_AGENTD_BIN"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "agentd"))
	}
	candidates = append(candidates, "bin/agentd", "/opt/agentbox/agentd")

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}
