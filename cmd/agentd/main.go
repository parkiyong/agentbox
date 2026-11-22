package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/parkiyong/agentbox/pkg/harness"
	"github.com/parkiyong/agentbox/pkg/protocol"
)

func main() {
	var (
		sessionID     = flag.String("session-id", envOrDefault("AGENTBOX_SESSION_ID", protocol.NewID("ses_")), "Session ID")
		customerID    = flag.String("customer-id", envOrDefault("AGENTBOX_CUSTOMER_ID", "local"), "Customer ID")
		workspace     = flag.String("workspace", envOrDefault("AGENTBOX_WORKSPACE", "/workspace"), "Workspace directory")
		proxyURL      = flag.String("proxy-url", envOrDefault("AGENTBOX_PROXY_URL", "unix:///run/agentbox/proxy.sock"), "Host-Side Security Proxy URL")
		sessionNonce  = flag.String("session-nonce", os.Getenv("AGENTBOX_SESSION_NONCE"), "Ephemeral session nonce (zero raw secrets)")
		blueprintPath = flag.String("blueprint", os.Getenv("AGENTBOX_BLUEPRINT_PATH"), "Path to agentbox.yaml or JSON Blueprint")
		limitsJSON    = flag.String("limits-json", os.Getenv("AGENTBOX_LIMITS_JSON"), "Optional JSON-encoded LimitsConfig override")
		task          = flag.String("task", os.Getenv("AGENTBOX_TASK"), "Autonomous SWE task prompt")
	)
	flag.Parse()

	if *task == "" {
		fmt.Fprintln(os.Stderr, "agentd: --task or AGENTBOX_TASK is required")
		os.Exit(2)
	}

	bp, err := loadBlueprint(*blueprintPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentd: load blueprint: %v\n", err)
		os.Exit(2)
	}

	limits := bp.Limits
	if *limitsJSON != "" {
		var override protocol.LimitsConfig
		if err := json.Unmarshal([]byte(*limitsJSON), &override); err != nil {
			fmt.Fprintf(os.Stderr, "agentd: parse limits-json: %v\n", err)
			os.Exit(2)
		}
		limits = protocol.MergeLimits(bp.Limits, &override)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var outMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)

	engine := harness.NewEngine(harness.EngineConfig{
		SessionID:    *sessionID,
		CustomerID:   *customerID,
		Workspace:    *workspace,
		Task:         *task,
		Blueprint:    bp,
		Limits:       limits,
		ProxyAddr:    *proxyURL,
		SessionNonce: *sessionNonce,
		LLM:          harness.NewProxyLLMClient(*proxyURL, *sessionNonce),
		OnEvent: func(evt protocol.Event) {
			outMu.Lock()
			_ = enc.Encode(evt)
			outMu.Unlock()
		},
	})

	// Listen for JSONL interactive control signals (steer / approval / resume / cancel) on stdin.
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 32*1024), 1024*1024)
		for scanner.Scan() {
			var msg harness.ControlMessage
			if json.Unmarshal(scanner.Bytes(), &msg) == nil && msg.Kind != "" {
				engine.SendControl(msg)
			}
		}
	}()

	if _, err := engine.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agentd: session ended with error: %v\n", err)
		os.Exit(1)
	}
}

func loadBlueprint(path string) (*protocol.Blueprint, error) {
	if path == "" {
		return protocol.DefaultBlueprint("agentd-default"), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Accept either JSON (written by runner) or YAML (agentbox.yaml).
	if len(data) > 0 && data[0] == '{' {
		var bp protocol.Blueprint
		if err := json.Unmarshal(data, &bp); err != nil {
			return nil, err
		}
		bp.ApplyDefaults()
		return &bp, bp.Validate()
	}
	return protocol.ParseBlueprintYAML(data)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
