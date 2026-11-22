package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/parkiyong/agentbox/pkg/controlplane"
	"github.com/parkiyong/agentbox/pkg/harness"
	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox"
	"github.com/parkiyong/agentbox/pkg/sandbox/docker"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

const version = "0.1.0-alpha"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "dev":
		runDevServer(args)
	case "run":
		runOneShot(args)
	case "blueprint":
		runBlueprintCmd(args)
	case "version", "--version", "-v":
		fmt.Printf("agentbox %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", sub)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Print(`AgentBox — Autonomous SWE Agent Runtime CLI

Usage:
  agentbox dev [flags]                   Start local single-node Control Plane + Runner + Host Proxy
  agentbox run [flags]                   Run an autonomous SWE session locally and stream events
  agentbox blueprint validate <file>     Validate an agentbox.yaml Blueprint and display its hash
  agentbox version                       Print CLI version
`)
}

func runDevServer(args []string) {
	fs := flag.NewFlagSet("dev", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "Control Plane HTTP listen address")
	driverName := fs.String("driver", "local", "SandboxDriver: local | docker")
	agentdBin := fs.String("agentd-bin", "", "Path to static agentd binary (auto-detected if empty)")
	dataDir := fs.String("data-dir", filepath.Join(os.TempDir(), "agentbox-dev"), "Persistent data directory")
	mockLLM := fs.Bool("mock-llm", false, "Force deterministic MockSWEProvider")
	apiKey := fs.String("api-key", "", "Optional org API key (empty = open local dev mode)")
	_ = fs.Parse(args)

	store, err := controlplane.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	ledger := controlplane.NewCreditLedger()

	llmProvider, providerLabel := proxy.NewAutoProviderFromEnv(*mockLLM)
	log.Printf("LLM provider: %s", providerLabel)

	var gitBroker proxy.GitTokenBroker
	if tok := os.Getenv("AGENTBOX_GIT_TOKEN"); tok != "" {
		gitBroker = &proxy.StaticGitTokenBroker{Token: tok}
	}

	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: llmProvider,
		GitBroker:   gitBroker,
		Secrets:     proxy.NewMapSecretStore(nil),
	})
	proxy.RegisterBYOCProvidersFromEnv(hostProxy.LLM)
	if err := hostProxy.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		log.Fatalf("start host proxy: %v", err)
	}
	defer hostProxy.Close(context.Background())

	var drv sandbox.SandboxDriver
	switch *driverName {
	case "docker":
		drv, err = docker.NewDriver(filepath.Join(*dataDir, "docker"))
	default:
		drv, err = local.NewDriver(filepath.Join(*dataDir, "local"))
	}
	if err != nil {
		log.Fatalf("init sandbox driver: %v", err)
	}

	var orgKeys map[string]string
	if *apiKey != "" {
		orgKeys = map[string]string{*apiKey: "org_dev"}
	}
	auth := controlplane.NewAuthManager(os.Getenv("AGENTBOX_JWT_SECRET"), orgKeys)
	orch := controlplane.NewOrchestrator(store, ledger, hostProxy, drv)
	orch.AgentDBinary = sandbox.FindAgentDBinary(*agentdBin)
	apiSrv := controlplane.NewServer(orch, auth)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           apiSrv,
		ReadHeaderTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	execMode := "in-process"
	if orch.AgentDBinary != "" {
		execMode = "isolated agentd (" + orch.AgentDBinary + ")"
	}
	go func() {
		log.Printf("AgentBox local dev server listening on http://%s (driver=%s, mode=%s, proxy=%s, egress=%s)",
			*addr, drv.Name(), execMode, hostProxy.APIBaseURL(), hostProxy.EgressProxyURL())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func runOneShot(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	blueprintFile := fs.String("blueprint", "", "Path to agentbox.yaml Blueprint")
	repoFlag := fs.String("repo", ".", "Local repository directory OR remote Git URL (https://...)")
	baseBranch := fs.String("branch", "", "Optional base branch for remote Git repo")
	agentdBin := fs.String("agentd-bin", "", "Path to static agentd binary (auto-detected if empty)")
	task := fs.String("task", "", "Autonomous SWE task prompt")
	jsonOut := fs.Bool("json", false, "Stream canonical JSON events (one per line)")
	mockLLM := fs.Bool("mock-llm", false, "Use deterministic MockSWEProvider")
	_ = fs.Parse(args)

	if *task == "" {
		fmt.Fprintln(os.Stderr, "error: --task is required")
		os.Exit(2)
	}

	var bp *protocol.Blueprint
	if *blueprintFile != "" {
		loaded, err := protocol.LoadBlueprintFile(*blueprintFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		bp = loaded
	} else {
		bp = protocol.DefaultBlueprint("local-cli")
	}

	llmProvider, _ := proxy.NewAutoProviderFromEnv(*mockLLM)
	var gitBroker proxy.GitTokenBroker
	if tok := os.Getenv("AGENTBOX_GIT_TOKEN"); tok != "" {
		gitBroker = &proxy.StaticGitTokenBroker{Token: tok}
	}

	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: llmProvider,
		GitBroker:   gitBroker,
	})
	proxy.RegisterBYOCProvidersFromEnv(hostProxy.LLM)
	if err := hostProxy.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		log.Fatalf("start host proxy: %v", err)
	}
	defer hostProxy.Close(context.Background())

	drv, err := local.NewDriver(filepath.Join(os.TempDir(), "agentbox-run"))
	if err != nil {
		log.Fatalf("init local driver: %v", err)
	}

	var repoSpec protocol.RepoSpec
	if strings.HasPrefix(*repoFlag, "http://") || strings.HasPrefix(*repoFlag, "https://") {
		repoSpec = protocol.RepoSpec{URL: *repoFlag, BaseBranch: *baseBranch}
	} else {
		absRepo, err := filepath.Abs(*repoFlag)
		if err != nil {
			log.Fatalf("resolve repo path: %v", err)
		}
		repoSpec = protocol.RepoSpec{LocalPath: absRepo}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sessionID := protocol.NewID("ses_")
	nonce, _ := protocol.NewNonce()
	wsID := sandbox.WorkspaceKey("org_local", "local_user", repoSpec.URL+repoSpec.LocalPath, bp.Hash())
	handle, err := drv.Create(ctx, sandbox.SandboxSpec{
		SessionID:    sessionID,
		OrgID:        "org_local",
		CustomerID:   "local_user",
		WorkspaceID:  wsID,
		SessionNonce: nonce,
		ProxyAddr:    hostProxy.APIBaseURL(),
		EgressProxy:  hostProxy.EgressProxyURL(),
		Repo:         repoSpec,
	})
	if err != nil {
		log.Fatalf("create sandbox: %v", err)
	}
	defer drv.Destroy(context.Background(), handle)

	hostProxy.Registry.Register(&proxy.SessionBinding{
		Nonce:      nonce,
		SessionID:  sessionID,
		OrgID:      "org_local",
		CustomerID: "local_user",
		RepoURL:    repoSpec.URL,
		Blueprint:  bp,
	})
	defer hostProxy.Registry.Unregister(nonce)

	if _, err := sandbox.BootstrapWorkspace(ctx, sandbox.BootstrapConfig{
		WorkspacePath: handle.WorkspacePath,
		SessionID:     sessionID,
		Repo:          repoSpec,
		Blueprint:     bp,
		ProxyBaseURL:  hostProxy.APIBaseURL(),
		EgressProxy:   hostProxy.EgressProxyURL(),
		SessionNonce:  nonce,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap workspace failed: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	var finalSummary string
	onEvent := func(evt protocol.Event) {
		if evt.Type == protocol.EventSessionCompleted {
			var p protocol.SessionLifecyclePayload
			if json.Unmarshal(evt.Payload, &p) == nil {
				finalSummary = p.Summary
			}
		}
		if *jsonOut {
			_ = enc.Encode(evt)
			return
		}
		fmt.Printf("[%02d] %-20s %s\n", evt.Seq, evt.Type, string(evt.Payload))
	}

	// Prefer out-of-process static agentd binary with zero-secret environment when available.
	resolvedBin := sandbox.FindAgentDBinary(*agentdBin)
	if resolvedBin != "" {
		proc, err := drv.StartAgent(ctx, handle, sandbox.AgentRunRequest{
			SessionID:    sessionID,
			CustomerID:   "local_user",
			Task:         *task,
			Blueprint:    bp,
			Limits:       bp.Limits,
			SessionNonce: nonce,
			ProxyAddr:    hostProxy.APIBaseURL(),
			EgressProxy:  hostProxy.EgressProxyURL(),
			AgentDBinary: resolvedBin,
		}, onEvent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start agentd failed: %v\n", err)
			os.Exit(1)
		}
		if err := proc.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "session failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		engine := harness.NewEngine(harness.EngineConfig{
			SessionID:    sessionID,
			CustomerID:   "local_user",
			Workspace:    handle.WorkspacePath,
			Task:         *task,
			Blueprint:    bp,
			Limits:       bp.Limits,
			ProxyAddr:    hostProxy.APIBaseURL(),
			SessionNonce: nonce,
			LLM:          harness.NewProxyLLMClient(hostProxy.APIBaseURL(), nonce),
			OnEvent:      onEvent,
		})
		summary, err := engine.Run(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "session failed: %v\n", err)
			os.Exit(1)
		}
		finalSummary = summary
	}

	if !*jsonOut {
		fmt.Printf("\nCompleted (%s): %s\n", sessionID, finalSummary)
	}
}

func runBlueprintCmd(args []string) {
	if len(args) < 2 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: agentbox blueprint validate <agentbox.yaml>")
		os.Exit(2)
	}
	bp, err := protocol.LoadBlueprintFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID blueprint: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID Blueprint: %s@%s\n", bp.Metadata.Name, bp.Metadata.Version)
	fmt.Printf("  Hash:       %s\n", bp.Hash())
	fmt.Printf("  Image:      %s (%d vCPU, %dMB RAM, %dGB Disk)\n", bp.Runtime.Image, bp.Runtime.Resources.VCPU, bp.Runtime.Resources.MemoryMB, bp.Runtime.Resources.DiskGB)
	fmt.Printf("  Model:      %s\n", bp.Model.Profile)
	fmt.Printf("  Egress:     default=%s (%d allowlisted domains)\n", bp.Network.Egress.Default, len(bp.Network.Egress.AllowDomains))
	fmt.Printf("  MCP:        %d server(s)\n", len(bp.MCPServers))
	fmt.Printf("  Policies:   %d approval rule(s)\n", len(bp.Policies.Approvals))
	fmt.Printf("  Limits:     max_credits=%.0f, max_turns=%d, max_wall_clock=%ds\n", bp.Limits.MaxCredits, bp.Limits.MaxTurns, bp.Limits.MaxWallClockSeconds)
}
