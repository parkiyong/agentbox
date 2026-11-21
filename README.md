# AgentBox

**Vertically integrated, multi-tenant Autonomous Software Engineering (SWE) Agent Runtime (Managed Cloud + Self-Hosted BYOC).**

AgentBox collapses three layers into one cohesive primitive so software/devtools companies can embed autonomous SWE agents into their products without building microVM infrastructure, zero-trust security boundaries, or an SWE harness from scratch:

1. **Isolated Sandbox Runtime (`pkg/sandbox`)** — Pluggable `SandboxDriver` supporting Firecracker microVMs (Cloud), Kubernetes gVisor/Kata RuntimeClass (BYOC), hardened Docker, and local dev with warm workspace snapshots (`workspace_id`) and hibernation.
2. **Zero-Trust Host-Side Security Proxy (`pkg/proxy`)** — Zero raw credentials ever enter the sandbox. Ephemeral `AGENTBOX_SESSION_NONCE` authenticates to host-side LLM Proxy, Git & Secret Broker (RS256 GitHub App token minting, repo scoping, protected-branch & HITL push gating), MCP Tool Bridge, and Anti-SSRF Egress Firewall.
3. **One Opinionated Native SWE Harness (`cmd/agentd`, `pkg/harness`, `pkg/tools`)** — Static `CGO_ENABLED=0` Go binary (~7.6 MB) with Plan → Explore → Edit → Verify → Self-Heal loop, shadow git micro-checkpoints (`refs/agentbox/checkpoints/<step>`), Lean Core SWE toolset (`fs_read`, `fs_edit_patch`, `fs_search`, `code_outline`, `shell_exec`, `git_ops`, `mcp.*`), HITL approvals, and graceful `budget_paused` / resume.

---

## Repository Layout

```text
agentbox/
├── cmd/
│   ├── agentd/               # Static Go SWE harness binary (runs inside sandbox)
│   ├── agentbox-runner/      # Data plane runner + Host-Side Security Proxy (outbound mTLS)
│   └── agentbox/             # Developer CLI (`agentbox dev`, `agentbox run`, `blueprint validate`)
├── pkg/
│   ├── protocol/             # Canonical event envelope, session state machine, agentbox.yaml Blueprint & policy engine
│   ├── tools/                # Lean v1 tools: fs_read, fs_edit_patch, fs_search, code_outline, shell_exec, git_ops, mcp
│   ├── harness/              # Opinionated SWE loop, context compactor, checkpoints, HITL & budget pause/resume
│   ├── proxy/                # Host-side Git broker, LLM proxy, MCP bridge, Anti-SSRF egress firewall
│   ├── sandbox/              # SandboxDriver interface + local/, docker/, firecracker/, k8s/ drivers
│   └── controlplane/         # Single-node Control Plane REST/SSE API, durable JSONL event log, Credit Ledger, JWT Client Tokens, HMAC webhooks
├── sdks/
│   ├── typescript/           # @agentbox/sdk (Node/Edge, zero runtime deps)
│   ├── react/                # @agentbox/react white-label UI primitives
│   └── python/               # agentbox-python (zero runtime deps)
├── deploy/
│   └── helm/agentbox-runner/ # BYOC Kubernetes Helm chart (gVisor/Kata + zero-inbound NetworkPolicy + outbound mTLS)
└── examples/
    └── issue-to-pr-app/      # End-to-end B2B2C demo embedding AgentBox
```

---

## Quickstart

### 1. Build Static Binaries & Run Full Test Suite

```bash
make build
make test
```

### 2. Validate a Blueprint (`agentbox.yaml`)

```bash
./bin/agentbox blueprint validate examples/issue-to-pr-app/agentbox.yaml
```

### 3. Run a Local Autonomous SWE Session

```bash
./bin/agentbox run \
  --blueprint examples/issue-to-pr-app/agentbox.yaml \
  --repo . \
  --task "Inspect workspace and generate verification report" \
  --mock-llm
```

*(Set `AGENTBOX_LLM_API_KEY` or `OPENAI_API_KEY` and omit `--mock-llm` to run against live LLM inference via the Host-Side LLM Proxy.)*

### 4. Start the Local Control Plane (`agentbox dev`)

```bash
./bin/agentbox dev --addr 127.0.0.1:8080 --driver local
```

Then embed using `@agentbox/sdk`, `agentbox-python`, or `@agentbox/react`:

```tsx
<AgentBoxProvider clientToken={clientToken} apiBaseUrl="http://127.0.0.1:8080">
  <SessionHeader showBudgetBar showStatus />
  <SessionTimeline />
  <ApprovalBanner />
  <DiffViewer mode="split" />
  <SteerInput placeholder="Guide the agent or answer its question..." />
</AgentBoxProvider>
```

---

## License

Apache License 2.0 (see [LICENSE](LICENSE)).