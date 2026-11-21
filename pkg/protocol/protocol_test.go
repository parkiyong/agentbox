package protocol

import (
	"strings"
	"testing"
)

const sampleBlueprintYAML = `
apiVersion: agentbox.dev/v1
kind: Blueprint
metadata:
  name: acme-autofix-swe
  version: "1.2.0"

runtime:
  image: ghcr.io/agentbox/swe-node22-py312:v1
  resources:
    vcpu: 2
    memory_mb: 4096
    disk_gb: 20
  setup:
    commands:
      - "[ -f package-lock.json ] && npm ci || true"
    cache_paths:
      - node_modules
      - .venv

model:
  profile: swe-balanced
  byoc_provider: null

harness:
  system_instructions: |
    You are Acme's automated software engineer.
  skills:
    - path: ./skills/test-conventions.md
  git:
    branch_prefix: "agentbox/fix-"
    auto_create_pr: true
    protected_branches: ["main", "master", "production"]

network:
  egress:
    default: deny
    allow_domains:
      - registry.npmjs.org
      - pypi.org

mcp_servers:
  - name: sentry
    transport: streamable-http
    url: https://api.acme.internal/mcp/sentry
    auth_secret_ref: acme_sentry_mcp_token
    allowed_tools: ["get_issue", "get_stacktrace"]

policies:
  approvals:
    - action: git.push
      mode: require_approval
    - action: shell.exec
      match_regex: "(rm -rf|drop table|migrate|terraform apply)"
      mode: require_approval
    - action: fs.edit
      match_globs: [".github/workflows/**", "**/migrations/**"]
      mode: require_approval

limits:
  max_credits: 500
  max_turns: 40
  max_wall_clock_seconds: 1800
  idle_hibernate_seconds: 300
`

func TestParseBlueprintYAMLAndPolicies(t *testing.T) {
	bp, err := ParseBlueprintYAML([]byte(sampleBlueprintYAML))
	if err != nil {
		t.Fatalf("ParseBlueprintYAML failed: %v", err)
	}
	if bp.Metadata.Name != "acme-autofix-swe" || bp.Metadata.Version != "1.2.0" {
		t.Fatalf("unexpected metadata: %+v", bp.Metadata)
	}
	if bp.Hash() == "" || len(bp.Hash()) != 16 {
		t.Fatalf("unexpected hash: %q", bp.Hash())
	}

	// Protected branches
	if !bp.IsProtectedBranch("main") || !bp.IsProtectedBranch("refs/heads/production") {
		t.Fatalf("expected main and production to be protected")
	}
	if bp.IsProtectedBranch("agentbox/fix-123") {
		t.Fatalf("did not expect feature branch to be protected")
	}

	// Policy checks
	cases := []struct {
		action string
		target string
		want   PolicyMode
	}{
		{"git.push", "agentbox/fix-1", PolicyRequireApproval},
		{"shell.exec", "go test ./...", PolicyAlwaysAllow},
		{"shell.exec", "rm -rf /tmp/foo", PolicyRequireApproval},
		{"fs.edit", "src/app.ts", PolicyAlwaysAllow},
		{"fs.edit", ".github/workflows/ci.yml", PolicyRequireApproval},
		{"fs.edit", "services/billing/migrations/001_init.sql", PolicyRequireApproval},
	}
	for _, tc := range cases {
		got, _ := bp.EvaluatePolicy(tc.action, tc.target)
		if got != tc.want {
			t.Errorf("EvaluatePolicy(%q, %q) = %q, want %q", tc.action, tc.target, got, tc.want)
		}
	}
}

func TestSessionStateMachine(t *testing.T) {
	valid := [][2]SessionStatus{
		{SessionQueued, SessionProvisioning},
		{SessionProvisioning, SessionRunning},
		{SessionRunning, SessionWaitingApproval},
		{SessionWaitingApproval, SessionRunning},
		{SessionWaitingApproval, SessionHibernated},
		{SessionRunning, SessionBudgetPaused},
		{SessionBudgetPaused, SessionRunning},
		{SessionBudgetPaused, SessionHibernated},
		{SessionHibernated, SessionProvisioning},
		{SessionRunning, SessionCompleted},
	}
	for _, pair := range valid {
		if err := pair[0].ValidateTransition(pair[1]); err != nil {
			t.Errorf("expected valid transition %s -> %s, got err: %v", pair[0], pair[1], err)
		}
	}

	invalid := [][2]SessionStatus{
		{SessionCompleted, SessionRunning},
		{SessionFailed, SessionProvisioning},
		{SessionQueued, SessionCompleted},
		{SessionCancelled, SessionRunning},
	}
	for _, pair := range invalid {
		if err := pair[0].ValidateTransition(pair[1]); err == nil {
			t.Errorf("expected invalid transition %s -> %s to fail", pair[0], pair[1])
		}
	}
}

func TestIDAndNonceGeneration(t *testing.T) {
	id1 := NewID("ses_")
	id2 := NewID("ses_")
	if !strings.HasPrefix(id1, "ses_") || id1 == id2 {
		t.Fatalf("unexpected IDs: %q, %q", id1, id2)
	}
	nonce, err := NewNonce()
	if err != nil || !strings.HasPrefix(nonce, "abx_nonce_") || len(nonce) < 40 {
		t.Fatalf("unexpected nonce: %q, err=%v", nonce, err)
	}
}
