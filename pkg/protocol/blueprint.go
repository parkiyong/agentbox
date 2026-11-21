package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	BlueprintAPIVersion = "agentbox.dev/v1"
	BlueprintKind       = "Blueprint"
)

// Blueprint defines the declarative agentbox.yaml configuration for an autonomous SWE agent.
type Blueprint struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Metadata   BlueprintMetadata `yaml:"metadata" json:"metadata"`
	Runtime    RuntimeConfig     `yaml:"runtime" json:"runtime"`
	Model      ModelConfig       `yaml:"model" json:"model"`
	Harness    HarnessConfig     `yaml:"harness" json:"harness"`
	Network    NetworkConfig     `yaml:"network" json:"network"`
	MCPServers []MCPServerConfig `yaml:"mcp_servers,omitempty" json:"mcp_servers,omitempty"`
	Policies   PoliciesConfig    `yaml:"policies,omitempty" json:"policies,omitempty"`
	Limits     LimitsConfig      `yaml:"limits,omitempty" json:"limits,omitempty"`
}

type BlueprintMetadata struct {
	Name        string            `yaml:"name" json:"name"`
	Version     string            `yaml:"version" json:"version"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

type RuntimeConfig struct {
	Image     string         `yaml:"image" json:"image"`
	Resources ResourceConfig `yaml:"resources,omitempty" json:"resources,omitempty"`
	Setup     SetupConfig    `yaml:"setup,omitempty" json:"setup,omitempty"`
}

type ResourceConfig struct {
	VCPU     int `yaml:"vcpu,omitempty" json:"vcpu,omitempty"`
	MemoryMB int `yaml:"memory_mb,omitempty" json:"memory_mb,omitempty"`
	DiskGB   int `yaml:"disk_gb,omitempty" json:"disk_gb,omitempty"`
}

type SetupConfig struct {
	Commands   []string `yaml:"commands,omitempty" json:"commands,omitempty"`
	CachePaths []string `yaml:"cache_paths,omitempty" json:"cache_paths,omitempty"`
}

type ModelConfig struct {
	// Profile selects the managed inference tier: swe-fast | swe-balanced | swe-max
	Profile string `yaml:"profile" json:"profile"`
	// BYOCProvider optionally references a self-hosted BYOC provider (e.g., "anthropic-byok", "local-vllm").
	BYOCProvider *string `yaml:"byoc_provider,omitempty" json:"byoc_provider,omitempty"`
}

type HarnessConfig struct {
	SystemInstructions string        `yaml:"system_instructions,omitempty" json:"system_instructions,omitempty"`
	Skills             []SkillRef    `yaml:"skills,omitempty" json:"skills,omitempty"`
	Git                GitConfig     `yaml:"git,omitempty" json:"git,omitempty"`
}

type SkillRef struct {
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
	Content string `yaml:"content,omitempty" json:"content,omitempty"`
}

type GitConfig struct {
	BranchPrefix      string   `yaml:"branch_prefix,omitempty" json:"branch_prefix,omitempty"`
	AutoCreatePR      bool     `yaml:"auto_create_pr,omitempty" json:"auto_create_pr,omitempty"`
	ProtectedBranches []string `yaml:"protected_branches,omitempty" json:"protected_branches,omitempty"`
}

type NetworkConfig struct {
	Egress EgressConfig `yaml:"egress,omitempty" json:"egress,omitempty"`
}

type EgressConfig struct {
	Default      string   `yaml:"default,omitempty" json:"default,omitempty"` // deny | allow
	AllowDomains []string `yaml:"allow_domains,omitempty" json:"allow_domains,omitempty"`
}

type MCPServerConfig struct {
	Name          string   `yaml:"name" json:"name"`
	Transport     string   `yaml:"transport" json:"transport"` // streamable-http
	URL           string   `yaml:"url" json:"url"`
	AuthSecretRef string   `yaml:"auth_secret_ref,omitempty" json:"auth_secret_ref,omitempty"`
	AllowedTools  []string `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
}

type PoliciesConfig struct {
	Approvals []ApprovalRule `yaml:"approvals,omitempty" json:"approvals,omitempty"`
}

// PolicyMode determines how an action is handled by the policy engine.
type PolicyMode string

const (
	PolicyAlwaysAllow     PolicyMode = "always_allow"
	PolicyRequireApproval PolicyMode = "require_approval"
	PolicyDeny            PolicyMode = "deny"
)

type ApprovalRule struct {
	Action     string     `yaml:"action" json:"action"` // git.push | shell.exec | fs.edit | mcp.*
	MatchRegex string     `yaml:"match_regex,omitempty" json:"match_regex,omitempty"`
	MatchGlobs []string   `yaml:"match_globs,omitempty" json:"match_globs,omitempty"`
	Mode       PolicyMode `yaml:"mode" json:"mode"`
}

type LimitsConfig struct {
	MaxCredits           float64 `yaml:"max_credits,omitempty" json:"max_credits,omitempty"`
	MaxTurns             int     `yaml:"max_turns,omitempty" json:"max_turns,omitempty"`
	MaxWallClockSeconds  int     `yaml:"max_wall_clock_seconds,omitempty" json:"max_wall_clock_seconds,omitempty"`
	IdleHibernateSeconds int     `yaml:"idle_hibernate_seconds,omitempty" json:"idle_hibernate_seconds,omitempty"`
}

// ParseBlueprintYAML parses, applies defaults to, and validates an agentbox.yaml document.
func ParseBlueprintYAML(data []byte) (*Blueprint, error) {
	var bp Blueprint
	if err := yaml.Unmarshal(data, &bp); err != nil {
		return nil, fmt.Errorf("parse blueprint yaml: %w", err)
	}
	bp.ApplyDefaults()
	if err := bp.Validate(); err != nil {
		return nil, err
	}
	return &bp, nil
}

// LoadBlueprintFile reads and parses an agentbox.yaml file from disk.
func LoadBlueprintFile(filePath string) (*Blueprint, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read blueprint file: %w", err)
	}
	return ParseBlueprintYAML(data)
}

// DefaultBlueprint returns a sensible default Blueprint for quick local runs.
func DefaultBlueprint(name string) *Blueprint {
	if name == "" {
		name = "default-swe"
	}
	bp := &Blueprint{
		APIVersion: BlueprintAPIVersion,
		Kind:       BlueprintKind,
		Metadata: BlueprintMetadata{
			Name:    name,
			Version: "1.0.0",
		},
		Runtime: RuntimeConfig{
			Image: "ghcr.io/agentbox/swe-node22-py312:v1",
		},
		Model: ModelConfig{
			Profile: "swe-balanced",
		},
	}
	bp.ApplyDefaults()
	return bp
}

// ApplyDefaults populates safe production defaults for omitted Blueprint fields.
func (b *Blueprint) ApplyDefaults() {
	if b.APIVersion == "" {
		b.APIVersion = BlueprintAPIVersion
	}
	if b.Kind == "" {
		b.Kind = BlueprintKind
	}
	if b.Metadata.Version == "" {
		b.Metadata.Version = "0.1.0"
	}
	if b.Runtime.Image == "" {
		b.Runtime.Image = "ghcr.io/agentbox/swe-node22-py312:v1"
	}
	if b.Runtime.Resources.VCPU == 0 {
		b.Runtime.Resources.VCPU = 2
	}
	if b.Runtime.Resources.MemoryMB == 0 {
		b.Runtime.Resources.MemoryMB = 4096
	}
	if b.Runtime.Resources.DiskGB == 0 {
		b.Runtime.Resources.DiskGB = 20
	}
	if b.Model.Profile == "" {
		b.Model.Profile = "swe-balanced"
	}
	if b.Harness.Git.BranchPrefix == "" {
		b.Harness.Git.BranchPrefix = "agentbox/fix-"
	}
	if len(b.Harness.Git.ProtectedBranches) == 0 {
		b.Harness.Git.ProtectedBranches = []string{"main", "master", "production"}
	}
	if b.Network.Egress.Default == "" {
		b.Network.Egress.Default = "deny"
	}
	if b.Limits.MaxCredits <= 0 {
		b.Limits.MaxCredits = 500
	}
	if b.Limits.MaxTurns <= 0 {
		b.Limits.MaxTurns = 40
	}
	if b.Limits.MaxWallClockSeconds <= 0 {
		b.Limits.MaxWallClockSeconds = 1800
	}
	if b.Limits.IdleHibernateSeconds <= 0 {
		b.Limits.IdleHibernateSeconds = 300
	}
}

// Validate checks Blueprint schema invariants and regex rules.
func (b *Blueprint) Validate() error {
	if b.APIVersion != BlueprintAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (expected %q)", b.APIVersion, BlueprintAPIVersion)
	}
	if b.Kind != BlueprintKind {
		return fmt.Errorf("unsupported kind %q (expected %q)", b.Kind, BlueprintKind)
	}
	if strings.TrimSpace(b.Metadata.Name) == "" {
		return fmt.Errorf("metadata.name is required")
	}
	switch b.Model.Profile {
	case "swe-fast", "swe-balanced", "swe-max":
	default:
		return fmt.Errorf("invalid model.profile %q (allowed: swe-fast, swe-balanced, swe-max)", b.Model.Profile)
	}
	switch b.Network.Egress.Default {
	case "deny", "allow":
	default:
		return fmt.Errorf("invalid network.egress.default %q (allowed: deny, allow)", b.Network.Egress.Default)
	}
	for i, srv := range b.MCPServers {
		if strings.TrimSpace(srv.Name) == "" {
			return fmt.Errorf("mcp_servers[%d].name is required", i)
		}
		if strings.TrimSpace(srv.URL) == "" {
			return fmt.Errorf("mcp_servers[%d].url is required", i)
		}
		if srv.Transport != "" && srv.Transport != "streamable-http" {
			return fmt.Errorf("mcp_servers[%d].transport %q unsupported (allowed: streamable-http)", i, srv.Transport)
		}
	}
	for i, rule := range b.Policies.Approvals {
		if strings.TrimSpace(rule.Action) == "" {
			return fmt.Errorf("policies.approvals[%d].action is required", i)
		}
		switch rule.Mode {
		case PolicyAlwaysAllow, PolicyRequireApproval, PolicyDeny:
		default:
			return fmt.Errorf("policies.approvals[%d].mode %q invalid", i, rule.Mode)
		}
		if rule.MatchRegex != "" {
			if _, err := regexp.Compile(rule.MatchRegex); err != nil {
				return fmt.Errorf("policies.approvals[%d].match_regex invalid: %w", i, err)
			}
		}
	}
	if b.Runtime.Resources.VCPU < 1 || b.Runtime.Resources.MemoryMB < 128 || b.Runtime.Resources.DiskGB < 1 {
		return fmt.Errorf("runtime.resources must specify positive vcpu, memory_mb (>=128), and disk_gb")
	}
	if b.Limits.MaxCredits <= 0 || b.Limits.MaxTurns <= 0 || b.Limits.MaxWallClockSeconds <= 0 {
		return fmt.Errorf("limits must be positive values")
	}
	return nil
}

// Hash computes a deterministic SHA-256 hash of the Blueprint for warm workspace snapshot keys.
func (b *Blueprint) Hash() string {
	canonical, _ := json.Marshal(b)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:8])
}

// IsProtectedBranch reports whether the given branch name is protected by this Blueprint.
func (b *Blueprint) IsProtectedBranch(branch string) bool {
	branch = strings.TrimPrefix(branch, "refs/heads/")
	for _, p := range b.Harness.Git.ProtectedBranches {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(branch)) {
			return true
		}
	}
	return false
}

// EvaluatePolicy evaluates Blueprint approval policies for a given action and target
// (command string for shell.exec, file path for fs.edit, branch/ref for git.push).
// The strictest matching rule wins: deny > require_approval > always_allow.
func (b *Blueprint) EvaluatePolicy(action, target string) (PolicyMode, *ApprovalRule) {
	result := PolicyAlwaysAllow
	var matchedRule *ApprovalRule

	for i := range b.Policies.Approvals {
		rule := &b.Policies.Approvals[i]
		if !actionMatches(rule.Action, action) {
			continue
		}
		if !targetMatches(rule, target) {
			continue
		}
		if modePriority(rule.Mode) > modePriority(result) {
			result = rule.Mode
			matchedRule = rule
		}
	}
	return result, matchedRule
}

func modePriority(m PolicyMode) int {
	switch m {
	case PolicyDeny:
		return 3
	case PolicyRequireApproval:
		return 2
	default:
		return 1
	}
}

func actionMatches(ruleAction, action string) bool {
	if ruleAction == action || ruleAction == "*" {
		return true
	}
	if strings.HasSuffix(ruleAction, ".*") {
		prefix := strings.TrimSuffix(ruleAction, "*")
		return strings.HasPrefix(action, prefix)
	}
	return false
}

func targetMatches(rule *ApprovalRule, target string) bool {
	if rule.MatchRegex == "" && len(rule.MatchGlobs) == 0 {
		return true
	}
	if rule.MatchRegex != "" {
		re, err := regexp.Compile(rule.MatchRegex)
		if err == nil && re.MatchString(target) {
			return true
		}
	}
	normTarget := strings.TrimPrefix(path.Clean(strings.ReplaceAll(target, "\\", "/")), "./")
	for _, g := range rule.MatchGlobs {
		if matchGlob(g, normTarget) {
			return true
		}
	}
	return false
}

// matchGlob supports standard glob wildcards including `**` across path segments.
func matchGlob(pattern, name string) bool {
	pattern = strings.TrimPrefix(strings.ReplaceAll(pattern, "\\", "/"), "./")
	// Convert glob to regex cleanly so `**` works across nested directories.
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '*' {
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					re.WriteString("(?:.*/)?")
					i += 2
				} else {
					re.WriteString(".*")
					i++
				}
			} else {
				re.WriteString("[^/]*")
			}
		} else if c == '?' {
			re.WriteString("[^/]")
		} else if strings.ContainsRune(`.+()|[]{}^$\`, rune(c)) {
			re.WriteByte('\\')
			re.WriteByte(c)
		} else {
			re.WriteByte(c)
		}
	}
	re.WriteString("$")
	matched, err := regexp.MatchString(re.String(), name)
	return err == nil && matched
}

// MergeLimits merges optional per-session limit overrides onto Blueprint defaults.
func MergeLimits(base LimitsConfig, override *LimitsConfig) LimitsConfig {
	out := base
	if override == nil {
		return out
	}
	if override.MaxCredits > 0 {
		out.MaxCredits = override.MaxCredits
	}
	if override.MaxTurns > 0 {
		out.MaxTurns = override.MaxTurns
	}
	if override.MaxWallClockSeconds > 0 {
		out.MaxWallClockSeconds = override.MaxWallClockSeconds
	}
	if override.IdleHibernateSeconds > 0 {
		out.IdleHibernateSeconds = override.IdleHibernateSeconds
	}
	return out
}
