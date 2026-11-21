package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// Result holds the structured output of a tool execution.
type Result struct {
	Output   string         `json:"output"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Tool defines a single SWE capability exposed to agentd's LLM loop.
type Tool interface {
	Name() string
	Description() string
	Parameters() map[string]any
	Execute(ctx context.Context, args json.RawMessage) (Result, error)
}

// Registry stores built-in lean SWE tools and dynamically registered MCP tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
	}
}

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) Definitions() []protocol.LLMToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	defs := make([]protocol.LLMToolDefinition, 0, len(names))
	for _, name := range names {
		t := r.tools[name]
		defs = append(defs, protocol.LLMToolDefinition{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  t.Parameters(),
		})
	}
	return defs
}

// SafeWorkspacePath resolves relPath inside workspaceRoot and rejects any traversal
// outside the workspace boundary.
func SafeWorkspacePath(workspaceRoot, relPath string) (string, string, error) {
	if strings.TrimSpace(relPath) == "" {
		return "", "", fmt.Errorf("path is required")
	}
	absRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolve workspace root: %w", err)
	}
	var candidate string
	if filepath.IsAbs(relPath) {
		candidate = filepath.Clean(relPath)
	} else {
		candidate = filepath.Clean(filepath.Join(absRoot, relPath))
	}
	rel, err := filepath.Rel(absRoot, candidate)
	if err != nil {
		return "", "", fmt.Errorf("resolve path relative to workspace: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path %q escapes workspace boundary", relPath)
	}
	return candidate, filepath.ToSlash(rel), nil
}
