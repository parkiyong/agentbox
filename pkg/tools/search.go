package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultMaxSearchMatches = 100

// FSSearchTool wraps ripgrep (`rg --json`) respecting .gitignore, with a pure-Go fallback.
type FSSearchTool struct {
	Workspace string
}

func (t *FSSearchTool) Name() string { return "fs_search" }
func (t *FSSearchTool) Description() string {
	return "Search code in the workspace using ripgrep (regex or literal), respecting .gitignore."
}
func (t *FSSearchTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query":       map[string]any{"type": "string", "description": "Regex or literal search pattern"},
			"path":        map[string]any{"type": "string", "description": "Optional subdirectory or file to scope search"},
			"literal":     map[string]any{"type": "boolean", "description": "Treat query as fixed literal string"},
			"glob":        map[string]any{"type": "string", "description": "Optional glob filter (e.g., '*.go')"},
			"max_matches": map[string]any{"type": "integer", "description": "Max matching lines to return (default 100)"},
		},
		"required": []string{"query"},
	}
}

type searchMatch struct {
	Path string
	Line int
	Text string
}

func (t *FSSearchTool) Execute(ctx context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Query      string `json:"query"`
		Path       string `json:"path"`
		Literal    bool   `json:"literal"`
		Glob       string `json:"glob"`
		MaxMatches int    `json:"max_matches"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid fs_search args: %w", err)
	}
	if strings.TrimSpace(args.Query) == "" {
		return Result{}, fmt.Errorf("query is required")
	}
	maxMatches := args.MaxMatches
	if maxMatches <= 0 || maxMatches > 500 {
		maxMatches = defaultMaxSearchMatches
	}

	searchRoot := t.Workspace
	if args.Path != "" {
		var err error
		searchRoot, _, err = SafeWorkspacePath(t.Workspace, args.Path)
		if err != nil {
			return Result{}, err
		}
	}

	var matches []searchMatch
	var err error
	if rgPath, lookErr := exec.LookPath("rg"); lookErr == nil {
		matches, err = t.searchWithRipgrep(ctx, rgPath, searchRoot, args.Query, args.Literal, args.Glob, maxMatches)
	} else {
		matches, err = t.searchPureGo(searchRoot, args.Query, args.Literal, args.Glob, maxMatches)
	}
	if err != nil {
		return Result{}, err
	}

	if len(matches) == 0 {
		return Result{Output: fmt.Sprintf("No matches found for %q", args.Query)}, nil
	}
	var b strings.Builder
	for _, m := range matches {
		fmt.Fprintf(&b, "%s:%d: %s\n", m.Path, m.Line, strings.TrimRight(m.Text, "\r\n"))
	}
	if len(matches) >= maxMatches {
		fmt.Fprintf(&b, "... [truncated at %d matches]\n", maxMatches)
	}
	return Result{
		Output: b.String(),
		Metadata: map[string]any{
			"match_count": len(matches),
		},
	}, nil
}

func (t *FSSearchTool) searchWithRipgrep(ctx context.Context, rgPath, root, query string, literal bool, glob string, maxMatches int) ([]searchMatch, error) {
	cmdArgs := []string{"--json", "--line-number", "--color=never"}
	if literal {
		cmdArgs = append(cmdArgs, "--fixed-strings")
	}
	if glob != "" {
		cmdArgs = append(cmdArgs, "--glob", glob)
	}
	cmdArgs = append(cmdArgs, "--", query, root)

	cmd := exec.CommandContext(ctx, rgPath, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		// Exit code 1 means zero matches in ripgrep.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("ripgrep failed: %w", err)
	}

	absWorkspace, _ := filepath.Abs(t.Workspace)
	var matches []searchMatch
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var envelope struct {
			Type string `json:"type"`
			Data struct {
				Path struct {
					Text string `json:"text"`
				} `json:"path"`
				Lines struct {
					Text string `json:"text"`
				} `json:"lines"`
				LineNumber int `json:"line_number"`
			} `json:"data"`
		}
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil || envelope.Type != "match" {
			continue
		}
		rel, relErr := filepath.Rel(absWorkspace, envelope.Data.Path.Text)
		if relErr != nil {
			rel = envelope.Data.Path.Text
		}
		matches = append(matches, searchMatch{
			Path: filepath.ToSlash(rel),
			Line: envelope.Data.LineNumber,
			Text: envelope.Data.Lines.Text,
		})
		if len(matches) >= maxMatches {
			break
		}
	}
	return matches, nil
}

func (t *FSSearchTool) searchPureGo(root, query string, literal bool, glob string, maxMatches int) ([]searchMatch, error) {
	var re *regexp.Regexp
	if !literal {
		var err error
		re, err = regexp.Compile(query)
		if err != nil {
			return nil, fmt.Errorf("invalid search regex: %w", err)
		}
	}

	absWorkspace, _ := filepath.Abs(t.Workspace)
	var matches []searchMatch
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".venv" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if glob != "" {
			matched, _ := filepath.Match(glob, d.Name())
			if !matched {
				return nil
			}
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil || isBinary(data) {
			return nil
		}
		rel, _ := filepath.Rel(absWorkspace, p)
		relSlash := filepath.ToSlash(rel)
		lines := strings.Split(string(data), "\n")
		for idx, line := range lines {
			hit := false
			if literal {
				hit = strings.Contains(line, query)
			} else {
				hit = re.MatchString(line)
			}
			if hit {
				matches = append(matches, searchMatch{
					Path: relSlash,
					Line: idx + 1,
					Text: line,
				})
				if len(matches) >= maxMatches {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	return matches, err
}
