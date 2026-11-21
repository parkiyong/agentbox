package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

const (
	defaultReadMaxLines = 200
	hardReadMaxLines    = 500
	hardReadMaxBytes    = 48 * 1024
)

// FSReadTool reads bounded line ranges of files with binary detection and hard size caps.
type FSReadTool struct {
	Workspace string
}

func (t *FSReadTool) Name() string { return "fs_read" }
func (t *FSReadTool) Description() string {
	return "Read bounded line ranges of a file inside the workspace (1-indexed, inclusive). Rejects binary files."
}
func (t *FSReadTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":       map[string]any{"type": "string", "description": "Workspace-relative file path"},
			"start_line": map[string]any{"type": "integer", "description": "1-indexed start line (default 1)"},
			"end_line":   map[string]any{"type": "integer", "description": "1-indexed end line (inclusive, max 500 lines per call)"},
		},
		"required": []string{"path"},
	}
}

func (t *FSReadTool) Execute(_ context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid fs_read args: %w", err)
	}
	absPath, relPath, err := SafeWorkspacePath(t.Workspace, args.Path)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return Result{}, fmt.Errorf("stat %s: %w", relPath, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(absPath)
		if err != nil {
			return Result{}, err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Directory listing for %s:\n", relPath)
		for _, e := range entries {
			suffix := ""
			if e.IsDir() {
				suffix = "/"
			}
			fmt.Fprintf(&b, "  %s%s\n", e.Name(), suffix)
		}
		return Result{Output: b.String()}, nil
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", relPath, err)
	}
	if isBinary(data) {
		return Result{}, fmt.Errorf("refusing to read binary file %s (%d bytes)", relPath, len(data))
	}

	lines := strings.Split(string(data), "\n")
	totalLines := len(lines)
	start := args.StartLine
	if start < 1 {
		start = 1
	}
	end := args.EndLine
	if end <= 0 {
		end = start + defaultReadMaxLines - 1
	}
	if end-start+1 > hardReadMaxLines {
		end = start + hardReadMaxLines - 1
	}
	if start > totalLines {
		return Result{Output: fmt.Sprintf("File %s has %d lines; start_line %d is out of range.", relPath, totalLines, start)}, nil
	}
	if end > totalLines {
		end = totalLines
	}

	var b strings.Builder
	fmt.Fprintf(&b, "File: %s (lines %d-%d of %d)\n", relPath, start, end, totalLines)
	bytesWritten := 0
	truncated := false
	for i := start; i <= end; i++ {
		line := fmt.Sprintf("%4d | %s\n", i, lines[i-1])
		if bytesWritten+len(line) > hardReadMaxBytes {
			truncated = true
			break
		}
		b.WriteString(line)
		bytesWritten += len(line)
	}
	if truncated {
		b.WriteString("... [truncated at 48KB cap; request a narrower line range]\n")
	}
	return Result{
		Output: b.String(),
		Metadata: map[string]any{
			"path":        relPath,
			"total_lines": totalLines,
			"start_line":  start,
			"end_line":    end,
		},
	}, nil
}

func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	return len(sample) > 0 && !utf8.Valid(sample)
}

// EditHunk specifies one exact search-and-replace edit inside a file.
type EditHunk struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// FSEditPatchTool performs surgical multi-hunk edits or file creation with atomic writes
// and emits canonical file.diff payloads.
type FSEditPatchTool struct {
	Workspace string
	OnDiff    func(protocol.FileDiffPayload)
}

func (t *FSEditPatchTool) Name() string { return "fs_edit_patch" }
func (t *FSEditPatchTool) Description() string {
	return "Apply surgical multi-hunk search-and-replace edits to an existing file, or create/overwrite a file when create=true."
}
func (t *FSEditPatchTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":    map[string]any{"type": "string", "description": "Workspace-relative path to edit or create"},
			"create":  map[string]any{"type": "boolean", "description": "If true, create or overwrite the file with content"},
			"content": map[string]any{"type": "string", "description": "Full file content when create=true"},
			"hunks": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"old": map[string]any{"type": "string"},
						"new": map[string]any{"type": "string"},
					},
					"required": []string{"old", "new"},
				},
			},
		},
		"required": []string{"path"},
	}
}

func (t *FSEditPatchTool) Execute(_ context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Path    string     `json:"path"`
		Create  bool       `json:"create"`
		Content string     `json:"content"`
		Hunks   []EditHunk `json:"hunks"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid fs_edit_patch args: %w", err)
	}
	absPath, relPath, err := SafeWorkspacePath(t.Workspace, args.Path)
	if err != nil {
		return Result{}, err
	}

	var oldContent string
	operation := "modify"
	existingBytes, readErr := os.ReadFile(absPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			operation = "create"
		} else {
			return Result{}, fmt.Errorf("read %s: %w", relPath, readErr)
		}
	} else {
		oldContent = string(existingBytes)
	}

	var newContent string
	if args.Create {
		newContent = args.Content
	} else {
		if operation == "create" {
			return Result{}, fmt.Errorf("file %s does not exist (set create=true to create it)", relPath)
		}
		if len(args.Hunks) == 0 {
			return Result{}, fmt.Errorf("at least one edit hunk is required")
		}
		newContent = oldContent
		for idx, h := range args.Hunks {
			if h.Old == "" {
				return Result{}, fmt.Errorf("hunk[%d].old must be non-empty", idx)
			}
			count := strings.Count(newContent, h.Old)
			if count == 0 {
				return Result{}, fmt.Errorf("hunk[%d]: target text not found in %s", idx, relPath)
			}
			if count > 1 {
				return Result{}, fmt.Errorf("hunk[%d]: target text matched %d times in %s; include more surrounding context", idx, count, relPath)
			}
			newContent = strings.Replace(newContent, h.Old, h.New, 1)
		}
	}

	if err := atomicWriteFile(absPath, []byte(newContent), 0o644); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", relPath, err)
	}

	unified, ins, del := ComputeUnifiedDiff(relPath, oldContent, newContent)
	payload := protocol.FileDiffPayload{
		Path:       relPath,
		Operation:  operation,
		Unified:    unified,
		Insertions: ins,
		Deletions:  del,
	}
	if t.OnDiff != nil {
		t.OnDiff(payload)
	}
	return Result{
		Output: fmt.Sprintf("Updated %s (%s: +%d/-%d lines)\n%s", relPath, operation, ins, del, unified),
		Metadata: map[string]any{
			"path":       relPath,
			"operation":  operation,
			"insertions": ins,
			"deletions":  del,
		},
	}, nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agentbox-edit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// ComputeUnifiedDiff generates a clean unified diff with line counts using LCS diffing.
func ComputeUnifiedDiff(relPath, oldText, newText string) (string, int, int) {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)

	type op struct {
		kind byte // ' ', '-', '+'
		line string
	}

	// Standard O(NM) LCS bounded cleanly for typical source files; falls back to full hunk for huge files.
	var ops []op
	if len(oldLines)*len(newLines) <= 2_000_000 {
		m, n := len(oldLines), len(newLines)
		dp := make([][]int, m+1)
		for i := range dp {
			dp[i] = make([]int, n+1)
		}
		for i := m - 1; i >= 0; i-- {
			for j := n - 1; j >= 0; j-- {
				if oldLines[i] == newLines[j] {
					dp[i][j] = dp[i+1][j+1] + 1
				} else if dp[i+1][j] >= dp[i][j+1] {
					dp[i][j] = dp[i+1][j]
				} else {
					dp[i][j] = dp[i][j+1]
				}
			}
		}
		i, j := 0, 0
		for i < m && j < n {
			if oldLines[i] == newLines[j] {
				ops = append(ops, op{' ', oldLines[i]})
				i++
				j++
			} else if dp[i+1][j] >= dp[i][j+1] {
				ops = append(ops, op{'-', oldLines[i]})
				i++
			} else {
				ops = append(ops, op{'+', newLines[j]})
				j++
			}
		}
		for i < m {
			ops = append(ops, op{'-', oldLines[i]})
			i++
		}
		for j < n {
			ops = append(ops, op{'+', newLines[j]})
			j++
		}
	} else {
		for _, l := range oldLines {
			ops = append(ops, op{'-', l})
		}
		for _, l := range newLines {
			ops = append(ops, op{'+', l})
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", relPath, relPath)
	ins, del := 0, 0
	const ctxLines = 3

	// Find changed spans and emit unified hunks with 3 lines of context.
	changed := make([]bool, len(ops))
	for i, o := range ops {
		if o.kind != ' ' {
			if o.kind == '+' {
				ins++
			} else {
				del++
			}
			for k := max(0, i-ctxLines); k <= min(len(ops)-1, i+ctxLines); k++ {
				changed[k] = true
			}
		}
	}

	oldLineNum, newLineNum := 1, 1
	i := 0
	for i < len(ops) {
		if !changed[i] {
			if ops[i].kind != '+' {
				oldLineNum++
			}
			if ops[i].kind != '-' {
				newLineNum++
			}
			i++
			continue
		}
		hunkStartOld, hunkStartNew := oldLineNum, newLineNum
		hunkOldCount, hunkNewCount := 0, 0
		var hunkBody strings.Builder
		for i < len(ops) && changed[i] {
			o := ops[i]
			hunkBody.WriteByte(o.kind)
			hunkBody.WriteString(o.line)
			hunkBody.WriteByte('\n')
			if o.kind != '+' {
				hunkOldCount++
				oldLineNum++
			}
			if o.kind != '-' {
				hunkNewCount++
				newLineNum++
			}
			i++
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", hunkStartOld, hunkOldCount, hunkStartNew, hunkNewCount)
		b.WriteString(hunkBody.String())
	}
	return b.String(), ins, del
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}
