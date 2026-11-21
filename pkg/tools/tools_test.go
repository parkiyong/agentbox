package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

func TestFSReadAndEditPatch(t *testing.T) {
	dir := t.TempDir()
	var diffs []protocol.FileDiffPayload

	editTool := &FSEditPatchTool{
		Workspace: dir,
		OnDiff: func(p protocol.FileDiffPayload) {
			diffs = append(diffs, p)
		},
	}
	readTool := &FSReadTool{Workspace: dir}

	// Create a new file
	_, err := editTool.Execute(context.Background(), json.RawMessage(`{
		"path": "src/math.go",
		"create": true,
		"content": "package math\n\nfunc Add(a, b int) int {\n\treturn a - b\n}\n"
	}`))
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// Surgical patch edit
	res, err := editTool.Execute(context.Background(), json.RawMessage(`{
		"path": "src/math.go",
		"hunks": [{"old": "return a - b", "new": "return a + b"}]
	}`))
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	if !strings.Contains(res.Output, "+	return a + b") {
		t.Fatalf("expected unified diff output, got: %s", res.Output)
	}
	if len(diffs) != 2 || diffs[1].Operation != "modify" || diffs[1].Insertions != 1 || diffs[1].Deletions != 1 {
		t.Fatalf("unexpected diff events: %+v", diffs)
	}

	// Read bounded lines
	readRes, err := readTool.Execute(context.Background(), json.RawMessage(`{"path":"src/math.go","start_line":3,"end_line":5}`))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !strings.Contains(readRes.Output, "return a + b") {
		t.Fatalf("unexpected read output: %s", readRes.Output)
	}

	// Path traversal blocked
	if _, err := readTool.Execute(context.Background(), json.RawMessage(`{"path":"../../etc/passwd"}`)); err == nil {
		t.Fatalf("expected path traversal to fail")
	}

	// Binary file rejected
	_ = os.WriteFile(filepath.Join(dir, "bin.dat"), []byte{0x00, 0x01, 0x02}, 0o644)
	if _, err := readTool.Execute(context.Background(), json.RawMessage(`{"path":"bin.dat"}`)); err == nil {
		t.Fatalf("expected binary file read to fail")
	}
}

func TestFSSearchAndCodeOutline(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"main.go": "package main\n\ntype Server struct{}\n\nfunc (s *Server) Start() error {\n\treturn nil\n}\n",
		"app.ts":  "export interface Config {\n  port: number;\n}\nexport class App {\n  run(): void {\n    console.log('hi');\n  }\n}\n",
		"svc.py":  "class Worker:\n    def execute(self, job):\n        return job\n\ndef helper():\n    pass\n",
		"lib.rs":  "pub struct Engine {}\npub fn run_engine() -> bool {\n    true\n}\n",
		"App.java": "public class App {\n    public static void main(String[] args) {\n    }\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	searchTool := &FSSearchTool{Workspace: dir}
	sRes, err := searchTool.Execute(context.Background(), json.RawMessage(`{"query":"Start"}`))
	if err != nil {
		t.Fatalf("fs_search failed: %v", err)
	}
	if !strings.Contains(sRes.Output, "main.go:5:") {
		t.Fatalf("expected match in main.go:5, got: %s", sRes.Output)
	}

	outlineTool := &CodeOutlineTool{Workspace: dir}
	for name, expectedSym := range map[string]string{
		"main.go":  "Start",
		"app.ts":   "Config",
		"svc.py":   "Worker",
		"lib.rs":   "run_engine",
		"App.java": "main",
	} {
		oRes, err := outlineTool.Execute(context.Background(), json.RawMessage(`{"path":"`+name+`"}`))
		if err != nil {
			t.Fatalf("code_outline(%s) failed: %v", name, err)
		}
		if !strings.Contains(oRes.Output, expectedSym) {
			t.Fatalf("outline for %s missing %q:\n%s", name, expectedSym, oRes.Output)
		}
	}
}

func TestShellExecStatefulAndStreaming(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	var chunks []protocol.TerminalChunkPayload
	sh := NewShellExecTool(dir, nil, func(c protocol.TerminalChunkPayload) {
		chunks = append(chunks, c)
	})

	if _, err := sh.Execute(context.Background(), json.RawMessage(`{"command":"cd sub && echo hello"}`)); err != nil {
		t.Fatalf("shell_exec 1 failed: %v", err)
	}
	res, err := sh.Execute(context.Background(), json.RawMessage(`{"command":"basename \"$PWD\""}`))
	if err != nil {
		t.Fatalf("shell_exec 2 failed: %v", err)
	}
	if !strings.Contains(res.Output, "sub") {
		t.Fatalf("expected stateful cwd to persist in sub, got: %s", res.Output)
	}
	if len(chunks) == 0 {
		t.Fatalf("expected streaming terminal chunks")
	}
}

func TestGitCheckpointsAndRewind(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	cm := NewCheckpointManager(dir, nil)
	if err := cm.EnsureGitRepo(ctx); err != nil {
		t.Fatalf("EnsureGitRepo failed: %v", err)
	}

	filePath := filepath.Join(dir, "hello.txt")
	_ = os.WriteFile(filePath, []byte("v1\n"), 0o644)
	cp1, err := cm.Create(ctx, "version 1")
	if err != nil {
		t.Fatalf("checkpoint 1 failed: %v", err)
	}

	_ = os.WriteFile(filePath, []byte("v2 broken\n"), 0o644)
	if _, err := cm.Create(ctx, "version 2"); err != nil {
		t.Fatalf("checkpoint 2 failed: %v", err)
	}

	if err := cm.Rewind(ctx, cp1.ID); err != nil {
		t.Fatalf("rewind failed: %v", err)
	}
	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1\n" {
		t.Fatalf("expected rewound content 'v1\\n', got %q", string(got))
	}
}
