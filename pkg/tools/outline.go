package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Symbol represents an extracted AST/structural symbol and its line span.
type Symbol struct {
	Kind      string `json:"kind"` // func | method | class | interface | struct | trait | enum | type
	Name      string `json:"name"`
	Signature string `json:"signature"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// CodeOutlineTool extracts symbol & function signature outlines for Go, TS/JS, Python, Rust, and Java
// in pure Go so agentd compiles cleanly as a static CGO_ENABLED=0 binary.
type CodeOutlineTool struct {
	Workspace string
}

func (t *CodeOutlineTool) Name() string { return "code_outline" }
func (t *CodeOutlineTool) Description() string {
	return "Extract AST symbol and function signature outline for a source file (Go, TS/JS, Python, Rust, Java)."
}
func (t *CodeOutlineTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Workspace-relative source file path"},
		},
		"required": []string{"path"},
	}
}

func (t *CodeOutlineTool) Execute(_ context.Context, raw json.RawMessage) (Result, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return Result{}, fmt.Errorf("invalid code_outline args: %w", err)
	}
	absPath, relPath, err := SafeWorkspacePath(t.Workspace, args.Path)
	if err != nil {
		return Result{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", relPath, err)
	}

	ext := strings.ToLower(filepath.Ext(absPath))
	var symbols []Symbol
	switch ext {
	case ".go":
		symbols, err = outlineGo(absPath, data)
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		symbols = outlineTSJS(string(data))
	case ".py":
		symbols = outlinePython(string(data))
	case ".rs":
		symbols = outlineRust(string(data))
	case ".java":
		symbols = outlineJava(string(data))
	default:
		return Result{}, fmt.Errorf("unsupported language extension %q for code_outline (supported: .go, .ts/.js, .py, .rs, .java)", ext)
	}
	if err != nil {
		return Result{}, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Outline for %s (%d symbols):\n", relPath, len(symbols))
	for _, s := range symbols {
		if s.EndLine > s.StartLine {
			fmt.Fprintf(&b, "  L%d-%d [%s] %s\n", s.StartLine, s.EndLine, s.Kind, s.Signature)
		} else {
			fmt.Fprintf(&b, "  L%d [%s] %s\n", s.StartLine, s.Kind, s.Signature)
		}
	}
	return Result{
		Output: b.String(),
		Metadata: map[string]any{
			"path":    relPath,
			"symbols": symbols,
		},
	}, nil
}

func outlineGo(filename string, src []byte) ([]Symbol, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse go file: %w", err)
	}
	lines := strings.Split(string(src), "\n")
	var out []Symbol

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			start := fset.Position(d.Pos()).Line
			end := fset.Position(d.End()).Line
			kind := "func"
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind = "method"
			}
			sig := strings.TrimSpace(strings.TrimSuffix(lines[start-1], "{"))
			out = append(out, Symbol{
				Kind:      kind,
				Name:      name,
				Signature: sig,
				StartLine: start,
				EndLine:   end,
			})
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				start := fset.Position(ts.Pos()).Line
				end := fset.Position(ts.End()).Line
				kind := "type"
				switch ts.Type.(type) {
				case *ast.StructType:
					kind = "struct"
				case *ast.InterfaceType:
					kind = "interface"
				}
				out = append(out, Symbol{
					Kind:      kind,
					Name:      ts.Name.Name,
					Signature: fmt.Sprintf("type %s %s", ts.Name.Name, kind),
					StartLine: start,
					EndLine:   end,
				})
			}
		}
	}
	return out, nil
}

var (
	reTSClass     = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)`)
	reTSInterface = regexp.MustCompile(`^\s*(?:export\s+)?interface\s+(\w+)`)
	reTSType      = regexp.MustCompile(`^\s*(?:export\s+)?type\s+(\w+)\s*=`)
	reTSFunc      = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(`)
	reTSArrow     = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>`)
	reTSMethod    = regexp.MustCompile(`^\s*(?:public|private|protected|static|async|readonly|\s)*(\w+)\s*\([^)]*\)\s*(?::\s*[^\{]+)?\{`)

	rePyClass = regexp.MustCompile(`^(\s*)class\s+(\w+)`)
	rePyDef   = regexp.MustCompile(`^(\s*)(?:async\s+)?def\s+(\w+)\s*\(`)

	reRustFn     = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)`)
	reRustStruct = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)`)
	reRustEnum   = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+(\w+)`)
	reRustTrait  = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+(\w+)`)
	reRustImpl   = regexp.MustCompile(`^\s*impl(?:<[^>]+>)?\s+([A-Za-z0-9_:<>,\s]+)\{`)

	reJavaType   = regexp.MustCompile(`^\s*(?:public|private|protected|abstract|final|static|\s)*(class|interface|enum|record)\s+(\w+)`)
	reJavaMethod = regexp.MustCompile(`^\s*(?:public|private|protected|static|final|synchronized|abstract|\s)+[\w<>\[\],?\s]+\s+(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w,\s]+)?\{`)
)

func outlineTSJS(src string) []Symbol {
	lines := strings.Split(src, "\n")
	var out []Symbol
	for i, line := range lines {
		ln := i + 1
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "*") {
			continue
		}
		if m := reTSClass.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "class", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reTSInterface.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "interface", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reTSType.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "type", Name: m[1], Signature: trim, StartLine: ln, EndLine: ln})
		} else if m := reTSFunc.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "func", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reTSArrow.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "func", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reTSMethod.FindStringSubmatch(line); m != nil {
			name := m[1]
			if name != "if" && name != "for" && name != "while" && name != "switch" && name != "catch" && name != "function" {
				out = append(out, Symbol{Kind: "method", Name: name, Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
			}
		}
	}
	return out
}

func outlinePython(src string) []Symbol {
	lines := strings.Split(src, "\n")
	var out []Symbol
	for i, line := range lines {
		ln := i + 1
		if m := rePyClass.FindStringSubmatch(line); m != nil {
			indent := len(m[1])
			out = append(out, Symbol{Kind: "class", Name: m[2], Signature: strings.TrimSpace(line), StartLine: ln, EndLine: findIndentEnd(lines, i, indent)})
		} else if m := rePyDef.FindStringSubmatch(line); m != nil {
			indent := len(m[1])
			kind := "func"
			if indent > 0 {
				kind = "method"
			}
			out = append(out, Symbol{Kind: kind, Name: m[2], Signature: strings.TrimSpace(line), StartLine: ln, EndLine: findIndentEnd(lines, i, indent)})
		}
	}
	return out
}

func outlineRust(src string) []Symbol {
	lines := strings.Split(src, "\n")
	var out []Symbol
	for i, line := range lines {
		ln := i + 1
		trim := strings.TrimSpace(line)
		if m := reRustStruct.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "struct", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reRustEnum.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "enum", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reRustTrait.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "trait", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reRustImpl.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "impl", Name: strings.TrimSpace(m[1]), Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reRustFn.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: "func", Name: m[1], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		}
	}
	return out
}

func outlineJava(src string) []Symbol {
	lines := strings.Split(src, "\n")
	var out []Symbol
	for i, line := range lines {
		ln := i + 1
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "*") {
			continue
		}
		if m := reJavaType.FindStringSubmatch(line); m != nil {
			out = append(out, Symbol{Kind: m[1], Name: m[2], Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
		} else if m := reJavaMethod.FindStringSubmatch(line); m != nil {
			name := m[1]
			if name != "if" && name != "for" && name != "while" && name != "switch" && name != "catch" {
				out = append(out, Symbol{Kind: "method", Name: name, Signature: trimBrace(trim), StartLine: ln, EndLine: findBraceEnd(lines, i)})
			}
		}
	}
	return out
}

func trimBrace(s string) string {
	return strings.TrimSpace(strings.TrimSuffix(s, "{"))
}

func findBraceEnd(lines []string, startIdx int) int {
	depth := 0
	seenOpen := false
	for i := startIdx; i < len(lines); i++ {
		for _, ch := range lines[i] {
			if ch == '{' {
				depth++
				seenOpen = true
			} else if ch == '}' {
				depth--
				if seenOpen && depth <= 0 {
					return i + 1
				}
			}
		}
	}
	return startIdx + 1
}

func findIndentEnd(lines []string, startIdx, baseIndent int) int {
	last := startIdx + 1
	for i := startIdx + 1; i < len(lines); i++ {
		trim := strings.TrimSpace(lines[i])
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
		if indent <= baseIndent {
			return last
		}
		last = i + 1
	}
	return last
}
