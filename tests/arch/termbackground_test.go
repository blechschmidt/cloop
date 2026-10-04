package arch_test

// Nothing in cloop reads the terminal's background colour (Task 20374).
//
// internal/termquery tells lipgloss the background is dark before bubbletea's
// init can ask the terminal, which under a pty that never answers cost every
// command five seconds. Pinning the answer is harmless only while nothing uses
// it, and lipgloss uses it for exactly two things: AdaptiveColor and
// CompleteAdaptiveColor pick their light or dark variant by it. The day a TUI
// adopts one, it would render the dark variant on a light terminal and nothing
// would say why.
//
// So this gate fails first. A TUI that wants an adaptive colour has to ask the
// terminal itself, before its Program takes the terminal over —
// lipgloss.SetHasDarkBackground(termenv.HasDarkBackground()) at the top of its
// Run, where the wait costs only that interactive command — and then remove
// the name it uses from backgroundReaders.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// backgroundReaders are the lipgloss identifiers whose result depends on the
// background answer internal/termquery pins.
var backgroundReaders = map[string]bool{
	"AdaptiveColor":         true,
	"CompleteAdaptiveColor": true,
	"HasDarkBackground":     true,
}

const lipglossPath = "github.com/charmbracelet/lipgloss"

func TestNothingReadsTheTerminalBackground(t *testing.T) {
	found, err := backgroundReads(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("%s uses lipgloss.%s, whose value depends on the terminal's background — which "+
			"internal/termquery pins to dark so that startup never queries the terminal. Ask the terminal "+
			"in the TUI's Run before its Program starts (lipgloss.SetHasDarkBackground("+
			"termenv.HasDarkBackground())), then allow the name here.", f.where, f.name)
	}
}

func TestBackgroundGateFlagsWhatItShould(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/m\n")
	write("pkg/a/a.go", `package a
import "`+lipglossPath+`"
var c = lipgloss.AdaptiveColor{Light: "0", Dark: "15"}
`)
	write("pkg/b/b.go", `package b
import lg "`+lipglossPath+`"
func dark() bool { return lg.HasDarkBackground() }
func fine() lg.Style { return lg.NewStyle().Foreground(lg.Color("1")) }
`)
	write("pkg/c/c_test.go", `package c
import "`+lipglossPath+`"
var c = lipgloss.CompleteAdaptiveColor{}
`)
	got, err := backgroundReads(root)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range got {
		lines = append(lines, f.where+" "+f.name)
	}
	want := "pkg/a/a.go:3 AdaptiveColor; pkg/b/b.go:3 HasDarkBackground"
	if strings.Join(lines, "; ") != want {
		t.Fatalf("flagged %q, want %q", lines, want)
	}
}

type backgroundRead struct {
	where string
	name  string
}

// backgroundReads lists every use of a backgroundReaders identifier from
// lipgloss in root's non-test source.
func backgroundReads(root string) ([]backgroundRead, error) {
	var out []backgroundRead
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		names := map[string]bool{}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == lipglossPath {
				name := "lipgloss"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				names[name] = true
			}
		}
		if len(names) == 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && names[x.Name] && backgroundReaders[sel.Sel.Name] {
				out = append(out, backgroundRead{
					where: fmt.Sprintf("%s:%d", filepath.ToSlash(rel), fset.Position(sel.Pos()).Line),
					name:  sel.Sel.Name,
				})
			}
			return true
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].where < out[j].where })
	return out, err
}
