package arch_test

// Retired dependencies stay retired (Task 20411).
//
// nhooyr.io/websocket carried every WebSocket the hub speaks: the dashboard's,
// the hub-to-agent transport, hub-cluster traffic and the sandbox attach — all
// of them parsing frames from browsers and remote devices the threat model
// treats as hostile. It was deprecated when its maintainer handed the project
// to Coder, and only github.com/coder/websocket receives fixes now, so a
// frame-parsing bug found upstream would never reach the old path.
//
// The move was one import path in 29 files, and so is the way back. An
// editor's auto-import, a snippet copied from an old answer, or a dependency
// that requires the old module would compile, vet and pass every test while
// quietly putting the hub's most exposed parser back on code nobody maintains.
// Nothing else in CI can see that. staticcheck's SA1019 reports a deprecated
// import, but only while the deprecated module still says so in a release this
// module resolves; this gate does not depend on what any release says.
//
// So no Go file in the module may import a retired module, test files and the
// tests/ harnesses included, and go.mod may not name one — as a requirement
// (direct or // indirect), a replace on either side, or an exclusion. go.sum is
// deliberately not checked: it can list a module's go.mod hash merely because
// something in the module graph mentions it, which puts no code in the build.

import (
	"bufio"
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// retired maps a module path to why it is retired and what replaces it.
var retired = map[string]string{
	"nhooyr.io/websocket": "deprecated upstream; use github.com/coder/websocket, its maintained " +
		"successor with the same API (Task 20411)",
}

func TestNoRetiredModules(t *testing.T) {
	root := repoRoot(t)

	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, v := range retiredModulesInGoMod(gomod, retired) {
		t.Errorf("go.mod %s.\n    Remove the requirement and run `go mod tidy`; if a dependency pulls it "+
			"back in, that dependency needs replacing or upgrading, not an exemption.", v)
	}

	violations, scanned, err := retiredModuleImports(root, retired)
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	// A gate that reads nothing passes. If a layout change or a bug in the walk
	// left it with almost no files, that must fail rather than report green on
	// an empty set: the module has over two thousand.
	if scanned < 500 {
		t.Fatalf("the retired-module gate parsed only %d Go files, which cannot be right for this "+
			"module — the walk has drifted and it is no longer checking anything", scanned)
	}
	t.Logf("parsed the imports of %d Go files", scanned)
	for _, v := range violations {
		t.Errorf("%s.\n    Import the replacement instead; the gate covers tests as well as "+
			"production code, because a test is where the old path would come back first.", v)
	}
}

// The gate must flag what it exists for — an import of the module or of any
// of its packages, in any file, and any go.mod directive naming it — and
// nothing else: not a module whose path merely starts the same way, not the
// path appearing in a string or a comment, and not a file the go tool would
// never build.
func TestRetiredModuleGateFlagsImportsAndRequirements(t *testing.T) {
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
	const mod = "example.com/m"
	gomod := "module " + mod + "\n\ngo 1.26.0\n\n" +
		"require (\n" +
		"\tgithub.com/coder/websocket v1.8.15\n" +
		"\tnhooyr.io/websocket v1.8.17 // indirect\n" +
		"\tnhooyr.io/websocketx v1.0.0 // a different module that shares the prefix\n" +
		")\n\n" +
		"// nhooyr.io/websocket was retired in Task 20411; a comment is not a requirement.\n" +
		"replace nhooyr.io/websocket => github.com/coder/websocket v1.8.15\n" +
		"exclude \"nhooyr.io/websocket\" v1.8.7\n"
	write("go.mod", gomod)
	write("pkg/a/a.go", "package a\n\nimport \"nhooyr.io/websocket\"\n\nvar _ = websocket.Accept\n")
	write("pkg/a/a_test.go", "package a\n\nimport (\n\t\"testing\"\n\n\tws \"nhooyr.io/websocket/wsjson\"\n)\n")
	write("tests/h/h_test.go", "package h\n\nimport _ \"nhooyr.io/websocket\"\n")
	write("pkg/b/b.go", "package b\n\nimport \"github.com/coder/websocket\"\n\nvar _ = websocket.Accept\n")
	write("pkg/c/c.go", "package c\n\n// nhooyr.io/websocket is mentioned, not imported.\nconst s = \"nhooyr.io/websocket\"\n")
	write("pkg/d/d.go", "package d\n\nimport _ \"nhooyr.io/websocketx\"\n")
	// Never built by the go tool, so never part of the module.
	write("pkg/e/testdata/x.go", "package x\n\nimport _ \"nhooyr.io/websocket\"\n")
	write(".hidden/x.go", "package x\n\nimport _ \"nhooyr.io/websocket\"\n")
	write("_scratch/x.go", "package x\n\nimport _ \"nhooyr.io/websocket\"\n")
	// Another module's business.
	write("nested/go.mod", "module example.com/nested\n")
	write("nested/n.go", "package n\n\nimport _ \"nhooyr.io/websocket\"\n")

	gotMod := retiredModulesInGoMod([]byte(gomod), retired)
	wantMod := []string{
		"line 7 names nhooyr.io/websocket (" + retired["nhooyr.io/websocket"] + ")",
		"line 12 names nhooyr.io/websocket (" + retired["nhooyr.io/websocket"] + ")",
		"line 13 names nhooyr.io/websocket (" + retired["nhooyr.io/websocket"] + ")",
	}
	if strings.Join(gotMod, "\n") != strings.Join(wantMod, "\n") {
		t.Errorf("go.mod findings:\n%s\nwant:\n%s", strings.Join(gotMod, "\n"), strings.Join(wantMod, "\n"))
	}

	got, scanned, err := retiredModuleImports(root, retired)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, v := range got {
		files = append(files, strings.Fields(v)[0])
	}
	want := []string{"pkg/a/a.go", "pkg/a/a_test.go", "tests/h/h_test.go"}
	if strings.Join(files, " ") != strings.Join(want, " ") {
		t.Errorf("flagged %q, want %q; full findings:\n%s", files, want, strings.Join(got, "\n"))
	}
	if !strings.Contains(strings.Join(got, "\n"), "pkg/a/a_test.go imports nhooyr.io/websocket/wsjson") {
		t.Errorf("a subpackage import must name the package it imports; findings:\n%s", strings.Join(got, "\n"))
	}
	// go.mod is not a Go file; a/a.go, a/a_test.go, h_test.go, b.go, c.go, d.go.
	if scanned != 6 {
		t.Errorf("parsed %d files, want 6 — the walk entered a directory the go tool ignores", scanned)
	}
}

// retiredModulesInGoMod reports every line of a go.mod that names a retired
// module outside a comment, in any directive.
//
// It reads tokens rather than resolving the file with golang.org/x/mod, which
// would make a tests-only parser a direct requirement of the module. go.mod's
// grammar makes that safe: a module path is always a token of its own,
// possibly quoted, and `//` starts a comment everywhere.
func retiredModulesInGoMod(gomod []byte, retiredMods map[string]string) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(gomod))
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.Index(text, "//"); i >= 0 {
			text = text[:i]
		}
		for _, field := range strings.Fields(text) {
			if unq, err := strconv.Unquote(field); err == nil {
				field = unq
			}
			if mod, why, ok := retiredModuleOf(field, retiredMods); ok {
				out = append(out, fmt.Sprintf("line %d names %s (%s)", line, mod, why))
				break
			}
		}
	}
	return out
}

// retiredModuleImports parses the imports of every Go file the go tool would
// consider part of the module rooted at root, and reports each import of a
// retired module or one of its packages. It also returns how many files it
// parsed, so a walk that silently finds nothing can be told apart from a clean
// module.
//
// Build constraints are ignored on purpose: a retired import behind a build tag
// is still a retired import, merely one this platform does not compile.
func retiredModuleImports(root string, retiredMods map[string]string) ([]string, int, error) {
	var violations []string
	scanned := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path == root {
				return nil
			}
			// What `go build ./...` skips: testdata, vendored trees, and any
			// directory whose name starts with "." or "_" (which keeps the
			// project's own .git and .cloop out of the walk).
			if name == "testdata" || name == "vendor" || name == "node_modules" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			// An unparseable file fails `go build`, which is the gate for it;
			// reporting it here too would only bury this gate's own message.
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		for _, imp := range f.Imports {
			ip, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			mod, why, ok := retiredModuleOf(ip, retiredMods)
			switch {
			case !ok:
			case ip == mod:
				violations = append(violations, fmt.Sprintf("%s imports the retired module %s (%s)",
					filepath.ToSlash(rel), mod, why))
			default:
				violations = append(violations, fmt.Sprintf("%s imports %s, from the retired module %s (%s)",
					filepath.ToSlash(rel), ip, mod, why))
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, scanned, err
}

// retiredModuleOf reports whether path is a retired module or a package inside
// one. The boundary matters: "nhooyr.io/websocketx" is a different module.
func retiredModuleOf(path string, retiredMods map[string]string) (mod, why string, ok bool) {
	for m, w := range retiredMods {
		if path == m || strings.HasPrefix(path, m+"/") {
			return m, w, true
		}
	}
	return "", "", false
}
