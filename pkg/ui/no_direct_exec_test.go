// Guard test: the Web UI package must never spawn processes directly
// (Task 20156).
//
// This is the enforcement half of the executor refactor. pkg/ui is the
// control plane: it accepts requests from the network, potentially from
// several tenants, and decides what work to run. If it can call
// exec.Command it can only ever run that work as itself, on its own host,
// with its own privileges — which defeats remote executors, container
// sandboxes, and any deployment that promises "the UI never spawns a
// harness on the host".
//
// A `go vet`-adjacent source check is the right tool here because the
// property is syntactic, not behavioral: no test of runtime behavior can
// prove that some rarely-hit handler does not fork. Parsing the package with
// go/ast rather than grepping means comments and string literals mentioning
// exec.Command (like this file, and the explanatory comments in
// subprocess.go) do not produce false positives.

package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenExecPkg is the import path pkg/ui may not use in non-test code.
const forbiddenExecPkg = "os/exec"

// TestNoDirectProcessSpawning fails if any non-test file in this package
// imports os/exec or references exec.Command / exec.CommandContext.
//
// The fix when this fails is never to add an exemption: route the call
// through executor.Resolve(projectPath).Start(...) (see executor.go for the
// startWorkload / runWorkload helpers).
func TestNoDirectProcessSpawning(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go sources found — the guard would silently pass")
	}

	fset := token.NewFileSet()
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			// Tests may legitimately fork helper processes; the guard is
			// about production request-handling code.
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		parsed, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		checked++

		// 1. Import check. Catches the package even if it is aliased or
		//    used via a helper we did not think to look for.
		for _, imp := range parsed.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if path == forbiddenExecPkg {
				t.Errorf("%s imports %q: the UI must not spawn processes directly. "+
					"Use executor.Resolve(projectPath).Start(...) — see pkg/ui/executor.go.",
					file, forbiddenExecPkg)
			}
		}

		// 2. Selector check. Catches a dot-import or a local shim named
		//    `exec` that would slip past the import check.
		ast.Inspect(parsed, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "exec" {
				return true
			}
			switch sel.Sel.Name {
			case "Command", "CommandContext":
				pos := fset.Position(sel.Pos())
				t.Errorf("%s:%d: exec.%s is forbidden in pkg/ui. "+
					"Use executor.Resolve(projectPath).Start(...) — see pkg/ui/executor.go.",
					file, pos.Line, sel.Sel.Name)
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("every source file was skipped — the guard would silently pass")
	}
}

// TestGuardDetectsViolation is a meta-test: it verifies the AST checks above
// actually fire on offending source. Without it a refactor could neuter the
// guard (wrong glob, wrong node type) and TestNoDirectProcessSpawning would
// keep passing vacuously.
func TestGuardDetectsViolation(t *testing.T) {
	const offending = `package ui

import "os/exec"

func spawn() { _ = exec.Command("cloop", "run") }
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "offending.go", offending, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	sawImport := false
	for _, imp := range parsed.Imports {
		if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == forbiddenExecPkg {
			sawImport = true
		}
	}
	if !sawImport {
		t.Error("import check failed to flag a file importing os/exec")
	}

	sawCall := false
	ast.Inspect(parsed, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "exec" &&
			(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
			sawCall = true
		}
		return true
	})
	if !sawCall {
		t.Error("selector check failed to flag an exec.Command call")
	}
}
