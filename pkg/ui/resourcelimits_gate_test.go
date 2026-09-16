package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryDispatchAppliesTheResourceCeiling is a drift gate, and it is here
// because this package already knows why one is needed:
//
//	a security control with one enforcement point is a security control with
//	a bypass.
//
// — the comment above RequireRevocable in executor.go.
//
// A resource ceiling is enforced by being applied to a Spec before that Spec
// reaches a driver. There is no type that makes an unclamped Spec
// undispatchable, so the guarantee rests entirely on every dispatch site
// remembering to call applyResourceCeiling. Sites get added: this gate found
// redispatchSession, the failover path, which re-dispatches a spec persisted at
// its *original* dispatch and would otherwise have restored a workload to an
// allowance an operator had since revoked.
//
// So the rule is checked against the source rather than trusted: any function
// in this package that starts a workload must also clamp it.
func TestEveryDispatchAppliesTheResourceCeiling(t *testing.T) {
	const clampCall = "applyResourceCeiling"

	// Functions that reach a driver. Matched on the call rather than on a name
	// list, so a new dispatch site is caught the day it is written.
	dispatches := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		// executor.Run(ctx, ex, spec) — the synchronous path.
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "executor" && sel.Sel.Name == "Run" {
			return true
		}
		// <something>.Start(ctx, spec) — the detached path. Narrowed by arity
		// and by a final argument named "spec", because Start is a common
		// method name: the supervisor's own sv.Start(ctx) is not a dispatch.
		if sel.Sel.Name != "Start" || len(call.Args) != 2 {
			return false
		}
		ident, ok := call.Args[1].(*ast.Ident)
		return ok && ident.Name == "spec"
	}

	// pkg/apiserver is scanned alongside this package because it is a second
	// dispatch surface on the same hub, and its own comment predicted exactly
	// this: "a guarantee that has to be remembered at each new dispatch site is
	// a guarantee that will eventually be forgotten at one." It builds a Spec
	// with no limits at all, which means *unlimited*, so a ceiling enforced only
	// in pkg/ui left the REST API as a quieter way to start an unbounded run.
	dirs := []string{".", filepath.Join("..", "apiserver")}

	var files []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, filepath.Join(dir, name))
		}
	}

	fset := token.NewFileSet()
	checked := 0

	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var starts, clamps bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if dispatches(call) {
					starts = true
				}
				// Either the pkg/ui wrapper or the shared primitive it
				// delegates to. pkg/apiserver calls the latter directly,
				// having no control-plane directory concept to wrap.
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if fn.Name == clampCall {
						clamps = true
					}
				case *ast.SelectorExpr:
					if fn.Sel.Name == "BoundSpec" {
						clamps = true
					}
				}
				return true
			})
			if !starts {
				continue
			}
			checked++
			if !clamps {
				t.Errorf("%s: %s starts a workload but never clamps the spec (%s / executor.BoundSpec).\n"+
					"Every dispatch must clamp the spec to the operator's ceilings first, or "+
					"this path is the way around them. See pkg/ui/resourcelimits.go.",
					fset.Position(fn.Pos()), fn.Name.Name, clampCall)
			}
		}
	}

	// A gate that matches nothing passes forever. If the dispatch idiom is
	// refactored past the matcher above, this is what says so.
	if checked < 4 {
		t.Fatalf("the dispatch matcher found only %d call sites; it has drifted away from "+
			"how this package starts workloads and is no longer checking anything", checked)
	}
}
