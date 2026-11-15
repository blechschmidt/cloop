package arch_test

// The project-move surface is deny-by-default, and every route of it is
// classified here (Task 20496).
//
// A move changes where a project's code runs and, after a verified one,
// cleanup removes the copy its source kept — so the routes that do either are
// held to what binding a project to an executor is held to: executor.manage
// in the project's scope, a recent sign-in on a hub with single sign-on, and,
// in the handler, the caller's place on the access list of the executor the
// work lands on. Reading a move is the project's readers'; planning one, its
// maintainers'.
//
// The gate reads pkg/ui/routes.go and fails on:
//
//   - a route under /api/projects/{idx}/move or /moves that is not classified
//     below, so a new one is decided on rather than inherited by accident;
//   - a classified route whose permission, scope or sudo marking differs from
//     its classification, or that is gone;
//   - a mutating route whose handler no longer asks the access list it is
//     classified as asking.

import (
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

// moveRouteClass is what one route of the move surface must declare.
type moveRouteClass struct {
	// perm is the routeTable shorthand: read, write or execMgmt.
	perm string
	// sudo is the routeSpec Sudo marking, "" for none.
	sudo string
	// asks are the access-list checks the handler must make.
	asks []string
}

// moveRouteClasses classifies every route of the project-move surface.
var moveRouteClasses = map[string]moveRouteClass{
	// What a move would lose or break: a maintainer's question, on a target
	// the maintainer may use (Task 20493).
	"GET /api/projects/{idx}/move/preflight": {perm: "write", asks: []string{"admitExecutorAudience", "admitPoolAudience"}},
	// Starting one: what binding takes (Task 20494).
	"POST /api/projects/{idx}/move": {perm: "execMgmt", sudo: "sudoWrites", asks: []string{"admitExecutorAudience", "admitPoolAudience"}},
	// Following one, and listing a project's: its readers'.
	"GET /api/projects/{idx}/moves":     {perm: "read"},
	"GET /api/projects/{idx}/move/{id}": {perm: "read"},
	// Cleaning up after one, which removes the source's copy after a
	// verified move: what moving takes, and the access list of the executor
	// that copy is on.
	"POST /api/projects/{idx}/move/{id}/cleanup": {perm: "execMgmt", sudo: "sudoWrites", asks: []string{"admitExecutorAudience"}},
}

// moveRoute is one route the gate found.
type moveRoute struct {
	perm, scope, sudo, handler string
}

func TestEveryProjectMoveRouteIsClassified(t *testing.T) {
	root := repoRoot(t)
	found, err := moveRoutesIn(filepath.Join(root, "pkg/ui/routes.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < len(moveRouteClasses) {
		t.Fatalf("found %d move routes in pkg/ui/routes.go, fewer than the %d classified: the scan has gone blind or routes went",
			len(found), len(moveRouteClasses))
	}
	patterns := make([]string, 0, len(found))
	for p := range found {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	handlers := map[string]map[string]bool{}
	for _, pattern := range patterns {
		got := found[pattern]
		want, ok := moveRouteClasses[pattern]
		if !ok {
			t.Errorf("%s is a project-move route nobody classified: add it to moveRouteClasses with the permission, "+
				"sudo marking and access-list checks it needs", pattern)
			continue
		}
		if got.perm != want.perm {
			t.Errorf("%s declares Perm %s, classified %s", pattern, got.perm, want.perm)
		}
		if got.scope != "scopeProjectIdx" {
			t.Errorf("%s is evaluated in scope %s: a move's routes are the project's, scopeProjectIdx", pattern, got.scope)
		}
		if got.sudo != want.sudo {
			t.Errorf("%s declares Sudo %q, classified %q", pattern, got.sudo, want.sudo)
		}
		if len(want.asks) == 0 {
			continue
		}
		if handlers[got.handler] == nil {
			calls, err := methodCallsIn(filepath.Join(root, "pkg/ui"), got.handler)
			if err != nil {
				t.Errorf("%s: %v", pattern, err)
				continue
			}
			handlers[got.handler] = calls
		}
		for _, ask := range want.asks {
			if !handlers[got.handler][ask] {
				t.Errorf("%s's handler %s no longer calls %s: the route's permission alone would let a caller put work "+
					"on an executor whose access list leaves them out", pattern, got.handler, ask)
			}
		}
	}
	for pattern := range moveRouteClasses {
		if _, ok := found[pattern]; !ok {
			t.Errorf("moveRouteClasses names %s, which pkg/ui no longer registers: remove it, or register it again", pattern)
		}
	}
}

// moveRoutesIn reads the route table's composite literals whose Pattern is
// under a project's move routes.
func moveRoutesIn(path string) (map[string]moveRoute, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]moveRoute{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var pattern string
		var r moveRoute
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Pattern":
				if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					pattern, _ = strconv.Unquote(bl.Value)
				}
			case "Perm":
				r.perm = exprName(kv.Value)
			case "Scope":
				r.scope = exprName(kv.Value)
			case "Sudo":
				r.sudo = exprName(kv.Value)
			case "Handler":
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
					r.handler = sel.Sel.Name
				}
			}
		}
		_, p, _ := strings.Cut(pattern, " ")
		if strings.HasPrefix(p, "/api/projects/{idx}/move/") || p == "/api/projects/{idx}/move" ||
			strings.HasPrefix(p, "/api/projects/{idx}/moves") {
			out[pattern] = r
		}
		return true
	})
	return out, nil
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprName(v.X) + "." + v.Sel.Name
	}
	return ""
}

// methodCallsIn finds the method named fn among dir's non-test files and
// returns the names of the methods and functions its body calls.
func methodCallsIn(dir, fn string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			f, ok := decl.(*ast.FuncDecl)
			if !ok || f.Name.Name != fn || f.Body == nil {
				continue
			}
			calls := map[string]bool{}
			ast.Inspect(f.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					calls[fun.Sel.Name] = true
				case *ast.Ident:
					calls[fun.Name] = true
				}
				return true
			})
			return calls, nil
		}
	}
	return nil, os.ErrNotExist
}
