// Package security is an executable specification of cloop's threat model.
//
// The security guarantees this suite protects are stated in prose in the
// README and enforced in code across four packages that do not import each
// other: pkg/executor (the host-execution policy), pkg/secretbroker (scoped
// credential grants), pkg/executorstore (enrollment token persistence), and
// pkg/ui (the control plane that must never execute anything itself). Nothing
// in that arrangement fails loudly when a refactor quietly reconnects the UI
// to os/exec, widens a container's privileges, or lets an expired lease
// redeem. A guarantee that only exists in prose is a guarantee that regresses
// silently.
//
// So these tests assert the properties directly, at the boundary a reviewer
// would check by hand: not "does this function work" but "is it still
// impossible to reach exec.Command from an HTTP handler". They live outside
// the packages they audit on purpose — an external test can only use the
// exported surface, which is the same surface an attacker and an embedder
// see, and it cannot be weakened by a change to package internals without
// that change being visible here.
//
// This file implements the static reachability analysis behind guarantee (1).
// The rest of the suite is behavioral.
package security

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ModulePath is the import path prefix of this module. Everything outside it
// is a dependency we do not audit.
const ModulePath = "github.com/blechschmidt/cloop"

// ExecutorBoundary is the one package tree permitted to spawn processes.
//
// The whole architecture rests on this being the only door: a driver under
// pkg/executor knows *where* a workload runs (this host, a container, a remote
// agent) and is the only code entitled to decide. Everything upstream of it
// speaks in Specs and Handles. Traversal stops here rather than treating it as
// a violation, which is what makes this a boundary check and not a ban.
const ExecutorBoundary = ModulePath + "/pkg/executor"

// AuditedRoots are the packages whose HTTP handlers must not reach process
// execution. Both terminate network requests from potentially untrusted
// callers, so both inherit the same obligation.
var AuditedRoots = []string{
	ModulePath + "/pkg/ui",
	ModulePath + "/pkg/apiserver",
}

// spawnFuncs are the standard-library functions that create a process. Keys
// are (*types.Func).FullName() values, which disambiguate methods from
// package functions and survive import aliasing — a check on the identifier
// `exec` is defeated by `import shell "os/exec"`, a check on the resolved
// object is not.
var spawnFuncs = map[string]string{
	"os/exec.Command":                "os/exec.Command",
	"os/exec.CommandContext":         "os/exec.CommandContext",
	"(*os/exec.Cmd).Start":           "(*exec.Cmd).Start",
	"(*os/exec.Cmd).Run":             "(*exec.Cmd).Run",
	"(*os/exec.Cmd).Output":          "(*exec.Cmd).Output",
	"(*os/exec.Cmd).CombinedOutput":  "(*exec.Cmd).CombinedOutput",
	"syscall.Exec":                   "syscall.Exec",
	"syscall.ForkExec":               "syscall.ForkExec",
	"syscall.StartProcess":           "syscall.StartProcess",
	"os.StartProcess":                "os.StartProcess",
	"golang.org/x/sys/unix.Exec":     "unix.Exec",
	"golang.org/x/sys/unix.ForkExec": "unix.ForkExec",
}

// node is one function in the reference graph.
type node struct {
	// key is (*types.Func).FullName().
	key string
	// pkgPath is the package that declares it.
	pkgPath string
	// pos is a "file:line" for human-readable failure output.
	pos string
	// callees are functions this one references. It is a *reference* graph,
	// not a strict call graph: taking a function's address counts as an
	// edge. That over-approximates, which is the safe direction — a handler
	// that stores exec.Command in a variable and calls it later is still a
	// handler that spawns a process.
	callees map[string]bool
	// spawns names the process-spawning function referenced directly here,
	// if any.
	spawns string
}

// Graph is a whole-module function reference graph.
type Graph struct {
	nodes map[string]*node
	// handlers are the net/http handler functions found in AuditedRoots,
	// keyed the same way as nodes, with a display name for output.
	handlers map[string]string
}

// moduleRoot locates the repository root from this file's compile-time path,
// so the analysis works regardless of the working directory a test runs in.
func moduleRoot() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller could not locate callgraph.go")
	}
	// tests/security/callgraph.go -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), nil
}

// LoadGraph type-checks every package in the module and builds the reference
// graph.
//
// It deliberately loads the whole module rather than just the audited packages:
// the interesting violations are transitive, hiding two or three hops away in
// a helper package that shells out to git, and a check that only reads pkg/ui
// would never see them.
func LoadGraph() (*Graph, error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports,
		Dir: root,
		// Test variants are excluded: a _test.go file may legitimately fork
		// a helper process, and the guarantee is about production
		// request-handling code.
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ModulePath+"/...")
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages loaded — the guard would silently pass")
	}

	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", p.PkgPath, e))
		}
	})
	if len(loadErrs) > 0 {
		// A package that failed to type-check contributes no edges, so its
		// handlers would appear to reach nothing. Refusing to continue is
		// the only way this analysis can fail safe.
		sort.Strings(loadErrs)
		if len(loadErrs) > 10 {
			loadErrs = append(loadErrs[:10], fmt.Sprintf("... and %d more", len(loadErrs)-10))
		}
		return nil, fmt.Errorf("packages failed to type-check:\n  %s", strings.Join(loadErrs, "\n  "))
	}

	g := &Graph{nodes: map[string]*node{}, handlers: map[string]string{}}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if !strings.HasPrefix(p.PkgPath, ModulePath) {
			return // dependency: we only audit our own code
		}
		g.addPackage(p)
	})
	if len(g.nodes) == 0 {
		return nil, fmt.Errorf("graph is empty — the guard would silently pass")
	}
	return g, nil
}

// addPackage walks one package's syntax and records a node per function.
func (g *Graph) addPackage(p *packages.Package) {
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			obj, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			n := &node{
				key:     obj.FullName(),
				pkgPath: p.PkgPath,
				pos:     shortPos(p, fd.Pos()),
				callees: map[string]bool{},
			}
			// Walking the entire body includes nested function literals, so
			// a handler that spawns inside a `go func(){}` is attributed to
			// the handler. That is the correct attribution: the handler is
			// what a request reaches.
			ast.Inspect(fd.Body, func(nd ast.Node) bool {
				id, ok := nd.(*ast.Ident)
				if !ok {
					return true
				}
				callee, ok := p.TypesInfo.Uses[id].(*types.Func)
				if !ok || callee.Pkg() == nil {
					return true
				}
				full := callee.FullName()
				if _, bad := spawnFuncs[full]; bad {
					n.spawns = full
					return true
				}
				if strings.HasPrefix(callee.Pkg().Path(), ModulePath) {
					n.callees[full] = true
				}
				return true
			})
			g.nodes[n.key] = n

			if isHTTPHandler(obj) && inAuditedRoot(p.PkgPath) {
				g.handlers[n.key] = fmt.Sprintf("%s (%s)", obj.FullName(), n.pos)
			}
		}
	}
}

func shortPos(p *packages.Package, pos interface{ IsValid() bool }) string {
	_ = pos
	return p.PkgPath
}

// inAuditedRoot reports whether pkgPath is one of the audited packages or a
// sub-package of one.
func inAuditedRoot(pkgPath string) bool {
	for _, root := range AuditedRoots {
		if pkgPath == root || strings.HasPrefix(pkgPath, root+"/") {
			return true
		}
	}
	return false
}

// inExecutorBoundary reports whether pkgPath is the sanctioned execution
// boundary.
func inExecutorBoundary(pkgPath string) bool {
	return pkgPath == ExecutorBoundary || strings.HasPrefix(pkgPath, ExecutorBoundary+"/")
}

// isHTTPHandler reports whether fn has the net/http handler signature
// func(http.ResponseWriter, *http.Request).
//
// Matching on the resolved type rather than on a name convention means a
// handler called `doTheThing` and registered inline is still audited, and a
// helper named `handleFoo` that takes different arguments is not.
func isHTTPHandler(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 2 || sig.Results().Len() != 0 {
		return false
	}
	return isNamed(sig.Params().At(0).Type(), "net/http", "ResponseWriter") &&
		isPointerToNamed(sig.Params().At(1).Type(), "net/http", "Request")
}

func isNamed(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == pkgPath && named.Obj().Name() == name
}

func isPointerToNamed(t types.Type, pkgPath, name string) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	return isNamed(ptr.Elem(), pkgPath, name)
}

// Violation is one HTTP handler that can reach a process-spawning call
// without passing through the executor boundary.
type Violation struct {
	Handler string
	// Path is the chain of functions from handler to spawn, inclusive.
	Path []string
	// Spawn is the display name of the offending stdlib call.
	Spawn string
}

// String renders the violation as the path a reviewer needs to see. Printing
// the chain rather than just the endpoints is the difference between a test
// that reports a problem and a test that helps fix one — the fix is almost
// always at an intermediate hop, not at either end.
func (v Violation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "handler %s can reach %s:\n", v.Handler, v.Spawn)
	for i, step := range v.Path {
		fmt.Fprintf(&b, "    %s%s\n", strings.Repeat("  ", i), step)
	}
	fmt.Fprintf(&b, "    %s%s  <-- process spawned here\n", strings.Repeat("  ", len(v.Path)), v.Spawn)
	return b.String()
}

// HandlerCount reports how many HTTP handlers were discovered, so a test can
// refuse to pass vacuously when a refactor renames or moves them all.
func (g *Graph) HandlerCount() int { return len(g.handlers) }

// FindSpawnReachable returns every audited handler that transitively reaches
// process execution outside the executor boundary.
//
// Search is breadth-first so the reported path is the shortest one, which is
// almost always the one that explains the violation best. Packages under
// pkg/executor terminate the search: reaching a driver is the intended
// architecture, and the drivers spawn processes because that is their job.
func (g *Graph) FindSpawnReachable() []Violation {
	var out []Violation
	keys := make([]string, 0, len(g.handlers))
	for k := range g.handlers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, start := range keys {
		if v, found := g.searchFrom(start); found {
			v.Handler = g.handlers[start]
			out = append(out, v)
		}
	}
	return out
}

// searchFrom does the BFS for one root, reconstructing the shortest path on a
// hit.
func (g *Graph) searchFrom(start string) (Violation, bool) {
	parent := map[string]string{start: ""}
	queue := []string{start}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		n := g.nodes[cur]
		if n == nil {
			continue
		}
		if n.spawns != "" {
			return Violation{
				Path:  reconstruct(parent, cur),
				Spawn: spawnFuncs[n.spawns],
			}, true
		}
		callees := make([]string, 0, len(n.callees))
		for c := range n.callees {
			callees = append(callees, c)
		}
		sort.Strings(callees) // deterministic path selection across runs
		for _, c := range callees {
			if _, seen := parent[c]; seen {
				continue
			}
			next := g.nodes[c]
			if next == nil {
				continue // declared in a package we do not audit
			}
			if inExecutorBoundary(next.pkgPath) {
				continue // the sanctioned door
			}
			parent[c] = cur
			queue = append(queue, c)
		}
	}
	return Violation{}, false
}

func reconstruct(parent map[string]string, end string) []string {
	var rev []string
	for cur := end; cur != ""; cur = parent[cur] {
		rev = append(rev, cur)
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// ---------------------------------------------------------------------------
// Reachability between named functions
// ---------------------------------------------------------------------------
//
// FindSpawnReachable answers "can a handler reach a forbidden thing". The
// destruction guarantees need the mirror image: "does a required thing sit on
// a path that always runs". A credential wipe that exists, is correct, and is
// only reachable from an optional code path is indistinguishable from no wipe
// at all on every execution that does not take it — which is exactly how
// credential files came to survive normal task exits.

// FindFunc returns the graph key for a function declared in pkgPath.
//
// name may be a plain function ("forget") or a method ("(*Agent).forget" is
// matched by "forget" too, since a package rarely declares both). The lookup is
// by suffix rather than by an assembled FullName because the receiver's
// rendering — pointer, alias, type parameters — is a detail a test should not
// have to reproduce exactly.
func (g *Graph) FindFunc(pkgPath, name string) (string, bool) {
	var found string
	for key, n := range g.nodes {
		if n.pkgPath != pkgPath {
			continue
		}
		if !strings.HasSuffix(key, "."+name) {
			continue
		}
		if found != "" && found != key {
			// Ambiguity would make a passing test meaningless: the assertion
			// would be about whichever overload the map happened to yield.
			return "", false
		}
		found = key
	}
	return found, found != ""
}

// Reaches reports whether `to` is reachable from `from`, returning the path.
//
// Same reference-graph semantics as FindSpawnReachable: taking a function's
// address counts as an edge. For a "the wipe is reachable" assertion that
// over-approximates in the *unsafe* direction, so the path is returned for the
// test to print and a human to sanity-check rather than trusted blindly.
func (g *Graph) Reaches(from, to string) ([]string, bool) {
	if from == "" || to == "" {
		return nil, false
	}
	if _, ok := g.nodes[from]; !ok {
		return nil, false
	}
	parent := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == to {
			return reconstruct(parent, cur), true
		}
		n := g.nodes[cur]
		if n == nil {
			continue
		}
		callees := make([]string, 0, len(n.callees))
		for callee := range n.callees {
			callees = append(callees, callee)
		}
		// Sorted so a failure prints the same path every run.
		sort.Strings(callees)
		for _, callee := range callees {
			if _, seen := parent[callee]; seen {
				continue
			}
			parent[callee] = cur
			queue = append(queue, callee)
		}
	}
	return nil, false
}
