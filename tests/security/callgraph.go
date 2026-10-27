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
	"sync"

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
	// abstract marks a method of an interface declared in this module: it has
	// no body, and its callees are the module's implementations of it
	// (interfaceEdges). The executor boundary applies to those, not to it —
	// see searchFrom.
	abstract bool
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

// The type-checked module, loaded once per test binary (Task 20372).
//
// Every static check in this suite reads the same thing: the whole module
// and its dependencies, type-checked from source. Under -race that load costs
// about 30 seconds, and nine tests each made their own, which was two thirds
// of this package's wall clock in CI's race step. The loaded packages are only
// ever read — each check builds its own Graph or walks the syntax itself, and
// the meta-tests that seed synthetic edges seed them into their own Graph — so
// one load serves them all and every check still sees exactly what it saw.
var (
	moduleLoadOnce sync.Once
	moduleLoadPkgs []*packages.Package
	moduleLoadErr  error
)

// loadModule returns the module's packages as packages.Load reports them: the
// roots matched by ModulePath/..., with their dependencies reachable through
// Imports. Callers must not modify what it returns.
func loadModule() ([]*packages.Package, error) {
	moduleLoadOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			moduleLoadErr = err
			return
		}
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
				packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
				packages.NeedImports,
			Dir: root,
			// Test variants are excluded: a _test.go file may legitimately
			// fork a helper process or stand up a server with a throwaway
			// certificate, and the guarantees are about the code that ships.
			Tests: false,
		}
		pkgs, err := packages.Load(cfg, ModulePath+"/...")
		if err != nil {
			moduleLoadErr = fmt.Errorf("load packages: %w", err)
			return
		}
		moduleLoadPkgs = pkgs
	})
	return moduleLoadPkgs, moduleLoadErr
}

// LoadGraph type-checks every package in the module and builds the reference
// graph. Each call returns a graph of its own, so a test may seed edges into
// it without another test seeing them.
//
// It deliberately loads the whole module rather than just the audited packages:
// the interesting violations are transitive, hiding two or three hops away in
// a helper package that shells out to git, and a check that only reads pkg/ui
// would never see them.
func LoadGraph() (*Graph, error) {
	pkgs, err := loadModule()
	if err != nil {
		return nil, err
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
	for iface, m := range interfaceEdges(pkgs) {
		n := g.nodes[iface]
		if n == nil {
			n = &node{key: iface, pkgPath: m.pkgPath, callees: map[string]bool{}}
			g.nodes[iface] = n
		}
		n.abstract = true
		for impl := range m.impls {
			n.callees[impl] = true
		}
	}
	return g, nil
}

// ---------------------------------------------------------------------------
// Calls through an interface
// ---------------------------------------------------------------------------
//
// A call on an interface value names the interface's method, which has no
// body: on its own the reference graph ends there. That is how four dashboard
// endpoints ran the Claude Code harness on the hub's host for months without
// this check noticing (Task 20442): each built the project's provider and
// called Complete through provider.Provider, and claudecode's Complete — the
// one that execs `claude` — was never an edge from anywhere.
//
// So a method of an interface declared in this module is resolved to every
// type in the module that implements the interface: class-hierarchy analysis,
// limited to the module's own interfaces, whose implementations are code this
// module ships. It over-approximates — a handler holding a mock provider is
// charged with what claudecode does — which is the safe direction, and the one
// the reference graph already takes. Implementations under pkg/executor are
// still the boundary: a call through executor.Executor reaches the drivers'
// Start and stops there, as a direct call to one does.

// ifaceMethod is one method of a module interface and what implements it.
type ifaceMethod struct {
	// pkgPath declares the interface.
	pkgPath string
	// impls are the FullNames of the implementing methods.
	impls map[string]bool
}

var (
	ifaceEdgesOnce sync.Once
	ifaceEdgesMemo map[string]ifaceMethod
)

// interfaceEdges maps each method of each interface declared in the module to
// the module's implementations of it, keyed by FullName. Computed once per
// test binary, like the load: every graph gets the same edges.
func interfaceEdges(pkgs []*packages.Package) map[string]ifaceMethod {
	ifaceEdgesOnce.Do(func() { ifaceEdgesMemo = computeInterfaceEdges(pkgs) })
	return ifaceEdgesMemo
}

func computeInterfaceEdges(pkgs []*packages.Package) map[string]ifaceMethod {
	var ifaces, concretes []*types.Named
	seen := map[*types.Package]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if !strings.HasPrefix(p.PkgPath, ModulePath) || p.Types == nil || seen[p.Types] {
			return
		}
		seen[p.Types] = true
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 {
				continue // generic types are instantiated elsewhere; none needs this yet
			}
			if types.IsInterface(named) {
				ifaces = append(ifaces, named)
			} else {
				concretes = append(concretes, named)
			}
		}
	})

	// Index the concrete types by the names in their pointer method sets, so
	// an interface is checked only against types that have all its names.
	byName := map[string][]*types.Named{}
	for _, c := range concretes {
		ms := types.NewMethodSet(types.NewPointer(c))
		for i := 0; i < ms.Len(); i++ {
			name := ms.At(i).Obj().Name()
			byName[name] = append(byName[name], c)
		}
	}

	out := map[string]ifaceMethod{}
	for _, in := range ifaces {
		it, ok := in.Underlying().(*types.Interface)
		if !ok || it.NumMethods() == 0 {
			continue // no method to call through
		}
		// The rarest of its method names bounds the candidates.
		var candidates []*types.Named
		for i := 0; i < it.NumMethods(); i++ {
			list := byName[it.Method(i).Name()]
			if i == 0 || len(list) < len(candidates) {
				candidates = list
			}
		}
		for _, c := range candidates {
			var recv types.Type
			switch {
			case types.Implements(c, it):
				recv = c
			case types.Implements(types.NewPointer(c), it):
				recv = types.NewPointer(c)
			default:
				continue
			}
			ms := types.NewMethodSet(recv)
			for i := 0; i < it.NumMethods(); i++ {
				m := it.Method(i)
				if m.Pkg() == nil || !strings.HasPrefix(m.Pkg().Path(), ModulePath) {
					continue // embedded from a dependency: calls to it are not edges
				}
				sel := ms.Lookup(m.Pkg(), m.Name())
				if sel == nil {
					continue
				}
				impl, ok := sel.Obj().(*types.Func)
				if !ok {
					continue
				}
				e, ok := out[m.FullName()]
				if !ok {
					e = ifaceMethod{pkgPath: m.Pkg().Path(), impls: map[string]bool{}}
					out[m.FullName()] = e
				}
				if impl.FullName() != m.FullName() {
					e.impls[impl.FullName()] = true
				}
			}
		}
	}
	return out
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

// notTheBoundary are packages under pkg/executor that are not a driver: code
// the hub itself runs, which reaches packages outside the tree. reconcile
// decides which executors exist and sweeps what they left behind — leaked
// task worktrees, through pkg/worktree's git — in the hub's own process, on
// a timer. Treating it as the sanctioned door hid exactly that from the
// background analysis (Task 20418), so it is audited like any other package.
var notTheBoundary = map[string]bool{
	ExecutorBoundary + "/reconcile": true,
}

// inExecutorBoundary reports whether pkgPath is the sanctioned execution
// boundary.
func inExecutorBoundary(pkgPath string) bool {
	if notTheBoundary[pkgPath] {
		return false
	}
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

// BackgroundRoots are where the hub runs code no request asked for (Task
// 20418): its construction — which bootstraps the executors and runs the
// startup sweep — and Run and Start, which start the watchers, the cluster
// bus and the periodic sweep. Every goroutine the hub starts outside a
// request is referenced from one of them, and the reference graph follows a
// function value as an edge, so these reach all of it. A goroutine a handler
// starts is the handler's, and the handler check covers it.
var BackgroundRoots = []string{
	"github.com/blechschmidt/cloop/pkg/ui.NewInCluster",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).Run",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).Start",
	"(*github.com/blechschmidt/cloop/pkg/apiserver.Server).Run",
	"(*github.com/blechschmidt/cloop/pkg/apiserver.Server).Start",
}

// MissingBackgroundRoots lists the roots the graph does not have, so a test
// can refuse to pass when a rename leaves the background check with nothing
// to start from.
func (g *Graph) MissingBackgroundRoots() []string {
	var out []string
	for _, r := range BackgroundRoots {
		if _, ok := g.nodes[r]; !ok {
			out = append(out, r)
		}
	}
	return out
}

// FindBackgroundSpawns returns every process the background roots reach
// outside the executor boundary, one Violation per spawning function, and the
// doors it stopped at.
//
// It differs from FindSpawnReachable in three ways. Every spawn is reported,
// not the first per root: a root here is the whole hub, and one violation
// must not hide the next. The search stops at an HTTP handler, which the
// handler check owns. And it stops at doors — functions that run one program
// on the hub deliberately, each with the reason it is allowed and a test
// proving the reason (sanctionedHostDoors in callgraph_test.go); a door the
// search never reaches is stale.
func (g *Graph) FindBackgroundSpawns(doors map[string]string) (spawns []Violation, reached map[string]bool) {
	reached = map[string]bool{}
	reported := map[string]bool{}
	for _, root := range BackgroundRoots {
		if _, ok := g.nodes[root]; !ok {
			continue
		}
		parent := map[string]string{root: ""}
		queue := []string{root}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			n := g.nodes[cur]
			if n == nil {
				continue
			}
			if n.spawns != "" && !reported[cur] {
				reported[cur] = true
				spawns = append(spawns, Violation{
					Handler: root + " (background)",
					Path:    reconstruct(parent, cur),
					Spawn:   spawnFuncs[n.spawns],
				})
			}
			callees := make([]string, 0, len(n.callees))
			for c := range n.callees {
				callees = append(callees, c)
			}
			sort.Strings(callees)
			for _, c := range callees {
				if _, seen := parent[c]; seen {
					continue
				}
				next := g.nodes[c]
				if next == nil || (inExecutorBoundary(next.pkgPath) && !next.abstract) {
					continue
				}
				if _, isHandler := g.handlers[c]; isHandler {
					continue
				}
				if _, isDoor := doors[c]; isDoor {
					reached[c] = true
					continue
				}
				parent[c] = cur
				queue = append(queue, c)
			}
		}
	}
	return spawns, reached
}

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
			// An interface method declared under pkg/executor is not a door: a
			// type outside the boundary may implement it. Its implementations
			// are judged one by one.
			if inExecutorBoundary(next.pkgPath) && !next.abstract {
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

// ReachesWithin is Reaches with FindSpawnReachable's boundary: the search does
// not enter the executor drivers, whose job is to start what a dispatch asks
// for, so `to` is reached only by running it in the caller's own process —
// the question for code that must never run a harness on the hub's account
// (Task 20449).
func (g *Graph) ReachesWithin(from, to string) ([]string, bool) {
	return g.reachesWithin(from, to, false)
}

// BackgroundReachesWithin is ReachesWithin from a background root, which also
// stops at an HTTP handler: the route table is referenced from Run, and what a
// handler reaches is the handler check's, as FindBackgroundSpawns has it.
func (g *Graph) BackgroundReachesWithin(from, to string) ([]string, bool) {
	return g.reachesWithin(from, to, true)
}

func (g *Graph) reachesWithin(from, to string, stopAtHandlers bool) ([]string, bool) {
	if _, ok := g.nodes[from]; !ok || to == "" {
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
		for c := range n.callees {
			callees = append(callees, c)
		}
		sort.Strings(callees)
		for _, c := range callees {
			if _, seen := parent[c]; seen {
				continue
			}
			next := g.nodes[c]
			if next == nil || (inExecutorBoundary(next.pkgPath) && !next.abstract) {
				continue
			}
			if _, isHandler := g.handlers[c]; isHandler && stopAtHandlers {
				continue
			}
			parent[c] = cur
			queue = append(queue, c)
		}
	}
	return nil, false
}

// HandlerKeys returns the audited HTTP handlers, sorted.
func (g *Graph) HandlerKeys() []string {
	out := make([]string, 0, len(g.handlers))
	for k := range g.handlers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// References reports whether from's own body references to.
func (g *Graph) References(from, to string) bool {
	n := g.nodes[from]
	return n != nil && n.callees[to]
}
