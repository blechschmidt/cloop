package arch_test

// Every dispatch settles the harness-credential preflight (Task 20379).
//
// A project bound to an executor that isolates from the host gets a Claude
// login only through a secret grant, and before this task nothing checked for
// one: the sandbox started, a device sometimes installed claude first, and the
// first task failed auth_refused. pkg/ui now builds a harnessClearance on every
// path that dispatches a workload, and the dispatch primitives settle it
// against the executor they resolve: for a harness — runs, the automatic
// resume, brainstorms and plans, the assistant chat, reproductions — a sandbox
// that would get no credential is refused before anything starts; for every
// workload, harness or not, the lease withholds other people's personal Claude
// credentials.
//
// A guarantee with one enforcement point per dispatch path is a guarantee that
// a new path forgets. This gate is what makes forgetting fail:
//
//   - a call to a primitive that takes a clearance must pass one built by a
//     preflight constructor — the call itself, or a variable assigned from one
//     in the same function. Never nil, never a value from somewhere else;
//   - the primitives that take none exist for tests: production code may not
//     call them;
//   - acquireSecretLease, and a raw executor dispatch, may be reached only by a
//     function that settles a constructor-built clearance before it;
//   - the primitives settle the clearance before they lease anything, and
//     settle runs the one shared helper, harnessPreflight.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// uiDir is the package whose dispatches the gate checks.
const uiDir = "pkg/ui"

// clearanceArg maps each primitive that takes a *harnessClearance to that
// argument's index.
var clearanceArg = map[string]int{
	"startWorkloadAs":       1,
	"runWorkloadEnvFor":     4,
	"runCloopSubcommandFor": 5,
}

// bareDispatchers dispatch without a clearance. They are wrappers that pass
// nil, kept for tests; production code calls the primitives above.
var bareDispatchers = map[string]bool{
	"startWorkload":         true,
	"runWorkload":           true,
	"runWorkloadEnv":        true,
	"runCloopSubcommand":    true,
	"runCloopSubcommandEnv": true,
}

// settlingPrimitives are the functions that dispatch and must settle the
// clearance they are handed before they lease.
var settlingPrimitives = map[string]bool{"startWorkloadAs": true, "runWorkloadEnvFor": true}

// preflightConstructors build the clearance whose settle runs the preflight.
var preflightConstructors = map[string]bool{
	"harnessClearanceFor": true, "newHarnessClearance": true,
	"leaseClearanceFor": true, "newLeaseClearance": true,
}

// rawDispatch is the key suffix for an executor.Run or Executor.Start call
// made outside the primitives.
const rawDispatch = "raw dispatch"

// exemptDispatches are dispatches the rules above do not fit, keyed
// "function → what", each with the reason. TestDispatchExemptionsAreStillUsed
// rejects an entry that no longer matches a call.
//
// It is empty since Task 20396: failover's replacement used to start the
// recorded spec raw, and now goes through startWorkloadAs like every run.
var exemptDispatches = map[string]string{}

func TestEveryDispatchSettlesThePreflight(t *testing.T) {
	scan, err := scanHarnessDispatches(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v)
	}
	if scan.calls == 0 {
		t.Fatal("the gate found no dispatch at all in pkg/ui — it is looking in the wrong place, and would pass anything")
	}
}

func TestDispatchExemptionsAreStillUsed(t *testing.T) {
	scan, err := scanHarnessDispatches(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for key := range exemptDispatches {
		if !scan.used[key] {
			t.Errorf("%q is exempt from the harness clearance but no longer matches a call — remove it from exemptDispatches", key)
		}
	}
}

// The primitives are the guarantee: each must settle its clearance, and before
// it leases, or a refused run would already have taken a credential.
func TestDispatchPrimitivesSettleBeforeTheyLease(t *testing.T) {
	scan, err := scanHarnessDispatches(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for name := range settlingPrimitives {
		p, ok := scan.primitives[name]
		switch {
		case !ok:
			t.Errorf("%s no longer exists; the gate needs to learn where dispatches settle now", name)
		case p.settle == token.NoPos:
			t.Errorf("%s never calls settle on its clearance, so no dispatch through it is checked", name)
		case p.lease != token.NoPos && p.lease < p.settle:
			t.Errorf("%s leases before it settles the clearance: a refused run would already hold a credential", name)
		}
	}
	if !scan.settleRunsPreflight {
		t.Error("(*harnessClearance).settle does not call harnessPreflight: the dispatch paths no longer share one helper")
	}
}

// The gate must flag what it exists for, and only that.
func TestHarnessGateFlagsWhatItShould(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("prims.go", `package ui
type harnessClearance struct{}
func (c *harnessClearance) settle(ex any, dir string) (map[string]string, error) { harnessPreflight(); return nil, nil }
func harnessPreflight() {}
func newHarnessClearance(string) *harnessClearance { return nil }
func newLeaseClearance(string) *harnessClearance { return nil }
func acquireSecretLease(string) {}
func startWorkloadAs(env any, c *harnessClearance, who, dir string) { c.settle(nil, dir); acquireSecretLease(dir) }
func runWorkloadEnvFor(dir string, a, b, c any, cl *harnessClearance) { acquireSecretLease(dir); cl.settle(nil, dir) }
func runWorkload(dir string) { runWorkloadEnvFor(dir, nil, nil, nil, nil) }
`)
	write("paths.go", `package ui
type Server struct{}
func (s *Server) good(dir string) { c := newHarnessClearance(dir); startWorkloadAs(nil, c, "", dir) }
func (s *Server) inline(dir string) { startWorkloadAs(nil, newLeaseClearance(dir), "", dir) }
func (s *Server) forgot(dir string) { startWorkloadAs(nil, nil, "", dir) }
func (s *Server) borrowed(dir string, c *harnessClearance) { startWorkloadAs(nil, c, "", dir) }
func (s *Server) decoy(dir string, c *harnessClearance) { _ = newHarnessClearance(dir); startWorkloadAs(nil, c, "", dir) }
func (s *Server) bare(dir string) { runWorkload(dir) }
func (s *Server) leases(dir string) { acquireSecretLease(dir) }
func (s *Server) settledLease(dir string) { c := newLeaseClearance(dir); c.settle(nil, dir); acquireSecretLease(dir) }
func (s *Server) lateSettle(dir string) { c := newLeaseClearance(dir); acquireSecretLease(dir); c.settle(nil, dir) }
func raw(ex interface{ Start(any, any) }) { ex.Start(nil, nil) }
`)
	write("paths_test.go", `package ui
func (s *Server) inATest(dir string) { startWorkloadAs(nil, nil, "", dir); runWorkload(dir) }
`)
	scan, err := scanHarnessDispatches(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scan.violations, "\n")
	for _, want := range []string{
		"(*Server).forgot passes a nil harness clearance to startWorkloadAs",
		"(*Server).borrowed passes startWorkloadAs a clearance it did not build",
		"(*Server).decoy passes startWorkloadAs a clearance it did not build",
		"(*Server).bare calls runWorkload",
		"(*Server).leases calls acquireSecretLease",
		"(*Server).lateSettle calls acquireSecretLease",
		"raw raw dispatches a workload",
		"runWorkloadEnvFor leases before it settles",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the gate did not report %q; it reported:\n%s", want, got)
		}
	}
	for _, clean := range []string{"(*Server).good", "(*Server).inline", "(*Server).settledLease", "inATest", "runWorkload passes"} {
		if strings.Contains(got, clean) {
			t.Errorf("the gate flagged %s, which is fine:\n%s", clean, got)
		}
	}
}

// harnessScan is what one pass over a package found.
type harnessScan struct {
	violations []string
	// calls counts the dispatch calls seen, so a gate pointed at the wrong
	// directory fails rather than passes.
	calls int
	// used are the exemptDispatches keys a call matched.
	used map[string]bool
	// primitives records where each settling primitive settles and leases.
	primitives map[string]primitivePos
	// settleRunsPreflight says (*harnessClearance).settle calls harnessPreflight.
	settleRunsPreflight bool
}

type primitivePos struct{ settle, lease token.Pos }

// scanHarnessDispatches walks the production files of the package in dir.
func scanHarnessDispatches(dir string) (*harnessScan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	scan := &harnessScan{used: map[string]bool{}, primitives: map[string]primitivePos{}}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			scanHarnessFunc(fset, fd, scan)
		}
	}
	return scan, nil
}

// isPrimitive reports whether fd is one of the dispatch functions themselves,
// which call one another and are held to their own rules.
func isPrimitive(fd *ast.FuncDecl) bool {
	if fd.Recv != nil {
		return false
	}
	_, takes := clearanceArg[fd.Name.Name]
	return takes || bareDispatchers[fd.Name.Name] || fd.Name.Name == "acquireSecretLease"
}

func scanHarnessFunc(fset *token.FileSet, fd *ast.FuncDecl, scan *harnessScan) {
	name := harnessFuncName(fd)
	if name == "(*harnessClearance).settle" {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && calleeName(c) == "harnessPreflight" {
				scan.settleRunsPreflight = true
			}
			return true
		})
		return
	}

	// built are the identifiers this function assigns from a preflight
	// constructor; settled is where it first settles one of them.
	built := map[string]bool{}
	var settled token.Pos
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				if c, ok := rhs.(*ast.CallExpr); ok && preflightConstructors[calleeName(c)] && i < len(x.Lhs) {
					if id, ok := x.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
						built[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, v := range x.Values {
				if c, ok := v.(*ast.CallExpr); ok && preflightConstructors[calleeName(c)] && i < len(x.Names) {
					built[x.Names[i].Name] = true
				}
			}
		}
		return true
	})
	isBuilt := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.CallExpr:
			return preflightConstructors[calleeName(v)]
		case *ast.Ident:
			return built[v.Name]
		}
		return false
	}

	var lease token.Pos
	type call struct {
		c      *ast.CallExpr
		callee string
	}
	var calls []call
	var raws []token.Pos
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := calleeName(c)
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok && callee == "settle" && settled == token.NoPos && isBuilt(sel.X) {
			settled = c.Pos()
		}
		if callee == "acquireSecretLease" && lease == token.NoPos {
			lease = c.Pos()
		}
		if _, takes := clearanceArg[callee]; (takes || bareDispatchers[callee] || callee == "acquireSecretLease") && isIdentCall(c) {
			calls = append(calls, call{c, callee})
		}
		if isRawDispatch(c) {
			raws = append(raws, c.Pos())
		}
		return true
	})

	if settlingPrimitives[fd.Name.Name] && fd.Recv == nil {
		var settle token.Pos
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && calleeName(c) == "settle" && settle == token.NoPos {
				settle = c.Pos()
			}
			return true
		})
		scan.primitives[fd.Name.Name] = primitivePos{settle: settle, lease: lease}
		if settle != token.NoPos && lease != token.NoPos && lease < settle {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s leases before it settles its harness clearance", fset.Position(lease), name))
		}
	}
	if isPrimitive(fd) {
		scan.calls += len(calls)
		return
	}

	for _, cl := range calls {
		scan.calls++
		where := fset.Position(cl.c.Pos())
		key := name + " → " + cl.callee
		if _, ok := exemptDispatches[key]; ok {
			scan.used[key] = true
			continue
		}
		idx, takes := clearanceArg[cl.callee]
		switch {
		case takes && idx < len(cl.c.Args) && isNilIdent(cl.c.Args[idx]):
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s passes a nil harness clearance to %s. Every dispatch carries one: "+
					"s.harnessClearanceFor(r, workDir) / newHarnessClearance(…) for a workload that runs a harness, "+
					"s.leaseClearanceFor(r, workDir) / newLeaseClearance(…) for one that runs none — so a sandbox "+
					"that would get no Claude login is refused before it starts, and no lease carries a colleague's "+
					"personal Claude credential.", where, name, cl.callee))
		case takes && (idx >= len(cl.c.Args) || !isBuilt(cl.c.Args[idx])):
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s passes %s a clearance it did not build. Build it in the function that knows whom the "+
					"dispatch acts for, with a preflight constructor, and pass that — the call itself or the "+
					"variable it was assigned to.", where, name, cl.callee))
		case bareDispatchers[cl.callee]:
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s calls %s, which dispatches with no harness clearance and exists for tests. Call the "+
					"primitive it wraps with a clearance built here.", where, name, cl.callee))
		case cl.callee == "acquireSecretLease" && (settled == token.NoPos || settled > cl.c.Pos()):
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s calls acquireSecretLease without first settling a clearance built here: its lease "+
					"would not withhold what the preflight decides, nor wait on its refusal.", where, name))
		}
	}
	for _, pos := range raws {
		scan.calls++
		key := name + " → " + rawDispatch
		if _, ok := exemptDispatches[key]; ok {
			scan.used[key] = true
			continue
		}
		if settled == token.NoPos || settled > pos {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s raw dispatches a workload (executor.Run / Executor.Start) without first settling a "+
					"harness clearance built here. Go through startWorkloadAs, or build and settle one.",
				fset.Position(pos), name))
		}
	}
}

// harnessFuncName renders a function as the allowlist spells it.
func harnessFuncName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	switch t := fd.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + fd.Name.Name
		}
	case *ast.Ident:
		return "(" + t.Name + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

// calleeName is the called function's own name: f for f(…), Sel for x.Sel(…).
func calleeName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isIdentCall reports a call to a package-level function by its bare name,
// which is how the primitives are reached; a method of the same name on some
// other type is not one of them.
func isIdentCall(c *ast.CallExpr) bool {
	_, ok := c.Fun.(*ast.Ident)
	return ok
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// isRawDispatch reports executor.Run(ctx, ex, spec) and x.Start(ctx, spec):
// the two ways to start a workload without a primitive. Start is matched by
// shape (two arguments), which leaves out the supervisor's one-argument Start.
func isRawDispatch(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "executor" && sel.Sel.Name == "Run" {
		return true
	}
	return sel.Sel.Name == "Start" && len(c.Args) == 2
}
