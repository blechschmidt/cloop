package arch_test

// Every dispatch pins its harness to a Claude account (Task 20443).
//
// handleRun, a project's Run and the new-project autorun hand startWorkloadAs
// s.claudeEnvResolver(r): on a hub with single sign-on, a run on an executor
// that shares the hub's filesystem gets its caller's Claude home and a cleared
// ambient token (Task 20241). The automatic resume after a usage cap and a
// failover's replacement handed it nil — no resolver — so on that same hub
// they ran on the hub process's own login: the shared account
// pkg/ui/claude_identity.go says nobody may fall back to. A nil compiles, vets
// clean and passes every test that does not read the child's environment,
// which is how both went unnoticed. This gate is what makes the next one fail:
//
//   - a call to a dispatch primitive that takes an environment resolver may
//     pass a literal nil only from a caller listed in nilEnvCallers, with the
//     reason it needs no account;
//   - a dispatch that acts for a run's recorded starter — its clearance built
//     by newResumeClearance(acct) — passes that same account's acct.envFor, so
//     the account the clearance checked is the one the run is pinned to.
//
// The Copilot CLI's account is pinned by the clearance itself, and
// copilotenv_test.go holds every lease to it (Task 20449).

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

// envArg maps each dispatch primitive that takes an environment resolver
// (func(executor.Executor) []string) to that argument's index.
var envArg = map[string]int{
	"startWorkloadAs":          0,
	"runWorkloadEnvFor":        3,
	"runCloopSubcommandFor":    4,
	"streamCloopSubcommandFor": 4,
}

// nilEnvCallers may pass a nil resolver, keyed "caller → primitive", each with
// the reason. TestNilEnvCallersAreStillUsed rejects an entry no call matches.
var nilEnvCallers = map[string]string{
	"startWorkload → startWorkloadAs": "the test-only wrapper: it settles no harness clearance either, and " +
		"TestEveryDispatchSettlesThePreflight keeps production code off it",
	"(*Server).handleReset → runCloopSubcommandFor": "`cloop reset` calls no model; its lease clearance only " +
		"withholds other people's personal credentials",
	"(*Server).handleProjectNew → runWorkloadEnvFor": "`cloop init` calls no model; its lease clearance only " +
		"withholds other people's personal credentials",
}

// resumeClearanceConstructor builds the clearance of a dispatch acting for a
// run's recorded starter.
const resumeClearanceConstructor = "newResumeClearance"

func TestEveryDispatchPinsAClaudeAccount(t *testing.T) {
	scan, err := scanEnvResolvers(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v)
	}
	if scan.calls == 0 {
		t.Fatal("the gate found no dispatch at all in pkg/ui — it is looking in the wrong place, and would pass anything")
	}
	if scan.resumeCalls == 0 {
		t.Fatal("no dispatch acts for a run's recorded starter (newResumeClearance) any more — the automatic resume " +
			"and failover moved, and this gate needs to learn where")
	}
}

func TestNilEnvCallersAreStillUsed(t *testing.T) {
	scan, err := scanEnvResolvers(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for key := range nilEnvCallers {
		if !scan.used[key] {
			t.Errorf("%q may pass a nil environment resolver but no longer matches a call — remove it from nilEnvCallers", key)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestEnvResolverGateFlagsWhatItShould(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("prims.go", `package ui
type harnessClearance struct{}
type resumeAccount struct{}
func (a *resumeAccount) envFor(any) []string { return nil }
func newResumeClearance(a *resumeAccount) *harnessClearance { return nil }
func newHarnessClearance(string) *harnessClearance { return nil }
func startWorkloadAs(env func(any) []string, c *harnessClearance, who, dir string) {}
func runCloopSubcommandFor(a, b, c, d any, env func(any) []string, cl *harnessClearance) {}
func startWorkload(dir string) { startWorkloadAs(nil, nil, "", dir) }
`)
	write("paths.go", `package ui
type Server struct{}
func (s *Server) resolver() func(any) []string { return nil }
func (s *Server) run(dir string) { startWorkloadAs(s.resolver(), newHarnessClearance(dir), "", dir) }
func (s *Server) forgot(dir string) { startWorkloadAs(nil, newHarnessClearance(dir), "", dir) }
func (s *Server) chat(dir string) { runCloopSubcommandFor(nil, nil, nil, nil, nil, newHarnessClearance(dir)) }
func (s *Server) resume(dir string, acct *resumeAccount) { startWorkloadAs(acct.envFor, newResumeClearance(acct), "", dir) }
func (s *Server) resumeUnpinned(dir string, acct *resumeAccount) { startWorkloadAs(s.resolver(), newResumeClearance(acct), "", dir) }
func (s *Server) resumeOther(dir string, a, b *resumeAccount) { startWorkloadAs(b.envFor, newResumeClearance(a), "", dir) }
func (s *Server) resumeByVar(dir string, acct *resumeAccount) { c := newResumeClearance(acct); startWorkloadAs(acct.envFor, c, "", dir) }
func (s *Server) resumeByVarUnpinned(dir string, acct *resumeAccount) { c := newResumeClearance(acct); startWorkloadAs(s.resolver(), c, "", dir) }
func (s *Server) accountUnchecked(dir string, acct *resumeAccount) { startWorkloadAs(acct.envFor, newHarnessClearance(dir), "", dir) }
func (s *Server) resumeByVarDecl(dir string, acct *resumeAccount) { var c = newResumeClearance(acct); startWorkloadAs(s.resolver(), c, "", dir) }
func (s *Server) claudeEnvResolver(r any) func(any) []string { return nil }
func (s *Server) noRequest(dir string) { startWorkloadAs(s.claudeEnvResolver(nil), newHarnessClearance(dir), "", dir) }
`)
	write("paths_test.go", `package ui
func (s *Server) inATest(dir string) { startWorkloadAs(nil, nil, "", dir) }
`)
	scan, err := scanEnvResolvers(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scan.violations, "\n")
	for _, want := range []string{
		"(*Server).forgot passes startWorkloadAs no environment resolver",
		"(*Server).chat passes runCloopSubcommandFor no environment resolver",
		"(*Server).resumeUnpinned acts for acct's starter",
		"(*Server).resumeOther acts for a's starter",
		"(*Server).resumeByVarUnpinned acts for acct's starter",
		"(*Server).accountUnchecked pins its run to acct's account",
		"(*Server).resumeByVarDecl acts for acct's starter",
		"(*Server).noRequest passes startWorkloadAs claudeEnvResolver(nil)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the gate did not report %q; it reported:\n%s", want, got)
		}
	}
	// The test-only wrapper is a listed caller, and a test file is no
	// production caller at all.
	if !scan.used["startWorkload → startWorkloadAs"] {
		t.Error("the listed test-only wrapper was not matched as a listed caller")
	}
	for _, clean := range []string{"(*Server).run ", "(*Server).resume ", "(*Server).resumeByVar ", "startWorkload passes", "inATest"} {
		if strings.Contains(got, clean) {
			t.Errorf("the gate flagged %s, which is fine:\n%s", strings.TrimSpace(clean), got)
		}
	}
	if scan.resumeCalls != 6 {
		t.Errorf("counted %d dispatches acting for a recorded starter, want 6", scan.resumeCalls)
	}
}

// envScan is what one pass over a package found.
type envScan struct {
	violations []string
	// calls counts the dispatch calls seen, and resumeCalls those acting for
	// a recorded starter, so a gate pointed at the wrong place fails.
	calls, resumeCalls int
	// used are the nilEnvCallers keys a call matched.
	used map[string]bool
}

// scanEnvResolvers walks the production files of the package in dir.
func scanEnvResolvers(dir string) (*envScan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	scan := &envScan{used: map[string]bool{}}
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
			scanEnvFunc(fset, fd, scan)
		}
	}
	return scan, nil
}

func scanEnvFunc(fset *token.FileSet, fd *ast.FuncDecl, scan *envScan) {
	name := harnessFuncName(fd)
	// resumeVars maps a variable assigned newResumeClearance(acct) in this
	// function to acct, so the rule below holds for `c := newResumeClearance(acct)`
	// as for the call written inline.
	resumeVars := map[string]string{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				if i >= len(x.Lhs) {
					break
				}
				if id, ok := x.Lhs[i].(*ast.Ident); ok {
					if acct, ok := resumeAccountOf(rhs); ok {
						resumeVars[id.Name] = acct
					}
				}
			}
		case *ast.ValueSpec:
			for i, v := range x.Values {
				if i < len(x.Names) {
					if acct, ok := resumeAccountOf(v); ok {
						resumeVars[x.Names[i].Name] = acct
					}
				}
			}
		}
		return true
	})
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || !isIdentCall(c) {
			return true
		}
		callee := calleeName(c)
		idx, takes := envArg[callee]
		if !takes {
			return true
		}
		scan.calls++
		where := fset.Position(c.Pos())
		if idx >= len(c.Args) {
			scan.violations = append(scan.violations, fmt.Sprintf("%s: %s calls %s with too few arguments for the "+
				"gate to find its environment resolver", where, name, callee))
			return true
		}
		env := c.Args[idx]
		key := name + " → " + callee
		if isNilIdent(env) {
			if _, ok := nilEnvCallers[key]; ok {
				scan.used[key] = true
				return true
			}
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s passes %s no environment resolver (nil). On a hub with single sign-on a run on an "+
					"executor that shares the hub's filesystem then inherits the hub's own Claude login — the shared "+
					"account no dispatch may fall back to. Pass s.claudeEnvResolver(r) for a dispatch a request "+
					"makes, the account's envFor for one acting for a run's recorded starter (resumeAccountFor), or "+
					"list the caller in nilEnvCallers with the reason it needs no account.", where, name, callee))
			return true
		}
		// A request's resolver resolves the request's caller: one built from
		// no request resolves nobody, and pins nothing.
		if ec, ok := env.(*ast.CallExpr); ok && calleeName(ec) == "claudeEnvResolver" &&
			len(ec.Args) == 1 && isNilIdent(ec.Args[0]) {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s passes %s claudeEnvResolver(nil), which resolves no caller and pins no account — the "+
					"nil this gate refuses, spelled another way.", where, name, callee))
			return true
		}
		// A dispatch acting for a run's recorded starter pins that account,
		// and a resume account pins only the dispatch whose clearance checks it.
		clearanceAcct, resumeClearance := "", false
		if ci, ok := clearanceArg[callee]; ok && ci < len(c.Args) {
			switch arg := c.Args[ci].(type) {
			case *ast.CallExpr:
				clearanceAcct, resumeClearance = resumeAccountOf(arg)
			case *ast.Ident:
				clearanceAcct, resumeClearance = resumeVars[arg.Name]
			}
		}
		envAcct, envIsAccount := "", false
		if sel, ok := env.(*ast.SelectorExpr); ok && sel.Sel.Name == "envFor" {
			if x, ok := sel.X.(*ast.Ident); ok {
				envAcct, envIsAccount = x.Name, true
			}
		}
		if resumeClearance {
			scan.resumeCalls++
		}
		switch {
		case resumeClearance && clearanceAcct == "":
			scan.violations = append(scan.violations, fmt.Sprintf("%s: %s builds its resume clearance from an "+
				"expression; assign the account to a variable and pass its envFor", where, name))
		case resumeClearance && (!envIsAccount || envAcct != clearanceAcct):
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s acts for %s's starter (newResumeClearance(%s)) but pins its run with another resolver. "+
					"Pass %s.envFor: the account the clearance checked is the one the run must be pinned to.",
				where, name, clearanceAcct, clearanceAcct, clearanceAcct))
		case !resumeClearance && envIsAccount:
			scan.violations = append(scan.violations, fmt.Sprintf(
				"%s: %s pins its run to %s's account (%s.envFor) under a clearance that does not check it. "+
					"Build the clearance with newResumeClearance(%s), whose settle refuses an account the dispatch "+
					"may not act for.", where, name, envAcct, envAcct, envAcct))
		}
		return true
	})
}

// resumeAccountOf reports whether e is newResumeClearance(acct), and acct's
// name — "" when the argument is not a plain identifier.
func resumeAccountOf(e ast.Expr) (string, bool) {
	c, ok := e.(*ast.CallExpr)
	if !ok || calleeName(c) != resumeClearanceConstructor || len(c.Args) != 1 {
		return "", false
	}
	if id, ok := c.Args[0].(*ast.Ident); ok {
		return id.Name, true
	}
	return "", true
}
