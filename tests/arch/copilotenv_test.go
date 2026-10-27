package arch_test

// Every dispatch pins the Copilot CLI to whom it acts for (Task 20449).
//
// claudeenv_test.go keeps every dispatch on a Claude account: a resolver that
// is never nil without a reason, and a resume pinned to the account its
// clearance checked. The Copilot CLI's account is pinned by the clearance
// itself — on a hub with single sign-on a copilot dispatch to the hub's own
// host settles a credential that counts for its person, and copilotEnv hands
// the primitive the hub's own Copilot and GitHub credentials blanked, for
// before the lease, and the pin naming the person's Copilot home, for after it.
// A nil, a forgotten call or one in the wrong place compiles and passes every
// test that does not read the child's environment, exactly as the Claude nil
// did. So:
//
//   - a function that leases — acquireSecretLease — or dispatches a workload
//     raw takes the clearance's Copilot environment after it settles the
//     clearance and before it leases, puts the blanks into the environment
//     before the lease too, and uses the pin after the lease and after every
//     step that shapes the spec — a sandbox's env allowlist would otherwise
//     drop it — so the lease's grants come between the hub's blanked Copilot
//     variables and the person's home; or is listed in copilotPinExempt with
//     the reason it can never dispatch to the hub's own host;
//   - a dispatch under a lease clearance — which checks nothing and pins no
//     Copilot account, being for workloads that call no model — comes only
//     from a caller listed in leaseClearanceCallers, with the reason its
//     workload calls no model. A new path that runs a harness under one fails
//     here rather than running the Copilot CLI on the hub's own sign-in.

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

// copilotPinExempt may lease without the clearance's Copilot environment,
// each with the reason. TestCopilotPinExemptionsAreStillUsed rejects an entry
// no function matches.
var copilotPinExempt = map[string]string{
	"(*reproduceRunner).run": "a reproduction runs only on an isolating executor (resolveIsolatingExecutor) — never " +
		"on the hub's own host, the one place a Copilot run is pinned to its person",
}

// specShapers are the dispatch steps that rewrite a spec's environment, or
// could: the pin goes after every one of them a function calls.
var specShapers = map[string]bool{
	"applyLease": true, "applyRepoGrants": true, "applyDeviceGrants": true, "applyInterfaceGrants": true,
	"applySandbox": true, "applyFirewall": true, "applyForwardedDevices": true, "applyEgressSession": true,
	"applyWorkspace": true, "applyWorkspaceFor": true, "applyGitProxyTrust": true, "applyModelRelay": true,
	"labelHubCATrust": true, "applyResourceCeiling": true,
}

// leaseClearanceConstructors build a clearance for a workload that runs no
// harness.
var leaseClearanceConstructors = map[string]bool{"leaseClearanceFor": true, "newLeaseClearance": true}

// leaseClearanceCallers may dispatch under a lease clearance, keyed
// "caller → primitive", each with the reason its workload calls no model.
// TestLeaseClearanceCallersAreStillUsed rejects an entry no call matches.
var leaseClearanceCallers = map[string]string{
	"(*Server).openFeaturePR → runCloopSubcommandFor": "`cloop feature pr` opens a pull request on GitHub; it " +
		"calls no model",
	"(*Server).handleProjectFeaturePRRefresh → runCloopSubcommandFor": "`cloop feature pr-status` reads a pull " +
		"request's state from GitHub; it calls no model",
	"(*Server).dispatchFeatureCommand → runCloopSubcommandFor": "a `cloop feature` subcommand is git and GitHub; " +
		"it calls no model",
	"(*Server).handleVoice → runCloopSubcommandFor": "`cloop listen` transcribes a recording with the " +
		"speech-to-text service, not the project's model",
	"(*Server).handleReset → runCloopSubcommandFor":  "`cloop reset` calls no model",
	"(*Server).handleProjectNew → runWorkloadEnvFor": "`cloop init --skip-clarify` calls no model",
}

func TestEveryLeaseTakesTheCopilotPin(t *testing.T) {
	scan, err := scanCopilotPins(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v)
	}
	if scan.leasers < 3 {
		t.Fatalf("the gate found %d functions that lease in pkg/ui, want the two dispatch primitives and the "+
			"inline model calls' helper at least — it is looking in the wrong place, and would pass anything",
			scan.leasers)
	}
	if scan.leaseDispatches == 0 {
		t.Fatal("no dispatch under a lease clearance found — the gate would pass anything")
	}
}

func TestCopilotPinExemptionsAreStillUsed(t *testing.T) {
	scan, err := scanCopilotPins(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for key := range copilotPinExempt {
		if !scan.used[key] {
			t.Errorf("%q is exempt from the Copilot pin but no longer leases — remove it from copilotPinExempt", key)
		}
	}
}

func TestLeaseClearanceCallersAreStillUsed(t *testing.T) {
	scan, err := scanCopilotPins(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for key := range leaseClearanceCallers {
		if !scan.used[key] {
			t.Errorf("%q may dispatch under a lease clearance but no longer matches a call — remove it from "+
				"leaseClearanceCallers", key)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestCopilotGateFlagsWhatItShould(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("prims.go", `package ui
type harnessClearance struct{}
func (c *harnessClearance) settle(ex any, dir string) (map[string]string, error) { return nil, nil }
func (c *harnessClearance) copilotEnv(ex any) ([]string, []string) { return nil, nil }
func newHarnessClearance(string) *harnessClearance { return nil }
func newLeaseClearance(string) *harnessClearance { return nil }
func acquireSecretLease(string) {}
func pinCopilotHome(spec, pin []string) []string { return spec }
func runCloopSubcommandFor(a, b, c, d, env any, cl *harnessClearance) {}
func applySandbox(spec []string) []string { return spec }
func good(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	blanks, pin := c.copilotEnv(nil)
	_ = blanks
	acquireSecretLease(dir)
	spec := applySandbox(nil)
	_ = pinCopilotHome(spec, pin)
}
func forgot(c *harnessClearance, dir string) { c.settle(nil, dir); acquireSecretLease(dir) }
func late(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	acquireSecretLease(dir)
	blanks, pin := c.copilotEnv(nil)
	_, _ = blanks, pin
}
func early(c *harnessClearance, dir string) {
	blanks, pin := c.copilotEnv(nil)
	_ = blanks
	c.settle(nil, dir)
	acquireSecretLease(dir)
	_ = pin
}
func pinFirst(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	blanks, pin := c.copilotEnv(nil)
	_ = blanks
	_ = pinCopilotHome(nil, pin)
	acquireSecretLease(dir)
}
func dropped(c *harnessClearance, dir string) { c.settle(nil, dir); c.copilotEnv(nil); acquireSecretLease(dir) }
func noBlanks(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	_, pin := c.copilotEnv(nil)
	acquireSecretLease(dir)
	_ = pinCopilotHome(nil, pin)
}
func blanksLate(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	blanks, pin := c.copilotEnv(nil)
	acquireSecretLease(dir)
	_ = blanks
	_ = pinCopilotHome(nil, pin)
}
func beforeSandbox(c *harnessClearance, dir string) {
	c.settle(nil, dir)
	blanks, pin := c.copilotEnv(nil)
	_ = blanks
	acquireSecretLease(dir)
	spec := pinCopilotHome(nil, pin)
	_ = applySandbox(spec)
}
type ex struct{}
func (ex) Start(a, b any) {}
func rawForgot(c *harnessClearance, dir string) { c.settle(nil, dir); ex{}.Start(nil, nil) }
`)
	write("paths.go", `package ui
type Server struct{}
func (s *Server) handleReset(dir string) { runCloopSubcommandFor(nil, nil, nil, nil, nil, newLeaseClearance(dir)) }
func (s *Server) sneaky(dir string) { runCloopSubcommandFor(nil, nil, nil, nil, nil, newLeaseClearance(dir)) }
func (s *Server) sneakyVar(dir string) { c := newLeaseClearance(dir); runCloopSubcommandFor(nil, nil, nil, nil, nil, c) }
func (s *Server) either(dir string, h bool) {
	c := newLeaseClearance(dir)
	if h {
		c = newHarnessClearance(dir)
	}
	runCloopSubcommandFor(nil, nil, nil, nil, nil, c)
}
func (s *Server) harness(dir string) { runCloopSubcommandFor(nil, nil, nil, nil, nil, newHarnessClearance(dir)) }
`)
	write("paths_test.go", `package ui
func inATest(c *harnessClearance, dir string) { acquireSecretLease(dir) }
`)
	scan, err := scanCopilotPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scan.violations, "\n")
	for _, want := range []string{
		"forgot leases or dispatches without the clearance's Copilot environment",
		"late takes the clearance's Copilot environment after it leases",
		"early takes the clearance's Copilot environment before it settles",
		"pinFirst uses the Copilot pin before it leases",
		"dropped leases or dispatches without the clearance's Copilot environment",
		"noBlanks leases or dispatches without the clearance's Copilot environment",
		"blanksLate never puts the Copilot blanks into the environment before it leases",
		"beforeSandbox uses the Copilot pin before it leases or before a step that shapes the spec",
		"rawForgot leases or dispatches without the clearance's Copilot environment",
		"(*Server).sneaky dispatches under a lease clearance",
		"(*Server).sneakyVar dispatches under a lease clearance",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the gate did not report %q; it reported:\n%s", want, got)
		}
	}
	for _, clean := range []string{"good ", "(*Server).handleReset", "(*Server).either", "(*Server).harness", "inATest"} {
		if strings.Contains(got, clean) {
			t.Errorf("the gate flagged %s, which is fine:\n%s", strings.TrimSpace(clean), got)
		}
	}
	if !scan.used["(*Server).handleReset → runCloopSubcommandFor"] {
		t.Error("the listed lease-clearance caller was not matched")
	}
}

// copilotScan is what one pass over a package found.
type copilotScan struct {
	violations []string
	// leasers counts the functions that lease, and leaseDispatches the
	// dispatches under a lease clearance, so a gate pointed at the wrong
	// place fails.
	leasers, leaseDispatches int
	used                     map[string]bool
}

func scanCopilotPins(dir string) (*copilotScan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	scan := &copilotScan{used: map[string]bool{}}
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
			scanCopilotLease(fset, fd, scan)
			scanLeaseClearances(fset, fd, scan)
		}
	}
	return scan, nil
}

// scanCopilotLease holds a function that leases or dispatches raw to the
// order settle → copilotEnv → blanks → acquireSecretLease → every spec shaper →
// the pin.
func scanCopilotLease(fset *token.FileSet, fd *ast.FuncDecl, scan *copilotScan) {
	if fd.Name.Name == "acquireSecretLease" && fd.Recv == nil {
		return
	}
	name := harnessFuncName(fd)
	var settle, env, lease, merge, raw, lastShaper token.Pos
	blanksVar, pinVar := "", ""
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && len(x.Lhs) == 2 {
				if c, ok := x.Rhs[0].(*ast.CallExpr); ok && calleeName(c) == "copilotEnv" {
					if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
						blanksVar = id.Name
					}
					if id, ok := x.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
						pinVar = id.Name
					}
				}
			}
		case *ast.CallExpr:
			callee := calleeName(x)
			switch {
			case callee == "settle":
				if settle == token.NoPos {
					settle = x.Pos()
				}
			case callee == "copilotEnv":
				if env == token.NoPos {
					env = x.Pos()
				}
			case callee == "acquireSecretLease":
				if lease == token.NoPos {
					lease = x.Pos()
				}
			case specShapers[callee]:
				if x.Pos() > lastShaper {
					lastShaper = x.Pos()
				}
				if callee == "applyLease" && merge == token.NoPos {
					merge = x.Pos()
				}
			}
			if isRawDispatch(x) && raw == token.NoPos {
				raw = x.Pos()
			}
		}
		return true
	})
	if lease == token.NoPos && raw == token.NoPos {
		return
	}
	scan.leasers++
	if _, ok := copilotPinExempt[name]; ok {
		scan.used[name] = true
		return
	}
	at := lease
	if at == token.NoPos {
		at = raw
	}
	where := fset.Position(at)
	// Where the lease's material joins the environment: applyLease, or the
	// lease itself in a function that takes its environment by hand.
	if merge == token.NoPos {
		merge = lease
	}
	switch {
	case env == token.NoPos || pinVar == "" || blanksVar == "":
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s leases or dispatches without the clearance's Copilot environment. On a hub with single sign-on a Copilot "+
				"CLI on the hub's own host would then inherit the hub's Copilot sign-in: take blanks, pin := "+
				"clear.copilotEnv(ex) after settling the clearance, put the blanks into the environment before the "+
				"lease and the pin after everything else (pinCopilotHome) — or list the function in "+
				"copilotPinExempt with the reason it never dispatches to the hub's own host.", where, name))
		return
	case settle == token.NoPos || env < settle:
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s takes the clearance's Copilot environment before it settles the clearance, which is what "+
				"decides it.", where, name))
	case lease != token.NoPos && env > lease:
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s takes the clearance's Copilot environment after it leases: the blanks must come before "+
				"the lease's grants, or they blank the person's credential.", where, name))
	}
	// The blanks are used before the lease; the pin only after the lease and
	// after every step that shapes the spec. A mention at env's own
	// assignment is not a use.
	blanksUsed, pinUsed := false, false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || id.Pos() <= env {
			return true
		}
		switch id.Name {
		case blanksVar:
			if merge == token.NoPos || id.Pos() < merge {
				blanksUsed = true
			}
		case pinVar:
			pinUsed = true
			if (lease != token.NoPos && id.Pos() < lease) || id.Pos() < lastShaper {
				scan.violations = append(scan.violations, fmt.Sprintf(
					"%s: %s uses the Copilot pin before it leases or before a step that shapes the spec: a grant "+
						"delivered after the pin could point the run at another person's home, and a sandbox's env "+
						"allowlist could drop it.", fset.Position(id.Pos()), name))
			}
		}
		return true
	})
	if !blanksUsed {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s never puts the Copilot blanks into the environment before it leases: without them a run with "+
				"no Copilot credential of its own keeps the hub's.", where, name))
	}
	if !pinUsed {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s never uses the Copilot pin: a Copilot CLI the workload starts would not be pinned to its "+
				"person.", where, name))
	}
}

// scanLeaseClearances finds dispatches made under a lease clearance.
func scanLeaseClearances(fset *token.FileSet, fd *ast.FuncDecl, scan *copilotScan) {
	name := harnessFuncName(fd)
	// For each variable, whether every constructor assigned to it builds a
	// lease clearance: one also assigned a harness clearance may run a harness
	// and is checked as one.
	onlyLease := map[string]bool{}
	note := func(id *ast.Ident, rhs ast.Expr) {
		c, ok := rhs.(*ast.CallExpr)
		if !ok || id.Name == "_" {
			return
		}
		callee := calleeName(c)
		switch {
		case leaseClearanceConstructors[callee]:
			if _, seen := onlyLease[id.Name]; !seen {
				onlyLease[id.Name] = true
			}
		case preflightConstructors[callee]:
			onlyLease[id.Name] = false
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				if i < len(x.Lhs) {
					if id, ok := x.Lhs[i].(*ast.Ident); ok {
						note(id, rhs)
					}
				}
			}
		case *ast.ValueSpec:
			for i, v := range x.Values {
				if i < len(x.Names) {
					note(x.Names[i], v)
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
		idx, takes := clearanceArg[callee]
		if !takes || idx >= len(c.Args) {
			return true
		}
		lease := false
		switch arg := c.Args[idx].(type) {
		case *ast.CallExpr:
			lease = leaseClearanceConstructors[calleeName(arg)]
		case *ast.Ident:
			lease = onlyLease[arg.Name]
		}
		if !lease {
			return true
		}
		scan.leaseDispatches++
		key := name + " → " + callee
		if _, ok := leaseClearanceCallers[key]; ok {
			scan.used[key] = true
			return true
		}
		scan.violations = append(scan.violations, fmt.Sprintf(
			"%s: %s dispatches under a lease clearance, which checks no harness credential and pins no Copilot "+
				"account: a copilot workload sent this way would sign in with the hub's own. Build the clearance "+
				"with harnessClearanceFor(r, dir), or list the caller in leaseClearanceCallers with the reason its "+
				"workload calls no model.", fset.Position(c.Pos()), name))
		return true
	})
}
