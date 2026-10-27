package security

// Guarantee: on a hub with single sign-on, the Copilot CLI never signs in with
// the hub's own credentials for a person — on a run, a dashboard model call or
// a resume (Task 20449).
//
// The CLI signs in with the first credential it finds: COPILOT_GITHUB_TOKEN,
// GH_TOKEN, GITHUB_TOKEN, the account `copilot login` stored under its home,
// then the GitHub CLI's. Anything that runs it with the hub's environment —
// which is what inheriting it means on the hub's own host — therefore runs it
// on the hub's sign-in, for whoever asked: the failure Tasks 20241, 20442 and
// 20443 closed for Claude. claudeidentity_test.go pins the Claude half; this
// file pins the Copilot one, the same three ways:
//
//   - structurally, every spawn of the copilot binary takes its environment
//     from the one builder that applies the per-person mode (copilotauth's
//     ChildEnv, through the provider's childEnv);
//   - by value, that mode strips every variable the CLI signs in with, or is
//     sent somewhere to sign in, but the run's own credential;
//   - by reachability, an HTTP handler that can run the Copilot CLI in the
//     hub's own process — not through an executor — pins the caller's
//     credential and home with inlineHarnessEnv, and the hub's background
//     reaches it nowhere. Dispatches go through the executor and are pinned by
//     their clearance, which tests/arch/copilotenv_test.go holds every lease
//     to.

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/copilotauth"
)

// copilotSpawnPackage is the package allowed to exec the copilot binary.
const copilotSpawnPackage = "pkg/provider/copilot"

// copilotSpawn is the function that execs it, and copilotPin what a handler
// running it in the hub's process pins its caller with.
const (
	copilotSpawn = "(*github.com/blechschmidt/cloop/pkg/provider/copilot.Provider).run"
	copilotPin   = "(*github.com/blechschmidt/cloop/pkg/ui.Server).inlineHarnessEnv"
)

// copilotInlineCallers are the HTTP handlers that can run the Copilot CLI in
// the hub's own process, each with why it does. Every one of them must pin its
// caller with inlineHarnessEnv. TestHandlersRunningTheCopilotCLIPinTheirCaller
// rejects an entry that no longer reaches it, and one that is not listed.
var copilotInlineCallers = map[string]string{
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleProviderCallReplay": "re-runs a recorded call in the " +
		"hub's process to compare answers (gatedHostExecution); a recorded copilot call runs the CLI there",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleReplayRunCreate": "replays a task inline against a " +
		"target and a judge provider (gatedHostExecution); either may be copilot",
}

// TestEveryCopilotSpawnPinsItsEnvironment walks every function that execs the
// copilot binary and requires its Env to come from childEnv, which is the
// provider's one door to copilotauth.ChildEnv.
func TestEveryCopilotSpawnPinsItsEnvironment(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files, err := parseNonTestGoFiles(fset, filepath.Join(root, copilotSpawnPackage))
	if err != nil {
		t.Fatal(err)
	}
	checked := map[string]bool{}
	childEnvPins := false
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			if fn.Name.Name == "childEnv" && fn.Recv == nil {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if e, ok := n.(ast.Expr); ok && callsIdent(e, "ChildEnv") {
						childEnvPins = true
					}
					return !childEnvPins
				})
			}
			if !spawnsCopilot(fn) {
				return true
			}
			checked[fn.Name.Name] = true
			if !envFromChildEnv(fn) {
				t.Errorf("%s: %s execs the copilot binary but does not set Env from childEnv. On a hub with "+
					"single sign-on the CLI would then sign in with whatever the hub's environment holds, for "+
					"whichever person the run acts for.", fset.Position(fn.Pos()), fn.Name.Name)
			}
			return true
		})
	}
	if !checked["run"] {
		t.Error("run is no longer recognised as a copilot spawn site; the scan has gone stale and is not protecting it")
	}
	if !childEnvPins {
		t.Error("childEnv no longer builds the CLI's environment with copilotauth.ChildEnv, which is what " +
			"applies the per-person mode")
	}
}

// spawnsCopilot reports whether fn resolves the copilot binary and execs
// something — coarse on purpose, as spawnsClaude is.
func spawnsCopilot(fn *ast.FuncDecl) bool {
	resolves, execs := false, false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "FindBinary" {
			resolves = true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "exec" &&
				(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
				execs = true
			}
		}
		return true
	})
	return resolves && execs
}

// envFromChildEnv reports whether fn assigns an .Env field from childEnv,
// directly or through a variable it assigned from childEnv.
func envFromChildEnv(fn *ast.FuncDecl) bool {
	fromChildEnv := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || !callsIdent(assign.Rhs[0], "childEnv") {
			return true
		}
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				fromChildEnv[id.Name] = true
			}
		}
		return true
	})
	scoped := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Env" || i >= len(assign.Rhs) && len(assign.Rhs) != 1 {
				continue
			}
			rhs := assign.Rhs[0]
			if i < len(assign.Rhs) {
				rhs = assign.Rhs[i]
			}
			if id, ok := rhs.(*ast.Ident); ok && fromChildEnv[id.Name] {
				scoped = true
			}
			if callsIdent(rhs, "childEnv") {
				scoped = true
			}
		}
		return true
	})
	return scoped
}

// TestCopilotPinningStripsWhatTheCLISignsInWith pins the values: every way the
// CLI is known to take a credential, or to be pointed somewhere to present one,
// is stripped in the per-person mode, and only the run's own credential passes.
func TestCopilotPinningStripsWhatTheCLISignsInWith(t *testing.T) {
	hub := []string{
		"COPILOT_GITHUB_TOKEN=hub", "GH_TOKEN=hub", "GITHUB_TOKEN=hub", "GH_ENTERPRISE_TOKEN=hub",
		"GITHUB_ENTERPRISE_TOKEN=hub", "GITHUB_COPILOT_GITHUB_TOKEN=hub", "GITHUB_COPILOT_AGENT_GITHUB_TOKEN=hub",
		"GH_HOST=hub.example", "COPILOT_GH_HOST=hub.example", "COPILOT_API_URL=https://hub.example",
		"COPILOT_PROVIDER_API_KEY_COMMAND=hub", "COPILOT_PROVIDER_GHES_HOST=hub.example",
		"COPILOT_HOME=/hub/.copilot", "GH_CONFIG_DIR=/hub/.config/gh",
	}
	run := append(append(append([]string{}, hub...), copilotauth.HubBlanks(hub)...),
		"COPILOT_GITHUB_TOKEN=person", copilotauth.Pin("/homes/person/copilot"))
	env, pinned := copilotauth.ChildEnv(nil, run, nil)
	if !pinned {
		t.Fatal("a run naming its person's home was not pinned")
	}
	for _, kv := range env {
		if strings.Contains(kv, "hub") {
			t.Errorf("the pinned CLI's environment carries %q", kv)
		}
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["COPILOT_GITHUB_TOKEN"] != "person" || got["COPILOT_HOME"] != "/homes/person/copilot" ||
		got["GH_CONFIG_DIR"] != "/homes/person/copilot/gh" {
		t.Errorf("the pinned CLI got token %q, home %q, gh config %q — want the person's own",
			got["COPILOT_GITHUB_TOKEN"], got["COPILOT_HOME"], got["GH_CONFIG_DIR"])
	}
	for _, k := range []string{"COPILOT_PROVIDER_API_KEY_COMMAND", "COPILOT_API_URL", "COPILOT_GH_HOST",
		"COPILOT_PROVIDER_GHES_HOST", "GH_TOKEN", "GITHUB_TOKEN"} {
		if contains(copilotauth.CredentialVars, k) {
			t.Errorf("%s is a CredentialVar, so a pinned run passes it on: it runs a command, names a host "+
				"or is a token the CLI would sign in with in the person's place", k)
		}
	}
}

// The core reachability guarantee.
func TestHandlersRunningTheCopilotCLIPinTheirCaller(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("build reference graph: %v", err)
	}
	if _, ok := g.nodes[copilotSpawn]; !ok {
		t.Fatalf("%s is not in the graph — the copilot provider moved, and this check would pass vacuously", copilotSpawn)
	}
	if _, ok := g.nodes[copilotPin]; !ok {
		t.Fatalf("%s is not in the graph — the inline pin moved", copilotPin)
	}
	violations, seen := copilotInlineViolations(g, copilotInlineCallers)
	for _, v := range violations {
		t.Error(v)
	}
	var stale []string
	for key := range copilotInlineCallers {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("%s is listed in copilotInlineCallers but no longer reaches the Copilot CLI in the hub's "+
			"process — remove the entry", key)
	}
	if len(seen) == 0 {
		t.Fatal("no handler reaches the Copilot CLI in the hub's process: the graph lost the provider.Provider " +
			"edges, and the check would pass anything")
	}
	for _, root := range BackgroundRoots {
		if path, ok := g.BackgroundReachesWithin(root, copilotSpawn); ok {
			t.Errorf("the hub's background runs the Copilot CLI in its own process, acting for nobody:\n    %s",
				strings.Join(path, "\n    "))
		}
	}
}

// copilotInlineViolations reports every handler that reaches the copilot spawn
// outside the executor boundary and is not a listed caller that pins its
// caller, and the handlers that reach it at all.
func copilotInlineViolations(g *Graph, allowed map[string]string) (violations []string, seen map[string]bool) {
	seen = map[string]bool{}
	for _, h := range g.HandlerKeys() {
		path, ok := g.ReachesWithin(h, copilotSpawn)
		if !ok {
			continue
		}
		seen[h] = true
		chain := strings.Join(path, "\n    ")
		if _, listed := allowed[h]; !listed {
			violations = append(violations, "handler "+h+" can run the Copilot CLI in the hub's own process:\n    "+
				chain+"\nDispatch it through the project's executor instead (runCloopSubcommandFor with "+
				"s.harnessClearanceFor(r, dir)), whose clearance pins the caller's Copilot account; or, if it must "+
				"run in the hub, take its environment from inlineHarnessEnv and list it in copilotInlineCallers.")
			continue
		}
		if !g.References(h, copilotPin) {
			violations = append(violations, "handler "+h+" runs the Copilot CLI in the hub's own process without "+
				"inlineHarnessEnv:\n    "+chain+"\nOn a hub with single sign-on it would sign in with the hub's "+
				"own credentials for whoever asked.")
		}
	}
	return violations, seen
}

// The check must flag what it exists for, and only that.
func TestCopilotInlineCheckFlagsWhatItShould(t *testing.T) {
	g := &Graph{nodes: map[string]*node{}, handlers: map[string]string{}}
	add := func(key, pkg string, callees ...string) {
		n := &node{key: key, pkgPath: pkg, callees: map[string]bool{}}
		for _, c := range callees {
			n.callees[c] = true
		}
		g.nodes[key] = n
	}
	const (
		ui      = ModulePath + "/pkg/ui"
		helper  = "(*" + ModulePath + "/pkg/ui.Server).helper"
		driver  = "(*" + ModulePath + "/pkg/executor/local.Driver).Start"
		pinned  = "(*" + ModulePath + "/pkg/ui.Server).pinned"
		forgot  = "(*" + ModulePath + "/pkg/ui.Server).forgot"
		stray   = "(*" + ModulePath + "/pkg/ui.Server).stray"
		through = "(*" + ModulePath + "/pkg/ui.Server).dispatches"
	)
	add(copilotSpawn, ModulePath+"/pkg/provider/copilot")
	add(copilotPin, ui)
	add(helper, ui, copilotSpawn)
	add(driver, ModulePath+"/pkg/executor/local", copilotSpawn)
	add(pinned, ui, copilotPin, helper)
	add(forgot, ui, helper)
	add(stray, ui, helper, copilotPin)
	add(through, ui, driver)
	for _, h := range []string{pinned, forgot, stray, through} {
		g.handlers[h] = h
	}
	violations, seen := copilotInlineViolations(g, map[string]string{pinned: "", forgot: ""})
	got := strings.Join(violations, "\n")
	if !strings.Contains(got, "handler "+forgot+" runs the Copilot CLI in the hub's own process without") {
		t.Errorf("a listed handler with no pin was not flagged:\n%s", got)
	}
	if !strings.Contains(got, "handler "+stray+" can run the Copilot CLI") {
		t.Errorf("an unlisted handler was not flagged:\n%s", got)
	}
	if strings.Contains(got, pinned+" ") || strings.Contains(got, through) {
		t.Errorf("flagged a handler that pins, or one that dispatches through an executor:\n%s", got)
	}
	if seen[through] || !seen[pinned] {
		t.Errorf("reach: %v — a dispatch through an executor driver does not run the CLI in the hub's process", seen)
	}
}
