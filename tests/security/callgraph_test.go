package security

// Guarantee 1: no HTTP handler in the control plane can spawn a process
// except through the pkg/executor boundary.
//
// This is the load-bearing guarantee of the whole remote-executor design. If
// an HTTP handler can call exec.Command, then "where does agent code run" is
// decided by whichever handler happens to be on the stack, not by the
// project's executor binding — and a deployment that promises isolated
// sandboxes silently runs the harness as the control plane, with the control
// plane's filesystem, network, and credentials.
//
// The check is transitive because the violations are. pkg/ui's own
// no_direct_exec_test.go already forbids importing os/exec *in that package*,
// which is necessary and not sufficient: a handler that calls a helper in
// pkg/somethingelse that shells out to git is exactly as much host execution,
// and passes a per-package import check without complaint. Only whole-module
// reachability analysis sees it.

import (
	"sort"
	"strings"
	"testing"
)

// gatedHostExecution enumerates the handlers that legitimately cause a program
// to run on the control-plane host, with the reason each cannot go through an
// executor.
//
// These are not suppressions. Each one is gated on
// executor.HostExecutionAllowed() and refuses with a typed
// *HostExecutionDeniedError under strict mode —
// TestGatedHandlersRefuseUnderStrictMode proves it. The static check and the
// behavioral check together say: this list is the complete set of host
// execution reachable from HTTP, and every member of it is switched off by
// the same policy flag.
//
// Keys are (*types.Func).FullName() values.
var gatedHostExecution = map[string]string{
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthStatus": "runs `claude` to read login state; credentials live in the control " +
		"plane's own home directory, so this cannot be delegated to a sandbox",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLoginStart": "runs `claude auth login`, which writes credentials into the control " +
		"plane's home directory",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLoginCode": "completes `claude auth login` for the control plane's own identity",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClaudeCodeAuthLogout":    "runs `claude auth logout` against the control plane's credentials",
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleReplayRunCreate": "replays a task inline, and context collection shells out to git in the " +
		"project directory; migrating this to a dispatched workload is tracked work",
}

// minExpectedHandlers guards against the analysis silently finding nothing.
// If a refactor renames Server methods or changes the handler signature, the
// count collapses and this test must fail loudly rather than pass vacuously —
// a security check that stops checking is worse than no check, because it
// still reads as green.
const minExpectedHandlers = 80

func TestNoHandlerReachesProcessExecution(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("build reference graph: %v", err)
	}

	if n := g.HandlerCount(); n < minExpectedHandlers {
		t.Fatalf("only %d HTTP handlers discovered, expected at least %d — "+
			"the analysis is no longer finding the control plane's handlers "+
			"and would pass vacuously. Check isHTTPHandler and AuditedRoots.",
			n, minExpectedHandlers)
	}

	violations := g.FindSpawnReachable()

	// Report anything not on the enumerated list. This is the assertion that
	// actually protects the architecture: a new handler that shells out, or
	// an existing one that grows a path to a helper that does, fails here
	// with the exact chain to fix.
	seen := map[string]bool{}
	for _, v := range violations {
		key := handlerKey(v.Handler)
		seen[key] = true
		if _, allowed := gatedHostExecution[key]; allowed {
			continue
		}
		t.Errorf("host execution reachable from an HTTP handler:\n%s\n"+
			"Route this through executor.Resolve(projectPath).Start(...) — see "+
			"pkg/ui/executor.go (startWorkload/runWorkload) or "+
			"pkg/apiserver.startRun. If the program genuinely must run on the "+
			"control plane itself, gate it with denyHostSideEffect and add it to "+
			"gatedHostExecution in tests/security/callgraph_test.go with a reason.",
			v)
	}

	// Stale entries are their own failure. Without this the list only ever
	// grows: someone fixes a handler, the exemption stays, and the next
	// regression at that spot is silently pre-approved.
	var stale []string
	for key := range gatedHostExecution {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("gatedHostExecution lists %s, but it no longer reaches process "+
			"execution. Remove the entry — the exemption list must only shrink.", key)
	}
}

// handlerKey strips the trailing " (pkgpath)" that Violation.Handler carries
// for readability, leaving the stable FullName used as a map key.
func handlerKey(display string) string {
	if i := strings.LastIndex(display, " ("); i > 0 {
		return display[:i]
	}
	return display
}

// TestAnalysisDetectsASeededViolation is the meta-test. The reachability
// analysis is itself code, and a subtly broken version of it (wrong node kind,
// edges never recorded, boundary check inverted) would report zero violations
// forever. Seeding a synthetic edge into a loaded graph and confirming it is
// found proves the traversal actually traverses.
func TestAnalysisDetectsASeededViolation(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("build reference graph: %v", err)
	}
	before := len(g.FindSpawnReachable())

	// Pick a real handler that is currently clean, and give it a two-hop path
	// to a spawning function through a package outside the executor boundary.
	victim := g.cleanHandlerKey(t)
	const midKey = "github.com/blechschmidt/cloop/pkg/seeded.helper"
	g.nodes[midKey] = &node{
		key:     midKey,
		pkgPath: "github.com/blechschmidt/cloop/pkg/seeded",
		callees: map[string]bool{},
		spawns:  "os/exec.Command",
	}
	g.nodes[victim].callees[midKey] = true

	after := g.FindSpawnReachable()
	if len(after) != before+1 {
		t.Fatalf("seeded a reachable exec.Command from %s but violations went "+
			"from %d to %d; the traversal is not following edges",
			victim, before, len(after))
	}
	// The reported path must actually name the intermediate hop, or the
	// failure output would not lead a reader to the fix.
	var found bool
	for _, v := range after {
		if handlerKey(v.Handler) == victim {
			found = true
			if len(v.Path) < 2 || v.Path[len(v.Path)-1] != midKey {
				t.Errorf("path does not end at the seeded helper: %v", v.Path)
			}
			if v.Spawn != "os/exec.Command" {
				t.Errorf("Spawn = %q, want os/exec.Command", v.Spawn)
			}
		}
	}
	if !found {
		t.Errorf("seeded violation for %s was not reported", victim)
	}
}

// TestExecutorBoundaryIsNotTraversed proves the carve-out is a boundary and
// not a blanket exemption: a spawn *inside* pkg/executor is reachable in
// principle but deliberately not reported, while the same spawn one package
// outside it is.
func TestExecutorBoundaryIsNotTraversed(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("build reference graph: %v", err)
	}
	victim := g.cleanHandlerKey(t)

	for _, tc := range []struct {
		name      string
		pkgPath   string
		wantFound bool
	}{
		{"inside the boundary", ExecutorBoundary + "/localprocess", false},
		{"a package that merely looks like it", ExecutorBoundary + "ish", true},
		{"outside the boundary", ModulePath + "/pkg/elsewhere", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.pkgPath + ".spawner"
			g.nodes[key] = &node{
				key: key, pkgPath: tc.pkgPath,
				callees: map[string]bool{}, spawns: "os/exec.Command",
			}
			g.nodes[victim].callees[key] = true
			defer func() {
				delete(g.nodes, key)
				delete(g.nodes[victim].callees, key)
			}()

			var got bool
			for _, v := range g.FindSpawnReachable() {
				if handlerKey(v.Handler) == victim {
					got = true
				}
			}
			if got != tc.wantFound {
				t.Errorf("violation reported = %v, want %v for a spawn in %s",
					got, tc.wantFound, tc.pkgPath)
			}
		})
	}
}

// cleanHandlerKey returns a handler that currently reaches no spawn, for use
// as a seed point in the meta-tests.
func (g *Graph) cleanHandlerKey(t *testing.T) string {
	t.Helper()
	dirty := map[string]bool{}
	for _, v := range g.FindSpawnReachable() {
		dirty[handlerKey(v.Handler)] = true
	}
	keys := make([]string, 0, len(g.handlers))
	for k := range g.handlers {
		if !dirty[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		t.Fatal("no clean handler available to seed a synthetic violation")
	}
	sort.Strings(keys)
	return keys[0]
}
