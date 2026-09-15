package arch_test

// This file gates a failure mode the compiler cannot see: a reconcile.Options
// field that one hub entry point passes and the other silently does not.
//
// The bug that prompted it happened during Task 20281. SweepInterval was added
// to Options, wired into pkg/apiserver, and *not* into pkg/ui — and everything
// stayed green. It built, it vetted, and every test passed, because the field's
// zero value is a legitimate "use the default". The only symptom was that
// `cloop ui` ignored executors.orphan_sweep_interval_minutes entirely: an
// operator who set 0 to disable the periodic sweep would have had it run
// anyway, and nothing would ever have told them.
//
// That is the general shape. reconcile.Options is a struct whose zero values
// are all deliberately the production default, which is the right design and
// also the reason a missing field is invisible. Two binaries construct it —
// `cloop ui` and `cloop serve` — and they are supposed to be the same control
// plane with different front doors. A field only one of them sets is a
// divergence between the two, not a configuration choice, and it will be
// discovered as "the setting does nothing on my deployment".
//
// The check is structural because the behavioural one does not exist: asserting
// "the UI hub honours this setting" would mean booting a hub with a cluster
// behind it. Comparing the two literals costs nothing and catches the whole
// class on the commit that introduces it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"
)

// bootstrapCallSites are the files that construct reconcile.Options for a
// long-running control plane, relative to the repository root.
//
// Deliberately only the two hubs. Short-lived CLI callers (cmd/root.go) set
// SkipPreflight and legitimately want a different, smaller set of fields —
// including them would make the gate fire on the one difference that is a real
// decision rather than an oversight.
var bootstrapCallSites = []string{
	"pkg/ui/executor.go",
	"pkg/apiserver/server.go",
}

// TestBootstrapOptions_BothHubsSetTheSameFields compares the reconcile.Options
// literals the two hubs build.
func TestBootstrapOptions_BothHubsSetTheSameFields(t *testing.T) {
	root := repoRoot(t)

	fields := map[string]map[string]bool{} // file -> field set
	for _, rel := range bootstrapCallSites {
		got := optionsFieldsIn(t, filepath.Join(root, rel))
		if len(got) == 0 {
			t.Fatalf("%s: found no reconcile.Options literal. If the call site moved, update "+
				"bootstrapCallSites in this file — do not delete the check.", rel)
		}
		fields[rel] = got
	}

	a, b := bootstrapCallSites[0], bootstrapCallSites[1]
	for _, missing := range diffFields(fields[a], fields[b]) {
		t.Errorf("%s sets reconcile.Options.%s and %s does not.\n"+
			"Both are the same control plane with different front doors, so a field only one of "+
			"them passes is a divergence rather than a choice: the setting works on one hub and "+
			"silently does nothing on the other. Set it in both, or — if the difference is "+
			"deliberate — record it in knownOptionsSkew with the consequence.", a, missing, b)
	}
	for _, missing := range diffFields(fields[b], fields[a]) {
		t.Errorf("%s sets reconcile.Options.%s and %s does not.\n"+
			"See above: set it in both, or record it in knownOptionsSkew.",
			b, missing, a)
	}
}

// knownOptionsSkew records fields that one hub sets and the other does not, so
// the gate can still catch *new* divergence.
//
// Deliberately not named "intentional": the first entry was not a decision, it
// was a gap this check found on the commit that introduced it, and calling it
// intentional would have buried a real finding under an allowlist. An entry
// here needs the consequence spelled out, not just a name, so a reader can tell
// the two apart.
var knownOptionsSkew = map[string]string{
	// Pre-existing, found by this gate rather than caused by it. pkg/ui routes
	// the Kubernetes driver's workspace fetches and write-back pushes through
	// the git interception proxy; pkg/apiserver does not, so a run dispatched
	// through `cloop serve` pushes straight to the upstream and the proxy's
	// branch allowlist (Task 20184) never sees it.
	//
	// Not fixed here because the fix is not a one-line addition: activeGitProxy
	// and its singleton live in pkg/ui, and sharing them means lifting the
	// service out into a package both hubs can import. That is its own change
	// with its own tests, not a rider on Task 20281.
	"WrapWorkspaceSource": "pkg/apiserver does not wire the git interception proxy — real gap, " +
		"needs gitProxyService lifted out of pkg/ui first",
}

// diffFields returns the fields in have that want lacks, minus the ones
// already recorded in knownOptionsSkew.
func diffFields(have, want map[string]bool) []string {
	var out []string
	for f := range have {
		if want[f] {
			continue
		}
		if _, ok := knownOptionsSkew[f]; ok {
			continue
		}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// optionsFieldsIn returns the field names set in every reconcile.Options
// composite literal in path.
//
// Parsed rather than grepped, because a field name inside a comment or a string
// would otherwise count — and this gate's whole value is that it does not
// produce noise that gets suppressed.
func optionsFieldsIn(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Options" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "reconcile" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				out[key.Name] = true
			}
		}
		return true
	})
	return out
}
