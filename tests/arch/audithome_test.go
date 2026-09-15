package arch_test

// Structural gate on where each audit action is recorded (Task 20292).
//
// auditaction_test.go proves every emitted action *name* is registered. This
// file proves every registered action says which of the two `audit_events`
// chains it belongs in — the hub's control-plane state.db, or a project's
// .cloop/state.db.
//
// The declaration matters because nothing else can supply it. The home is
// decided at runtime by which *statedb.DB handle an emission site happens to
// hold, which is a fact about a call stack: it is not in the row, so a reader
// of the trail cannot recover it, and a mis-routed row is indistinguishable
// from a correct one. Both chains stay internally consistent either way, so
// `cloop audit-log verify` passes on a trail with events in the wrong database
// — the check meant to catch tampering is structurally blind to this.
//
// With a home declared per action, pkg/statedb can assert that a classified
// handle only writes its own events, and `cloop hub audit` can read both chains
// and say which is which. Both depend on the declaration being present, which
// is what this file checks.
//
// It is a registry check rather than an AST walk on purpose. The emission-site
// direction is covered at runtime, where the handle actually exists — see
// pkg/statedb/audit_home_test.go — and a static approximation of "which
// database does this call stack end up in" would be the kind of gate that is
// confidently wrong.

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// TestEveryActionDeclaresAHome is the gate.
//
// An entry with no home is not a documentation gap: auditaction.HomeOf returns
// the zero value for it, the emit-path assertion compares against that zero and
// matches nothing, and the action silently drops out of the only check that
// covers it. A missing home disables enforcement for exactly the action that
// forgot to declare one.
func TestEveryActionDeclaresAHome(t *testing.T) {
	entries := auditaction.All()

	// Without this the gate passes on an empty registry — a renamed symbol, a
	// build tag, a refactor that left All() returning nothing.
	if len(entries) < 100 {
		t.Fatalf("only %d registered actions; this gate is not seeing the registry it used to.\n"+
			"    Check pkg/auditaction/registry.go before trusting a pass.", len(entries))
	}

	for _, e := range entries {
		if e.Home.Valid() {
			continue
		}
		t.Errorf("action %q declares no home (Home is %q).\n"+
			"    Every action has to say which `audit_events` chain it is written to:\n"+
			"      auditaction.HomeControlPlane  the hub's own state.db — fleet facts\n"+
			"      auditaction.HomeProject       the project's .cloop/state.db — the plan's life\n"+
			"      auditaction.HomeEither        scoped; genuinely both (needs a Note saying what varies)\n"+
			"    Nothing else can catch a wrong answer here: a mis-routed row appends,\n"+
			"    verifies and exports cleanly, and is simply absent from the trail the\n"+
			"    operator reads. Add Home to its entry in pkg/auditaction/registry.go and\n"+
			"    run `make docs-audit`.", e.Action, e.Home)
	}
}

// TestEitherHomeIsJustified keeps the escape hatch from becoming the default.
//
// HomeEither switches the runtime assertion off for an action, so it is the one
// declaration that can quietly remove coverage. It is legitimate — an
// authorization decision really is filed against whatever it was scoped to —
// but "I could not decide" and "it genuinely varies" produce the same constant,
// and only a sentence tells them apart. Requiring that sentence is the same
// bargain orphan_test.go's exempt map and auditaction_test.go's
// passThroughNames make: an exemption costs a reason.
func TestEitherHomeIsJustified(t *testing.T) {
	for _, e := range auditaction.InHome(auditaction.HomeEither) {
		if len(e.Note) < 40 {
			t.Errorf("action %q declares HomeEither but does not explain what varies.\n"+
				"    HomeEither disables the emit-path assertion for this action, so it is the\n"+
				"    one declaration that silently removes coverage. Say in Note which scope\n"+
				"    sends it to which chain, or pick a definite home.", e.Action)
		}
	}
}

// TestBothChainsAreActuallyUsed is a smell test on the split itself.
//
// If every action ended up in one home, the distinction would be decorative and
// the merged reader pointless — and the most likely cause would be a bulk edit
// that assigned one value everywhere rather than a real architectural change.
// Either outcome is worth a failure that makes somebody look.
func TestBothChainsAreActuallyUsed(t *testing.T) {
	for _, h := range []auditaction.HomeDB{auditaction.HomeControlPlane, auditaction.HomeProject} {
		if got := len(auditaction.InHome(h)); got == 0 {
			t.Errorf("no registered action is homed in %s.\n"+
				"    Both chains exist and both are written to, so an empty side means the\n"+
				"    registry stopped describing the system rather than the system changing.", h)
		}
	}
}
