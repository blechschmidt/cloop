package statedb

// Proof that a mis-routed audit event is now caught (Task 20292).
//
// The defect these tests describe is the one nothing else in the build can see.
// `audit_events` exists in both the hub's control-plane state.db and every
// project's .cloop/state.db, with an independent hash chain in each, and until
// this landed the choice between them was made implicitly by whichever *DB
// handle an emission site was holding. Writing an executor event into a
// project's chain — or a task event into the hub's — produced a row that
// appends, verifies, and exports cleanly, and is simply absent from the trail
// anybody would think to read.
//
// Every test below fails on the parent commit, and for the right reason: there
// was no Role to set, no Home to compare it against, and no assertion in the
// append path. They are not asserting that a warning is printed; they are
// asserting that the wrong database is refused loudly.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// TestControlPlaneEventIntoAProjectChainIsCaught is the headline case: the
// fleet event that lands in a plan's trail.
//
// This is the direction that actually bites. An operator investigating a
// project reads that project's chain, and an executor enrolment or a credential
// lease filed there is invisible to the hub-wide view where a reviewer would
// look for it — while `cloop audit-log verify` reports both chains intact,
// because both are.
func TestControlPlaneEventIntoAProjectChainIsCaught(t *testing.T) {
	db := newAuditDB(t).AsProject()

	caught := catchMisroute(t, func() {
		_ = db.AppendAuditEvent(&AuditEvent{
			Actor:      "operator",
			EventType:  string(auditaction.ActionExecutorEnroll),
			EntityType: "executor",
			EntityID:   "docker-1",
			Payload:    `{"action":"enroll"}`,
		})
	})
	if caught == "" {
		t.Fatal("an executor.enroll written through a project handle was accepted silently.\n" +
			"    That row is a fleet fact filed in one plan's chain: it will never appear in\n" +
			"    the hub-wide trail, and chain verification passes on both databases because\n" +
			"    each remains internally consistent. Nothing else in the build can see this.")
	}
	// The message has to name both the action and where it should have gone,
	// or the person who hits it at 3am learns only that something is wrong.
	for _, want := range []string{"executor.enroll", "control-plane", "project"} {
		if !strings.Contains(caught, want) {
			t.Errorf("assertion message does not mention %q; got:\n%s", want, caught)
		}
	}
}

// TestProjectEventIntoTheControlPlaneChainIsCaught is the same defect pointed
// the other way: a plan's own event filed in the hub's chain, where it is
// mixed in with every other project's and absent from the one trail that
// travels with the project directory.
func TestProjectEventIntoTheControlPlaneChainIsCaught(t *testing.T) {
	db := newAuditDB(t).AsControlPlane()

	caught := catchMisroute(t, func() {
		_ = db.AppendAuditEvent(&AuditEvent{
			Actor:      "orchestrator",
			EventType:  string(auditaction.ActionTaskDispatch),
			EntityType: "task",
			EntityID:   "42",
			Payload:    `{"task_id":42}`,
		})
	})
	if caught == "" {
		t.Fatal("a task.dispatch written through the control-plane handle was accepted silently")
	}
}

// TestCorrectlyRoutedEventsAreNotDisturbed guards the assertion against being
// the kind of check that fires on correct code.
//
// A gate with false positives gets deleted rather than obeyed, so both homes
// are exercised on handles that match them, and the row is checked to have
// actually been written — an assertion that silently swallowed the write would
// be a worse bug than the one it is here to catch.
func TestCorrectlyRoutedEventsAreNotDisturbed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mark   func(*DB) *DB
		action auditaction.Action
		entity string
	}{
		{"fleet event, hub handle", (*DB).AsControlPlane, auditaction.ActionExecutorEnroll, "executor"},
		{"plan event, project handle", (*DB).AsProject, auditaction.ActionTaskDispatch, "task"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := tc.mark(newAuditDB(t))
			if err := db.AppendAuditEvent(&AuditEvent{
				Actor:      "system",
				EventType:  string(tc.action),
				EntityType: tc.entity,
				EntityID:   "1",
				Payload:    `{}`,
			}); err != nil {
				t.Fatalf("append: %v", err)
			}
			if got := countAudit(t, db, string(tc.action)); got != 1 {
				t.Fatalf("%s wrote %d rows through a matching handle, want 1", tc.action, got)
			}
		})
	}
}

// TestUnclassifiedHandlesAssertNothing pins the compatibility promise.
//
// Most handles in the tree are opened by statedb.Open and never classified.
// That has to keep working exactly as before — otherwise this change would be a
// flag day across eighty-odd call sites, and the pressure would be to weaken
// the assertion rather than to classify the handles that matter.
func TestUnclassifiedHandlesAssertNothing(t *testing.T) {
	db := newAuditDB(t)
	if db.Role() != RoleUnknown {
		t.Fatalf("a freshly opened handle has role %v, want unclassified", db.Role())
	}
	if err := db.AppendAuditEvent(&AuditEvent{
		EventType:  string(auditaction.ActionExecutorEnroll),
		EntityType: "executor",
		EntityID:   "x",
	}); err != nil {
		t.Fatalf("append through an unclassified handle: %v", err)
	}
	if got := countAudit(t, db, string(auditaction.ActionExecutorEnroll)); got != 1 {
		t.Fatalf("unclassified handle wrote %d rows, want 1", got)
	}
}

// TestScopedActionsAreAcceptedByBothChains covers HomeEither.
//
// An authorization decision is filed wherever it was scoped: a check against a
// project lands in that project's chain, a fleet-wide one in the hub's. Both
// are correct, so neither may be refused — and this is the test that keeps
// somebody from "tidying" HomeEither away into a single home and breaking
// whichever half they did not think about.
func TestScopedActionsAreAcceptedByBothChains(t *testing.T) {
	for _, mark := range []func(*DB) *DB{(*DB).AsControlPlane, (*DB).AsProject} {
		db := mark(newAuditDB(t))
		if err := db.AppendAuditEvent(&AuditEvent{
			EventType:  string(auditaction.ActionAuthzDenied),
			EntityType: "permission",
			EntityID:   "secret.grant",
		}); err != nil {
			t.Fatalf("append authz.denied through a %s handle: %v", db.Role(), err)
		}
		if got := countAudit(t, db, string(auditaction.ActionAuthzDenied)); got != 1 {
			t.Fatalf("authz.denied through a %s handle wrote %d rows, want 1", db.Role(), got)
		}
	}
}

// TestUnregisteredActionsAreLeftToTheArchGate keeps the two checks from
// blaming each other.
//
// An action pkg/auditaction does not know has no declared home, so this path
// cannot say whether it was mis-routed. Guessing would report a typo as a
// routing bug and send the next reader after the wrong defect;
// tests/arch/auditaction_test.go is what fails on an unregistered name.
func TestUnregisteredActionsAreLeftToTheArchGate(t *testing.T) {
	db := newAuditDB(t).AsProject()
	if err := db.AppendAuditEvent(&AuditEvent{
		EventType:  "executor.enrol", // a typo: one 'l', registered nowhere
		EntityType: "executor",
		EntityID:   "x",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if got := countAudit(t, db, "executor.enrol"); got != 1 {
		t.Fatalf("an unregistered action wrote %d rows, want 1 — the emit path must not filter", got)
	}
}

// TestEveryRegisteredActionDeclaresAHome is the registry-side half of the
// drift gate, kept next to the assertion that depends on it.
//
// tests/arch checks this too, over the whole module. It is repeated here
// because this package is where an undeclared home does its damage: HomeOf
// would return the zero value, the assertion would compare against it, and the
// check would silently stop covering that action.
func TestEveryRegisteredActionDeclaresAHome(t *testing.T) {
	for _, e := range auditaction.All() {
		if !e.Home.Valid() {
			t.Errorf("action %q declares no home (%q).\n"+
				"    Without one the emit-path assertion cannot check it, and it will be\n"+
				"    routed by whichever handle a call site happens to hold.",
				e.Action, e.Home)
		}
	}
}

// catchMisroute runs fn and returns the panic message the assertion raised, or
// "" when it did not fire.
//
// The assertion panics under test deliberately — a mis-route that only logged
// would be a test that passes — so recovering it here is how a test observes it
// without taking the process down.
func catchMisroute(t *testing.T, fn func()) (msg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			s, ok := r.(string)
			if !ok {
				t.Fatalf("assertion panicked with %T, want a string message: %v", r, r)
			}
			msg = s
		}
	}()
	fn()
	return ""
}
