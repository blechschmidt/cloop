package statedb

// Which chain a handle is allowed to write to (Task 20292).
//
// `audit_events` lives in two places — the hub's control-plane state.db and
// every project's .cloop/state.db — with an independent hash chain in each.
// Which one an event lands in was decided entirely by which *DB handle the
// emission site happened to be holding, and a wrong choice was silent: the row
// appends, the chain verifies, the SIEM export succeeds, and the operator
// asking about a project reads one chain and gets a confident, incomplete
// answer. Chain verification is structurally incapable of catching it, because
// each chain stays internally consistent either way.
//
// pkg/auditaction now declares, per action, which chain is its home. This file
// is the other half: a handle can be told what it is being used as, and the
// append path refuses to let it write somebody else's events.
//
// # Why the role is on the handle and not the file
//
// The hub runs from a directory which is itself a cloop project, so the hub's
// state.db really is both the control plane and a project database. There is no
// fact about the file that separates them. What separates them is how a handle
// was obtained: controlPlaneDB() opens it as the control plane, and opening the
// same directory as a project opens it as a project. Both are correct, at the
// same time, through different handles — so the role belongs to the handle.
//
// # What is not covered
//
// RoleUnknown asserts nothing. Most handles in the tree are opened by
// statedb.Open and never classified, and that is deliberate: this landed
// without reclassifying eighty-five call sites, and a default that guessed
// would fire on correct code. The handles that matter are marked explicitly —
// the control plane's, and the project handles the orchestrator and the audit
// read paths use — and every one that is marked is checked.
//
// The in-transaction batch in offboard.go reaches appendAuditEventsTx directly
// and so is not checked here; its actions are all control-plane-homed and it
// writes to the control-plane database, so there is nothing for the assertion
// to find there today. A future in-transaction emitter should route through a
// handle-aware path rather than assume that stays true.

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

// Role is what a *DB handle is being used as.
type Role int32

const (
	// RoleUnknown is an unclassified handle. It asserts nothing.
	RoleUnknown Role = iota
	// RoleControlPlane is the hub's own database, holding fleet-wide facts.
	RoleControlPlane
	// RoleProject is one project's database, holding that plan's life.
	RoleProject
)

// String renders the role as it appears in an assertion message.
func (r Role) String() string {
	switch r {
	case RoleControlPlane:
		return "control-plane"
	case RoleProject:
		return "project"
	}
	return "unclassified"
}

// home returns the auditaction home a handle in this role may write.
func (r Role) home() auditaction.HomeDB {
	switch r {
	case RoleControlPlane:
		return auditaction.HomeControlPlane
	case RoleProject:
		return auditaction.HomeProject
	}
	return ""
}

// AsControlPlane marks d as the hub's control-plane handle and returns it, so
// it can be chained onto an Open:
//
//	db, err := statedb.Open(state.DBPath(s.WorkDir))
//	... db.AsControlPlane()
//
// Marking is idempotent and safe to repeat.
func (d *DB) AsControlPlane() *DB { return d.withRole(RoleControlPlane) }

// AsProject marks d as one project's handle and returns it.
func (d *DB) AsProject() *DB { return d.withRole(RoleProject) }

// Role reports how this handle has been classified.
func (d *DB) Role() Role {
	if d == nil {
		return RoleUnknown
	}
	return Role(d.role.Load())
}

// withRole sets the role. Stored atomically rather than under d.mu because it
// is read on every append — which already holds d.mu — and a handle is
// classified by whoever opened it, before it is shared. The atomic is what
// keeps that "before" from being a promise the race detector has to take on
// faith.
func (d *DB) withRole(r Role) *DB {
	if d == nil {
		return nil
	}
	d.role.Store(int32(r))
	return d
}

// roleField is the type of DB.role. Declared here rather than inline in the
// struct so the whole routing concern reads in one file.
type roleField = atomic.Int32

// assertAuditHome checks that every event in evs belongs in d's chain.
//
// The return value says whether the batch is correctly routed. Callers write
// the rows regardless: dropping an audit record to punish a routing mistake
// would turn a bookkeeping defect into an evidence gap, which is the same
// argument pkg/auditaction makes for not filtering unregistered names. What a
// mis-route costs is a loud failure under test and a warning in production, not
// the row.
func (d *DB) assertAuditHome(evs []*AuditEvent) bool {
	want := d.Role().home()
	if want == "" {
		return true // unclassified handle: nothing was promised, nothing is checked
	}
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		home, known := auditaction.HomeOf(auditaction.Action(ev.EventType))
		switch {
		case !known:
			// An unregistered action has no declared home. That is
			// tests/arch/auditaction_test.go's failure to report, not this
			// path's — and guessing here would make a typo look like a
			// mis-route, sending the next reader after the wrong bug.
			continue
		case home == auditaction.HomeEither:
			// Scoped to whatever the decision was about; both chains are
			// correct by construction.
			continue
		case home == want:
			continue
		}
		reportMisroutedAudit(d.Role(), ev.EventType, home)
		return false
	}
	return true
}

// reportMisroutedAudit is what a wrong home costs.
//
// Under test it panics, because a mis-routed event is precisely the class of
// defect that no other check can see and a test that merely logged would be a
// test that passes. In production it warns and lets the write proceed, because
// an audit trail that drops rows when it is unsure is worse than one that
// records them in the wrong place — the row is still evidence, and the warning
// is what gets it moved.
func reportMisroutedAudit(role Role, eventType string, home auditaction.HomeDB) {
	msg := fmt.Sprintf(
		"audit event %q belongs in the %s chain, but is being written through a %s handle.\n"+
			"    audit_events exists in both the hub's state.db and every project's, with a\n"+
			"    separate hash chain in each — so this row will append cleanly, verify\n"+
			"    cleanly, and be missing from the only trail anybody thinks to read.\n"+
			"    Fix it one of two ways:\n"+
			"      (a) the handle is wrong — emit through the %s database instead;\n"+
			"      (b) the declared home is wrong — correct Home in pkg/auditaction/registry.go\n"+
			"          and run `make docs-audit`.",
		eventType, home, role, home)

	if testing.Testing() {
		panic("statedb: " + msg)
	}
	// Once per process, and with its own sync.Once rather than auditWarn's.
	// The high-volume actions are project-homed — task.upsert alone was once
	// 99.7% of the table — so a mis-routed one would print on every save and
	// bury whatever else the operator was reading. Sharing auditWarn's Once
	// would fix the flood but let an unrelated first warning suppress this
	// message entirely, which for the one warning nothing else can produce is
	// the wrong trade.
	misrouteWarnOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"[audit] %s\n    (further mis-routing warnings suppressed)\n", msg)
	})
}

var misrouteWarnOnce sync.Once
