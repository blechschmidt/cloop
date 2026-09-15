package auditaction

// Which of the two audit chains an action belongs in (Task 20292).
//
// `audit_events` is not one table. It exists in the hub's own control-plane
// state.db *and* in every project's .cloop/state.db, and each copy carries its
// own independent hash chain. Nothing about a row says which database it came
// from, and until this file nothing in the code said which one an action was
// supposed to land in: routing was decided implicitly, by whichever
// *statedb.DB handle an emission site happened to be holding.
//
// That is a bad way to decide, because getting it wrong is silent in every
// direction that would normally catch a mistake:
//
//   - The row appends. Both databases have the table.
//   - `cloop audit-log verify` passes. It verifies one chain at a time, and a
//     mis-routed row is a perfectly well-formed link in whichever chain it
//     landed in — each chain stays internally consistent, so the check meant
//     to catch tampering is exactly the check that cannot see this.
//   - The SIEM export succeeds, from whichever database was opened.
//   - The operator asking "what happened to project X" reads one chain and
//     gets a confident, incomplete answer.
//
// So the home is declared, per action, in the registry. Two things then become
// possible that were not before: a gate can check every declaration is present
// (tests/arch), and the emit path can assert a handle is only asked to write
// actions that belong to it (pkg/statedb) — turning a silent mis-route into a
// loud test failure.
//
// # Why this is a property of the handle, not of the file
//
// The hub runs *from* a directory, and that directory is itself a cloop
// project — index 0 in the project list. So the hub's state.db is both the
// control plane and a project database, and there is no fact about the file
// that distinguishes them. What distinguishes them is intent: a handle opened
// by controlPlaneDB() is being used as the control plane, and a handle opened
// from a project's WorkDir is being used as that project. The same file backs
// both, legitimately, through two different handles. See statedb.Role.

// HomeDB names the chain an action is recorded in.
type HomeDB string

const (
	// HomeControlPlane: the hub's own state.db. Facts about the fleet and the
	// hub as a whole — which executors exist, who holds a credential, who
	// logged in, what an operator administered. These outlive any one project
	// and several of them belong to no project at all, so a project's chain is
	// the wrong place for them even when a project is what triggered them.
	HomeControlPlane HomeDB = "control-plane"

	// HomeProject: the project's own .cloop/state.db. The plan's life — tasks
	// created, dispatched and finished, steps appended, the project's config
	// written. These travel with the project directory, which is what makes a
	// project's trail readable after it has been moved off the hub that ran it.
	HomeProject HomeDB = "project"

	// HomeEither: genuinely both, depending on the scope of the thing being
	// recorded — not "we did not decide".
	//
	// One family needs this honestly. An authorization decision is recorded
	// against whatever it was scoped to: a permission check on a project lands
	// in that project's chain, and a fleet-wide one lands in the hub's. Forcing
	// either answer would make the declaration a lie, and a lie here is worse
	// than the ambiguity it papers over, because the runtime assertion would
	// then fire on correct code and the next person would delete the assertion
	// rather than the lie.
	//
	// The gate keeps this from becoming a dumping ground: an entry declaring
	// HomeEither must carry a Note explaining what varies, or tests/arch fails.
	// An escape hatch that costs a sentence stays rare.
	HomeEither HomeDB = "either"
)

// Valid reports whether h is one of the declared homes. The zero value is not
// valid, which is the point: an entry that forgot to say fails the gate rather
// than defaulting into somebody's chain.
func (h HomeDB) Valid() bool {
	switch h {
	case HomeControlPlane, HomeProject, HomeEither:
		return true
	}
	return false
}

// String renders the home as it appears in the generated docs and in the
// --source column of a merged read.
func (h HomeDB) String() string { return string(h) }

// Describe is the one-line gloss the generated page uses. Kept next to the
// constants so a reader changing what a home means changes its description in
// the same edit.
func (h HomeDB) Describe() string {
	switch h {
	case HomeControlPlane:
		return "the hub's own state.db"
	case HomeProject:
		return "the project's .cloop/state.db"
	case HomeEither:
		return "whichever chain the decision was scoped to"
	}
	return "undeclared"
}

// HomeOf returns where a registered action is recorded, and whether the action
// is registered at all. An unregistered action has no declared home — callers
// deciding whether to assert must not treat that as a mismatch, because an
// unknown name is tests/arch's problem, not the emit path's.
func HomeOf(a Action) (HomeDB, bool) {
	e, ok := byAction[a]
	if !ok {
		return "", false
	}
	return e.Home, true
}

// InHome returns every registered action whose home is h, sorted by name.
//
// Used by the generated page and by the merged reader, which needs to know
// which actions it should expect to find in which chain in order to tell "this
// project has no executor events because none happened" apart from "because I
// was reading the wrong database".
func InHome(h HomeDB) []Entry {
	var out []Entry
	for _, e := range All() {
		if e.Home == h {
			out = append(out, e)
		}
	}
	return out
}
