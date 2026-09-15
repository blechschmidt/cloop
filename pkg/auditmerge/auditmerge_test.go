package auditmerge

// Tests for reading both audit chains as one trail (Task 20292).
//
// Three of these exist because a review of the first draft found the bugs they
// pin: a missing database aborted the whole merged read, a shared database
// double-counted every row, and the same shared database reported hundreds of
// correctly-placed rows as mis-routed. All three are the same underlying
// mistake — assuming the two chains are always two distinct, always-present
// files — and all three are invisible unless a test builds the awkward case on
// purpose.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// chainDir creates a directory with an initialised .cloop/state.db and appends
// the given events to its audit chain.
func chainDir(t *testing.T, name string, evs ...*statedb.AuditEvent) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer db.Close()
	for _, ev := range evs {
		if err := db.AppendAuditEvent(ev); err != nil {
			t.Fatalf("append to %s: %v", name, err)
		}
	}
	return dir
}

func ev(action auditaction.Action, entity, id string) *statedb.AuditEvent {
	return &statedb.AuditEvent{
		Actor: "tester", EventType: string(action),
		EntityType: entity, EntityID: id, Payload: `{}`,
	}
}

// TestMergedReadSpansBothChains is the capability itself: the question the
// whole task exists to make answerable.
//
// A project's chain holds the plan's life and the hub's holds the executor that
// ran it. Neither alone answers "what happened to project X", and before this
// every reader saw exactly one.
func TestMergedReadSpansBothChains(t *testing.T) {
	project := chainDir(t, "proj",
		ev(auditaction.ActionTaskDispatch, "task", "1"),
		ev(auditaction.ActionTaskFinish, "task", "1"))
	hub := chainDir(t, "hub",
		ev(auditaction.ActionExecutorEnroll, "executor", "docker-1"),
		ev(auditaction.ActionSecretLease, "secret", "gh-pat"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, total, err := r.List(statedb.AuditFilter{Order: "asc"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 4 {
		t.Errorf("total = %d, want 4 (two chains of two)", total)
	}

	seen := map[string]Source{}
	for _, row := range rows {
		seen[row.EventType] = row.Source
	}
	for action, want := range map[string]Source{
		string(auditaction.ActionTaskDispatch):   SourceProject,
		string(auditaction.ActionExecutorEnroll): SourceControlPlane,
		string(auditaction.ActionSecretLease):    SourceControlPlane,
	} {
		got, ok := seen[action]
		if !ok {
			t.Errorf("merged read is missing %q — it is present in one of the two chains", action)
			continue
		}
		if got != want {
			t.Errorf("%q labelled %q, want %q; an unlabelled or wrongly-labelled row "+
				"makes the merge less useful than reading one chain, because the reader "+
				"cannot tell which trail a row is evidence from", action, got, want)
		}
	}
}

// TestMergedReadIsTimestampOrdered pins the ordering contract.
//
// The chains have independent id sequences, so ids collide and mean nothing
// across a merge. Timestamp is the only comparable field, and a reader
// reconstructing what happened needs the interleaving to be right — not each
// chain's rows in a block.
func TestMergedReadIsTimestampOrdered(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	stamp := func(e *statedb.AuditEvent, d time.Duration) *statedb.AuditEvent {
		e.Timestamp = base.Add(d)
		return e
	}
	project := chainDir(t, "proj",
		stamp(ev(auditaction.ActionTaskDispatch, "task", "1"), 0),
		stamp(ev(auditaction.ActionTaskFinish, "task", "1"), 2*time.Second))
	hub := chainDir(t, "hub",
		stamp(ev(auditaction.ActionSecretLease, "secret", "gh"), 1*time.Second),
		stamp(ev(auditaction.ActionSecretRelease, "secret", "gh"), 3*time.Second))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{Order: "asc"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, row := range rows {
		got = append(got, row.EventType)
	}
	want := []string{
		string(auditaction.ActionTaskDispatch),
		string(auditaction.ActionSecretLease),
		string(auditaction.ActionTaskFinish),
		string(auditaction.ActionSecretRelease),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged order = %v, want %v — the chains were concatenated rather "+
				"than interleaved, which is the one thing a merged view must not do", got, want)
		}
	}
}

// TestSharedDatabaseIsReadOnce is the hub's own project.
//
// The hub runs from a directory that is itself a project, so naming it as both
// chains names one file twice. Reading it twice would duplicate every row — and
// a duplicated audit trail reads exactly like the double-write bug somebody
// would then go hunting for in the emitters.
func TestSharedDatabaseIsReadOnce(t *testing.T) {
	dir := chainDir(t, "hubproj",
		ev(auditaction.ActionExecutorEnroll, "executor", "docker-1"),
		ev(auditaction.ActionTaskDispatch, "task", "1"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: dir},
		{Source: SourceProject, Dir: dir},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if n := len(r.Chains()); n != 1 {
		t.Errorf("one file named as two chains opened %d chains, want 1", n)
	}
	rows, total, err := r.List(statedb.AuditFilter{Order: "asc"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 || total != 2 {
		t.Errorf("got %d rows (total %d), want 2 — the shared database was read twice",
			len(rows), total)
	}
	if v := r.Verify(); len(v) != 1 {
		t.Errorf("Verify returned %d verdicts for one file, want 1", len(v))
	}
}

// TestSharedDatabaseReportsNoStrays is the second half of the shared case.
//
// One file legitimately holds both homes, so judging it against a single label
// would report every task and config row in the hub's own project as
// mis-routed. Hundreds of false findings do not just annoy: they bury the one
// real finding the check exists to surface.
func TestSharedDatabaseReportsNoStrays(t *testing.T) {
	dir := chainDir(t, "hubproj",
		ev(auditaction.ActionExecutorEnroll, "executor", "d1"), // control-plane-homed
		ev(auditaction.ActionTaskDispatch, "task", "1"),        // project-homed
		ev(auditaction.ActionStateSave, "plan", ""),            // project-homed
	)
	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: dir},
		{Source: SourceProject, Dir: dir},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if stray := Misrouted(rows); len(stray) != 0 {
		t.Errorf("shared database reported %d mis-routed rows, want 0; first is %s (%s)",
			len(stray), stray[0].Ref(), stray[0].EventType)
	}
}

// TestMissingChainIsSkippedNotFatal covers a project that has never run.
//
// The first draft matched the driver's error text to detect this, and the text
// it matched was not the text the driver produces — so a never-run project
// aborted the entire merged read rather than being skipped. That is the failure
// this test exists to keep fixed.
func TestMissingChainIsSkippedNotFatal(t *testing.T) {
	hub := chainDir(t, "hub", ev(auditaction.ActionExecutorEnroll, "executor", "d1"))
	absent := filepath.Join(t.TempDir(), "never-initialised")

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: absent},
	})
	if err != nil {
		t.Fatalf("a project with no state.db made the whole merged read fail: %v", err)
	}
	defer r.Close()

	if n := len(r.Chains()); n != 1 {
		t.Fatalf("opened %d chains, want 1 (the absent one skipped)", n)
	}
	rows, _, err := r.List(statedb.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("got %d rows from the one present chain, want 1", len(rows))
	}
}

// TestMisroutedFindsAStrayRow is the read-side detector.
//
// The emit-path assertion only guards handles this binary classified, and only
// from the moment it shipped. Rows written by an older build are already on
// disk, and reading both chains is the only way to find them.
func TestMisroutedFindsAStrayRow(t *testing.T) {
	// An executor enrolment — control-plane-homed — sitting in a project chain.
	project := chainDir(t, "proj", ev(auditaction.ActionExecutorEnroll, "executor", "d1"))
	hub := chainDir(t, "hub", ev(auditaction.ActionSecretLease, "secret", "gh"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	stray := Misrouted(rows)
	if len(stray) != 1 {
		t.Fatalf("found %d mis-routed rows, want 1", len(stray))
	}
	if stray[0].EventType != string(auditaction.ActionExecutorEnroll) {
		t.Errorf("flagged %q, want the executor enrolment", stray[0].EventType)
	}
	if stray[0].Source != SourceProject {
		t.Errorf("flagged row came from %q, want the project chain", stray[0].Source)
	}
}

// TestMisroutedIsAsymmetric pins the direction rule.
//
// The hub runs from a directory that is itself a cloop project, so the
// control-plane database always also holds that project's own state.save,
// config.set and task rows — legitimately. Flagging them would fire on every
// real hub, and an advisory that always fires is one nobody reads, which buries
// the single stray this exists to find. Only the unambiguous direction — a
// fleet fact in a project's chain — is a finding.
func TestMisroutedIsAsymmetric(t *testing.T) {
	// The hub's own project rows, in the control-plane chain.
	hub := chainDir(t, "hub",
		ev(auditaction.ActionExecutorEnroll, "executor", "d1"),
		ev(auditaction.ActionStateSave, "plan", ""),
		ev(auditaction.ActionConfigSet, "config", ""))
	project := chainDir(t, "proj", ev(auditaction.ActionTaskDispatch, "task", "1"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if stray := Misrouted(rows); len(stray) != 0 {
		t.Errorf("project-homed rows in the control-plane chain were reported as strays "+
			"(%d of them, first %s %s). The hub's directory is always also a project, so "+
			"this would fire on every real deployment.",
			len(stray), stray[0].Ref(), stray[0].EventType)
	}
}

// TestVerifyReportsEveryChain is the `verify` contract.
//
// One hash chain says nothing about the other, so a single boolean would let an
// intact hub chain vouch for a broken project one — which is precisely the
// false assurance `cloop audit-log verify` gave by verifying whichever database
// it happened to open.
func TestVerifyReportsEveryChain(t *testing.T) {
	project := chainDir(t, "proj", ev(auditaction.ActionTaskDispatch, "task", "1"))
	hub := chainDir(t, "hub", ev(auditaction.ActionExecutorEnroll, "executor", "d1"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	verdicts := r.Verify()
	if len(verdicts) != 2 {
		t.Fatalf("Verify returned %d verdicts, want one per chain", len(verdicts))
	}
	got := map[Source]bool{}
	for _, v := range verdicts {
		got[v.Source] = v.OK()
		if !v.OK() {
			t.Errorf("%s chain at %s did not verify: ok=%v err=%v reason=%q",
				v.Source, v.Path, v.Report.OK, v.Err, v.Report.Reason)
		}
	}
	for _, want := range []Source{SourceControlPlane, SourceProject} {
		if _, ok := got[want]; !ok {
			t.Errorf("no verdict for the %s chain — a verify that silently skips a "+
				"chain is the failure this replaces", want)
		}
	}
}

// TestPagingAppliesToTheMergedSequence guards the subtle paging bug.
//
// Taking the first N from each chain and calling it the first N overall is
// wrong whenever the chains are not evenly interleaved, and they never are.
func TestPagingAppliesToTheMergedSequence(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	stamp := func(e *statedb.AuditEvent, d time.Duration) *statedb.AuditEvent {
		e.Timestamp = base.Add(d)
		return e
	}
	// The three oldest rows are all in the project chain.
	project := chainDir(t, "proj",
		stamp(ev(auditaction.ActionTaskDispatch, "task", "1"), 0),
		stamp(ev(auditaction.ActionTaskFinish, "task", "1"), 1*time.Second),
		stamp(ev(auditaction.ActionTaskDispatch, "task", "2"), 2*time.Second))
	hub := chainDir(t, "hub",
		stamp(ev(auditaction.ActionExecutorEnroll, "executor", "d1"), 9*time.Second))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{Order: "asc", Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	for _, row := range rows {
		if row.Source != SourceProject {
			t.Errorf("the two oldest rows are both in the project chain, but page 1 "+
				"contains a %s row (%s) — paging was applied per chain, not to the merge",
				row.Source, row.EventType)
		}
	}

	// And the window moves through the merged sequence, not through one chain.
	next, _, err := r.List(statedb.AuditFilter{Order: "asc", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(next) != 2 {
		t.Fatalf("page 2 returned %d rows, want 2", len(next))
	}
	if next[1].Source != SourceControlPlane {
		t.Errorf("the newest row is the hub's enrolment; page 2 ended with a %s row instead",
			next[1].Source)
	}
}

// TestFiltersApplyAcrossChains checks that a filter is not quietly one-sided.
func TestFiltersApplyAcrossChains(t *testing.T) {
	project := chainDir(t, "proj",
		ev(auditaction.ActionTaskDispatch, "task", "1"),
		ev(auditaction.ActionTaskFinish, "task", "1"))
	hub := chainDir(t, "hub",
		ev(auditaction.ActionExecutorEnroll, "executor", "d1"))

	r, err := Open([]Chain{
		{Source: SourceControlPlane, Dir: hub},
		{Source: SourceProject, Dir: project},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rows, _, err := r.List(statedb.AuditFilter{EntityType: "task"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("entity_type=task matched %d rows across the merge, want 2", len(rows))
	}
	for _, row := range rows {
		if row.EntityType != "task" {
			t.Errorf("filter leaked a %q row from the %s chain", row.EntityType, row.Source)
		}
	}
}
