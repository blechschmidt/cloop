package statedb

// The requirements spec file's side of the store (Task 20459): the status
// column an older build must keep, the merge base, and imports that apply
// whole or not at all.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

func TestRequirementsSpecMigrationIsAdditive(t *testing.T) {
	embedded, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range embedded {
		if m.Version == 86 {
			if got := classifyMigration(m.SQL); got != CompatAdditive {
				t.Fatalf("migration %s classifies as %q, want additive: the build before it must keep opening the "+
					"project databases it applies to", m.Name, got)
			}
			return
		}
	}
	t.Fatal("migration 0086 is missing")
}

// TestAnOlderBuildKeepsTheStatus: Task 20458's build, which knows no status,
// adds and edits requirements with exactly these statements. What it adds is
// approved — checked, as it was when it added it — and its edit of a draft
// leaves a draft.
func TestAnOlderBuildKeepsTheStatus(t *testing.T) {
	db := openFresh(t)
	draft, err := db.AddRequirement(requirements.Requirement{Title: "proposed", Status: requirements.StatusDraft}, "alice")
	if err != nil || draft.Status != requirements.StatusDraft {
		t.Fatalf("a draft added as %+v (%v)", draft, err)
	}
	// Task 20458's UpdateRequirement, verbatim.
	if _, err := db.conn.Exec(`UPDATE requirements SET title = ?, description = ?, priority = ?, tags = ?, tests = ?,
			updated_at = ?, updated_by = ? WHERE id = ?`,
		"proposed, edited", "", "", "[]", "[]", formatReqTime(draft.UpdatedAt), "old-build", draft.ID); err != nil {
		t.Fatal(err)
	}
	// And its AddRequirement.
	if _, err := db.conn.Exec(`INSERT INTO requirements
			(title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"added by the old build", "", "", "[]", "[]", "", "", "old-build", "old-build"); err != nil {
		t.Fatal(err)
	}
	all, err := db.Requirements()
	if err != nil || len(all) != 2 {
		t.Fatalf("%v %+v", err, all)
	}
	if all[0].Title != "proposed, edited" || all[0].Status != requirements.StatusDraft {
		t.Errorf("the older build's edit left %+v", all[0])
	}
	if all[1].Status != requirements.StatusApproved {
		t.Errorf("the older build's requirement reads %q", all[1].Status)
	}

	// This build's edit keeps a status it was not given, and changes one it
	// was; the change is audited.
	r := all[0]
	r.Status = ""
	if got, err := db.UpdateRequirement(r, "bob"); err != nil || got.Status != requirements.StatusDraft {
		t.Fatalf("an edit with no status: %+v %v", got, err)
	}
	r.Status = requirements.StatusApproved
	if got, err := db.UpdateRequirement(r, "bob"); err != nil || got.Status != requirements.StatusApproved {
		t.Fatalf("approving: %+v %v", got, err)
	}
	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionRequirementUpdate)})
	if err != nil || len(rows) == 0 || !strings.Contains(rows[0].Payload, `"status"`) {
		t.Errorf("approving was not audited as a status change: %+v %v", rows, err)
	}

	// A status nothing in this package wrote is not taken for approval.
	if _, err := db.conn.Exec(`UPDATE requirements SET status = 'shipped' WHERE id = ?`, r.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.Requirement(r.ID); got.Status != requirements.StatusDraft {
		t.Errorf("an unknown status reads %q", got.Status)
	}
}

func specReq(id int, title string, tests ...string) requirements.Requirement {
	r := requirements.Requirement{ID: id, Title: title, Status: requirements.StatusApproved}
	for _, c := range tests {
		r.Tests = append(r.Tests, requirements.Test{Command: c})
	}
	return r
}

// exported adds reqs to the hub and records them exported, as `cloop
// requirements export` leaves a project: the file and the hub agree.
func exported(t *testing.T, db *DB, titles ...string) []requirements.Requirement {
	t.Helper()
	var out []requirements.Requirement
	for _, title := range titles {
		out = append(out, addReq(t, db, title, "test "+title))
	}
	if err := db.RecordRequirementSpecExport(out, RequirementSpecSync{Actor: "alice", Source: "cli",
		Path: requirements.SpecFileName, SHA256: "aa"}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestImportAppliesTheMergeAndMovesTheBase(t *testing.T) {
	db := openFresh(t)
	hub := exported(t, db, "one", "two", "three")
	if _, err := db.RecordRequirementChecks(CheckRecord{CheckedBy: "x"}, []requirements.Result{{
		RequirementID: 3, Fingerprint: hub[2].Fingerprint(), Method: requirements.MethodTests, Verdict: requirements.VerdictFulfilled,
	}}); err != nil {
		t.Fatal(err)
	}
	// The hub tightens R-1's priority; the file renames R-2, drops R-3 and
	// adds R-7.
	r1 := hub[0]
	r1.Priority = requirements.PriorityMust
	if _, err := db.UpdateRequirement(r1, "bob"); err != nil {
		t.Fatal(err)
	}
	file := []requirements.Requirement{specReq(1, "one", "test one"), specReq(2, "two, renamed", "test two"),
		specReq(7, "seven", "make seven")}

	res, err := db.ImportRequirementSpec(RequirementSpecImport{File: file, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Plan; p.Imports != 3 || p.Exports != 1 || p.Conflicts != 0 || p.Digest == "" {
		t.Fatalf("the plan %+v", p)
	}
	if got, _ := db.Requirements(); len(got) != 3 || got[1].Title != "two" {
		t.Fatalf("a dry run wrote: %+v", got)
	}

	res, err = db.ImportRequirementSpec(RequirementSpecImport{
		File: file, Digest: res.Plan.Digest,
		Sync: RequirementSpecSync{Actor: "carol", Source: "dashboard", Path: requirements.SpecFileName, SHA256: "bb",
			Commit: "0123456789abcdef0123456789abcdef01234567"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.Requirements()
	if err != nil {
		t.Fatal(err)
	}
	ids := []int{}
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []int{1, 2, 7}) {
		t.Fatalf("after the import the hub holds %v", ids)
	}
	if got[0].Priority != requirements.PriorityMust || got[1].Title != "two, renamed" || got[1].UpdatedBy != "carol" ||
		got[2].Title != "seven" || got[2].CreatedBy != "carol" || got[2].Tests[0].Command != "make seven" {
		t.Errorf("after the import: %+v", got)
	}
	if res.ChecksDeleted[3] != 1 {
		t.Errorf("R-3 was deleted with %d checks, want 1", res.ChecksDeleted[3])
	}
	if c, _ := db.RequirementChecks(3, 0); len(c) != 0 {
		t.Errorf("R-3's checks outlived it: %+v", c)
	}
	// An id is never given again: not R-3, deleted by the import, nor any
	// below R-7, which the file took.
	if r := addReq(t, db, "after"); r.ID != 8 {
		t.Errorf("the next requirement got R-%d, want R-8", r.ID)
	}

	// The base is the file: the hub's own change to R-1 is now what an
	// export would write, and nothing is left to import.
	snap, err := db.RequirementSpecSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	p := requirements.Merge(snap.Base, snap.Hub, file, snap.Assigned)
	if p.Imports != 0 || p.Conflicts != 0 || p.Exports != 2 {
		t.Errorf("after the import the merge still plans %+v", p)
	}
	sync, ok, err := db.LastRequirementSpecSync()
	if err != nil || !ok || sync.Direction != RequirementSpecImported || sync.Actor != "carol" || sync.SHA256 != "bb" ||
		sync.Source != "dashboard" || sync.Commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("the last sync: %+v %v %v", sync, ok, err)
	}

	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionRequirementImport)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("%d import rows (%v)", len(rows), err)
	}
	var payload struct {
		Source  string           `json:"source"`
		SHA256  string           `json:"sha256"`
		Added   []int            `json:"added"`
		Updated []map[string]any `json:"updated"`
		Deleted []map[string]any `json:"deleted"`
		Exports int              `json:"exports_pending"`
	}
	if err := json.Unmarshal([]byte(rows[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if rows[0].Actor != "carol" || payload.Source != "dashboard" || payload.SHA256 != "bb" ||
		!slices.Equal(payload.Added, []int{7}) || len(payload.Updated) != 1 || len(payload.Deleted) != 1 ||
		payload.Deleted[0]["checks"] != float64(1) || payload.Exports != 1 {
		t.Errorf("the import was audited as %s", rows[0].Payload)
	}
}

func TestImportAppliesNothingItWasNotAskedTo(t *testing.T) {
	db := openFresh(t)
	hub := exported(t, db, "one", "two")
	// Both sides change R-1's title.
	r1 := hub[0]
	r1.Title = "one, the hub's"
	if _, err := db.UpdateRequirement(r1, "bob"); err != nil {
		t.Fatal(err)
	}
	file := []requirements.Requirement{specReq(1, "one, the file's", "test one"), specReq(2, "two, the file's", "test two")}
	before, _ := db.Requirements()

	_, err := db.ImportRequirementSpec(RequirementSpecImport{File: file})
	var cerr *requirements.ConflictError
	if !errors.As(err, &cerr) || !errors.Is(err, requirements.ErrSpecConflict) || !slices.Equal(cerr.Unresolved, []int{1}) {
		t.Fatalf("an unsettled conflict: %v", err)
	}
	if after, _ := db.Requirements(); after[1].Title != before[1].Title {
		t.Error("an import refused for a conflict on R-1 imported R-2")
	}
	if n := auditCount(t, db, auditaction.ActionRequirementImport); n != 0 {
		t.Errorf("a refused import was audited %d times", n)
	}

	// The plan reviewed is not the plan there is: the hub changed meanwhile.
	plan, err := db.ImportRequirementSpec(RequirementSpecImport{File: file, Resolutions: map[int]string{1: requirements.TakeFile}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	r1.Title = "one, the hub's again"
	if _, err := db.UpdateRequirement(r1, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ImportRequirementSpec(RequirementSpecImport{File: file, Digest: plan.Plan.Digest,
		Resolutions: map[int]string{1: requirements.TakeFile}}); !errors.Is(err, ErrRequirementSpecChanged) {
		t.Fatalf("an import of a plan nobody reviewed: %v", err)
	}
	if HTTPStatus(ErrRequirementSpecChanged) != 409 {
		t.Error("a changed plan is not a conflict")
	}

	// Settled: R-1 takes the file's, R-2 imports.
	if _, err := db.ImportRequirementSpec(RequirementSpecImport{File: file,
		Resolutions: map[int]string{1: requirements.TakeFile}}); err != nil {
		t.Fatal(err)
	}
	after, _ := db.Requirements()
	if after[0].Title != "one, the file's" || after[1].Title != "two, the file's" {
		t.Errorf("after settling: %+v", after)
	}

	// Kept for the hub: the import leaves it, and the next merge sees it as
	// the hub's own change.
	r1 = after[0]
	r1.Title = "one, the hub's once more"
	if _, err := db.UpdateRequirement(r1, "bob"); err != nil {
		t.Fatal(err)
	}
	file[0].Title = "one, the file's once more"
	if _, err := db.ImportRequirementSpec(RequirementSpecImport{File: file,
		Resolutions: map[int]string{1: requirements.KeepHub}}); err != nil {
		t.Fatal(err)
	}
	snap, _ := db.RequirementSpecSnapshot()
	if snap.Hub[0].Title != "one, the hub's once more" {
		t.Errorf("keeping the hub's changed it: %+v", snap.Hub[0])
	}
	if p := requirements.Merge(snap.Base, snap.Hub, file, snap.Assigned); p.Conflicts != 0 || p.Exports != 1 {
		t.Errorf("a conflict settled for the hub is not the hub's change next: %+v", p)
	}

	// A file reusing a deleted id is refused, whatever else it says.
	if _, err := db.DeleteRequirement(2, "bob"); err != nil {
		t.Fatal(err)
	}
	reused := []requirements.Requirement{file[0], specReq(5, "new"), specReq(2, "not the old R-2")}
	if err := db.RecordRequirementSpecExport([]requirements.Requirement{file[0]}, RequirementSpecSync{}); err != nil {
		t.Fatal(err)
	}
	_, err = db.ImportRequirementSpec(RequirementSpecImport{File: reused})
	if !errors.As(err, &cerr) || !slices.Equal(cerr.Refused, []int{2}) {
		t.Errorf("a reused id: %v", err)
	}
}

func TestReadingTheSpecMovesTheBaseOnAgreement(t *testing.T) {
	db := openFresh(t)
	addReq(t, db, "one", "t1")
	addReq(t, db, "two", "t2")
	file := []requirements.Requirement{specReq(1, "one", "t1"), specReq(2, "two, changed", "t2"), specReq(3, "three")}
	content := []byte("version: 1\nrequirements: []\n")
	if err := db.SaveRequirementSpecRead(RequirementSpecRead{
		ReadBy: "alice", ExecutorID: "box", Path: requirements.SpecFileName, Found: true, Content: content,
		SHA256: requirements.SpecSHA256(content), Commit: "ABCDEF0123", Dirty: true, Ignored: true,
	}, file); err != nil {
		t.Fatal(err)
	}
	snap, err := db.RequirementSpecSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Base) != 1 || snap.Base[0].ID != 1 {
		t.Fatalf("the base after the read: %+v", snap.Base)
	}
	rd, ok, err := db.RequirementSpecRead()
	if err != nil || !ok || string(rd.Content) != string(content) || rd.Commit != "abcdef0123" || !rd.Dirty || !rd.Ignored ||
		rd.ExecutorID != "box" || rd.ReadBy != "alice" || rd.ReadAt.IsZero() {
		t.Fatalf("read back %+v %v %v", rd, ok, err)
	}

	// A file that did not parse moves nothing.
	if err := db.SaveRequirementSpecRead(RequirementSpecRead{Found: true, Content: []byte("x")}, nil); err != nil {
		t.Fatal(err)
	}
	if snap2, _ := db.RequirementSpecSnapshot(); len(snap2.Base) != 1 {
		t.Errorf("an unparsed read moved the base: %+v", snap2.Base)
	}
	// One requirement gone from both is forgotten.
	if _, err := db.DeleteRequirement(1, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveRequirementSpecRead(RequirementSpecRead{Found: true}, []requirements.Requirement{}); err != nil {
		t.Fatal(err)
	}
	if snap3, _ := db.RequirementSpecSnapshot(); len(snap3.Base) != 0 {
		t.Errorf("a requirement deleted on both sides kept its base: %+v", snap3.Base)
	}

	// What is read back is bounded, whoever wrote it.
	if _, err := db.conn.Exec(`UPDATE requirement_spec_files SET content = ? WHERE slot = 'read'`,
		make([]byte, requirements.MaxSpecFileBytes+1)); err != nil {
		t.Fatal(err)
	}
	if rd, _, _ := db.RequirementSpecRead(); rd.Content != nil || rd.Error == "" {
		t.Errorf("an oversized stored file read back %d bytes, error %q", len(rd.Content), rd.Error)
	}
	if err := db.SaveRequirementSpecRead(RequirementSpecRead{Content: make([]byte, requirements.MaxSpecFileBytes+1)}, nil); err == nil {
		t.Error("an oversized file was stored")
	}
	if _, err := db.conn.Exec(`INSERT INTO requirement_spec_base (requirement_id, definition) VALUES (9, 'not json'),
		(10, '{"title": ""}')`); err != nil {
		t.Fatal(err)
	}
	if snap4, err := db.RequirementSpecSnapshot(); err != nil || len(snap4.Base) != 0 {
		t.Errorf("unreadable base rows were taken: %+v %v", snap4.Base, err)
	}
}
