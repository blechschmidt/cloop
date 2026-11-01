package statedb

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// auditPayloads are the payloads of the project's rows of action, oldest
// first, with the actor of each.
func auditPayloads(t *testing.T, db *DB, action auditaction.Action) []map[string]any {
	t.Helper()
	rows, _, err := db.ListAuditEvents(AuditFilter{EventType: string(action)})
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, row := range rows {
		p := map[string]any{}
		if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
			t.Fatalf("%s payload %q: %v", action, row.Payload, err)
		}
		p["@actor"] = row.Actor
		out = append(out, p)
	}
	return out
}

// Drafts the model proposed are stored as drafts, all or none, whatever they
// claim; each is a requirement.create naming where it was drafted from, and
// the set one requirement.draft row naming who asked (Task 20462).
func TestAddDraftRequirementsStoresDraftsOnly(t *testing.T) {
	db := openFresh(t)
	addReq(t, db, "already here")
	drafts := []requirements.Requirement{
		{Title: "When a config is malformed, the CLI shall exit 2.", Priority: requirements.PriorityMust,
			Tests: []requirements.Test{{Command: "go test ./pkg/config"}}},
		// A draft that claims to be approved is stored as a draft.
		{Title: "The API shall answer within 200 ms.", Status: requirements.StatusApproved, ApprovedBy: "the model"},
	}
	got, err := db.AddDraftRequirements(drafts, "alice", DraftOrigin{Source: "text", SHA256: "ab", Bytes: 120,
		ExecutorID: "sgx", Via: "dashboard", Refused: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 3 {
		t.Fatalf("stored %+v", got)
	}
	for _, r := range got {
		stored, err := db.Requirement(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != requirements.StatusDraft || stored.ApprovedBy != "" || !stored.ApprovedAt.IsZero() ||
			stored.CreatedBy != "alice" {
			t.Errorf("R-%d stored as %+v", r.ID, stored)
		}
	}
	creates := auditPayloads(t, db, auditaction.ActionRequirementCreate)
	if len(creates) != 3 || creates[1]["drafted"] != "text" || creates[1]["status"] != "draft" || creates[0]["drafted"] != nil {
		t.Errorf("requirement.create rows: %v", creates)
	}
	rows := auditPayloads(t, db, auditaction.ActionRequirementDraft)
	if len(rows) != 1 {
		t.Fatalf("requirement.draft rows: %v", rows)
	}
	r := rows[0]
	if r["@actor"] != "alice" || r["source"] != "text" || r["executor_id"] != "sgx" || r["refused"] != float64(1) ||
		r["via"] != "dashboard" || len(r["ids"].([]any)) != 2 {
		t.Errorf("requirement.draft row: %v", r)
	}

	// A set that does not fit is not stored in part.
	bad := []requirements.Requirement{{Title: "fine"}, {Title: ""}}
	if _, err := db.AddDraftRequirements(bad, "alice", DraftOrigin{Source: "goal"}); !errors.Is(err, requirements.ErrInvalid) {
		t.Errorf("an invalid draft: %v", err)
	}
	if all, _ := db.Requirements(); len(all) != 3 {
		t.Errorf("a refused set left %d requirements", len(all))
	}
}

// Approving is recorded: who and when on the requirement, a requirement.approve
// row — and nothing else changes. Approving twice is not an error; a
// deprecated requirement is not approved here.
func TestApproveRequirementsRecordsTheApprover(t *testing.T) {
	db := openFresh(t)
	drafts, err := db.AddDraftRequirements([]requirements.Requirement{
		{Title: "When a run ends, the hub shall record its exit status.", Tests: []requirements.Test{{Command: "make t"}}},
		{Title: "The CLI shall exit 2 on a malformed config."},
	}, "alice", DraftOrigin{Source: "goal"})
	if err != nil {
		t.Fatal(err)
	}
	approved, already, err := db.ApproveRequirements([]int{drafts[0].ID, drafts[0].ID}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || len(already) != 0 || approved[0].ApprovedBy != "bob" || approved[0].ApprovedAt.IsZero() {
		t.Fatalf("approved %+v, already %v", approved, already)
	}
	r, _ := db.Requirement(drafts[0].ID)
	if r.Status != requirements.StatusApproved || r.ApprovedBy != "bob" || r.ApprovedAt.IsZero() || r.UpdatedBy != "bob" ||
		r.CreatedBy != "alice" || r.Fingerprint() != drafts[0].Fingerprint() {
		t.Fatalf("after approval: %+v", r)
	}
	rows := auditPayloads(t, db, auditaction.ActionRequirementApprove)
	if len(rows) != 1 || rows[0]["@actor"] != "bob" || rows[0]["via"] != "approve" || rows[0]["previous_status"] != "draft" ||
		rows[0]["approved_by"] != "bob" || rows[0]["tests"].([]any)[0] != "make t" {
		t.Fatalf("requirement.approve rows: %v", rows)
	}
	if n := auditCount(t, db, auditaction.ActionRequirementUpdate); n != 0 {
		t.Errorf("an approval wrote %d requirement.update rows", n)
	}

	// Approving every draft again: the one approved stays as it was.
	approved, already, err = db.ApproveRequirements([]int{drafts[0].ID, drafts[1].ID}, "carol")
	if err != nil || len(approved) != 1 || approved[0].ID != drafts[1].ID || len(already) != 1 || already[0] != drafts[0].ID {
		t.Fatalf("approve both: %+v, %v, %v", approved, already, err)
	}
	if r, _ := db.Requirement(drafts[0].ID); r.ApprovedBy != "bob" {
		t.Errorf("approving it again changed its approver to %q", r.ApprovedBy)
	}

	gone := addReq(t, db, "retired")
	gone.Status = requirements.StatusDeprecated
	if _, err := db.UpdateRequirement(gone, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ApproveRequirements([]int{gone.ID}, "bob"); !errors.Is(err, requirements.ErrInvalid) {
		t.Errorf("approving a deprecated requirement: %v", err)
	}
	if _, _, err := db.ApproveRequirements([]int{99}, "bob"); !errors.Is(err, ErrRequirementNotFound) {
		t.Errorf("approving a missing requirement: %v", err)
	}
	if _, _, err := db.ApproveRequirements(nil, "bob"); !errors.Is(err, requirements.ErrInvalid) {
		t.Errorf("approving nothing: %v", err)
	}
}

// Becoming approved by any route is an approval: added approved, edited to
// approved — with a requirement.update for the rest of the edit — and leaving
// approved takes it back.
func TestApprovalByEditAndAdd(t *testing.T) {
	db := openFresh(t)
	added := addReq(t, db, "added approved")
	if added.ApprovedBy != "alice" || added.ApprovedAt.IsZero() {
		t.Fatalf("a requirement added approved: %+v", added)
	}
	if r, _ := db.Requirement(added.ID); r.ApprovedBy != "alice" {
		t.Fatalf("stored: %+v", r)
	}
	if n := auditCount(t, db, auditaction.ActionRequirementApprove); n != 0 {
		t.Errorf("adding a requirement approved wrote %d requirement.approve rows; its create row says it", n)
	}

	draft, err := db.AddRequirement(requirements.Requirement{Title: "a draft", Status: requirements.StatusDraft}, "alice")
	if err != nil || draft.ApprovedBy != "" {
		t.Fatalf("a draft: %+v, %v", draft, err)
	}
	// Edited and approved in one save.
	draft.Status, draft.Title = requirements.StatusApproved, "a draft, edited"
	up, err := db.UpdateRequirement(draft, "bob")
	if err != nil || up.ApprovedBy != "bob" || up.ApprovedAt.IsZero() {
		t.Fatalf("edited to approved: %+v, %v", up, err)
	}
	approvals := auditPayloads(t, db, auditaction.ActionRequirementApprove)
	updates := auditPayloads(t, db, auditaction.ActionRequirementUpdate)
	if len(approvals) != 1 || approvals[0]["via"] != "edit" || len(updates) != 1 ||
		!strings.Contains(strings.Join(anyStrings(updates[0]["changed"]), ","), "title") {
		t.Fatalf("approvals %v, updates %v", approvals, updates)
	}

	// Edited again, still approved: the approver stays.
	up.Description = "more"
	if up, err = db.UpdateRequirement(up, "carol"); err != nil || up.ApprovedBy != "bob" {
		t.Fatalf("an edit of an approved requirement: %+v, %v", up, err)
	}
	// Back to a draft: no approver; approved again: the new one.
	up.Status = requirements.StatusDraft
	if up, err = db.UpdateRequirement(up, "carol"); err != nil || up.ApprovedBy != "" {
		t.Fatalf("back to a draft: %+v, %v", up, err)
	}
	if r, _ := db.Requirement(up.ID); r.ApprovedBy != "" || !r.ApprovedAt.IsZero() {
		t.Fatalf("stored back as a draft: %+v", r)
	}
	up.Status = requirements.StatusApproved
	if up, err = db.UpdateRequirement(up, "dave"); err != nil || up.ApprovedBy != "dave" {
		t.Fatalf("approved again: %+v, %v", up, err)
	}
	if n := auditCount(t, db, auditaction.ActionRequirementApprove); n != 2 {
		t.Errorf("requirement.approve rows = %d, want 2", n)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// A spec file that approves a draft approves it as whoever imported it.
func TestImportThatApprovesRecordsTheImporter(t *testing.T) {
	db := openFresh(t)
	d, err := db.AddRequirement(requirements.Requirement{Title: "drafted", Status: requirements.StatusDraft,
		Tests: []requirements.Test{{Command: "make check"}}}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	file := []requirements.Requirement{{ID: d.ID, Title: "drafted", Status: requirements.StatusApproved,
		Tests: []requirements.Test{{Command: "make check"}}}}
	// Never synced, the hub and the file differ over R-1: the file's is taken.
	if _, err := db.ImportRequirementSpec(RequirementSpecImport{File: file, Resolutions: map[int]string{d.ID: requirements.TakeFile},
		Sync: RequirementSpecSync{Actor: "erin", Source: "cli", Path: requirements.SpecFileName}}); err != nil {
		t.Fatal(err)
	}
	r, err := db.Requirement(d.ID)
	if err != nil || r.Status != requirements.StatusApproved || r.ApprovedBy != "erin" || r.ApprovedAt.IsZero() {
		t.Fatalf("after the import: %+v, %v", r, err)
	}
	rows := auditPayloads(t, db, auditaction.ActionRequirementApprove)
	if len(rows) != 1 || rows[0]["via"] != "import" || rows[0]["@actor"] != "erin" || rows[0]["previous_status"] != "draft" {
		t.Fatalf("requirement.approve rows: %v", rows)
	}
}

// A draft has no verdict until it is approved: nothing checks it, and nobody
// records one by hand.
func TestADraftIsGivenNoVerdict(t *testing.T) {
	db := openFresh(t)
	d, err := db.AddRequirement(requirements.Requirement{Title: "drafted", Status: requirements.StatusDraft}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRequirementVerdict(d.ID, requirements.VerdictFulfilled, "", "bob"); !errors.Is(err, requirements.ErrInvalid) {
		t.Fatalf("a verdict on a draft: %v", err)
	}
	if _, _, err := db.ApproveRequirements([]int{d.ID}, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRequirementVerdict(d.ID, requirements.VerdictFulfilled, "", "bob"); err != nil {
		t.Fatalf("a verdict once approved: %v", err)
	}
}
