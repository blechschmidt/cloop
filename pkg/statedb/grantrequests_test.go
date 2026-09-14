package statedb

// Storage-level tests for self-service grant requests (Task 20271).
//
// The policy is tested against an in-memory store in pkg/secretbroker. What is
// tested here is the part only a real database can answer: that the migration is
// classified additive so the older hub sharing this control plane keeps working,
// that the expiry UPDATE touches only pending rows, and that task attribution is
// reconciled from live handles without ever overwriting an answer already given.

import (
	"path/filepath"
	"testing"
	"time"
)

func openRequestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestGrantRequestsMigrationIsAdditive is the compatibility gate.
//
// :8080 and :8888 run from the same directory and therefore share one
// control-plane database (and dev builds migrate every registered project's
// state.db). A migration classified breaking makes the older binary refuse to
// open them, which blanks its dashboard until the nightly rebuild — that has
// happened before, with 0034_telemetry, and it is why classifyMigration exists.
//
// This asserts the verdict for *this* migration rather than trusting that two
// CREATE TABLEs "look additive": the classifier is conservative and rejects
// shapes it cannot parse, so a future edit that adds an ALTER, or a UNIQUE index
// over a pre-existing table, must fail here rather than in production at 08:44.
func TestGrantRequestsMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	var found bool
	for _, m := range migrations {
		if m.Version != 37 {
			continue
		}
		found = true
		if got := classifyMigration(m.SQL); got != CompatAdditive {
			t.Errorf("0037 classified %q, want %q.\n"+
				"  A breaking migration here makes every binary older than this one refuse\n"+
				"  to open the shared control-plane database until it is rebuilt.",
				got, CompatAdditive)
		}
	}
	if !found {
		t.Fatal("no migration at version 37 — this test names the wrong version")
	}
}

// TestGrantRequestRoundTrip covers the column set, including the ones that are
// empty in every state but one.
func TestGrantRequestRoundTrip(t *testing.T) {
	db := openRequestDB(t)

	row := GrantRequestRow{
		ID: "req_1", RequestedBy: "alice", SecretID: "sec_1", SecretName: "deploy-pat",
		Kind: "github_pat", SubjectType: "project", SubjectValue: "/srv/app",
		Scope: "ci", ConstraintsJSON: `{"repos":["acme/app"]}`, TTLSeconds: 7200,
		Justification: "shipping INC-2291", State: "pending",
		CreatedAt: "2026-09-14T10:00:00Z", ExpiresAt: "2026-09-17T10:00:00Z",
	}
	if err := db.PutGrantRequest(row); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := db.GetGrantRequest("req_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != row {
		t.Errorf("round trip lost a column:\n got %+v\nwant %+v", got, row)
	}

	// The decided shape, which is where grant_id becomes the join back into
	// broker_grants.
	row.State, row.DecidedBy, row.DecidedAt = "approved", "bob", "2026-09-14T11:00:00Z"
	row.GrantID, row.GrantExpiresAt = "grant_9", "2026-09-14T13:00:00Z"
	row.DecisionNote = "one repo only"
	if err := db.PutGrantRequest(row); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = db.GetGrantRequest("req_1")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.GrantID != "grant_9" || got.State != "approved" || got.DecisionNote != "one repo only" {
		t.Errorf("decided row = %+v", got)
	}

	if _, err := db.GetGrantRequest("req_missing"); err == nil {
		t.Error("an unknown request id must not read as found")
	}
}

// TestExpireTouchesOnlyPendingRows guards the approval-versus-sweep race at the
// SQL level. An expiry that moved an approved row would contradict a credential
// that already exists.
func TestExpireTouchesOnlyPendingRows(t *testing.T) {
	db := openRequestDB(t)
	deadline := "2026-09-14T10:00:00Z"

	for _, tc := range []struct{ id, state string }{
		{"req_pending", "pending"},
		{"req_approved", "approved"},
		{"req_denied", "denied"},
		{"req_withdrawn", "withdrawn"},
	} {
		if err := db.PutGrantRequest(GrantRequestRow{
			ID: tc.id, RequestedBy: "alice", SecretID: "sec_1",
			State: tc.state, CreatedAt: "2026-09-13T10:00:00Z", ExpiresAt: deadline,
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}
	// One with no deadline: the broker always sets one, and a row that
	// deliberately has none must not be swept by a rule it never opted into.
	if err := db.PutGrantRequest(GrantRequestRow{
		ID: "req_forever", RequestedBy: "alice", SecretID: "sec_1",
		State: "pending", CreatedAt: "2026-09-13T10:00:00Z",
	}); err != nil {
		t.Fatalf("seed req_forever: %v", err)
	}

	now := time.Date(2026, 9, 14, 11, 0, 0, 0, time.UTC)
	lapsed, err := db.ExpireGrantRequests(now)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if len(lapsed) != 1 || lapsed[0].ID != "req_pending" {
		t.Fatalf("expired %d row(s) %v, want only req_pending", len(lapsed), idsOf(lapsed))
	}
	if lapsed[0].State != "expired" {
		t.Errorf("the returned row says %q, want expired — callers audit from it", lapsed[0].State)
	}
	for _, id := range []string{"req_approved", "req_denied", "req_withdrawn"} {
		got, gerr := db.GetGrantRequest(id)
		if gerr != nil {
			t.Fatalf("get %s: %v", id, gerr)
		}
		if got.State == "expired" {
			t.Errorf("%s was expired despite already being decided", id)
		}
	}
	if got, _ := db.GetGrantRequest("req_forever"); got.State != "pending" {
		t.Errorf("a request with no deadline became %q", got.State)
	}

	// Idempotent: a second sweep finds nothing, so a janitor running hourly does
	// not re-emit an audit event for every lapse it has already reported.
	again, err := db.ExpireGrantRequests(now)
	if err != nil {
		t.Fatalf("second expire: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a second sweep reported %d row(s), want 0", len(again))
	}
}

// TestRequestUseUpsertPreservesFirstSeen checks the property the ON CONFLICT
// clause exists for: a renewal advances last_seen and must not rewrite when the
// credential came into use. The pair is what bounds how long it was held.
func TestRequestUseUpsertPreservesFirstSeen(t *testing.T) {
	db := openRequestDB(t)

	base := GrantRequestUseRow{
		RequestID: "req_1", LeaseID: "lease_a", GrantID: "grant_9",
		ExecutorID: "edge-1", ProjectPath: "/srv/app",
		FirstSeen: "2026-09-14T10:00:00Z", LastSeen: "2026-09-14T10:00:00Z",
	}
	if err := db.PutGrantRequestUse(base); err != nil {
		t.Fatalf("put: %v", err)
	}
	renewed := base
	renewed.FirstSeen = "2026-09-14T10:15:00Z" // what a naive renewal would write
	renewed.LastSeen = "2026-09-14T10:15:00Z"
	if err := db.PutGrantRequestUse(renewed); err != nil {
		t.Fatalf("renew: %v", err)
	}

	uses, err := db.ListGrantRequestUses("req_1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(uses) != 1 {
		t.Fatalf("a renewal added a row: %d uses, want 1", len(uses))
	}
	if uses[0].FirstSeen != base.FirstSeen {
		t.Errorf("first_seen moved to %q; when a credential came into use is a fact "+
			"a renewal must not rewrite", uses[0].FirstSeen)
	}
	if uses[0].LastSeen != renewed.LastSeen {
		t.Errorf("last_seen = %q, want %q", uses[0].LastSeen, renewed.LastSeen)
	}

	// A later observation carrying no task must not blank an attribution
	// already made — the lease path always writes 0, and it runs repeatedly.
	if err := db.PutGrantRequestUse(GrantRequestUseRow{
		RequestID: "req_1", LeaseID: "lease_a", TaskID: 41,
		FirstSeen: base.FirstSeen, LastSeen: renewed.LastSeen,
	}); err != nil {
		t.Fatalf("attribute: %v", err)
	}
	if err := db.PutGrantRequestUse(renewed); err != nil {
		t.Fatalf("re-renew: %v", err)
	}
	uses, _ = db.ListGrantRequestUses("req_1")
	if uses[0].TaskID != 41 {
		t.Errorf("task_id = %d after a renewal that named no task, want 41 to survive", uses[0].TaskID)
	}
}

// TestAttributeRequestUseTasks covers the reconciliation that answers "which
// task consumed this".
//
// It has to be a reconciliation rather than a write at lease time, because the
// hub leases credentials *before* it dispatches the workload that holds them —
// at lease time there is genuinely no task to name. The handle written at
// dispatch carries both, and this joins them.
func TestAttributeRequestUseTasks(t *testing.T) {
	db := openRequestDB(t)

	for _, u := range []GrantRequestUseRow{
		{RequestID: "req_1", LeaseID: "lease_task", FirstSeen: "2026-09-14T10:00:00Z"},
		{RequestID: "req_2", LeaseID: "lease_run", FirstSeen: "2026-09-14T10:00:00Z"},
		{RequestID: "req_3", LeaseID: "lease_done", TaskID: 7, FirstSeen: "2026-09-14T10:00:00Z"},
	} {
		if err := db.PutGrantRequestUse(u); err != nil {
			t.Fatalf("seed use %s: %v", u.LeaseID, err)
		}
	}

	// A task-scoped dispatch naming the lease it was started with.
	if err := db.PutExecutorHandle(ExecutorHandleRow{
		HandleID: "h1", ExecutorID: "edge-1", Driver: "container", ExternalID: "c1",
		ProjectPath: "/srv/app", TaskID: 41,
		SecretsJSON: `[{"lease_id":"lease_task","env_keys":["GITHUB_TOKEN"]}]`,
	}); err != nil {
		t.Fatalf("seed handle: %v", err)
	}
	// A run-scoped dispatch: no task, so nothing to attribute. This is the
	// ordinary case and must not be mistaken for a failure.
	if err := db.PutExecutorHandle(ExecutorHandleRow{
		HandleID: "h2", ExecutorID: "edge-1", Driver: "container", ExternalID: "c2",
		ProjectPath: "/srv/app", TaskID: 0,
		SecretsJSON: `[{"lease_id":"lease_run"}]`,
	}); err != nil {
		t.Fatalf("seed run handle: %v", err)
	}
	// A handle whose bindings do not decode must be skipped, not fail the sweep.
	if err := db.PutExecutorHandle(ExecutorHandleRow{
		HandleID: "h3", ExecutorID: "edge-1", Driver: "container", ExternalID: "c3",
		TaskID: 99, SecretsJSON: `{not json`,
	}); err != nil {
		t.Fatalf("seed bad handle: %v", err)
	}

	filled, err := db.AttributeRequestUseTasks()
	if err != nil {
		t.Fatalf("attribute: %v", err)
	}
	if filled != 1 {
		t.Errorf("filled %d attribution(s), want 1", filled)
	}

	byLease := map[string]int{}
	uses, err := db.ListGrantRequestUses("")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, u := range uses {
		byLease[u.LeaseID] = u.TaskID
	}
	if byLease["lease_task"] != 41 {
		t.Errorf("lease_task attributed to task %d, want 41", byLease["lease_task"])
	}
	if byLease["lease_run"] != 0 {
		t.Errorf("lease_run attributed to task %d; a run-scoped lease has no task and "+
			"inventing one would misreport what the approval did", byLease["lease_run"])
	}
	if byLease["lease_done"] != 7 {
		t.Errorf("lease_done = %d, want its existing attribution 7 to be left alone",
			byLease["lease_done"])
	}

	// Idempotent: nothing left to fill, and no rewriting of what is there.
	filled, err = db.AttributeRequestUseTasks()
	if err != nil {
		t.Fatalf("second attribute: %v", err)
	}
	if filled != 0 {
		t.Errorf("a second pass filled %d more, want 0", filled)
	}
}

func idsOf(rows []GrantRequestRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}
