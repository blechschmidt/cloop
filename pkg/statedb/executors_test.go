package statedb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// openTestDB is shared with kill_requests_test.go.

func TestExecutorUpsertAndGet(t *testing.T) {
	db := openTestDB(t)

	created := time.Now().Add(-2 * time.Hour).Truncate(time.Millisecond)
	beat := time.Now().Truncate(time.Millisecond)
	row := ExecutorRow{
		ID:            "edge-01",
		Name:          "Berlin edge box",
		Kind:          "remote",
		Endpoint:      "wss://edge-01.internal/agent",
		Status:        ExecutorStatusOnline,
		Capabilities:  json.RawMessage(`{"isolation":"remote","supports_stream":true}`),
		Labels:        map[string]string{"region": "eu-central", "arch": "arm64"},
		LastHeartbeat: beat,
		CreatedAt:     created,
		EnrolledBy:    "oidc|alice",
	}
	if err := db.UpsertExecutor(row); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}

	got, err := db.GetExecutor("edge-01")
	if err != nil {
		t.Fatalf("GetExecutor: %v", err)
	}
	if got.Name != row.Name || got.Kind != row.Kind || got.Endpoint != row.Endpoint {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if got.Status != ExecutorStatusOnline {
		t.Errorf("Status = %q, want online", got.Status)
	}
	if got.EnrolledBy != "oidc|alice" {
		t.Errorf("EnrolledBy = %q, want oidc|alice", got.EnrolledBy)
	}
	if got.Labels["region"] != "eu-central" || got.Labels["arch"] != "arm64" {
		t.Errorf("Labels = %v, want the two enrolled labels", got.Labels)
	}
	var caps map[string]any
	if err := json.Unmarshal(got.Capabilities, &caps); err != nil {
		t.Fatalf("capabilities did not survive as JSON: %v", err)
	}
	if caps["isolation"] != "remote" {
		t.Errorf("capabilities.isolation = %v, want remote", caps["isolation"])
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, created)
	}
	if !got.LastHeartbeat.Equal(beat) {
		t.Errorf("LastHeartbeat = %v, want %v", got.LastHeartbeat, beat)
	}

	// Upsert must update in place and preserve the original enrollment date:
	// re-enrolling an agent is not a new enrollment.
	row.Name = "Berlin edge box (renamed)"
	row.Status = ExecutorStatusDegraded
	row.CreatedAt = time.Now()
	if err := db.UpsertExecutor(row); err != nil {
		t.Fatalf("second UpsertExecutor: %v", err)
	}
	got, err = db.GetExecutor("edge-01")
	if err != nil {
		t.Fatalf("GetExecutor after update: %v", err)
	}
	if got.Name != "Berlin edge box (renamed)" || got.Status != ExecutorStatusDegraded {
		t.Errorf("update not applied: %+v", got)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt was rewritten to %v; want the original %v", got.CreatedAt, created)
	}

	if all, err := db.ListExecutors(); err != nil || len(all) != 1 {
		t.Fatalf("ListExecutors = (%d rows, %v), want (1, nil)", len(all), err)
	}
}

func TestExecutorValidationAndMissingRows(t *testing.T) {
	db := openTestDB(t)

	if err := db.UpsertExecutor(ExecutorRow{Kind: "remote"}); err == nil {
		t.Error("UpsertExecutor with a blank ID succeeded, want error")
	}
	if err := db.UpsertExecutor(ExecutorRow{ID: "x"}); err == nil {
		t.Error("UpsertExecutor with a blank kind succeeded, want error")
	}
	if _, err := db.GetExecutor("ghost"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("GetExecutor(unknown) = %v, want ErrExecutorNotFound", err)
	}
	if err := db.TouchExecutorHeartbeat("ghost", ExecutorStatusOnline, time.Now()); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("heartbeat for an unknown executor = %v, want ErrExecutorNotFound", err)
	}

	// Status defaults to unknown rather than an empty string, so a listing
	// never shows a blank health column.
	if err := db.UpsertExecutor(ExecutorRow{ID: "bare", Kind: "container"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	got, err := db.GetExecutor("bare")
	if err != nil {
		t.Fatalf("GetExecutor: %v", err)
	}
	if got.Status != ExecutorStatusUnknown {
		t.Errorf("default Status = %q, want unknown", got.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be stamped when omitted")
	}
	if !got.LastHeartbeat.IsZero() {
		t.Errorf("LastHeartbeat = %v, want zero for an executor that never beat", got.LastHeartbeat)
	}
}

func TestExecutorHeartbeat(t *testing.T) {
	db := openTestDB(t)
	if err := db.UpsertExecutor(ExecutorRow{ID: "edge", Kind: "remote", Status: ExecutorStatusUnknown}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}

	beat := time.Now().Truncate(time.Millisecond)
	if err := db.TouchExecutorHeartbeat("edge", "", beat); err != nil {
		t.Fatalf("TouchExecutorHeartbeat: %v", err)
	}
	got, err := db.GetExecutor("edge")
	if err != nil {
		t.Fatalf("GetExecutor: %v", err)
	}
	if got.Status != ExecutorStatusOnline {
		t.Errorf("Status = %q, want online (empty status defaults to online)", got.Status)
	}
	if !got.LastHeartbeat.Equal(beat) {
		t.Errorf("LastHeartbeat = %v, want %v", got.LastHeartbeat, beat)
	}

	if err := db.TouchExecutorHeartbeat("edge", ExecutorStatusDegraded, time.Time{}); err != nil {
		t.Fatalf("TouchExecutorHeartbeat(degraded): %v", err)
	}
	got, _ = db.GetExecutor("edge")
	if got.Status != ExecutorStatusDegraded {
		t.Errorf("Status = %q, want degraded", got.Status)
	}
	if got.LastHeartbeat.IsZero() {
		t.Error("a zero timestamp should default to now, not clear the heartbeat")
	}
}

func TestProjectExecutorBinding(t *testing.T) {
	db := openTestDB(t)
	if err := db.UpsertExecutor(ExecutorRow{ID: "sandbox", Kind: "container"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	if err := db.UpsertExecutor(ExecutorRow{ID: "edge", Kind: "remote"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}

	// Unbound projects report "no binding", which the registry reads as
	// "use the default" — distinct from an error.
	id, ok, err := db.ProjectExecutor("/srv/app")
	if err != nil {
		t.Fatalf("ProjectExecutor: %v", err)
	}
	if ok || id != "" {
		t.Fatalf("unbound project reported binding %q", id)
	}

	if err := db.BindProjectExecutor("/srv/app", "sandbox", "oidc|alice"); err != nil {
		t.Fatalf("BindProjectExecutor: %v", err)
	}
	id, ok, err = db.ProjectExecutor("/srv/app")
	if err != nil || !ok || id != "sandbox" {
		t.Fatalf("ProjectExecutor = (%q, %v, %v), want (sandbox, true, nil)", id, ok, err)
	}

	// Rebinding replaces rather than duplicating.
	if err := db.BindProjectExecutor("/srv/app", "edge", "oidc|bob"); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	bindings, err := db.ListProjectExecutorBindings()
	if err != nil {
		t.Fatalf("ListProjectExecutorBindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("rebind produced %d rows, want 1", len(bindings))
	}
	if bindings[0].ExecutorID != "edge" || bindings[0].BoundBy != "oidc|bob" {
		t.Errorf("binding = %+v, want edge/oidc|bob", bindings[0])
	}
	if bindings[0].BoundAt.IsZero() {
		t.Error("BoundAt not recorded")
	}

	// Binding to an unknown executor is refused, so a typo cannot strand a
	// project on a backend that will never resolve.
	if err := db.BindProjectExecutor("/srv/other", "typo", ""); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("bind to unknown executor = %v, want ErrExecutorNotFound", err)
	}
	if err := db.BindProjectExecutor("", "edge", ""); err == nil {
		t.Error("bind with a blank project path succeeded, want error")
	}
	if err := db.BindProjectExecutor("/srv/app", "  ", ""); err == nil {
		t.Error("bind with a blank executor id succeeded, want error")
	}

	if err := db.UnbindProjectExecutor("/srv/app"); err != nil {
		t.Fatalf("UnbindProjectExecutor: %v", err)
	}
	if _, ok, _ := db.ProjectExecutor("/srv/app"); ok {
		t.Error("binding survived Unbind")
	}
	// Unbinding an unbound project is not an error.
	if err := db.UnbindProjectExecutor("/srv/never-bound"); err != nil {
		t.Fatalf("UnbindProjectExecutor(unbound) = %v, want nil", err)
	}
}

// TestDeleteExecutorCascadesBindings: leaving a dangling binding behind would
// make every subsequent Resolve for that project fail closed until an
// operator noticed, so removal must clean up.
func TestDeleteExecutorCascadesBindings(t *testing.T) {
	db := openTestDB(t)
	if err := db.UpsertExecutor(ExecutorRow{ID: "sandbox", Kind: "container"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	for _, p := range []string{"/srv/a", "/srv/b"} {
		if err := db.BindProjectExecutor(p, "sandbox", ""); err != nil {
			t.Fatalf("BindProjectExecutor(%s): %v", p, err)
		}
	}

	if err := db.DeleteExecutor("sandbox"); err != nil {
		t.Fatalf("DeleteExecutor: %v", err)
	}
	if _, err := db.GetExecutor("sandbox"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("GetExecutor after delete = %v, want ErrExecutorNotFound", err)
	}
	bindings, err := db.ListProjectExecutorBindings()
	if err != nil {
		t.Fatalf("ListProjectExecutorBindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("%d bindings survived executor deletion: %+v", len(bindings), bindings)
	}
	// Deleting a nonexistent executor is a no-op, not an error.
	if err := db.DeleteExecutor("sandbox"); err != nil {
		t.Fatalf("DeleteExecutor(missing) = %v, want nil", err)
	}
}

func TestExecutorMalformedLabelsDoNotBreakListing(t *testing.T) {
	db := openTestDB(t)
	if err := db.UpsertExecutor(ExecutorRow{ID: "edge", Kind: "remote"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	// Simulate corruption (or a future schema writing a different shape).
	db.mu.Lock()
	_, err := db.conn.Exec(`UPDATE executors SET labels_json = ? WHERE id = ?`, `{not json`, "edge")
	db.mu.Unlock()
	if err != nil {
		t.Fatalf("corrupt labels: %v", err)
	}

	rows, err := db.ListExecutors()
	if err != nil {
		t.Fatalf("ListExecutors with a corrupt label blob = %v; advisory metadata must not break the listing", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Labels != nil {
		t.Errorf("Labels = %v, want nil after dropping an unparseable blob", rows[0].Labels)
	}
}

// TestExecutorsMigrationIsIdempotent: reopening a database must not re-run
// 0010 or duplicate its schema_migrations row, and the tables must survive.
func TestExecutorsMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	firstVersion, err := db.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("CurrentSchemaVersion: %v", err)
	}
	if firstVersion < 10 {
		t.Fatalf("schema version %d after Open, want >= 10 (0010_executors)", firstVersion)
	}
	if err := db.UpsertExecutor(ExecutorRow{ID: "edge", Kind: "remote"}); err != nil {
		t.Fatalf("UpsertExecutor: %v", err)
	}
	if err := db.BindProjectExecutor("/srv/app", "edge", ""); err != nil {
		t.Fatalf("BindProjectExecutor: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen twice: migrations already applied are skipped.
	for i := 0; i < 2; i++ {
		db, err = Open(path)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		v, err := db.CurrentSchemaVersion()
		if err != nil {
			t.Fatalf("CurrentSchemaVersion: %v", err)
		}
		if v != firstVersion {
			t.Fatalf("schema version drifted to %d on reopen %d, want %d", v, i, firstVersion)
		}

		// Exactly one bookkeeping row for our migration.
		db.mu.Lock()
		var n int
		scanErr := db.conn.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 10`).Scan(&n)
		db.mu.Unlock()
		if scanErr != nil {
			t.Fatalf("count schema_migrations: %v", scanErr)
		}
		if n != 1 {
			t.Fatalf("schema_migrations has %d rows for version 10, want 1", n)
		}

		// Data written before the reopen is intact.
		if _, err := db.GetExecutor("edge"); err != nil {
			t.Fatalf("executor row lost across reopen %d: %v", i, err)
		}
		id, ok, err := db.ProjectExecutor("/srv/app")
		if err != nil || !ok || id != "edge" {
			t.Fatalf("binding lost across reopen %d: (%q, %v, %v)", i, id, ok, err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// TestExecutorsMigrationCreatesIndexes locks in the indexes the executor
// list and per-executor project lookups rely on.
func TestExecutorsMigrationCreatesIndexes(t *testing.T) {
	db := openTestDB(t)
	want := []string{
		"idx_executors_kind",
		"idx_executors_status",
		"idx_project_executors_executor",
	}
	for _, name := range want {
		db.mu.Lock()
		var got string
		err := db.conn.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&got)
		db.mu.Unlock()
		if errors.Is(err, sql.ErrNoRows) {
			t.Errorf("index %s was not created by migration 0010", name)
			continue
		}
		if err != nil {
			t.Fatalf("inspect sqlite_master for %s: %v", name, err)
		}
	}
}
