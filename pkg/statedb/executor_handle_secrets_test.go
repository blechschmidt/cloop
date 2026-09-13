package statedb

// The secrets_json column added by migration 0031 encodes three states, and
// the difference between two of them is a security property rather than a
// storage detail:
//
//	''      nobody recorded what this workload holds
//	'[]'    it was recorded, and it holds nothing
//	'[…]'   these are the bindings
//
// A driver reading '' marks the adopted handle unresolved and every revocation
// on that executor reports a failure naming it; a driver reading '[]' reports
// an honest nothing-to-revoke. Collapsing them turns "I cannot say whether this
// credential is still in use" into "it is not", which is the bug Task 20231
// exists to close.
//
// The round trip through the adapter is asserted in tests/security. What is
// asserted here is the one thing only an in-package test can reach: that a row
// written *before* the column existed reads back as '' rather than as '[]'.
// That state is produced by the ALTER TABLE's DEFAULT and by nothing else, so
// a migration rewritten to `DEFAULT '[]'` — which looks tidier, and is what a
// reader who has not seen this file would reach for — would silently make
// every pre-upgrade workload report as holding nothing.

import (
	"path/filepath"
	"testing"
	"time"
)

func openHandleDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestExecutorHandleSecretsDefaultsToUnrecorded simulates a row carried across
// the upgrade: written with the pre-0031 column set, read back through the
// normal path.
func TestExecutorHandleSecretsDefaultsToUnrecorded(t *testing.T) {
	db := openHandleDB(t)

	// The insert a pre-0031 binary wrote: every column it knew, and no
	// secrets_json. Raw rather than through PutExecutorHandle, because that
	// function now always supplies the column — which is exactly why it cannot
	// be used to reach this case.
	if _, err := db.conn.Exec(
		`INSERT INTO executor_handles(handle_id, executor_id, driver, external_id,
		                              project_path, task_id, pid, image, meta_json,
		                              started_at, deadline, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		"h-legacy", "exec-1", "localprocess", "4242", "/srv/project", 7, 4242, "",
		"{}", formatOptionalTime(time.Now()), "", formatOptionalTime(time.Now()),
	); err != nil {
		t.Fatalf("insert pre-0031 row: %v", err)
	}

	row, err := db.GetExecutorHandle("h-legacy")
	if err != nil {
		t.Fatalf("GetExecutorHandle: %v", err)
	}
	if row.SecretsJSON != "" {
		t.Fatalf("a row written before secrets_json existed read back as %q, want \"\".\n"+
			"  Anything else — and %q in particular — tells the adopting driver that this\n"+
			"  workload authoritatively holds no leases, so a revocation aimed at it reports\n"+
			"  success while the credential is still in use.", row.SecretsJSON, "[]")
	}

	// And the two recorded states survive verbatim, so the encoding the reader
	// distinguishes is the encoding the writer produces.
	for _, tc := range []struct{ name, json string }{
		{"recorded-empty", "[]"},
		{"recorded-bindings", `[{"lease_id":"lease_a","env_keys":["GITHUB_TOKEN"]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.PutExecutorHandle(ExecutorHandleRow{
				HandleID: "h-" + tc.name, ExecutorID: "exec-1", ExternalID: "1",
				SecretsJSON: tc.json,
			}); err != nil {
				t.Fatalf("PutExecutorHandle: %v", err)
			}
			got, err := db.GetExecutorHandle("h-" + tc.name)
			if err != nil {
				t.Fatalf("GetExecutorHandle: %v", err)
			}
			if got.SecretsJSON != tc.json {
				t.Errorf("secrets_json round-tripped as %q, want %q", got.SecretsJSON, tc.json)
			}
		})
	}

	// ListExecutorHandles is the path rehydration actually uses, so it must
	// carry the column too — a SELECT that forgot it would default every row to
	// unrecorded and make every executor permanently unable to confirm a
	// revocation.
	rows, err := db.ListExecutorHandles("exec-1")
	if err != nil {
		t.Fatalf("ListExecutorHandles: %v", err)
	}
	seen := map[string]string{}
	for _, r := range rows {
		seen[r.HandleID] = r.SecretsJSON
	}
	if got := seen["h-recorded-bindings"]; got == "" {
		t.Errorf("ListExecutorHandles dropped secrets_json for a row that had it: %q", got)
	}
	if got, ok := seen["h-legacy"]; !ok || got != "" {
		t.Errorf("ListExecutorHandles reported the pre-0031 row as %q, want \"\"", got)
	}
}
