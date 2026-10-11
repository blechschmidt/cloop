package hubdoctor

// An acknowledged restore, as the doctor reports it (Task 20410).

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// A restore the chain agrees with, sealed under the hub's key, is a warning
// that names it — not the failure a truncation is, and not silence either.
func TestAnAcknowledgedRestoreIsAWarning(t *testing.T) {
	const pass = "doctor-restore-key-0123456789abcdef0123"
	t.Setenv(auditcheckpoint.EnvKey, pass)
	key, err := auditcheckpoint.KeyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	dir, dbPath := auditHubDir(t) // ids 1–5
	abs, _ := filepath.Abs(dbPath)
	file := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	cfg := config.Default()
	cfg.Audit.Checkpoints.File = file

	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	backedUp, _ := db.AuditHead()
	for i := 0; i < 4; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{Actor: "t", EventType: string(auditaction.ActionExecutorCordon)}); err != nil {
			t.Fatal(err)
		}
	}
	seen, _ := db.AuditHead()
	t0 := time.Now().UTC()
	lost := auditcheckpoint.HeadRecord(seen, auditcheckpoint.ChainControlPlane, abs, auditcheckpoint.ReasonInterval, 1, "m", t0)
	key.Seal(&lost)

	// Restore to id 5, as `cloop db restore` does: the backup's head, its
	// own row, and a sealed record of both.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM audit_events WHERE id > 5`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	restoredAt := t0.Add(time.Minute)
	if err := db.AppendAuditEvent(&statedb.AuditEvent{Timestamp: restoredAt, Actor: "cli:alice",
		EventType: string(auditaction.ActionAuditRestored), EntityType: "audit"}); err != nil {
		t.Fatal(err)
	}
	after, _ := db.AuditHead()
	x := auditcheckpoint.RestoreFrom(backedUp)
	x.BackupSHA256, x.Sidecar, x.Actor, x.Reason = strings.Repeat("ab", 32), "sealed", "cli:alice", "disk failure"
	x.SupersededID, x.SupersededRowHash, x.SupersededTime = lost.LastID, lost.LastRowHash, lost.Time
	rec := auditcheckpoint.RestoreRecord(after, auditcheckpoint.ChainControlPlane, abs, "hub-1", restoredAt, x)
	key.Seal(&rec)
	if err := (auditcheckpoint.Sink{File: file}).Write([]auditcheckpoint.Record{lost, rec}); err != nil {
		t.Fatal(err)
	}

	f := auditFindings(t, dir, cfg, restoredAt.Add(time.Minute))["audit.checkpoints.chain"]
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "restored (acknowledged): 4 events lost") ||
		!strings.Contains(f.Message, "cli:alice") {
		t.Fatalf("an acknowledged restore: %+v", f)
	}

	// Without the record, the same chain is an incident.
	if err := writeOnly(file, lost); err != nil {
		t.Fatal(err)
	}
	f = auditFindings(t, dir, cfg, restoredAt.Add(time.Minute))["audit.checkpoints.chain"]
	if f.Severity != SeverityFail {
		t.Fatalf("an unrecorded restore: %+v", f)
	}
}

// writeOnly replaces the checkpoint file's contents with recs.
func writeOnly(file string, recs ...auditcheckpoint.Record) error {
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		return err
	}
	return (auditcheckpoint.Sink{File: file}).Write(recs)
}
