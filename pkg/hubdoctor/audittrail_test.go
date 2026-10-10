package hubdoctor

// The audit trail checks (Task 20404).

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditHubDir is a hub directory with a few audit rows.
func auditHubDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := mustInitStateDB(t, dir)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 5; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{Actor: "t", EventType: string(auditaction.ActionExecutorCordon)}); err != nil {
			t.Fatal(err)
		}
	}
	return dir, path
}

func auditFindings(t *testing.T, dir string, cfg *config.Config, now time.Time) map[string]Finding {
	t.Helper()
	out := map[string]Finding{}
	checkAuditTrail(dir, cfg, Options{Now: func() time.Time { return now }}, func(f Finding) {
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("%s is %s without a remediation: %s", f.Check, f.Severity, f.Message)
		}
		out[f.Check] = f
	})
	return out
}

func TestAuditCheckpointFindings(t *testing.T) {
	dir, dbPath := auditHubDir(t)
	now := time.Now().UTC()

	t.Run("off", func(t *testing.T) {
		off := false
		cfg := config.Default()
		cfg.Audit.Checkpoints.Stderr = &off
		f := auditFindings(t, dir, cfg, now)["audit.checkpoints"]
		if f.Severity != SeverityWarn || !strings.Contains(f.Message, "off") {
			t.Errorf("checkpoints off: %+v", f)
		}
	})

	t.Run("unsigned, stderr only", func(t *testing.T) {
		t.Setenv(auditcheckpoint.EnvKey, "")
		got := auditFindings(t, dir, config.Default(), now)
		if f := got["audit.checkpoints.signed"]; f.Severity != SeverityWarn || !strings.Contains(f.Message, "unsigned") {
			t.Errorf("without a key the doctor must say checkpoints are unsigned: %+v", f)
		}
		if f := got["audit.checkpoints"]; f.Severity != SeverityWarn || !strings.Contains(f.Message, "stderr only") {
			t.Errorf("stderr only: %+v", f)
		}
	})

	t.Run("a file inside .cloop", func(t *testing.T) {
		cfg := config.Default()
		cfg.Audit.Checkpoints.File = filepath.Join(dir, ".cloop", "checkpoints.jsonl")
		if f := auditFindings(t, dir, cfg, now)["audit.checkpoints"]; f.Severity != SeverityFail {
			t.Errorf("a checkpoint file beside the database passed: %+v", f)
		}
	})

	t.Run("signed, fresh and agreeing, then truncated", func(t *testing.T) {
		t.Setenv(auditcheckpoint.EnvKey, "doctor-key-0123456789abcdef0123456789")
		key, err := auditcheckpoint.KeyFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "checkpoints.jsonl")
		cfg := config.Default()
		cfg.Audit.Checkpoints.File = file

		if f := auditFindings(t, dir, cfg, now)["audit.checkpoints"]; f.Severity != SeverityWarn ||
			!strings.Contains(f.Message, "no checkpoint yet") {
			t.Errorf("an empty checkpoint file: %+v", f)
		}

		db, err := statedb.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		head, err := db.AuditHead()
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		abs, _ := filepath.Abs(dbPath)
		// Read after the rows it pins were written, as the hub's always is;
		// the doctor runs a minute later.
		recordedAt := time.Now().UTC()
		now := recordedAt.Add(time.Minute)
		rec := auditcheckpoint.HeadRecord(head, auditcheckpoint.ChainControlPlane, abs,
			auditcheckpoint.ReasonInterval, 1, "m", recordedAt)
		key.Seal(&rec)
		if err := (auditcheckpoint.Sink{File: file}).Write([]auditcheckpoint.Record{rec}); err != nil {
			t.Fatal(err)
		}

		got := auditFindings(t, dir, cfg, now)
		if f := got["audit.checkpoints.signed"]; f.Severity != SeverityPass || !strings.Contains(f.Message, key.Fingerprint()) {
			t.Errorf("signed: %+v", f)
		}
		if f := got["audit.checkpoints"]; f.Severity != SeverityPass {
			t.Errorf("a fresh checkpoint file: %+v", f)
		}
		if f := got["audit.checkpoints.chain"]; f.Severity != SeverityPass {
			t.Errorf("an agreeing chain: %+v", f)
		}

		// Three intervals on, with nothing new written: stale.
		if f := auditFindings(t, dir, cfg, now.Add(time.Hour))["audit.checkpoints"]; f.Severity != SeverityWarn ||
			!strings.Contains(f.Message, "old") {
			t.Errorf("a stale checkpoint: %+v", f)
		}

		raw, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if _, err := raw.Exec(`DELETE FROM audit_events WHERE id > 2`); err != nil {
			t.Fatal(err)
		}
		f := auditFindings(t, dir, cfg, now)["audit.checkpoints.chain"]
		if f.Severity != SeverityFail || !strings.Contains(f.Message, "tail truncated after id 2") {
			t.Errorf("a truncated chain: %+v", f)
		}
	})
}

func TestAuditGapAndUnrecordedFindings(t *testing.T) {
	dir, dbPath := auditHubDir(t)
	now := time.Now().UTC()
	if f := auditFindings(t, dir, config.Default(), now)["audit.gaps"]; f.Severity != SeverityPass {
		t.Errorf("no gaps: %+v", f)
	}
	if f := auditFindings(t, dir, config.Default(), now)["audit.unrecorded"]; f.Severity != SeverityPass {
		t.Errorf("nothing unrecorded: %+v", f)
	}

	// Lose two events through a closed handle, and record them.
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_ = db.AppendAuditEvent(&statedb.AuditEvent{EventType: string(auditaction.ActionExecutorDrain)})
	_ = db.AppendAuditEvent(&statedb.AuditEvent{EventType: string(auditaction.ActionExecutorDrain)})
	statedb.FlushAuditGaps(statedb.GapRecordedByFlush)
	if f := auditFindings(t, dir, config.Default(), now)["audit.gaps"]; f.Severity != SeverityWarn ||
		!strings.Contains(f.Message, "1 audit.gap row(s) recording 2 event(s)") {
		t.Errorf("a recorded gap: %+v", f)
	}

	// A process that died owing the trail left its status file.
	statusDir := statedb.AuditFailureStatusDir(dir)
	if err := os.MkdirAll(statusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	const deadPID = 1 << 30
	body, _ := json.Marshal(statedb.AuditFailureStatus{PID: deadPID, Host: host, Chains: []statedb.AuditChainFailures{{
		Path: dbPath, Unrecorded: statedb.AuditLoss{Events: 7, Appends: 7, FirstAt: now, LastAt: now, LastError: "disk is full"},
	}}})
	if err := os.WriteFile(filepath.Join(statusDir, "h-"+strconv.Itoa(deadPID)+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	f := auditFindings(t, dir, config.Default(), now)["audit.unrecorded"]
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "exited with 7 audit event(s)") {
		t.Errorf("an exited process's unrecorded loss: %+v", f)
	}
}
