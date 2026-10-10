package cmd

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditDir is a directory holding a migrated .cloop/state.db.
func auditDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := state.DBPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	statedbtest.Template().Seed(t, path)
	return dir
}

func appendAudit(t *testing.T, dir string, n int, action auditaction.Action) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < n; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{Actor: "test", EventType: string(action), EntityType: "task"}); err != nil {
			t.Fatal(err)
		}
	}
}

// loseAuditEvents fails n appends to dir's chain — through a handle that was
// closed under its emitter, one real way a row goes missing — and then lets a
// later append record the loss as a gap row.
func loseAuditEvents(t *testing.T, dir string, n int) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	for i := 0; i < n; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{EventType: string(auditaction.ActionTaskUpsert)}); err == nil {
			t.Fatal("an append through a closed handle succeeded")
		}
	}
	appendAudit(t, dir, 1, auditaction.ActionTaskUpsert)
}

func runVerify(t *testing.T, opts hubAuditVerifyOptions) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code, err := runHubAuditVerify(&out, opts)
	if err != nil {
		t.Fatalf("verify could not run: %v\n%s", err, out.String())
	}
	return code, out.String()
}

// cloop hub audit verify exits 0 intact, 3 intact with recorded gaps (0 with
// --allow-gaps), and 2 broken (Task 20404).
func TestHubAuditVerifyExitCodes(t *testing.T) {
	hub, project := auditDir(t), auditDir(t)
	appendAudit(t, hub, 3, auditaction.ActionExecutorCordon)
	appendAudit(t, project, 3, auditaction.ActionTaskUpsert)

	code, out := runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project})
	if code != auditExitIntact || strings.Count(out, "OK ") < 2 {
		t.Fatalf("intact chains: exit %d\n%s", code, out)
	}

	loseAuditEvents(t, project, 4)
	code, out = runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project})
	if code != auditExitGaps {
		t.Fatalf("a chain with a recorded gap exited %d, want 3\n%s", code, out)
	}
	if !strings.Contains(out, "GAPS") || !strings.Contains(out, "1 recorded gap covering 4 lost event(s)") {
		t.Errorf("the gap is not reported:\n%s", out)
	}
	if code, _ := runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, AllowGaps: true}); code != auditExitIntact {
		t.Errorf("--allow-gaps exited %d, want 0", code)
	}

	rawDB(t, state.DBPath(hub), `UPDATE audit_events SET payload='{"x":1}' WHERE id=2`)
	code, out = runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, AllowGaps: true})
	if code != auditExitBroken || !strings.Contains(out, "CHAIN BROKEN") {
		t.Errorf("a broken chain exited %d, want 2 even with --allow-gaps\n%s", code, out)
	}
}

// --checkpoints catches the newest rows of a chain being deleted, covers both
// chains, and refuses a record whose seal does not verify.
func TestHubAuditVerifyAgainstCheckpoints(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "cmd-test-key-0123456789abcdef0123456789")
	key, err := auditcheckpoint.KeyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	hub, project := auditDir(t), auditDir(t)
	appendAudit(t, hub, 4, auditaction.ActionExecutorCordon)
	appendAudit(t, project, 6, auditaction.ActionTaskUpsert)

	file := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	var recs []auditcheckpoint.Record
	for _, c := range []struct{ dir, chain string }{
		{hub, auditcheckpoint.ChainControlPlane}, {project, auditcheckpoint.ChainProject},
	} {
		path, _ := filepath.Abs(state.DBPath(c.dir))
		db, err := statedb.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		head, err := db.AuditHead()
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		r := auditcheckpoint.HeadRecord(head, c.chain, path, auditcheckpoint.ReasonInterval, 1, "m", time.Now().Add(time.Second))
		key.Seal(&r)
		recs = append(recs, r)
	}
	if err := (auditcheckpoint.Sink{File: file}).Write(recs); err != nil {
		t.Fatal(err)
	}

	code, out := runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: file})
	if code != auditExitIntact {
		t.Fatalf("chains that match their checkpoints exited %d\n%s", code, out)
	}
	for _, want := range []string{"control-plane", "project", "saw id 4", "saw id 6"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}

	rawDB(t, state.DBPath(project), `DELETE FROM audit_events WHERE id > 3`)
	code, out = runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: file})
	if code != auditExitBroken {
		t.Fatalf("a truncated project chain exited %d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "tail truncated after id 3 although a checkpoint at") ||
		!strings.Contains(out, "saw id 6") {
		t.Errorf("the truncation is not named:\n%s", out)
	}

	// A forged record — the truncated head, under a seal that is not the
	// key's — is refused rather than believed.
	forged := recs[1]
	forged.LastID = 3
	if err := (auditcheckpoint.Sink{File: file}).Write([]auditcheckpoint.Record{forged}); err != nil {
		t.Fatal(err)
	}
	code, out = runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: file})
	if code != auditExitBroken || !strings.Contains(out, "refused") {
		t.Errorf("a forged checkpoint did not fail verification (exit %d)\n%s", code, out)
	}
}

func TestAuditVerifyExit(t *testing.T) {
	for _, c := range []struct {
		statuses  []string
		allowGaps bool
		want      int
	}{
		{[]string{statedb.AuditChainIntact, statedb.AuditChainIntact}, false, 0},
		{[]string{statedb.AuditChainIntact, statedb.AuditChainGaps}, false, 3},
		{[]string{statedb.AuditChainGaps}, true, 0},
		{[]string{statedb.AuditChainGaps, statedb.AuditChainBroken}, true, 2},
		{[]string{statedb.AuditChainBroken, statedb.AuditChainGaps}, false, 2},
	} {
		if got := auditVerifyExit(c.statuses, c.allowGaps); got != c.want {
			t.Errorf("auditVerifyExit(%v, %v) = %d, want %d", c.statuses, c.allowGaps, got, c.want)
		}
	}
}

// rawDB runs stmt against path behind statedb's back, as someone holding the
// file would.
func rawDB(t *testing.T, path, stmt string) {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}
