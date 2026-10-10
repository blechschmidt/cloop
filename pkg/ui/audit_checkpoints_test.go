package ui

// The leader's audit head checkpoints (Task 20404): one record per chain per
// window, written once cluster-wide, signed when the hub has a key, and a last
// one at clean shutdown.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// checkpointHub is a hub directory and one project, each with audit rows, a
// config sending checkpoints to a file outside both, and a fixed clock.
func checkpointHub(t *testing.T, now *time.Time) (*Server, string, string, string) {
	t.Helper()
	hub, project := statedbtest.Dir(t), statedbtest.Dir(t)
	appendUIAudit(t, hub, 3, auditaction.ActionExecutorCordon)
	appendUIAudit(t, project, 2, auditaction.ActionTaskUpsert)

	file := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	cfg := "audit:\n  checkpoints:\n    interval: 5m\n    file: " + file + "\n    stderr: false\n"
	if err := os.WriteFile(filepath.Join(hub, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := &Server{WorkDir: hub, Projects: []string{project}, Log: &captureLogger{}}
	srv.auditCheckpoints.now = func() time.Time { return *now }
	srv.auditCheckpoints.member = "member-a"
	return srv, hub, project, file
}

func appendUIAudit(t *testing.T, dir string, n int, action auditaction.Action) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < n; i++ {
		if err := db.AppendAuditEvent(&statedb.AuditEvent{Actor: "test", EventType: string(action)}); err != nil {
			t.Fatal(err)
		}
	}
}

func readCheckpoints(t *testing.T, file string) []auditcheckpoint.Located {
	t.Helper()
	res, err := auditcheckpoint.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return res.Records
}

func TestAuditCheckpointsOnePerChainPerWindow(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "ui-checkpoint-key-0123456789abcdef0123")
	key, err := auditcheckpoint.KeyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 12, 2, 0, 0, time.UTC)
	srv, hub, project, file := checkpointHub(t, &now)

	wait := srv.auditCheckpointTick(context.Background())
	if want := 3 * time.Minute; wait != want {
		t.Errorf("waits %s for the next window, want %s", wait, want)
	}
	recs := readCheckpoints(t, file)
	if len(recs) != 2 {
		t.Fatalf("first window wrote %d records, want one per chain: %+v", len(recs), recs)
	}
	hubPath, _ := filepath.Abs(state.DBPath(hub))
	projPath, _ := filepath.Abs(state.DBPath(project))
	byPath := map[string]auditcheckpoint.Record{}
	for _, r := range recs {
		if auditcheckpoint.Check(r.Record, key) != auditcheckpoint.SealValid {
			t.Errorf("record for %s is not sealed under the hub's key", r.Path)
		}
		if r.Member != "member-a" || r.Reason != auditcheckpoint.ReasonInterval || r.Window != now.Unix()/300 {
			t.Errorf("record = %+v", r.Record)
		}
		byPath[r.Path] = r.Record
	}
	if byPath[hubPath].Chain != auditcheckpoint.ChainControlPlane || byPath[hubPath].LastID != 3 {
		t.Errorf("control-plane record = %+v", byPath[hubPath])
	}
	if byPath[projPath].Chain != auditcheckpoint.ChainProject || byPath[projPath].LastID != 2 {
		t.Errorf("project record = %+v", byPath[projPath])
	}

	// The same window again — this member, or a newly elected one — writes
	// nothing: the window is done.
	now = now.Add(time.Minute)
	srv.auditCheckpointTick(context.Background())
	other, _, _, _ := checkpointHubOver(t, hub, project, file, &now, "member-b")
	other.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 2 {
		t.Fatalf("a finished window was written again: %d records", n)
	}

	// The next window, written by the new leader: the control plane always,
	// the project only once its head moves.
	now = now.Add(5 * time.Minute)
	other.auditCheckpointTick(context.Background())
	recs = readCheckpoints(t, file)
	if len(recs) != 4 {
		t.Fatalf("after the next window there are %d records, want 4 (a new leader writes every chain once)", len(recs))
	}
	now = now.Add(5 * time.Minute)
	other.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 5 {
		t.Fatalf("an unchanged project was recorded again, or the control plane was not: %d records", n)
	}
	appendUIAudit(t, project, 1, auditaction.ActionTaskUpsert)
	now = now.Add(5 * time.Minute)
	other.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 7 {
		t.Fatalf("a project whose head moved was not recorded: %d records", n)
	}

	// Clean shutdown records every chain once more.
	other.writeShutdownAuditCheckpoints()
	recs = readCheckpoints(t, file)
	if len(recs) != 9 || recs[8].Reason != auditcheckpoint.ReasonShutdown {
		t.Fatalf("shutdown wrote %d records in all, last %+v", len(recs), recs[len(recs)-1].Record)
	}

	// And every record agrees with its chain.
	for path, group := range auditcheckpoint.ByPath(recs) {
		db, err := statedb.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := auditcheckpoint.VerifyChain(db, path, group[0].Chain, group, key)
		_ = db.Close()
		if err != nil || !rep.OK() {
			t.Errorf("%s fails its own checkpoints: %+v %v", path, rep, err)
		}
	}
}

// checkpointHubOver is a second hub member over the same directories.
func checkpointHubOver(t *testing.T, hub, project, file string, now *time.Time, member string) (*Server, string, string, string) {
	t.Helper()
	srv := &Server{WorkDir: hub, Projects: []string{project}, Log: &captureLogger{}}
	srv.auditCheckpoints.now = func() time.Time { return *now }
	srv.auditCheckpoints.member = member
	return srv, hub, project, file
}

// A leader that claimed a window and died before writing it does not cost the
// window: the next leader waits out the claim, then writes it.
func TestAuditCheckpointWindowIsTakenOverFromADeadLeader(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "")
	now := time.Date(2026, 10, 10, 12, 0, 10, 0, time.UTC)
	srv, hub, _, file := checkpointHub(t, &now)

	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := db.ClaimAuditCheckpointWindow(now.Unix()/300, 5*time.Minute, "died-mid-window", now, auditCheckpointStale); err != nil || !c.Claimed {
		t.Fatal(c, err)
	}
	_ = db.Close()

	now = now.Add(10 * time.Second)
	wait := srv.auditCheckpointTick(context.Background())
	if wait != auditCheckpointStale-10*time.Second {
		t.Errorf("waits %s, want to look again when the claim goes stale (%s)", wait, auditCheckpointStale-10*time.Second)
	}
	if n := len(readCheckpoints(t, file)); n != 0 {
		t.Fatalf("wrote %d records during another member's claim", n)
	}
	now = now.Add(wait)
	srv.auditCheckpointTick(context.Background())
	recs := readCheckpoints(t, file)
	if len(recs) != 2 {
		t.Fatalf("the abandoned window was not written: %d records", len(recs))
	}
	// Without CLOOP_SECRET_KEY the records are unsigned, and say so.
	if recs[0].Signed() {
		t.Errorf("a hub without a key sealed a record: %+v", recs[0].Record)
	}
}

// A control plane that has stopped taking writes cannot hold the window
// marker, and that is when a record of its heads matters most: the window is
// written anyway, once.
func TestAuditCheckpointWrittenUnmarkedWhenTheMarkerCannotBe(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "")
	now := time.Date(2026, 10, 10, 12, 0, 10, 0, time.UTC)
	srv, hub, _, file := checkpointHub(t, &now)

	conn, err := sql.Open("sqlite", state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, stmt := range []string{
		`CREATE TRIGGER refuse_marker_insert BEFORE INSERT ON metadata
		 WHEN NEW.key = 'hub.audit.checkpoint.window' BEGIN SELECT RAISE(ABORT, 'attempt to write a readonly database'); END`,
		`CREATE TRIGGER refuse_marker_update BEFORE UPDATE ON metadata
		 WHEN NEW.key = 'hub.audit.checkpoint.window' BEGIN SELECT RAISE(ABORT, 'attempt to write a readonly database'); END`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}

	wait := srv.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 2 {
		t.Fatalf("with no marker the window wrote %d records, want one per chain", n)
	}
	if want := 4*time.Minute + 50*time.Second; wait != want {
		t.Errorf("waits %s, want the next window (%s)", wait, want)
	}
	// A retry in the same window does not write it again.
	now = now.Add(30 * time.Second)
	srv.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 2 {
		t.Fatalf("the unmarked window was written again: %d records", n)
	}
}

// A leader that dies in the last seconds of a window leaves a claim that goes
// stale only in the next one. The new leader writes the abandoned window late
// and then the current one: no window is skipped.
func TestAuditCheckpointAbandonedWindowIsWrittenLate(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "")
	now := time.Date(2026, 10, 10, 12, 4, 55, 0, time.UTC)
	srv, hub, _, file := checkpointHub(t, &now)

	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	abandoned := now.Unix() / 300
	if c, err := db.ClaimAuditCheckpointWindow(abandoned, 5*time.Minute, "died-at-the-end", now, auditCheckpointStale); err != nil || !c.Claimed {
		t.Fatal(c, err)
	}
	_ = db.Close()

	now = now.Add(10 * time.Second) // 12:05:05, the next window
	wait := srv.auditCheckpointTick(context.Background())
	if n := len(readCheckpoints(t, file)); n != 0 {
		t.Fatalf("wrote %d records during the dead leader's fresh claim", n)
	}
	now = now.Add(wait)
	for i := 0; i < 2; i++ { // the late window, then straight on to the current one
		if wait = srv.auditCheckpointTick(context.Background()); wait > 0 {
			break
		}
	}
	recs := readCheckpoints(t, file)
	windows := map[int64]int{}
	for _, r := range recs {
		windows[r.Window]++
	}
	if windows[abandoned] != 2 || windows[abandoned+1] != 1 {
		t.Fatalf("records per window = %v, want the abandoned window's two chains and the current window's control plane", windows)
	}
}
