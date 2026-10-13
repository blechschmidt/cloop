package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/auditforward"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runForwarder forwards dir's chain to sinks until stop is called.
func runForwarder(t *testing.T, dir string, sinks ...config.AuditForwardSink) (stop func()) {
	t.Helper()
	cp, _ := filepath.Abs(state.DBPath(dir))
	fwd, err := auditforward.New(auditforward.Options{
		ControlPlane: cp,
		Config: func() (config.AuditForwardConfig, error) {
			return config.AuditForwardConfig{Sinks: sinks}, nil
		},
		Chains: func() []auditforward.Chain {
			return []auditforward.Chain{{Source: auditforward.SourceControlPlane, Dir: dir, Path: cp}}
		},
		Poll:       20 * time.Millisecond,
		ConfigPoll: 50 * time.Millisecond,
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fwd.Run(ctx)
	}()
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)
	return stop
}

func cursorAt(t *testing.T, dir, sink string) int64 {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cp, _ := filepath.Abs(state.DBPath(dir))
	c, _, err := db.AuditForwardCursorFor(sink, cp)
	if err != nil {
		t.Fatal(err)
	}
	return c.AckedID
}

func headID(t *testing.T, dir string) int64 {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.MaxAuditID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Rows deleted from state.db after they were forwarded are still at the sink —
// whole, verifiable — and `cloop hub audit verify --checkpoints` names the
// truncation in the chain they were deleted from (Task 20426).
func TestRowsDeletedAfterForwardingStayAtTheSinkAndCheckpointsCatchIt(t *testing.T) {
	t.Setenv(auditcheckpoint.EnvKey, "cmd-forward-test-key-0123456789abcdef0123")
	key, err := auditcheckpoint.KeyFromRoots()
	if err != nil {
		t.Fatal(err)
	}
	hub, project := auditDir(t), auditDir(t)
	appendAudit(t, hub, 12, auditaction.ActionExecutorCordon)
	appendAudit(t, project, 3, auditaction.ActionTaskUpsert)

	sinkFile := filepath.Join(t.TempDir(), "siem.jsonl")
	stop := runForwarder(t, hub, config.AuditForwardSink{Name: "siem", Type: config.AuditSinkFile, Path: sinkFile})
	waitUntil(t, 20*time.Second, "the sink to acknowledge the whole chain", func() bool {
		return headID(t, hub) > 12 && cursorAt(t, hub, "siem") == headID(t, hub)
	})
	stop()
	head := headID(t, hub)

	// The leader's checkpoint of the head, sealed off the database.
	cps := filepath.Join(t.TempDir(), "checkpoints.jsonl")
	path, _ := filepath.Abs(state.DBPath(hub))
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := db.AuditHead()
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	rec := auditcheckpoint.HeadRecord(h, auditcheckpoint.ChainControlPlane, path, auditcheckpoint.ReasonInterval, 1, "m", time.Now().Add(time.Second))
	key.Seal(&rec)
	if err := (auditcheckpoint.Sink{File: cps}).Write([]auditcheckpoint.Record{rec}); err != nil {
		t.Fatal(err)
	}

	// Someone who can write the database deletes the newest rows.
	rawDB(t, state.DBPath(hub), `DELETE FROM audit_events WHERE id > 8`)

	f, err := os.Open(sinkFile)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := auditforward.VerifyStream(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Chains) != 1 || !rep.Chains[0].OK() || rep.Chains[0].LastID != head || rep.Chains[0].FirstID != 1 {
		t.Fatalf("the sink should still hold ids 1…%d, whole: %+v", head, rep.Chains)
	}

	code, out := runVerify(t, hubAuditVerifyOptions{Hub: hub, Project: project, CheckpointsFile: cps})
	if code != auditExitBroken {
		t.Fatalf("a chain truncated after forwarding exited %d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "tail truncated after id 8") {
		t.Errorf("verify does not name the truncation:\n%s", out)
	}
}

// `cloop hub audit prune` stops at the newest row every audit sink has
// acknowledged, says which sink held the rest, and removes it only when
// forced.
func TestHubAuditPruneStopsAtTheSlowestSink(t *testing.T) {
	hub := auditDir(t)
	appendAudit(t, hub, 10, auditaction.ActionExecutorCordon)
	sinkFile := filepath.Join(t.TempDir(), "siem.jsonl")
	stop := runForwarder(t, hub,
		config.AuditForwardSink{Name: "siem", Type: config.AuditSinkFile, Path: sinkFile, BatchSize: 4})
	waitUntil(t, 20*time.Second, "the sink to acknowledge the first rows", func() bool { return cursorAt(t, hub, "siem") >= 4 })
	stop()
	acked := cursorAt(t, hub, "siem")
	appendAudit(t, hub, 5, auditaction.ActionExecutorCordon)

	t.Chdir(hub)
	defer func() {
		hubAuditPruneBefore, hubAuditPruneExportDir, hubAuditPruneForce = "", "", false
	}()
	hubAuditPruneBefore = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	hubAuditPruneExportDir = t.TempDir()
	out, err := captureStdout(t, func() error { return hubAuditPruneCmd.RunE(hubAuditPruneCmd, nil) })
	if err != nil {
		t.Fatalf("prune: %v\n%s", err, out)
	}
	if !strings.Contains(out, `audit sink "siem" has acknowledged only through id`) {
		t.Errorf("the prune does not say which sink held it:\n%s", out)
	}
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	h, err := db.AuditHead()
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if h.FirstID != acked+1 {
		t.Fatalf("the chain starts at id %d; a prune held by a sink at %d must stop there", h.FirstID, acked)
	}

	hubAuditPruneForce = true
	out, err = captureStdout(t, func() error { return hubAuditPruneCmd.RunE(hubAuditPruneCmd, nil) })
	if err != nil {
		t.Fatalf("forced prune: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Forced past what audit sink(s) siem") {
		t.Errorf("the forced prune does not say whose rows it removed:\n%s", out)
	}
}
