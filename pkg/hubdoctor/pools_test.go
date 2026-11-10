package hubdoctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// poolsFixture is a hub directory with executor pools in every state the
// check reports on, as of now.
func poolsFixture(t *testing.T, now time.Time) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := executorpool.NewStore(db.AsControlPlane()).WithClock(func() time.Time { return now })
	mk := func(name string, max int) executorpool.Pool {
		p, err := store.Create(executorpool.Spec{Name: name, MaxRunners: max}, "admin")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	queue := func(p executorpool.Pool, id string, at time.Time) {
		if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: id, PoolID: p.ID, ProjectPath: "/srv/" + id,
			CreatedAt: at, UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	credential := func(p executorpool.Pool, used time.Time, protocol int) string {
		_, cred, err := store.MintCredential(p.ID, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if !used.IsZero() {
			if err := db.TouchExecutorPoolCredential(cred.ID, used); err != nil {
				t.Fatal(err)
			}
			if _, err := db.NoteExecutorPoolController(cred.ID, "v0.0.8", protocol); err != nil {
				t.Fatal(err)
			}
		}
		return cred.ID
	}

	orphan := mk("orphan", 2) // runs wait, and it has no controller credential
	queue(orphan, "o1", now.Add(-time.Minute))

	quiet := mk("quiet", 2) // runs wait, and its controller went quiet
	credential(quiet, now.Add(-time.Hour), executorpool.ControllerProtocol)
	queue(quiet, "q1", now.Add(-time.Minute))

	full := mk("full", 1) // every runner busy, a run waiting for an hour
	credential(full, now.Add(-time.Minute), executorpool.ControllerProtocol)
	cfgs, err := store.MintRunners(full, 1, executorpool.RunnerOptions{Server: "wss://hub/api/executors/connect"})
	if err != nil {
		t.Fatal(err)
	}
	_ = cfgs
	queue(full, "f1", now.Add(-time.Hour))

	stuck := mk("stuck", 3) // its volumes are stuck Pending
	cid := credential(stuck, now.Add(-time.Minute), executorpool.ControllerProtocol)
	if err := db.PutPoolControllerStatus(statedb.PoolControllerStatusRow{PoolID: stuck.ID, CredentialID: cid,
		Reason: "StoragePending", Message: "claim stuck-storage-0 is Pending: no storage class fast",
		ReportedAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	old := mk("old", 2) // its controller predates this hub's protocol
	credential(old, now.Add(-time.Minute), 0)

	fine := mk("fine", 2)
	credential(fine, now.Add(-time.Minute), executorpool.ControllerProtocol)

	gone := mk("gone", 2) // revoked: nothing to say
	queue(gone, "g1", now.Add(-time.Hour))
	if _, err := store.Revoke(gone.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestExecutorPoolFindings: each pool's problems are filed under their own
// check, with its name, and a pool without one passes.
func TestExecutorPoolFindings(t *testing.T) {
	now := time.Now().UTC()
	prev := poolsNow
	poolsNow = func() time.Time { return now }
	t.Cleanup(func() { poolsNow = prev })
	dir := poolsFixture(t, now)

	var got []Finding
	checkExecutorPools(dir, func(f Finding) { got = append(got, f) })
	byPool := map[string][]Finding{}
	for _, f := range got {
		name, _ := f.Details["pool"].(string)
		byPool[name] = append(byPool[name], f)
	}
	want := map[string]struct {
		check    string
		severity Severity
		says     string
	}{
		"orphan": {poolsContactCheck, SeverityFail, "no live controller credential"},
		"quiet":  {poolsContactCheck, SeverityFail, "last contacted the hub 60 minutes ago"},
		"full":   {poolsCapacityCheck, SeverityWarn, "all 1 runners max_runners allows"},
		"stuck":  {poolsStorageCheck, SeverityWarn, "stuck Pending"},
		"old":    {poolsProtocolCheck, SeverityWarn, "names no pool-controller protocol"},
		"fine":   {poolsCheck, SeverityPass, "is live: 0 of 2 runners"},
	}
	for name, w := range want {
		fs := byPool[name]
		if len(fs) != 1 {
			t.Errorf("pool %s: %d findings, want 1: %+v", name, len(fs), fs)
			continue
		}
		f := fs[0]
		if f.Check != w.check || f.Severity != w.severity || !strings.Contains(f.Message, w.says) ||
			f.Title != "Executor pool "+name {
			t.Errorf("pool %s: %s %s %q, want %s %s mentioning %q", name, f.Check, f.Severity, f.Message, w.check,
				w.severity, w.says)
		}
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("pool %s: a %s with no remedy", name, f.Severity)
		}
	}
	if fs := byPool["gone"]; len(fs) != 0 {
		t.Errorf("a revoked pool was reported: %+v", fs)
	}
	if empty := t.TempDir(); true {
		var none []Finding
		checkExecutorPools(empty, func(f Finding) { none = append(none, f) })
		if len(none) != 0 {
			t.Errorf("a hub without a database reported pools: %+v", none)
		}
	}
}

// TestTheHubHealthPanelReportsPools: the dashboard's diagnosis makes the same
// step, so a stuck pool reaches the Hub health panel.
func TestTheHubHealthPanelReportsPools(t *testing.T) {
	now := time.Now().UTC()
	prev := poolsNow
	poolsNow = func() time.Time { return now }
	t.Cleanup(func() { poolsNow = prev })
	dir := poolsFixture(t, now)
	var l Live
	rep := l.Run(context.Background(), dir, hubCfg(), liveOpts())
	found := false
	for _, f := range rep.Findings {
		if f.Check == poolsContactCheck && strings.Contains(f.Message, "orphan") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the live diagnosis has no finding for the orphaned pool: %+v", rep.Findings)
	}
}
