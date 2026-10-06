package hubdoctor

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runProject makes a project whose run-owner record says owner.
func runProject(t *testing.T, owner *runbuild.Owner) string {
	t.Helper()
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if owner != nil {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SaveRunOwner(owner); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}
	return dir
}

func TestRunBuildsWarnsAboutARunBehindThisHub(t *testing.T) {
	hub := runbuild.Build{Version: "dev+g89510f3", Sequence: 963, Schema: 59}
	behind := runProject(t, &runbuild.Owner{Ident: runbuild.Ident{PID: 101, StartTicks: 7, BootID: "boot"}, Executor: "localprocess", Adoptable: true,
		Build: runbuild.Build{Version: "dev+g4e35bf6", Sequence: 831}, StartedAt: time.Now()})
	level := runProject(t, &runbuild.Owner{Ident: runbuild.Ident{PID: 102, StartTicks: 7, BootID: "boot"}, Executor: "localprocess", Adoptable: true,
		Build: hub})
	container := runProject(t, &runbuild.Owner{Ident: runbuild.Ident{PID: 103, StartTicks: 7, BootID: "boot"}, Executor: "container",
		Build: runbuild.Build{Version: "dev+g1111111", Sequence: 960}})
	unreported := runProject(t, nil)
	// A record naming pid 999 from before it was reused.
	stale := runProject(t, &runbuild.Owner{Ident: runbuild.Ident{PID: 999, StartTicks: 3, BootID: "boot"}, Build: hub})

	oldRuns, oldSelf := hostRuns, selfRunBuild
	t.Cleanup(func() { hostRuns, selfRunBuild = oldRuns, oldSelf })
	id := func(pid int) runbuild.Ident { return runbuild.Ident{PID: pid, StartTicks: 7, BootID: "boot"} }
	hostRuns = func() []hostRun {
		return []hostRun{{id(101), behind}, {id(102), level}, {id(103), container}, {id(104), unreported}, {id(999), stale}}
	}
	selfRunBuild = func() runbuild.Build { return hub }

	var got []Finding
	checkRunBuilds(func(f Finding) { got = append(got, f) })
	if len(got) != 5 {
		t.Fatalf("%d findings, want one per run: %+v", len(got), got)
	}
	want := []struct {
		sev  Severity
		text string
	}{
		{SeverityWarn, "132 builds behind this hub"},
		{SeverityPass, "level with this hub"},
		{SeverityWarn, "3 builds behind this hub"},
		{SeverityWarn, "has not reported its build"},
		{SeverityWarn, "has not reported its build"},
	}
	for i, w := range want {
		f := got[i]
		if f.Check != "runs.build_lag" || f.Severity != w.sev || !strings.Contains(f.Message, w.text) {
			t.Errorf("finding %d = %s %q; want %s mentioning %q", i, f.Severity, f.Message, w.sev, w.text)
		}
	}
	if !strings.Contains(got[0].Remediation, "Adopt at next task boundary") {
		t.Errorf("a host run's remedy = %q", got[0].Remediation)
	}
	if !strings.Contains(got[2].Remediation, "own upgrade path") {
		t.Errorf("a container run's remedy = %q", got[2].Remediation)
	}
}

func TestRunBuildsIsQuietWithNoRuns(t *testing.T) {
	var got []Finding
	checkRunBuilds(func(f Finding) { got = append(got, f) })
	if len(got) != 0 {
		t.Fatalf("findings with no runs: %+v", got)
	}
}

// The doctor reads a project's record without writing to it: no migration,
// no new file.
func TestPeekRunOwnerNeverWrites(t *testing.T) {
	dir := t.TempDir()
	if _, err := statedb.PeekRunOwner(state.DBPath(dir)); err == nil {
		t.Fatal("a missing database was opened")
	}
	if _, err := os.Stat(state.DBPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("peeking created a database: %v", err)
	}
}
