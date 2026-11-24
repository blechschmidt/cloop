package agent

// Task 20517: a run holds its project's directory on this device. A helper the
// hub sends meanwhile is started on the directory as the run has it, and a
// second run is refused. Before, every start placed the hub's copy of the
// project there, deleting the run's database from under it.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const sharedTreeDir = "sgx-rust-attestation-4b55a93a"

// treeSeed is a seed for a project holding tasks with the given titles.
func treeSeed(t *testing.T, titles ...string) []byte {
	t.Helper()
	plan := &pm.Plan{Goal: "Attest an enclave"}
	for i, title := range titles {
		plan.Tasks = append(plan.Tasks, &pm.Task{ID: i + 1, Title: title, Status: pm.TaskPending})
	}
	seed, err := projectseed.Build(&state.ProjectState{Goal: plan.Goal, Plan: plan})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return seed
}

// startIn sends a start for handleID in the shared directory and returns the
// agent's answer to it: "" when the workload started, else why not.
func startIn(t *testing.T, cp *controlPlane, handleID, role, runID string, seed []byte, argv []string) string {
	t.Helper()
	labels := map[string]string{executor.LabelRunID: runID, "project": "/mnt/projects/sgx-rust-attestation"}
	if role != "" {
		labels[executor.LabelWorkload] = role
	}
	start, err := remote.NewFrameAt(remote.ProtocolVersion, remote.TypeStart, "start-"+handleID, handleID,
		remote.StartPayload{
			HandleID:    handleID,
			Spec:        executor.Spec{WorkDir: sharedTreeDir, Argv: argv, Labels: labels},
			ProjectSeed: seed,
		})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(start)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for the answer to %s: %v", handleID, err)
		}
		switch {
		case f.Type == remote.TypeStarted && f.Handle == handleID:
			sp, err := remote.DecodeStarted(f)
			if err != nil {
				t.Fatalf("DecodeStarted: %v", err)
			}
			return sp.Error
		case f.Type == remote.TypeError && f.ID == "start-"+handleID:
			return "error frame: " + string(f.Payload)
		}
	}
	t.Fatalf("no answer to the start of %s", handleID)
	return ""
}

// untilEnded reads frames until handleID's terminal status, and returns what
// it printed and whether it sent a project result.
func untilEnded(t *testing.T, cp *controlPlane, handleID string) (output string, projectResult bool) {
	t.Helper()
	var out strings.Builder
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for %s to end: %v", handleID, err)
		}
		if f.Handle != handleID {
			continue
		}
		switch f.Type {
		case remote.TypeLogChunk:
			if c, err := remote.DecodeLogChunk(f); err == nil {
				out.WriteString(c.Text)
			}
		case remote.TypeProjectResult:
			projectResult = true
		case remote.TypeStatus:
			if st, err := remote.DecodeStatus(f); err == nil && st.Status.State.Terminal() {
				return out.String(), projectResult
			}
		}
	}
	t.Fatalf("%s never ended", handleID)
	return "", false
}

// heldRun is a run's workload: it puts its own database in place of the
// seed's, then works until the test drops a release file beside it.
func heldRun() []string {
	return []string{"/bin/sh", "-c",
		"rm -f .cloop/state.db && echo the-run-s-own-database > .cloop/state.db && " +
			"while [ ! -e release ]; do sleep 0.05; done"}
}

// waitFile waits for path to hold want.
func waitFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never held %q", path, want)
}

func TestAHelperBesideARunUsesTheRunsDirectoryAsItIs(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "work")
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", remote.ProtocolVersion)

	project := filepath.Join(root, sharedTreeDir)
	runSeed := treeSeed(t, "Fix the OutOfDateConfigurationNeeded issue.")
	if why := startIn(t, cp, "h-run", executor.WorkloadRun, "run_device", runSeed, heldRun()); why != "" {
		t.Fatalf("the run was refused: %s", why)
	}
	db := filepath.Join(project, ".cloop", "state.db")
	waitFile(t, db, "the-run-s-own-database")
	placed, err := os.ReadFile(filepath.Join(project, ".cloop", projectseed.SeedFileName))
	if err != nil {
		t.Fatal(err)
	}

	// The Requirements tab opens on the hub, whose copy of the project now
	// holds a task added since the run started.
	hubSeed := treeSeed(t, "Fix the OutOfDateConfigurationNeeded issue.",
		"Add a GitHub Action to run an integration test against sgx-playground")
	why := startIn(t, cp, "h-spec-read", executor.WorkloadHelper, "run_helper", hubSeed,
		[]string{"/bin/sh", "-c", "cat .cloop/state.db"})
	if why != "" {
		t.Fatalf("the helper beside the run was refused: %s", why)
	}
	out, result := untilEnded(t, cp, "h-spec-read")
	if !strings.Contains(out, "the-run-s-own-database") {
		t.Errorf("the helper read %q, want the run's own database", out)
	}
	if result {
		t.Error("the helper sent a project result: the run's directory read back as the helper's")
	}

	// The run's directory is as the run left it.
	if b, _ := os.ReadFile(db); strings.TrimSpace(string(b)) != "the-run-s-own-database" {
		t.Fatalf("the run's database is now %q: the helper placed the hub's copy over it", b)
	}
	if b, _ := os.ReadFile(filepath.Join(project, ".cloop", projectseed.SeedFileName)); string(b) != string(placed) {
		t.Error("the helper rewrote the seed the run started from")
	}
	if rec, ok := artifact.LoadSandboxRun(project); !ok || rec.RunID != "run_device" {
		t.Errorf("placement record = %+v (found %v), want the run's own", rec, ok)
	}

	// The run ends and is read back as its own.
	if err := os.WriteFile(filepath.Join(project, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, result := untilEnded(t, cp, "h-run"); !result {
		t.Error("the run's project was not read back")
	}

	// With no run in it, a helper prepares the directory as before.
	if why := startIn(t, cp, "h-later", executor.WorkloadHelper, "run_later", hubSeed,
		[]string{"/bin/sh", "-c", "test ! -e .cloop/state.db && echo seeded"}); why != "" {
		t.Fatalf("a helper with no run beside it was refused: %s", why)
	}
	if out, _ := untilEnded(t, cp, "h-later"); !strings.Contains(out, "seeded") {
		t.Errorf("with no run, the helper found %q; the directory was not prepared for it", out)
	}
}

func TestASecondRunInARunsDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "work")
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", remote.ProtocolVersion)

	project := filepath.Join(root, sharedTreeDir)
	seed := treeSeed(t, "Push your implementation to a branch named feat/rust")
	if why := startIn(t, cp, "h-first", executor.WorkloadRun, "run_first", seed, heldRun()); why != "" {
		t.Fatalf("the first run was refused: %s", why)
	}
	waitFile(t, filepath.Join(project, ".cloop", "state.db"), "the-run-s-own-database")

	why := startIn(t, cp, "h-second", executor.WorkloadRun, "run_second", seed, []string{"/bin/true"})
	if !strings.Contains(why, "still working in") || !strings.Contains(why, "h-first") {
		t.Fatalf("a second run in the directory = %q, want refused naming the first", why)
	}
	if _, ok := a.workload("h-second"); ok {
		t.Error("the refused run kept its slot")
	}

	// A workload from a hub that labels nothing is started as before.
	if why := startIn(t, cp, "h-unlabelled", "", "run_old_hub", nil, []string{"/bin/true"}); why != "" {
		t.Errorf("an unlabelled workload was refused: %s", why)
	}
	untilEnded(t, cp, "h-unlabelled")

	if err := os.WriteFile(filepath.Join(project, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	untilEnded(t, cp, "h-first")
	// Once the first is over, the directory takes the next run.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, held := a.workload("h-first"); !held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first run was never forgotten")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if why := startIn(t, cp, "h-third", executor.WorkloadRun, "run_third", seed, []string{"/bin/true"}); why != "" {
		t.Fatalf("a run after the first ended was refused: %s", why)
	}
	untilEnded(t, cp, "h-third")
}

// TestOneWorkloadPreparesADirectoryAtATime: between a start and its directory
// being ready — a fetch can take minutes — a second labelled start for the
// directory waits. A helper that waited for a run then shares what the run
// made; a run that waited for a helper prepares it again, so nothing the
// helper does to the directory lands on the run after it has started.
func TestOneWorkloadPreparesADirectoryAtATime(t *testing.T) {
	a := &Agent{workloads: map[string]*workload{}}
	add := func(id string) *workload {
		wl := &workload{handleID: id}
		a.mu.Lock()
		a.workloads[id] = wl
		a.mu.Unlock()
		return wl
	}
	claimAsync := func(wl *workload, dir, role string) <-chan treeClaim {
		out := make(chan treeClaim, 1)
		go func() { out <- a.claimTree(context.Background(), wl, dir, role) }()
		return out
	}
	stillWaiting := func(ch <-chan treeClaim, who string) {
		t.Helper()
		select {
		case c := <-ch:
			t.Fatalf("%s did not wait: %+v", who, c)
		case <-time.After(100 * time.Millisecond):
		}
	}
	got := func(ch <-chan treeClaim, who string) treeClaim {
		t.Helper()
		select {
		case c := <-ch:
			return c
		case <-time.After(5 * time.Second):
			t.Fatalf("%s is still waiting", who)
			return treeClaim{}
		}
	}

	run := add("h-run")
	if c := a.claimTree(context.Background(), run, "/work/p", executor.WorkloadRun); c.refusal != "" || c.share {
		t.Fatalf("the run's own claim = %+v", c)
	}
	// A helper while the run prepares waits, and shares once it is ready.
	helper := add("h-helper")
	waiting := claimAsync(helper, "/work/p", executor.WorkloadHelper)
	stillWaiting(waiting, "a helper while the run prepares")
	a.markTreeReady(run)
	if c := got(waiting, "the helper"); !c.share || c.holder != "h-run" {
		t.Fatalf("the helper once the run was ready = %+v, want it to share the run's directory", c)
	}
	// A second run is refused, prepared or not.
	if c := a.claimTree(context.Background(), add("h-second"), "/work/p", executor.WorkloadRun); !strings.Contains(c.refusal, "still working in") {
		t.Fatalf("a second run = %+v, want refused", c)
	}
	// Once the run's outcome is read back the directory is free.
	a.releaseTree(run)
	next := add("h-next")
	if c := a.claimTree(context.Background(), next, "/work/p", executor.WorkloadRun); c.refusal != "" || c.share {
		t.Fatalf("a run after the first released its directory = %+v", c)
	}
	a.markTreeReady(next)
	a.releaseTree(next)

	// A run while a helper prepares waits for it, then prepares again.
	fetching := add("h-fetching")
	if c := a.claimTree(context.Background(), fetching, "/work/q", executor.WorkloadHelper); c.share || c.refusal != "" {
		t.Fatalf("a helper alone = %+v", c)
	}
	late := add("h-late-run")
	waiting = claimAsync(late, "/work/q", executor.WorkloadRun)
	stillWaiting(waiting, "a run while a helper prepares")
	a.markTreeReady(fetching)
	if c := got(waiting, "the run"); c.share || c.refusal != "" {
		t.Fatalf("the run once the helper was ready = %+v, want it to prepare the directory", c)
	}
	// And a helper that was forgotten while preparing — its start failed —
	// lets a waiting start go on too.
	failing := add("h-failing")
	if c := a.claimTree(context.Background(), failing, "/work/r", executor.WorkloadHelper); c.refusal != "" {
		t.Fatalf("a helper alone = %+v", c)
	}
	waiting = claimAsync(add("h-after-failure"), "/work/r", executor.WorkloadHelper)
	stillWaiting(waiting, "a helper while another prepares")
	a.mu.Lock()
	delete(a.workloads, failing.handleID)
	endPreparingLocked(failing)
	a.mu.Unlock()
	if c := got(waiting, "the second helper"); c.share || c.refusal != "" {
		t.Fatalf("after the first helper failed = %+v, want it to prepare the directory", c)
	}

	// A stop ends the wait and refuses the start.
	busy := add("h-busy")
	if c := a.claimTree(context.Background(), busy, "/work/s", executor.WorkloadRun); c.refusal != "" {
		t.Fatalf("a run alone = %+v", c)
	}
	stopped := add("h-stopped")
	waiting = claimAsync(stopped, "/work/s", executor.WorkloadHelper)
	stillWaiting(waiting, "a helper while the run prepares")
	stopped.cancelProvisioning()
	if c := got(waiting, "the stopped helper"); !strings.Contains(c.refusal, "stopped while it waited") {
		t.Fatalf("a helper stopped while it waited = %+v, want refused", c)
	}

	// Elsewhere, or unlabelled, nothing is shared, refused or waited for.
	if c := a.claimTree(context.Background(), add("h-other"), "/work/t", executor.WorkloadHelper); c.share || c.refusal != "" {
		t.Errorf("a helper in another directory = %+v", c)
	}
	if c := a.claimTree(context.Background(), add("h-old"), "/work/s", ""); c.share || c.refusal != "" {
		t.Errorf("an unlabelled workload = %+v, want it started as before", c)
	}
}
