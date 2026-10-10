package container

// The container driver's disk limit (Task 20405), without a container runtime:
// the request it resolves, the refusal at Start, the stop a breach triggers and
// the status that reports it, and what survives a restart. The workload half —
// a real sandbox writing past a real limit — is
// TestIntegration_DiskLimitStopsAWorkloadThatWritesPastIt, behind an opt-in.

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/diskwatch"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

func TestBuildRequest_DiskCeilingLowersAStatedRequest(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{DiskMB: 2048})
	ex := fakeExecutor(t, Options{})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir:        "/srv/proj",
		Argv:           []string{"cloop", "run"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 921600}, // 900g from a sandbox.yaml
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.DiskMB != 2048 || req.DiskLimitSource != executor.DiskLimitFromCeiling {
		t.Fatalf("DiskMB = %d from %q, want the ceiling's 2048", req.DiskMB, req.DiskLimitSource)
	}
}

// TestBuildRequest_DiskCeilingFillsAnUnstatedRequest is the case the ceiling
// exists for, and the one that was silently ignored: a project that asked for
// nothing, on an executor an admin capped at 20 GB.
func TestBuildRequest_DiskCeilingFillsAnUnstatedRequest(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	withExecutorCeiling(t, map[string]executor.ResourceCeiling{ex.id: {DiskMB: 20480}})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.DiskMB != 20480 || req.DiskLimitSource != executor.DiskLimitFromCeiling {
		t.Fatalf("DiskMB = %d from %q, want the executor ceiling's 20480", req.DiskMB, req.DiskLimitSource)
	}
	if req.Labels[LabelDiskLimit] != "20480" {
		t.Fatalf("label %s = %q", LabelDiskLimit, req.Labels[LabelDiskLimit])
	}
}

func TestBuildRequest_DiskCeilingNeverRaisesAStatedRequest(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{DiskMB: 20480})
	ex := fakeExecutor(t, Options{})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir:        "/srv/proj",
		Argv:           []string{"x"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 1024},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.DiskMB != 1024 || req.DiskLimitSource != executor.DiskLimitFromSpec {
		t.Fatalf("DiskMB = %d from %q, want the spec's own 1024", req.DiskMB, req.DiskLimitSource)
	}
}

// TestBuildRequest_DiskSourceTravelsWithTheSpec: a device's driver reads no
// ceiling of its own, so the hub's label is how it learns that the limit it
// enforces is an operator's.
func TestBuildRequest_DiskSourceTravelsWithTheSpec(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	ex := fakeExecutor(t, Options{})
	spec := executor.Spec{WorkDir: "/srv/proj", Argv: []string{"x"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 4096}}
	executor.MarkDiskLimitFromCeiling(&spec)
	req, err := ex.buildRequest(spec, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.DiskLimitSource != executor.DiskLimitFromCeiling {
		t.Fatalf("source = %q, want the ceiling's", req.DiskLimitSource)
	}
}

func TestBuildRequest_NoDiskLimitIsNone(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	ex := fakeExecutor(t, Options{})
	req, err := ex.buildRequest(executor.Spec{WorkDir: "/srv/proj", Argv: []string{"x"}}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.DiskMB != 0 || req.DiskLimitSource != "" || req.Labels[LabelDiskLimit] != "" {
		t.Fatalf("an unlimited workload got DiskMB=%d source=%q label=%q", req.DiskMB, req.DiskLimitSource,
			req.Labels[LabelDiskLimit])
	}
	if newDiskLimit(req, "/srv/proj", nil) != nil {
		t.Fatal("an unlimited workload got a disk watchdog")
	}
}

func TestContainerAdvertisesSampledDiskEnforcement(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	if got := ex.Capabilities().DiskEnforcement; got != executor.DiskEnforcementSampled {
		t.Fatalf("DiskEnforcement = %q, want %q", got, executor.DiskEnforcementSampled)
	}
	if executor.CeilingUnenforceable(ex, executor.ResourceCeiling{DiskMB: 1024}, nil) {
		t.Fatal("a disk ceiling on the container driver is reported as unenforced")
	}
}

// fill writes n bytes of real data, so the blocks are allocated.
func fill(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("d", n)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// noRuntimeExecutor is fakeExecutor over a runtime binary that does not
// exist, so a Start that got past its refusals would fail on its first runtime
// call — with an error that is not a DiskLimitError.
func noRuntimeExecutor(t *testing.T) *Executor {
	t.Helper()
	ex := fakeExecutor(t, Options{AllowRootUser: true})
	ex.rt = Runtime{Name: RuntimeDocker, Path: filepath.Join(t.TempDir(), "no-such-docker")}
	return ex
}

func TestStartRefusesAWorkspaceAlreadyOverItsDiskLimit(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	project := t.TempDir()
	fill(t, filepath.Join(project, "build", "out.bin"), 3<<20)

	ex := noRuntimeExecutor(t)
	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir:        project,
		Argv:           []string{"cloop", "run"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 1},
	})
	var refused *executor.DiskLimitError
	if !errors.As(err, &refused) || !errors.Is(err, executor.ErrDiskLimit) {
		t.Fatalf("Start = %v, want a DiskLimitError", err)
	}
	msg := err.Error()
	// Both sizes, the source, and how to raise the limit: the run never
	// started, so this sentence is all its author gets. The tree is the 3 MiB
	// file and its directories' own blocks, rounded up.
	held := "already holds " + executor.FormatUsedMB(refused.Breach.UsedMB())
	for _, want := range []string{held, "disk limit of 1 MB", "resources.disk",
		"free space in the workspace", project} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not name %q", msg, want)
		}
	}
	if refused.Breach.UsedBytes < 3<<20 || refused.Breach.LimitMB != 1 || refused.Executor != ex.id {
		t.Fatalf("breach = %+v", refused.Breach)
	}
	if len(ex.Handles()) != 0 {
		t.Fatal("a refused start left a handle behind")
	}
}

func TestStartDoesNotCountTheProjectStateDirectory(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	project := t.TempDir()
	fill(t, filepath.Join(project, "main.go"), 1024)
	// The hub's own bookkeeping, larger than the limit: not the workload's.
	fill(t, filepath.Join(project, ".cloop", "state.db"), 3<<20)

	ex := noRuntimeExecutor(t)
	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir:        project,
		Argv:           []string{"cloop", "run"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 1},
	})
	if err == nil {
		t.Fatal("Start succeeded against a runtime that does not exist")
	}
	if errors.Is(err, executor.ErrDiskLimit) {
		t.Fatalf("a workspace whose only weight is .cloop/ was refused: %v", err)
	}
}

// fakeAnswer is how the fake runtime answers one subcommand.
type fakeAnswer struct {
	stdout, stderr string
	exit           int
}

// fakeRuntime writes a runtime CLI that logs its arguments and answers `kill`
// and `inspect` as told, so the stop path runs for real without a container.
func fakeRuntime(t *testing.T, kill, inspect fakeAnswer) (Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n"
	for _, c := range []struct {
		cmd string
		a   fakeAnswer
	}{{"kill", kill}, {"inspect", inspect}} {
		script += "if [ \"$1\" = " + c.cmd + " ]; then\n"
		if c.a.stdout != "" {
			script += "  echo '" + c.a.stdout + "'\n"
		}
		if c.a.stderr != "" {
			script += "  echo '" + c.a.stderr + "' >&2\n"
		}
		script += "  exit " + strconv.Itoa(c.a.exit) + "\nfi\n"
	}
	script += "exit 0\n"
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}, log
}

func newRecord(id string) *record {
	return &record{
		id:        id,
		name:      "cloop-proj-" + id,
		startedAt: time.Now(),
		state:     executor.StateRunning,
		bus:       logbus.New(id, executor.StreamCombined, logbus.Options{}),
	}
}

func TestADiskBreachStopsTheWorkloadAndItsStatusSaysWhy(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	rt, calls := fakeRuntime(t, fakeAnswer{}, fakeAnswer{stdout: "true"})
	ex := fakeExecutor(t, Options{})
	ex.rt = rt
	rec := newRecord("c-disk1")
	ex.handles[rec.id] = rec

	b := executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64, Source: executor.DiskLimitFromSpec,
		Path: "/srv/proj", MeasuredAt: time.Now()}
	if !ex.stopForDiskLimit(context.Background(), rec, b) {
		t.Fatal("a stop the runtime accepted was reported as failed")
	}
	got, _ := os.ReadFile(calls)
	if !strings.Contains(string(got), "kill --signal SIGKILL "+rec.name) {
		t.Fatalf("runtime calls = %q, want a SIGKILL of %s", got, rec.name)
	}

	// The reaper then sees the container killed — exit 137, the same shape an
	// OOM kill has — and the stop's own account must win.
	ex.finish(rec, executor.StateKilled, 137, "")
	st, err := ex.Status(context.Background(), rec.id)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != executor.StateKilled || st.Outcome != executor.OutcomeDiskLimit || st.DiskLimit == nil {
		t.Fatalf("status = %+v, want killed with outcome disk_limit", st)
	}
	if st.DiskLimit.UsedMB() != 70 || st.DiskLimit.LimitMB != 64 {
		t.Fatalf("breach = %+v", st.DiskLimit)
	}
	if !strings.Contains(st.Error, "stopped at its disk limit") || !strings.Contains(st.Error, "70 MB") {
		t.Fatalf("Error = %q, want the stop named with its sizes", st.Error)
	}
	all, _ := ex.HandleStatuses(context.Background())
	if len(all) != 1 || all[0].Outcome != executor.OutcomeDiskLimit {
		t.Fatalf("HandleStatuses = %+v", all)
	}
}

func TestADiskStopRacingANaturalExitLeavesTheExitAlone(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	// Podman's wording, which names no "not running": the runtime is asked
	// instead of the message being read.
	rt, _ := fakeRuntime(t,
		fakeAnswer{stderr: "Error: can only kill running containers. x is in state exited: container state improper", exit: 125},
		fakeAnswer{stdout: "false"})
	ex := fakeExecutor(t, Options{})
	ex.rt = rt
	rec := newRecord("c-disk2")
	ex.handles[rec.id] = rec

	if !ex.stopForDiskLimit(context.Background(), rec, executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64}) {
		t.Fatal("a workload that had already ended was reported as still running")
	}
	ex.finish(rec, executor.StateExited, 0, "")
	st, _ := ex.Status(context.Background(), rec.id)
	if st.State != executor.StateExited || st.Outcome != "" || st.DiskLimit != nil {
		t.Fatalf("status = %+v: a stop that never happened was reported", st)
	}
}

func TestAFailedDiskStopIsRetried(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	for _, tc := range []struct {
		name    string
		inspect fakeAnswer
		// keep: the intent stays, so a death the kill did cause is credited.
		keep bool
	}{
		// The daemon is down: the kill fails and so does the question, which
		// must not be read as "it stopped" — nor as "it is still running".
		{"the runtime cannot say", fakeAnswer{stderr: "Cannot connect to the Docker daemon", exit: 1}, true},
		// Known to be running still: the stop did not happen.
		{"still running", fakeAnswer{stdout: "true"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := fakeRuntime(t, fakeAnswer{stderr: "Cannot connect to the Docker daemon", exit: 1}, tc.inspect)
			ex := fakeExecutor(t, Options{})
			ex.rt = rt
			rec := newRecord("c-disk3")
			ex.handles[rec.id] = rec
			if ex.stopForDiskLimit(context.Background(), rec, executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64}) {
				t.Fatal("a kill the runtime refused was reported as a stop")
			}
			rec.mu.Lock()
			kept := rec.diskBreach != nil
			rec.mu.Unlock()
			if kept != tc.keep {
				t.Fatalf("intent kept = %v, want %v", kept, tc.keep)
			}
		})
	}
}

func TestADiskStopOfAFinishedWorkloadDoesNothing(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	ex.rt = Runtime{Name: RuntimeDocker, Path: filepath.Join(t.TempDir(), "must-not-run")}
	rec := newRecord("c-disk4")
	ex.handles[rec.id] = rec
	ex.finish(rec, executor.StateExited, 0, "")
	if !ex.stopForDiskLimit(context.Background(), rec, executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64}) {
		t.Fatal("stopping a finished workload reported a failure")
	}
	st, _ := ex.Status(context.Background(), rec.id)
	if st.Outcome != "" {
		t.Fatalf("a finished workload was relabelled: %+v", st)
	}
}

// TestTheWatchdogStopsAWorkloadThatGrowsPastItsLimit runs the driver's own
// watchdog against a real tree on a millisecond schedule: the tree grows past
// the limit while the "workload" runs, and the fake runtime is asked to kill it.
func TestTheWatchdogStopsAWorkloadThatGrowsPastItsLimit(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	rt, calls := fakeRuntime(t, fakeAnswer{}, fakeAnswer{stdout: "true"})
	ex := fakeExecutor(t, Options{})
	ex.rt = rt
	ex.diskPolicy = diskwatch.Policy{MinInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond,
		CostFactor: 1, Deadline: 10 * time.Second}
	project := t.TempDir()
	fill(t, filepath.Join(project, "small"), 1024)
	rec := newRecord("c-disk5")
	ex.handles[rec.id] = rec

	d := &diskLimit{mb: 1, source: executor.DiskLimitFromCeiling, tree: project, stateBaseline: math.MaxInt64}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { ex.watchDisk(ctx, rec, d, nil); close(done) }()

	fill(t, filepath.Join(project, "grown"), 2<<20)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("the watchdog never stopped a workload twice its limit")
	}
	got, _ := os.ReadFile(calls)
	if !strings.Contains(string(got), "kill --signal SIGKILL "+rec.name) {
		t.Fatalf("runtime calls = %q", got)
	}
	rec.mu.Lock()
	b := rec.diskBreach
	rec.mu.Unlock()
	// Over the limit, which may be before the whole file landed: a sample
	// can catch the write in progress, and that is the point of sampling.
	if b == nil || b.Source != executor.DiskLimitFromCeiling || !b.Over() || b.Path != project {
		t.Fatalf("breach = %+v", b)
	}
}

func TestDiskLimitRootsCoverTheWorkspaceItsStateGrowthAndAFeaturesOutput(t *testing.T) {
	d := &diskLimit{mb: 64, tree: "/srv/proj", stateBaseline: math.MaxInt64}
	plain := d.roots()
	if len(plain) != 1 || plain[0].Path != "/srv/proj" || len(plain[0].Exclude) != 1 || plain[0].Exclude[0] != ".cloop" {
		t.Fatalf("roots with no state baseline = %+v", plain)
	}
	d.stateBaseline = 5 << 20
	withState := d.roots()
	if len(withState) != 2 || withState[1].Path != "/srv/proj/.cloop" || withState[1].Allowance != 5<<20 ||
		!withState[1].Optional {
		t.Fatalf("roots with a state baseline = %+v", withState)
	}
	f := &diskLimit{mb: 64, tree: "/tmp/f/workspace", out: "/tmp/f/out", stateBaseline: 0}
	feat := f.roots()
	if len(feat) != 3 || feat[1].Path != "/tmp/f/out" || feat[2].Path != "/tmp/f/workspace/.cloop" {
		t.Fatalf("feature roots = %+v", feat)
	}
}

// TestTheStateDirectorysGrowthCounts: .cloop/ is excluded as it stood at the
// start — the hub's bookkeeping — and what is added to it afterwards counts.
// Excluded outright it would be a directory the sandbox can write, through the
// same bind mount, that no sample ever counts.
func TestTheStateDirectorysGrowthCounts(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	project := t.TempDir()
	fill(t, filepath.Join(project, "main.go"), 1024)
	fill(t, filepath.Join(project, ".cloop", "state.db"), 3<<20)

	ex := fakeExecutor(t, Options{})
	d := &diskLimit{mb: 2, tree: project, stateBaseline: math.MaxInt64}
	if _, _, err := ex.checkDiskAtStart(context.Background(), d); err != nil {
		t.Fatalf("a workspace whose only weight is its state directory was refused: %v", err)
	}
	if d.stateBaseline < 3<<20 || d.stateBaseline == math.MaxInt64 {
		t.Fatalf("baseline = %d, want the state directory's size", d.stateBaseline)
	}

	fill(t, filepath.Join(project, ".cloop", "smuggled.bin"), 3<<20)
	u, err := measureDisk(context.Background(), d.roots(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if u.Bytes <= d.bytes() {
		t.Fatalf("Bytes = %d: 3 MB written into .cloop/ after the start did not count against a 2 MB limit", u.Bytes)
	}
}

// TestADiskLimitSurvivesARestart: the limit, the state baseline and a stop in
// flight ride with the persisted handle.
func TestADiskLimitSurvivesARestart(t *testing.T) {
	d := &diskLimit{mb: 512, source: executor.DiskLimitFromCeiling, tree: "/srv/proj", stateBaseline: 7 << 20}
	meta := withDiskMeta(handleMeta(RuntimeDocker, nil), d)
	saved := executor.HandleRecord{HandleID: "c-x", ExternalID: "cloop-proj-x", ProjectPath: "/srv/proj", Meta: meta}

	got := restoreDiskLimit(saved, nil)
	if got == nil || got.mb != 512 || got.source != executor.DiskLimitFromCeiling || got.path() != "/srv/proj" ||
		got.stateBaseline != 7<<20 {
		t.Fatalf("restored = %+v", got)
	}

	f := &featureRun{root: "/tmp/f", stage: "/tmp/f/workspace", out: "/tmp/f/out", bundleCap: 1}
	fmeta := withDiskMeta(handleMeta(RuntimeDocker, f), &diskLimit{mb: 64, stateBaseline: math.MaxInt64})
	frec := restoreFeature(fmeta)
	got = restoreDiskLimit(executor.HandleRecord{ProjectPath: "/srv/proj/.cloop/features/x", Meta: fmeta}, frec)
	if got == nil || got.path() != "/tmp/f/workspace" || got.out != "/tmp/f/out" || got.stateBaseline != math.MaxInt64 {
		t.Fatalf("restored feature limit = %+v", got)
	}

	if restoreDiskLimit(executor.HandleRecord{ProjectPath: "/srv/proj", Meta: handleMeta(RuntimeDocker, nil)}, nil) != nil {
		t.Fatal("a workload with no limit came back with one")
	}
	if restoreDiskLimit(executor.HandleRecord{ProjectPath: "relative", Meta: meta}, nil) != nil {
		t.Fatal("a limit was restored over a tree that cannot be named")
	}
	if restoreDiskBreach(saved) != nil {
		t.Fatal("a handle with no stop in flight came back with one")
	}
}

// TestFinishCreditsADiskStopOnlyForTheDeathItCauses: the stop is recorded
// before the kill, and a workload can end some other way in between.
func TestFinishCreditsADiskStopOnlyForTheDeathItCauses(t *testing.T) {
	b := executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64}
	for _, tc := range []struct {
		name     string
		exit     int
		state    executor.State
		msg      string
		credited bool
	}{
		{"its own SIGKILL", 137, executor.StateKilled, "the workload was killed (SIGKILL)", true},
		{"a clean exit first", 0, executor.StateExited, "", false},
		{"a failure first", 2, executor.StateExited, "", false},
		{"the OOM killer first", 137, executor.StateKilled, oomKilledMessage, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := fakeExecutor(t, Options{})
			rec := newRecord("c-fin")
			ex.handles[rec.id] = rec
			if !rec.requestDiskStop(b) {
				t.Fatal("a running workload refused the stop")
			}
			ex.finish(rec, tc.state, tc.exit, tc.msg)
			st, _ := ex.Status(context.Background(), rec.id)
			if got := st.Outcome == executor.OutcomeDiskLimit; got != tc.credited {
				t.Fatalf("status = %+v, want the disk stop credited = %v", st, tc.credited)
			}
			if !tc.credited && st.State != tc.state {
				t.Fatalf("state = %q, want the workload's own %q", st.State, tc.state)
			}
		})
	}
}

// TestADiskStopNeverOverwritesARevocation: the two used to share the kill
// intent, so a disk stop could replace a revocation's reason and its abandon
// could clear one.
func TestADiskStopNeverOverwritesARevocation(t *testing.T) {
	ex := fakeExecutor(t, Options{})
	rec := newRecord("c-rev")
	ex.handles[rec.id] = rec
	rec.requestKill("the grant was revoked")
	rec.requestDiskStop(executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64})
	rec.abandonDiskStop()
	rec.mu.Lock()
	intact := rec.killRequested && rec.killReason == "the grant was revoked"
	rec.mu.Unlock()
	if !intact {
		t.Fatal("abandoning a disk stop cleared a revocation's intent")
	}
	rec.requestDiskStop(executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64})
	ex.finish(rec, executor.StateKilled, 137, "")
	st, _ := ex.Status(context.Background(), rec.id)
	if st.Outcome != "" || st.Error != "the grant was revoked" {
		t.Fatalf("status = %+v, want the revocation's account", st)
	}
}

// adoptRuntime is a runtime CLI scripted for an adopted container: it keeps
// `logs --follow` open until killed, then `wait` reports 137.
func adoptRuntime(t *testing.T) (Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	killed := filepath.Join(dir, "killed")
	script := `#!/bin/sh
echo "$@" >> ` + calls + `
case "$1" in
logs) i=0; while [ ! -f ` + killed + ` ] && [ $i -lt 300 ]; do sleep 0.05; i=$((i+1)); done; exit 0 ;;
kill) touch ` + killed + `; exit 0 ;;
wait) echo 137; exit 0 ;;
inspect)
  case "$3" in
  *Running*) if [ -f ` + killed + ` ]; then echo false; else echo true; fi ;;
  *) echo '{"OOMKilled":false,"ExitCode":137}' ;;
  esac
  exit 0 ;;
esac
exit 0
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}, calls
}

// TestAdoptionResumesTheDiskWatchdog: a hub that restarts under a running
// container must go on holding it to its limit — it is tracked, so nothing else
// will ever stop it.
func TestAdoptionResumesTheDiskWatchdog(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	project := t.TempDir()
	fill(t, filepath.Join(project, "big"), 2<<20)

	store := executor.NewMemoryHandleStore()
	d := &diskLimit{mb: 1, source: executor.DiskLimitFromSpec, tree: project, stateBaseline: math.MaxInt64}
	if err := store.PutHandle(executor.HandleRecord{
		HandleID: "c-adopted", ExecutorID: "container", Driver: executor.KindContainer,
		ExternalID: "cloop-proj-adopted", ProjectPath: project, StartedAt: time.Now(),
		Meta: withDiskMeta(handleMeta(RuntimeDocker, nil), d),
	}); err != nil {
		t.Fatal(err)
	}

	rt, calls := adoptRuntime(t)
	ex := fakeExecutor(t, Options{})
	ex.rt = rt
	ex.store = store
	ex.leases = executor.NewLeaseIndex()
	ex.revocations = executor.NewRevocationLog()
	ex.diskPolicy = diskwatch.Policy{MinInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond,
		CostFactor: 1, Deadline: 10 * time.Second}
	ex.rehydrate()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lines, err := ex.Stream(ctx, "c-adopted")
	if err != nil {
		t.Fatalf("the adopted handle is not tracked: %v", err)
	}
	for range lines {
	}
	st, err := ex.Status(ctx, "c-adopted")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(calls)
	if !strings.Contains(string(got), "kill --signal SIGKILL cloop-proj-adopted") {
		t.Fatalf("the adopted container over its limit was never stopped; runtime calls:\n%s", got)
	}
	if st.Outcome != executor.OutcomeDiskLimit || st.DiskLimit == nil || st.DiskLimit.LimitMB != 1 {
		t.Fatalf("status = %+v, want the adopted workload stopped at its disk limit", st)
	}
}

// TestAStopInFlightIsPersistedBeforeTheKill: the measurement goes onto the
// handle's row first, so the hub that adopts a container which died of the
// kill credits the stop rather than calling exit 137 an out-of-memory kill.
func TestAStopInFlightIsPersistedBeforeTheKill(t *testing.T) {
	store := executor.NewMemoryHandleStore()
	if err := store.PutHandle(executor.HandleRecord{HandleID: "c-p", ExecutorID: "container",
		Driver: executor.KindContainer, ExternalID: "cloop-proj-p", ProjectPath: "/srv/proj",
		Meta: map[string]string{metaRuntime: RuntimeDocker}}); err != nil {
		t.Fatal(err)
	}
	ex := fakeExecutor(t, Options{})
	ex.store = store
	b := executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64, Source: executor.DiskLimitFromSpec}
	ex.persistDiskBreach("c-p", b)
	rows, _ := store.ListHandles("container")
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	got := restoreDiskBreach(rows[0])
	if got == nil || got.UsedBytes != b.UsedBytes || got.LimitMB != 64 || rows[0].Meta[metaRuntime] != RuntimeDocker {
		t.Fatalf("restored breach = %+v, meta %v", got, rows[0].Meta)
	}
}
