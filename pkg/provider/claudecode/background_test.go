package claudecode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// fakeHarness installs a stub `claude` on PATH whose body is the given shell
// script, so these tests exercise the real spawn/wait/settle path — process
// group and all — without the real CLI or a network.
func fakeHarness(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/bash\ncat > /dev/null\n" + script + "\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("process-group detection is procfs-only")
	}
}

// TestBackgroundWorkIsWaitedFor is Task 20205 in miniature, and the reason the
// feature exists.
//
// The harness starts a "training run" in the background and immediately
// reports TASK_DONE. Before the fix, Complete returned in single-digit
// milliseconds and the next task — which in the reported incident was three
// tasks meant to consume a trained model — ran against a file that did not
// exist yet. Complete must now block until the work it started is finished.
func TestBackgroundWorkIsWaitedFor(t *testing.T) {
	requireLinux(t)
	dir := t.TempDir()
	model := filepath.Join(dir, "model.bin")

	// nohup's redirection is what makes this invisible to a pipe-EOF check:
	// the child closes the inherited descriptors immediately.
	//
	// The sleep outlasts the default grace window on purpose: work that
	// finishes inside the grace is ordinary teardown, and the case being
	// reproduced here is the one where real work — a training run — is still
	// going long after the harness has claimed to be done.
	fakeHarness(t, `nohup bash -c 'sleep 4; echo trained > `+model+`' >/dev/null 2>&1 &
echo "Started the training run."
echo "TASK_DONE"`)

	// The zero-value policy: this is what production runs with.
	p := &Provider{}
	res, err := p.Complete(context.Background(), "train the model", provider.Options{WorkDir: dir})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if _, err := os.Stat(model); err != nil {
		t.Fatalf("Complete returned before the background work finished: %v", err)
	}
	if res.Background == nil {
		t.Fatal("background work must be reported, not silently absorbed")
	}
	if !res.Background.Drained {
		t.Errorf("work that finished within budget must report Drained: %+v", res.Background)
	}
	if res.Background.Incomplete() {
		t.Error("drained work does not make the task incomplete")
	}
	if res.Background.Detected == 0 {
		t.Error("Detected must count what was found")
	}
	if summary := res.Background.Summary(); summary == "" {
		t.Error("Summary must describe the wait for the UI and annotations")
	}
}

// TestBackgroundWorkPastBudgetIsIncomplete covers the other half of the
// policy: work that never finishes must not be reported as a completed task,
// because the task's output describes work that is still running.
func TestBackgroundWorkPastBudgetIsIncomplete(t *testing.T) {
	requireLinux(t)
	fakeHarness(t, `nohup sleep 300 >/dev/null 2>&1 &
echo "TASK_DONE"`)

	p := &Provider{Background: BackgroundPolicy{
		Grace:          100 * time.Millisecond,
		Wait:           300 * time.Millisecond,
		TerminateGrace: 500 * time.Millisecond,
	}}
	res, err := p.Complete(context.Background(), "go", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if res.Background == nil {
		t.Fatal("expected background activity to be reported")
	}
	if res.Background.Drained {
		t.Fatal("a 300s sleep cannot drain inside a 300ms budget")
	}
	if !res.Background.Incomplete() {
		t.Error("work outliving the budget must mark the task incomplete")
	}
	// Orphans are terminated so a retry of this task cannot race a leftover
	// copy of itself over the same output files.
	if res.Background.Terminated == 0 {
		t.Errorf("expected orphaned work to be terminated, got %+v", res.Background)
	}
}

// TestCleanHarnessReportsNothing guards against the false positive that would
// make this unusable: an ordinary task must be unaffected, and must not pay
// the grace window.
func TestCleanHarnessReportsNothing(t *testing.T) {
	requireLinux(t)
	fakeHarness(t, `echo "did the work inline"
echo "TASK_DONE"`)

	p := &Provider{Background: BackgroundPolicy{Grace: 3 * time.Second, Wait: time.Minute}}
	start := time.Now()
	res, err := p.Complete(context.Background(), "go", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	elapsed := time.Since(start)

	if res.Background != nil {
		t.Fatalf("a harness that left nothing behind must report nil, got %+v", res.Background)
	}
	if elapsed > 2*time.Second {
		t.Errorf("clean task paid %v of grace window; every task in every project pays this", elapsed)
	}
}

// TestShortLivedChildIsNotBackgroundWork covers the teardown race: harnesses
// leave children exiting just behind them, and flagging those would mark
// ordinary tasks incomplete.
func TestShortLivedChildIsNotBackgroundWork(t *testing.T) {
	requireLinux(t)
	fakeHarness(t, `nohup sleep 0.3 >/dev/null 2>&1 &
echo "TASK_DONE"`)

	p := &Provider{Background: BackgroundPolicy{Grace: 2 * time.Second, Wait: time.Minute}}
	res, err := p.Complete(context.Background(), "go", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Background != nil {
		t.Fatalf("a child exiting inside the grace window is teardown, not background work: %+v", res.Background)
	}
}

func TestBackgroundDetectionCanBeDisabled(t *testing.T) {
	requireLinux(t)
	// A short sleep rather than a long one: the disabled policy deliberately
	// leaves it running, and the test should not outlive itself by a process.
	fakeHarness(t, `nohup sleep 2 >/dev/null 2>&1 &
echo "TASK_DONE"`)

	p := &Provider{Background: BackgroundPolicy{Disabled: true}}
	start := time.Now()
	res, err := p.Complete(context.Background(), "go", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Background != nil {
		t.Errorf("disabled policy must not report activity, got %+v", res.Background)
	}
	// The point of the escape hatch is the old behaviour: return immediately,
	// background work and all.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("disabled policy must not wait, took %v", elapsed)
	}
}

func TestKeepOrphansLeavesWorkRunning(t *testing.T) {
	requireLinux(t)
	// Long enough to outlive the budget below, short enough to reap itself
	// soon after: this policy deliberately declines to kill the process, so a
	// `sleep 300` here would leave one running on the machine for five minutes
	// after the suite finishes.
	fakeHarness(t, `nohup sleep 3 >/dev/null 2>&1 &
echo "TASK_DONE"`)

	p := &Provider{Background: BackgroundPolicy{
		Grace:       100 * time.Millisecond,
		Wait:        200 * time.Millisecond,
		KeepOrphans: true,
	}}
	res, err := p.Complete(context.Background(), "go", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Background == nil || !res.Background.Incomplete() {
		t.Fatalf("expected incomplete background activity, got %+v", res.Background)
	}
	if res.Background.Terminated != 0 {
		t.Errorf("KeepOrphans must not kill anything, got Terminated=%d", res.Background.Terminated)
	}
}

func TestBackgroundPolicyResolve(t *testing.T) {
	got := BackgroundPolicy{}.resolve()
	if got.Grace != DefaultBackgroundGrace || got.Wait != DefaultBackgroundWait || got.TerminateGrace != DefaultTerminateGrace {
		t.Errorf("zero value must resolve to defaults, got %+v", got)
	}
	// A negative wait is the documented way to say "report it, do not wait".
	if got := (BackgroundPolicy{Wait: -1}).resolve(); got.Wait != 0 {
		t.Errorf("negative Wait must resolve to no wait, got %v", got.Wait)
	}
	custom := BackgroundPolicy{Grace: time.Second, Wait: time.Hour, TerminateGrace: time.Minute}
	if got := custom.resolve(); got != custom {
		t.Errorf("explicit values must be preserved, got %+v", got)
	}
}

func TestBackgroundActivitySummary(t *testing.T) {
	var nilActivity *provider.BackgroundActivity
	if nilActivity.Summary() != "" {
		t.Error("nil activity has no summary")
	}
	if nilActivity.Incomplete() {
		t.Error("nil activity is not incomplete")
	}

	drained := &provider.BackgroundActivity{
		Detected: 2, Commands: []string{"python3", "tee"}, Waited: 90 * time.Second, Drained: true,
	}
	if s := drained.Summary(); !strings.Contains(s, "python3") || !strings.Contains(s, "waited") {
		t.Errorf("drained summary should name the wait and the processes, got %q", s)
	}

	killed := &provider.BackgroundActivity{
		Detected: 1, Commands: []string{"train.py"}, Waited: time.Minute, Terminated: 1,
	}
	if s := killed.Summary(); !strings.Contains(s, "terminated") {
		t.Errorf("terminated summary should say so, got %q", s)
	}

	kept := &provider.BackgroundActivity{Detected: 1, Commands: []string{"srv"}, Waited: time.Minute}
	if s := kept.Summary(); strings.Contains(s, "terminated") {
		t.Errorf("kept orphans should not claim termination, got %q", s)
	}
}

// processGone reports whether pid has exited. A zombie counts: it is dead and
// only waiting for whichever ancestor adopted it to reap it.
func processGone(pid int) bool {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return true
	}
	// The state field follows the parenthesised command name.
	if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && i+2 < len(stat) {
		return stat[i+2] == 'Z'
	}
	return false
}

// readPID waits for a harness to write a pid to path and returns it.
func readPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if raw, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("harness never wrote a pid to %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireGone fails the test unless pid exits within a few seconds.
func requireGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("%s (pid %d) is still running after the stop", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStopEndsTheBackgroundWait is the provider half of Task 20348. A stop
// that arrived while cloop was waiting on background work was ignored until
// the wait budget ran out — half an hour by default — so pressing Stop
// appeared to do nothing. The wait must end with the stop, and the leftovers
// must not outlive it: the task is about to be retried, and the retry must not
// race them.
func TestStopEndsTheBackgroundWait(t *testing.T) {
	requireLinux(t)
	pidFile := filepath.Join(t.TempDir(), "bg.pid")
	fakeHarness(t, `nohup sleep 300 >/dev/null 2>&1 &
echo $! > `+pidFile+`
echo "TASK_DONE"`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Provider{Background: BackgroundPolicy{
		Grace:          100 * time.Millisecond,
		Wait:           time.Hour,
		TerminateGrace: 500 * time.Millisecond,
	}}
	start := time.Now()
	_, err := p.Complete(ctx, "go", provider.Options{
		// Stop the moment the wait begins.
		OnBackgroundWait: func(provider.BackgroundActivity) { cancel() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Complete = %v, want an error wrapping context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("Complete returned %v after starting — the wait ignored the stop", elapsed)
	}
	requireGone(t, readPID(t, pidFile), "the background work")
}

// TestStopDuringGraceTerminatesLeftovers covers a stop that lands after the
// harness exited but inside the grace window, before any background work has
// been counted. The wait ends there too, and what the harness left running is
// still terminated rather than orphaned by a run that has gone away.
func TestStopDuringGraceTerminatesLeftovers(t *testing.T) {
	requireLinux(t)
	dir := t.TempDir()
	bgPID := filepath.Join(dir, "bg.pid")
	harnessPID := filepath.Join(dir, "harness.pid")
	fakeHarness(t, `echo $$ > `+harnessPID+`
nohup sleep 300 >/dev/null 2>&1 &
echo $! > `+bgPID+`
echo "TASK_DONE"`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Stop once the harness itself has exited and been reaped: the provider is
	// then inside its grace window, which is long enough that nothing has been
	// counted yet.
	go func() {
		pid := readPID(t, harnessPID)
		for !processGone(pid) {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()

	p := &Provider{Background: BackgroundPolicy{
		Grace:          5 * time.Second,
		Wait:           3 * time.Second,
		TerminateGrace: 500 * time.Millisecond,
	}}
	start := time.Now()
	_, err := p.Complete(ctx, "go", provider.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Complete = %v, want an error wrapping context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("Complete returned %v after starting — it sat out the grace window after the stop", elapsed)
	}
	requireGone(t, readPID(t, bgPID), "the background work")
}

// TestTaskDeadlineDoesNotEndTheBackgroundWait pins the other side of that
// line. A task's own time budget expiring after the harness exited is not a
// request to abandon the work, so the wait goes on until the work drains. The
// deadline arrives the way the orchestrator's live task budget delivers it: a
// cancellation whose cause is context.DeadlineExceeded.
func TestTaskDeadlineDoesNotEndTheBackgroundWait(t *testing.T) {
	requireLinux(t)
	marker := filepath.Join(t.TempDir(), "trained")
	fakeHarness(t, `nohup bash -c 'sleep 2; touch `+marker+`' >/dev/null 2>&1 &
echo "TASK_DONE"`)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	p := &Provider{Background: BackgroundPolicy{Grace: 100 * time.Millisecond, Wait: time.Minute}}
	_, err := p.Complete(ctx, "go", provider.Options{
		OnBackgroundWait: func(provider.BackgroundActivity) { cancel(context.DeadlineExceeded) },
	})
	if err == nil {
		t.Fatal("Complete succeeded after its task deadline passed")
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("the wait ended at the task deadline instead of when the work finished: %v", statErr)
	}
}
