package ui

// Tests for the hub half of Task 20348: the Stop buttons reach a run through
// the executor it was dispatched to. A run on an edge device or in a container
// never shows up in this host's /proc, so before this the buttons could not
// stop it at all — they answered "no running cloop process found" while the
// run carried on.

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// recordingExecutor is a stubExecutor that remembers the signals it was asked
// to deliver, and fails them with signalErr when set.
type recordingExecutor struct {
	stubExecutor
	signalErr error
	// kind, when set, is what Kind reports — "localprocess" for a stand-in
	// for the driver that forks runs on this host.
	kind string

	mu      sync.Mutex
	signals []string
}

func (r *recordingExecutor) Kind() string {
	if r.kind != "" {
		return r.kind
	}
	return r.stubExecutor.Kind()
}

func (r *recordingExecutor) Signal(_ context.Context, handleID string, sig executor.Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, handleID+":"+string(sig))
	return r.signalErr
}

func (r *recordingExecutor) delivered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.signals...)
}

// hubWithTrackedRun serves a project whose persisted status says "running" and
// whose run the hub dispatched to ex under handle "h1". Nothing on this host
// is running it, exactly as for a run on another machine.
func hubWithTrackedRun(t *testing.T, ex executor.Executor) (*httptest.Server, string) {
	t.Helper()
	dir := setupProjectDir(t, cloopGoal, nil)
	setStatus(t, dir, "running")
	srv := New(dir, 0, "")
	// Tracked before serving: requests carry no happens-before edge to
	// anything done to the Server after the listener is up.
	srv.trackRun(dir, ex, "h1")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

func runningExecutor() *recordingExecutor {
	return &recordingExecutor{stubExecutor: stubExecutor{status: executor.Status{State: executor.StateRunning}}}
}

// TestStopReachesARunOnAnIsolatedExecutor: both Stop buttons interrupt the
// dispatched workload. Interrupt, not kill, is what lets the run put its task
// back to pending before it exits.
func TestStopReachesARunOnAnIsolatedExecutor(t *testing.T) {
	for _, path := range []string{"/api/stop", "/api/projects/0/stop"} {
		t.Run(path, func(t *testing.T) {
			ex := runningExecutor()
			ts, dir := hubWithTrackedRun(t, ex)

			out := apiPOST(t, ts, path, map[string]interface{}{})

			if ok, _ := out["ok"].(bool); !ok {
				t.Fatalf("POST %s: ok=false (message=%v) — the run on the executor was not stopped", path, out["message"])
			}
			if got := ex.delivered(); len(got) != 1 || got[0] != "h1:"+string(executor.SignalInterrupt) {
				t.Errorf("executor signals = %v, want exactly [h1:%s]", got, executor.SignalInterrupt)
			}
			// The run is still live until it exits on its own; the status is
			// the run's to change, not the Stop handler's.
			if got := loadStatus(t, dir); got != "running" {
				t.Errorf("status = %q right after Stop, want %q — a live run was reconciled as dead", got, "running")
			}
		})
	}
}

// TestStopSaysWhenTheExecutorCannotBeReached: an edge device that has dropped
// off cannot be told to stop, and the answer has to say that rather than
// "no running cloop process found" — which reads as "nothing is running".
func TestStopSaysWhenTheExecutorCannotBeReached(t *testing.T) {
	ex := runningExecutor()
	ex.signalErr = errors.New("agent sgx is not connected")
	ts, dir := hubWithTrackedRun(t, ex)

	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})

	if ok, _ := out["ok"].(bool); ok {
		t.Fatal("POST /api/stop reported success although the signal could not be delivered")
	}
	msg, _ := out["message"].(string)
	if !strings.Contains(msg, "could not reach the executor") || !strings.Contains(msg, "not connected") {
		t.Errorf("message = %q, want it to name the unreachable executor and why", msg)
	}
	if got := loadStatus(t, dir); got != "running" {
		t.Errorf("status = %q, want %q — an unreachable run must not be reconciled as dead", got, "running")
	}
}

// TestStopLeavesAFinishedWorkloadAlone: a workload the executor reports as over
// has nothing to interrupt. Stop must neither signal it nor claim to have
// stopped it, and falls through to clearing the status the run left behind.
func TestStopLeavesAFinishedWorkloadAlone(t *testing.T) {
	ex := &recordingExecutor{stubExecutor: stubExecutor{status: executor.Status{State: executor.StateExited}}}
	ts, dir := hubWithTrackedRun(t, ex)

	out := apiPOST(t, ts, "/api/stop", map[string]interface{}{})

	if got := ex.delivered(); len(got) != 0 {
		t.Errorf("signalled a finished workload: %v", got)
	}
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("POST /api/stop: ok=false (message=%v), want the stale status cleared", out["message"])
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "stale") {
		t.Errorf("message = %q, want it to say a stale status was cleared", msg)
	}
	if got := loadStatus(t, dir); got != "paused" {
		t.Errorf("status = %q, want %q", got, "paused")
	}
}

// TestBudgetStopReachesARunOnAnIsolatedExecutor: the budget stop goes through
// the same delivery as the Stop buttons, so an exhausted budget still stops a
// run that no /proc scan can see.
func TestBudgetStopReachesARunOnAnIsolatedExecutor(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ex := runningExecutor()
	srv := New(dir, 0, "")
	srv.trackRun(dir, ex, "h1")

	srv.stopRunForBudget(dir)

	if got := ex.delivered(); len(got) != 1 || got[0] != "h1:"+string(executor.SignalInterrupt) {
		t.Errorf("executor signals = %v, want exactly [h1:%s]", got, executor.SignalInterrupt)
	}
}

// TestStopInterruptsALocalRunOnce: a run the hub forked on this host is found
// twice — through its executor handle and by the /proc scan — and must be
// interrupted once. A second SIGINT is how a CLI is conventionally told to
// stop being graceful, so a Stop that sent two could one day skip the very
// cleanup that returns the interrupted task to pending.
//
// The run is bash under the name "cloop", running the script ./run, which is
// what the /proc scan recognises as a `cloop run`. Its INT trap records any
// interrupt that reaches it. The executor here only records the interrupt it
// is asked for, so a mark in the file can only come from the scan.
func TestStopInterruptsALocalRunOnce(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the /proc scan is Linux-only")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := setupProjectDir(t, cloopGoal, nil)
	fake := filepath.Join(t.TempDir(), "cloop")
	raw, err := os.ReadFile(bash)
	if err != nil {
		t.Skipf("read %s: %v", bash, err)
	}
	if err := os.WriteFile(fake, raw, 0o755); err != nil {
		t.Fatalf("stage fake cloop: %v", err)
	}
	marks := filepath.Join(t.TempDir(), "signals")
	// USR1 is the test's barrier: sent after the stop, it is delivered after
	// any SIGINT the stop sent (Linux delivers pending standard signals lowest
	// number first), so by the time the script exits every interrupt it was
	// sent has been written down.
	script := `trap 'echo int >> "$MARKS"' INT
trap 'echo usr1 >> "$MARKS"; kill $! 2>/dev/null; exit 0' USR1
sleep 60 &
echo ready >> "$MARKS"
while :; do wait; done
`
	if err := os.WriteFile(filepath.Join(dir, "run"), []byte(script), 0o644); err != nil {
		t.Fatalf("write run script: %v", err)
	}
	cmd := exec.Command(fake, "run")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "MARKS="+marks)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake cloop run: %v", err)
	}
	// Closed rather than sent on, so the test body and the cleanup can both
	// wait for the exit.
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})
	pid := cmd.Process.Pid
	// Wait for the traps as well as for the process: a signal that lands
	// before they are installed takes its default action and kills the run.
	deadline := time.Now().Add(10 * time.Second)
	for {
		marked, _ := os.ReadFile(marks)
		if strings.Contains(string(marked), "ready") && slices.Contains(multiui.CloopRunPIDsInDir(dir), pid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fake run (pid %d) never became ready in %s", pid, dir)
		}
		time.Sleep(20 * time.Millisecond)
	}

	ex := &recordingExecutor{
		stubExecutor: stubExecutor{status: executor.Status{State: executor.StateRunning, PID: pid}},
		kind:         executor.KindLocalProcess,
	}
	srv := &Server{WorkDir: dir}
	srv.trackRun(dir, ex, "h1")

	d := srv.interruptRun(dir)

	if d.Signalled != 1 {
		t.Errorf("Signalled = %d, want 1 — one run was stopped", d.Signalled)
	}
	if got := ex.delivered(); len(got) != 1 {
		t.Errorf("executor signals = %v, want one interrupt through the handle", got)
	}
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("signal the barrier: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake run did not exit on its barrier signal")
	}
	got, err := os.ReadFile(marks)
	if err != nil {
		t.Fatalf("read signal marks: %v", err)
	}
	if strings.Contains(string(got), "int") {
		t.Errorf("the /proc scan interrupted a run its executor had already reached; marks: %q", got)
	}
}
