// Round-trip tests for the host-process driver: start → stream → status →
// signal, plus the failure and validation paths.
//
// The tests fork the test binary itself rather than shelling out to system
// utilities, so they do not depend on /bin/sh, coreutils flags, or a
// particular PATH. TestMain switches on an env var to decide whether it is
// running the suite or acting as the fixture child.

package localprocess

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Fixture-child protocol. The parent re-execs the test binary with
// fixtureEnv set to one of these modes.
const (
	fixtureEnv = "CLOOP_LOCALPROCESS_FIXTURE"

	// modeEcho writes its arguments to stdout and stderr, then exits 0.
	modeEcho = "echo"
	// modeExit exits with the code in CLOOP_LOCALPROCESS_EXIT_CODE.
	modeExit = "exit"
	// modeSleep blocks until killed (bounded so a panicking test cannot
	// leak the process forever).
	modeSleep = "sleep"
	// modeSpew writes many lines then sleeps, so a subscriber can attach
	// mid-stream.
	modeSpew = "spew"
	// modeFlood writes continuously until killed, so tests can hold the
	// output pump busy while they churn subscribers.
	modeFlood = "flood"
	// modePrintCwd writes its working directory to stdout.
	modePrintCwd = "cwd"
	// modePrintEnv writes CLOOP_TEST_VAR to stdout.
	modePrintEnv = "env"
	// exitCodeEnv carries the exit code the modeExit fixture should use.
	exitCodeEnv = "CLOOP_LOCALPROCESS_EXIT_CODE"
)

func TestMain(m *testing.M) {
	switch os.Getenv(fixtureEnv) {
	case "":
		os.Exit(m.Run())
	case modeEcho:
		fmt.Fprint(os.Stdout, "stdout-marker\n")
		fmt.Fprint(os.Stderr, "stderr-marker\n")
		os.Exit(0)
	case modeExit:
		code, _ := strconv.Atoi(os.Getenv(exitCodeEnv))
		fmt.Fprint(os.Stdout, "before-exit\n")
		os.Exit(code)
	case modeSleep:
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case modeSpew:
		w := bufio.NewWriter(os.Stdout)
		for i := 0; i < 200; i++ {
			fmt.Fprintf(w, "line-%d\n", i)
		}
		_ = w.Flush()
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case modeFlood:
		deadline := time.Now().Add(60 * time.Second)
		for i := 0; time.Now().Before(deadline); i++ {
			fmt.Fprintf(os.Stdout, "flood-%d\n", i)
			time.Sleep(time.Millisecond)
		}
		os.Exit(0)
	case modePrintCwd:
		cwd, _ := os.Getwd()
		fmt.Fprint(os.Stdout, cwd+"\n")
		os.Exit(0)
	case modePrintEnv:
		fmt.Fprint(os.Stdout, os.Getenv("CLOOP_TEST_VAR")+"\n")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown fixture mode %q\n", os.Getenv(fixtureEnv))
		os.Exit(2)
	}
}

// fixtureSpec builds a Spec that re-execs the test binary in the given mode.
func fixtureSpec(t *testing.T, mode, workDir string, extraEnv ...string) executor.Spec {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	env := append(os.Environ(), fixtureEnv+"="+mode)
	env = append(env, extraEnv...)
	return executor.Spec{
		WorkDir: workDir,
		// -test.run selects a nonexistent test so the child does not
		// re-run the suite in the (impossible) case TestMain changes.
		Argv: []string{self, "-test.run", "TestNothingMatches"},
		Env:  env,
	}
}

// collect drains a stream channel into a single string, failing on timeout.
func collect(t *testing.T, lines <-chan executor.LogLine, timeout time.Duration) string {
	t.Helper()
	var sb strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return sb.String()
			}
			sb.WriteString(line.Text)
		case <-deadline:
			t.Fatalf("timed out after %s waiting for the stream to close; got %q", timeout, sb.String())
			return ""
		}
	}
}

func TestExecutorIdentityAndCapabilities(t *testing.T) {
	ex := New("")
	if ex.ID() != DefaultID {
		t.Fatalf("New(\"\").ID() = %q, want %q", ex.ID(), DefaultID)
	}
	if ex.Kind() != executor.KindLocalProcess {
		t.Fatalf("Kind() = %q, want %q", ex.Kind(), executor.KindLocalProcess)
	}
	caps := ex.Capabilities()
	if caps.Isolation != executor.IsolationNone {
		t.Errorf("Isolation = %q, want none — this driver shares the host", caps.Isolation)
	}
	if !caps.SupportsStream || !caps.SupportsSignal {
		t.Error("host driver must advertise stream and signal support")
	}
	if caps.SupportsResourceLimits {
		t.Error("host driver must not claim resource-limit enforcement it cannot deliver")
	}
	if err := ex.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if id := New("custom-id").ID(); id != "custom-id" {
		t.Fatalf("New(\"custom-id\").ID() = %q, want custom-id", id)
	}
}

// TestStartStreamStatusRoundTrip is the core happy path: a workload runs to
// completion, all of its combined output arrives, and Status reports a
// terminal state with the right exit code.
func TestStartStreamStatusRoundTrip(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeEcho, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if handle.PID <= 0 {
		t.Error("Handle.PID must be the real OS PID — pkg/multiui's /proc scan depends on it")
	}
	if handle.ExecutorID != "test" {
		t.Errorf("Handle.ExecutorID = %q, want test", handle.ExecutorID)
	}
	if handle.StartedAt.IsZero() {
		t.Error("Handle.StartedAt is zero")
	}

	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	out := collect(t, lines, 30*time.Second)

	// stdout and stderr are merged, as the live-log panel expects.
	if !strings.Contains(out, "stdout-marker") {
		t.Errorf("stdout not captured; got %q", out)
	}
	if !strings.Contains(out, "stderr-marker") {
		t.Errorf("stderr not captured; got %q", out)
	}

	// The channel closes only after the workload is reaped, so Status must
	// already be terminal here — executor.Run relies on this ordering.
	st, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateExited {
		t.Errorf("State = %q, want exited", st.State)
	}
	if st.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", st.ExitCode)
	}
	if st.FinishedAt.IsZero() {
		t.Error("FinishedAt not set on a terminal status")
	}
	if st.PID != handle.PID {
		t.Errorf("Status.PID = %d, want %d", st.PID, handle.PID)
	}
}

func TestStatusReportsNonZeroExit(t *testing.T) {
	ex := New("test")
	spec := fixtureSpec(t, modeExit, t.TempDir(), exitCodeEnv+"=7")

	handle, err := ex.Start(context.Background(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	out := collect(t, lines, 30*time.Second)
	if !strings.Contains(out, "before-exit") {
		t.Errorf("output before a non-zero exit was lost; got %q", out)
	}

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateExited || st.ExitCode != 7 {
		t.Fatalf("Status = {%q, %d}, want {exited, 7}", st.State, st.ExitCode)
	}
}

// TestSignalStopsWorkload covers the Stop button's path: a long-running
// workload receives a signal and lands in StateKilled.
func TestSignalStopsWorkload(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeSleep, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, handle.ID, executor.SignalKill) })

	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	st, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateRunning {
		t.Fatalf("State before signal = %q, want running", st.State)
	}

	if err := ex.Signal(ctx, handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	collect(t, lines, 30*time.Second) // blocks until the workload is reaped

	st, err = ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status after signal: %v", err)
	}
	if st.State != executor.StateKilled {
		t.Fatalf("State after kill = %q, want killed", st.State)
	}

	// Signalling an already-finished handle is a no-op success: the caller
	// wanted it stopped, and it is stopped.
	if err := ex.Signal(ctx, handle.ID, executor.SignalInterrupt); err != nil {
		t.Fatalf("Signal on finished handle = %v, want nil", err)
	}
}

func TestSignalValidation(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	if err := ex.Signal(ctx, "no-such-handle", executor.SignalKill); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("Signal(unknown handle) = %v, want ErrHandleNotFound", err)
	}
	handle, err := ex.Start(ctx, fixtureSpec(t, modeSleep, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, handle.ID, executor.SignalKill) })

	if err := ex.Signal(ctx, handle.ID, executor.Signal("sigsegv")); !errors.Is(err, executor.ErrInvalidSignal) {
		t.Fatalf("Signal(bogus) = %v, want ErrInvalidSignal", err)
	}
}

func TestStatusAndStreamRejectUnknownHandles(t *testing.T) {
	ex := New("test")
	if _, err := ex.Status(context.Background(), "ghost"); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("Status(unknown) = %v, want ErrHandleNotFound", err)
	}
	if _, err := ex.Stream(context.Background(), "ghost"); !errors.Is(err, executor.ErrHandleNotFound) {
		t.Fatalf("Stream(unknown) = %v, want ErrHandleNotFound", err)
	}
}

// TestStreamReplaysBacklog guards the Start→Stream race: output produced
// before the consumer subscribes must not be lost, or the live-log panel
// would miss the beginning of every run.
func TestStreamReplaysBacklog(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeSpew, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, handle.ID, executor.SignalKill) })

	// Let the child get ahead of us before subscribing.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := ex.Status(ctx, handle.ID); err == nil && st.State == executor.StateRunning {
			time.Sleep(200 * time.Millisecond)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	var sb strings.Builder
	timeout := time.After(20 * time.Second)
	for !strings.Contains(sb.String(), "line-199") {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("stream closed before the backlog was delivered; got %q", sb.String())
			}
			sb.WriteString(line.Text)
		case <-timeout:
			t.Fatalf("backlog not replayed within 20s; got %q", sb.String())
		}
	}
	if !strings.Contains(sb.String(), "line-0") {
		t.Error("the earliest buffered output was dropped from the replay")
	}
}

// TestStreamFanOut: several consumers (multiple browser tabs) each get a
// full copy, and one of them going away does not disturb the others.
func TestStreamFanOut(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeEcho, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	const consumers = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		outputs []string
	)
	for i := 0; i < consumers; i++ {
		lines, err := ex.Stream(ctx, handle.ID)
		if err != nil {
			t.Fatalf("Stream %d: %v", i, err)
		}
		wg.Add(1)
		go func(lines <-chan executor.LogLine) {
			defer wg.Done()
			var sb strings.Builder
			for line := range lines {
				sb.WriteString(line.Text)
			}
			mu.Lock()
			outputs = append(outputs, sb.String())
			mu.Unlock()
		}(lines)
	}
	wg.Wait()

	if len(outputs) != consumers {
		t.Fatalf("%d consumers finished, want %d", len(outputs), consumers)
	}
	for i, out := range outputs {
		if !strings.Contains(out, "stdout-marker") || !strings.Contains(out, "stderr-marker") {
			t.Errorf("consumer %d got a partial copy: %q", i, out)
		}
	}
}

// TestStreamUnsubscribeOnContextCancel: an abandoned viewer must be released
// without affecting the workload or other viewers.
func TestStreamUnsubscribeOnContextCancel(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeSleep, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, handle.ID, executor.SignalKill) })

	viewerCtx, cancel := context.WithCancel(ctx)
	lines, err := ex.Stream(viewerCtx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	cancel()

	select {
	case _, ok := <-lines:
		if ok {
			// A buffered replay chunk may arrive first; drain until closed.
			for range lines {
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled subscriber's channel was never closed — goroutine leak")
	}

	// The workload is untouched.
	st, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateRunning {
		t.Fatalf("State = %q after a viewer disconnected, want running", st.State)
	}
}

// TestStreamUnsubscribeDuringHeavyOutput is the regression test for a
// "send on closed channel" panic: a viewer disconnecting while the workload
// is actively writing meant the pump could send on a channel the ctx watcher
// had just closed. That is exactly the real-world sequence — a browser tab
// closed mid-run — and it would have taken down the whole UI server, not
// just the request.
func TestStreamUnsubscribeDuringHeavyOutput(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeFlood, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ex.Signal(ctx, handle.ID, executor.SignalKill) })

	// Wait for output to actually be flowing, otherwise the churn below
	// races an idle pump and proves nothing.
	warmup, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	select {
	case <-warmup:
	case <-time.After(30 * time.Second):
		t.Fatal("fixture produced no output within 30s")
	}

	// Churn subscribers for a while with the pump continuously emitting, so
	// disconnects land in the middle of sends.
	var wg sync.WaitGroup
	stop := time.Now().Add(1500 * time.Millisecond)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				viewerCtx, cancel := context.WithCancel(ctx)
				lines, err := ex.Stream(viewerCtx, handle.ID)
				if err != nil {
					cancel()
					return
				}
				// Read a little, then walk away mid-stream.
				select {
				case <-lines:
				case <-time.After(50 * time.Millisecond):
				}
				cancel()
				for range lines { //nolint:revive — drain until the driver closes it
				}
			}
		}()
	}
	wg.Wait()

	// The workload survived every disconnect.
	st, err := ex.Status(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateRunning {
		t.Fatalf("State = %q after subscriber churn, want running", st.State)
	}
}

// TestStreamAfterCompletion: subscribing to a finished handle still yields
// the retained output and a closed channel rather than blocking forever.
func TestStreamAfterCompletion(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeEcho, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	first, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collect(t, first, 30*time.Second)

	late, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("late Stream: %v", err)
	}
	out := collect(t, late, 5*time.Second)
	if !strings.Contains(out, "stdout-marker") {
		t.Errorf("late subscriber lost the retained output; got %q", out)
	}
}

func TestWorkDirAndEnvArePreserved(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	// WorkDir becomes the child's cwd.
	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		resolvedDir = dir
	}
	handle, err := ex.Start(ctx, fixtureSpec(t, modePrintCwd, dir))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	got := strings.TrimSpace(collect(t, lines, 30*time.Second))
	if got != resolvedDir && got != dir {
		t.Errorf("child cwd = %q, want %q", got, resolvedDir)
	}

	// A Spec-supplied environment reaches the child.
	handle, err = ex.Start(ctx, fixtureSpec(t, modePrintEnv, dir, "CLOOP_TEST_VAR=hello-executor"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err = ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got := strings.TrimSpace(collect(t, lines, 30*time.Second)); got != "hello-executor" {
		t.Errorf("child env CLOOP_TEST_VAR = %q, want hello-executor", got)
	}
}

func TestStartRejectsInvalidSpecs(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	if _, err := ex.Start(ctx, executor.Spec{}); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Start(empty spec) = %v, want ErrInvalidSpec", err)
	}
	missing := filepath.Join(t.TempDir(), "definitely-not-here")
	if _, err := ex.Start(ctx, executor.Spec{WorkDir: missing, Argv: []string{"/bin/true"}}); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Start(missing workdir) = %v, want ErrInvalidSpec", err)
	}

	// A file where a directory is expected.
	file := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := ex.Start(ctx, executor.Spec{WorkDir: file, Argv: []string{"/bin/true"}}); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Start(file as workdir) = %v, want ErrInvalidSpec", err)
	}

	// A nonexistent binary fails at Start rather than producing a phantom
	// handle that never reports a status.
	bogus := filepath.Join(t.TempDir(), "no-such-binary")
	if _, err := ex.Start(ctx, executor.Spec{WorkDir: t.TempDir(), Argv: []string{bogus}}); err == nil {
		t.Fatal("Start(nonexistent binary) succeeded, want error")
	}

	// Already-cancelled contexts abort before forking anything.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ex.Start(cancelled, fixtureSpec(t, modeEcho, t.TempDir())); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(cancelled ctx) = %v, want context.Canceled", err)
	}
}

// TestStartRejectsUnenforceableResourceLimits: silently ignoring a requested
// memory cap would give the caller a guarantee this driver cannot provide.
func TestStartRejectsUnenforceableResourceLimits(t *testing.T) {
	ex := New("test")
	spec := fixtureSpec(t, modeEcho, t.TempDir())
	spec.ResourceLimits = executor.ResourceLimits{MemoryMB: 512}

	_, err := ex.Start(context.Background(), spec)
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("Start with resource limits = %v, want ErrUnsupported", err)
	}
}

// TestStartHonoursTimeout: Spec.TimeoutMinutes is the driver-enforced
// wall-clock ceiling. Minutes are too coarse for a test, so this exercises
// the same machinery through executor.Run's ctx-bound kill instead, which is
// the path every UI subcommand takes.
func TestRunKillsOnContextDeadline(t *testing.T) {
	ex := New("test")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	res, err := executor.Run(ctx, ex, fixtureSpec(t, modeSleep, t.TempDir()))
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("Run took %s — the workload was not killed promptly", elapsed)
	}
	if res.Handle.PID <= 0 {
		t.Error("RunResult.Handle should still identify the killed workload")
	}

	// The workload really is gone, not merely abandoned.
	st, err := ex.Status(context.Background(), res.Handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.State.Terminal() {
		t.Fatalf("State = %q after a deadline kill, want terminal", st.State)
	}
}

func TestRunCollectsOutputAndExitCode(t *testing.T) {
	ex := New("test")

	res, err := executor.Run(context.Background(), ex, fixtureSpec(t, modeEcho, t.TempDir()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(res.Output), "stdout-marker") ||
		!strings.Contains(string(res.Output), "stderr-marker") {
		t.Errorf("Run output missing markers: %q", res.Output)
	}
	if res.Dropped {
		t.Error("Run reported dropped chunks for a tiny workload")
	}
	if res.Status.State != executor.StateExited || res.Status.ExitCode != 0 {
		t.Errorf("Status = {%q, %d}, want {exited, 0}", res.Status.State, res.Status.ExitCode)
	}

	// A non-zero exit is an error, but the output still comes back so the
	// caller can show it (this is how `cloop init` failures are reported).
	failing := fixtureSpec(t, modeExit, t.TempDir(), exitCodeEnv+"=3")
	res, err = executor.Run(context.Background(), ex, failing)
	if err == nil {
		t.Fatal("Run on a failing workload returned nil error")
	}
	if !strings.Contains(string(res.Output), "before-exit") {
		t.Errorf("output of a failing workload was lost: %q", res.Output)
	}
	if res.Status.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.Status.ExitCode)
	}
}

func TestRunRejectsNilExecutor(t *testing.T) {
	if _, err := executor.Run(context.Background(), nil, executor.Spec{Argv: []string{"/bin/true"}}); !errors.Is(err, executor.ErrExecutorNotFound) {
		t.Fatalf("Run(nil executor) = %v, want ErrExecutorNotFound", err)
	}
}

// TestEnsureIsIdempotent: bootstrap runs from several entry points (cmd init,
// ui.New, tests) and must not fail the second time.
func TestEnsureIsIdempotent(t *testing.T) {
	reg := executor.NewRegistry()
	if err := Ensure(reg); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if err := Ensure(reg); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := len(reg.List()); got != 1 {
		t.Fatalf("registry holds %d executors after two Ensures, want 1", got)
	}
	ex, err := reg.Resolve("/any/project")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ex.Kind() != executor.KindLocalProcess {
		t.Fatalf("Resolve fell back to %q, want the host driver", ex.Kind())
	}
	if Shared() != Shared() {
		t.Fatal("Shared() returned different singletons")
	}
}

func TestHandlesListing(t *testing.T) {
	ex := New("test")
	ctx := context.Background()

	handle, err := ex.Start(ctx, fixtureSpec(t, modeEcho, t.TempDir()))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	lines, err := ex.Stream(ctx, handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	collect(t, lines, 30*time.Second)

	ids := ex.Handles()
	found := false
	for _, id := range ids {
		if id == handle.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Handles() = %v, missing %q", ids, handle.ID)
	}
}
