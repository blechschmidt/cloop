package kubernetes

// Goroutine-leak regression test for the Pod lifecycle.
//
// Every Start spawns three long-lived goroutines — the watcher (pump), the
// log follower it starts on Running, and the lease renewer — plus one per
// logbus subscriber. All of them are bound to the pump context, which finish
// cancels. A regression that pinned any of them (a watch body never closed, a
// renewer whose timer outlived the handle, a log follower blocked on a Read
// that nobody cancels, a subscriber goroutine whose ctx is never cancelled)
// would scale linearly with the number of runs, and a control plane executing
// hundreds of tasks a day would accumulate them until it fell over.
//
// This mirrors the shape of pkg/orchestrator/goroutine_leak_test.go: run N
// short-lived sessions, then assert runtime.NumGoroutine has returned to
// within a small slack of the pre-test baseline. With N=15 a per-run leak
// produces a delta of ~15-60, far above the slack threshold; ambient flapping
// from the runtime and the HTTP transport's idle-connection reapers is ~0-5.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// k8sGoroutineLeakSlack absorbs runtime/scheduler and net/http ambient
// flapping. Picked to be much smaller than any real per-run leak at N=15.
const k8sGoroutineLeakSlack = 12

// settleK8sGoroutineCount triggers GC and waits briefly so transient
// goroutines — closed HTTP connections' readLoop/writeLoop in particular —
// have a chance to exit before NumGoroutine is sampled.
func settleK8sGoroutineCount() int {
	for i := 0; i < 3; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(60 * time.Millisecond)
	}
	runtime.GC()
	return runtime.NumGoroutine()
}

// runOneK8sSession drives a complete Pod lifecycle with a live log
// subscriber, then tears everything down.
func runOneK8sSession(t *testing.T, subscribe bool) {
	t.Helper()
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	ex, err := New(Options{
		ID:          "leak-test",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: src,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	drained := make(chan struct{})
	if subscribe {
		streamCtx, cancelStream := context.WithCancel(context.Background())
		defer cancelStream()
		lines, err := ex.Stream(streamCtx, handle.ID)
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		go func() {
			defer close(drained)
			for range lines {
			}
		}()
	} else {
		close(drained)
	}

	name := api.onlyPodName(t)
	api.run(name)
	api.emitLog(name, "working\n")
	api.terminate(name, 0, "Completed")

	waitStatus(t, ex, handle.ID, 5*time.Second)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the log stream never closed")
	}

	// Close is idempotent and the executor is finished either way; calling
	// it is what an embedder would do on shutdown.
	ex.Close()
	api.srv.Close()
}

// TestKubernetesExecutor_NoGoroutineLeak runs N complete Pod lifecycles and
// asserts the goroutine count returns to its baseline.
func TestKubernetesExecutor_NoGoroutineLeak(t *testing.T) {
	// Warm up so one-time package and net/http init does not pollute the
	// baseline.
	runOneK8sSession(t, true)

	baseline := settleK8sGoroutineCount()

	const sessions = 15
	for i := 0; i < sessions; i++ {
		runOneK8sSession(t, i%2 == 0)
	}

	after := settleK8sGoroutineCount()
	if delta := after - baseline; delta > k8sGoroutineLeakSlack {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutine count grew by %d over %d sessions (baseline %d, after %d); "+
			"that is ~%.1f leaked per run\n\n%s",
			delta, sessions, baseline, after, float64(delta)/float64(sessions), buf[:n])
	}
}

// TestKubernetesExecutor_AbandonedStreamDoesNotLeak: a browser tab closing
// mid-run cancels its Stream context. That must release the subscriber
// goroutine without touching the workload or the other subscribers.
func TestKubernetesExecutor_AbandonedStreamDoesNotLeak(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	ex, err := New(Options{
		ID:          "leak-test",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: src,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ex.Close()

	handle, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := api.onlyPodName(t)
	api.run(name)

	baseline := settleK8sGoroutineCount()

	// Open and abandon many subscribers, as a UI with a flapping WebSocket
	// would.
	const subscribers = 40
	for i := 0; i < subscribers; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := ex.Stream(ctx, handle.ID); err != nil {
			t.Fatalf("Stream: %v", err)
		}
		cancel()
	}

	after := settleK8sGoroutineCount()
	if delta := after - baseline; delta > k8sGoroutineLeakSlack {
		t.Errorf("goroutine count grew by %d over %d abandoned subscribers", delta, subscribers)
	}

	// The workload must be unaffected by subscribers coming and going.
	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != executor.StateRunning {
		t.Errorf("state = %q after subscribers detached, want still running", st.State)
	}

	api.terminate(name, 0, "Completed")
	waitStatus(t, ex, handle.ID, 5*time.Second)
}

// TestKubernetesExecutor_FailedStartDoesNotLeak: a Start refused by the API
// server spawns no pump and no renewer, so nothing needs cleaning up — but a
// regression that created the record before the create call would leak both.
func TestKubernetesExecutor_FailedStartDoesNotLeak(t *testing.T) {
	api := newFakeAPI(t)
	src := newFakeSource(api.restConfig())
	ex, err := New(Options{
		ID:          "leak-test",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: src,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ex.Close()
	api.failAlways("POST /pods", apiFailure{Code: 403, Reason: "Forbidden", Message: "nope"})

	baseline := settleK8sGoroutineCount()
	for i := 0; i < 20; i++ {
		if _, err := ex.Start(context.Background(), testSpec()); err == nil {
			t.Fatal("Start succeeded against an API server refusing creates")
		}
	}
	after := settleK8sGoroutineCount()
	if delta := after - baseline; delta > k8sGoroutineLeakSlack {
		t.Errorf("goroutine count grew by %d over 20 refused starts", delta)
	}
	if out := src.outstanding(); len(out) != 0 {
		t.Errorf("refused starts leaked %d leases: %v", len(out), out)
	}
	if len(ex.Handles()) != 0 {
		t.Errorf("refused starts left %d handles behind", len(ex.Handles()))
	}
}
