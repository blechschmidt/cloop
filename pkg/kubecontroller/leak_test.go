package kubecontroller

// leak_test.go: the controller's goroutines — three informers and their
// watches, the leader election, the workers, a feed per pool, the health
// server — all end when its context does. A controller restarted many times
// in one process (a test binary, an embedding) must not accumulate them, and
// a follower that lost its term must not leave the term's feeds running.

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const leakSlack = 10

func settledGoroutines() int {
	for i := 0; i < 5; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(50 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

func TestTheControllerLeavesNoGoroutinesBehind(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	// Warm the transports, the fakes' servers and the test's own machinery.
	warm := r.start(func(o *Options) { o.HealthAddr = "127.0.0.1:0" })
	r.eventually("a runner", func() bool { return len(r.runnerSecrets()) == 1 })
	warm.stop(t)
	r.k8s.srv.CloseClientConnections()
	r.hub.srv.CloseClientConnections()
	base := settledGoroutines()

	for i := 0; i < 8; i++ {
		rc := r.start(func(o *Options) {
			o.HealthAddr = "127.0.0.1:0"
			o.LeaderElection = &LeaderElection{Namespace: testNS, Name: "lease", Identity: "leak-" + string(rune('a'+i)),
				LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 200 * time.Millisecond}
		})
		r.eventually("leading", func() bool { return rc.c.Leading() })
		r.eventually("the pool reconciled", func() bool { return rc.c.reconciles.Load() > 0 })
		rc.stop(t)
	}
	r.k8s.srv.CloseClientConnections()
	r.hub.srv.CloseClientConnections()
	after := settledGoroutines()
	if after > base+leakSlack {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		var ours []string
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "kubecontroller") && !strings.Contains(g, "testing.tRunner") {
				ours = append(ours, g)
			}
		}
		t.Fatalf("goroutines: %d before, %d after eight controllers came and went\n%s", base, after,
			strings.Join(ours, "\n\n"))
	}
}

// A replica that loses its term stops its workers and feeds before it counts
// itself a follower.
func TestLosingTheLeaseStopsTheTermsWork(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	r.pool("build", r.spec())
	rc := r.start(func(o *Options) {
		o.LeaderElection = &LeaderElection{Namespace: testNS, Name: "lease", Identity: "me",
			LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 200 * time.Millisecond}
	})
	r.eventually("leading with a feed", func() bool {
		f := rc.c.feeds.Load()
		return rc.c.Leading() && f != nil && f.get(testNS+"/build") != nil
	})
	// The API server stops answering the Lease: the term ends at the renew
	// deadline.
	r.k8s.fail("GET /leases", 500)
	r.eventually("the term ended", func() bool { return !rc.c.Leading() && rc.c.feeds.Load() == nil && rc.c.queue.Load() == nil })
	r.k8s.fail("GET /leases", 0)
	r.eventually("leading again", func() bool { return rc.c.Leading() })
}

// heldCtx is a context whose Done closes when it is cancelled but which never
// runs an AfterFunc itself: the order the context package allows, in which
// Done is closed and Err answers before the children an AfterFunc hangs from
// are cancelled. context.AfterFunc hands its function to a parent that has an
// AfterFunc method of its own, so on this one it is held.
type heldCtx struct {
	done chan struct{}

	mu    sync.Mutex
	err   error
	funcs int
}

func newHeldCtx() *heldCtx { return &heldCtx{done: make(chan struct{})} }

func (h *heldCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (h *heldCtx) Done() <-chan struct{}       { return h.done }
func (h *heldCtx) Value(any) any               { return nil }

func (h *heldCtx) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *heldCtx) cancel() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err == nil {
		h.err = context.Canceled
		close(h.done)
	}
}

// AfterFunc keeps f and never calls it; stop reports that it prevented the
// call, as the context package's own stop does when it gets there first.
func (h *heldCtx) AfterFunc(f func()) func() bool {
	h.mu.Lock()
	h.funcs++
	h.mu.Unlock()
	var once sync.Once
	return func() bool {
		stopped := false
		once.Do(func() { stopped = true })
		return stopped
	}
}

func (h *heldCtx) afterFuncs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.funcs
}

// The health endpoint is shut down when Run returns even if the AfterFunc
// that should have shut it down when ctx ended has not run — or Serve never
// returns and Run waits on it for ever. A loaded CI runner hung
// TestTheControllerLeavesNoGoroutinesBehind exactly so.
func TestTheHealthEndpointStopsBeforeItsAfterFuncRuns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	ctx := newHeldCtx()
	var wg sync.WaitGroup
	done := serveHealth(ctx, &wg, srv, ln)
	if n := ctx.afterFuncs(); n != 1 {
		t.Fatalf("serveHealth registered %d AfterFuncs on its context, want the one this test holds", n)
	}
	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("the endpoint does not answer: %v", err)
	}
	resp.Body.Close()

	ctx.cancel()
	done()
	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		_ = srv.Close()
		t.Fatal("Serve did not return: nothing shut the endpoint down once the AfterFunc was stopped")
	}
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		c.Close()
		t.Error("the endpoint still accepts connections after it was shut down")
	}
}

// When the AfterFunc does run, the endpoint goes down as ctx ends, before Run
// returns, and the function Run calls on its way out does nothing more.
func TestTheHealthEndpointStopsWhenItsContextEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	done := serveHealth(ctx, &wg, srv, ln)
	cancel()
	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		_ = srv.Close()
		t.Fatal("Serve did not return after its context ended")
	}
	done()
}
