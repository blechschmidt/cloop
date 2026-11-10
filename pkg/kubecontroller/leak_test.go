package kubecontroller

// leak_test.go: the controller's goroutines — three informers and their
// watches, the leader election, the workers, a feed per pool, the health
// server — all end when its context does. A controller restarted many times
// in one process (a test binary, an embedding) must not accumulate them, and
// a follower that lost its term must not leave the term's feeds running.

import (
	"runtime"
	"strings"
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
