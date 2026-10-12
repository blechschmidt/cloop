package hubcluster_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
)

// stallingServer is a member's HTTP side that can stop answering: while
// stalled, every request — the probe's ping included — is accepted and held
// until the test ends or the stall is lifted.
type stallingServer struct {
	srv     *httptest.Server
	stalled atomic.Bool
	release chan struct{}
	once    sync.Once
	// held counts requests currently held.
	held atomic.Int32
}

func newStallingServer(t *testing.T) *stallingServer {
	t.Helper()
	s := &stallingServer{release: make(chan struct{})}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.stalled.Load() {
			s.held.Add(1)
			defer s.held.Add(-1)
			select {
			case <-s.release:
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(func() {
		s.once.Do(func() { close(s.release) })
		s.srv.Close()
	})
	return s
}

// TestAHungForwardIsBoundedByTheHeaderTimeout: a member that accepts a
// forwarded request and never answers it no longer holds the caller forever
// (Task 20419). The caller gets a 502 naming the member once the header
// timeout passes.
func TestAHungForwardIsBoundedByTheHeaderTimeout(t *testing.T) {
	path := dbPath(t)
	hung := newStallingServer(t)
	hung.stalled.Store(true)

	optsA := fastOpts(path)
	optsA.AdvertiseURL = "http://127.0.0.1:1"
	optsA.Peer.HeaderTimeout = 300 * time.Millisecond
	a := join(t, optsA)
	optsB := fastOpts(path)
	optsB.AdvertiseURL = hung.srv.URL
	b := join(t, optsB)
	eventually(t, "a to see b", func() bool { return a.IsAlive(b.ID()) })

	rec := httptest.NewRecorder()
	start := time.Now()
	err := a.Forward(rec, httptest.NewRequest(http.MethodPost, "/api/stop", strings.NewReader("{}")),
		memberOf(t, a, b.ID()), "203.0.113.9")
	took := time.Since(start)
	if err == nil || rec.Code != http.StatusBadGateway {
		t.Fatalf("Forward to a member that never answers = %v with %d, want a 502", err, rec.Code)
	}
	if took > 5*time.Second {
		t.Fatalf("the caller was held %s by a member that never answered", took)
	}
	if !strings.Contains(err.Error(), "timeout awaiting response headers") {
		t.Errorf("the error does not say the member never answered: %v", err)
	}
	if !strings.Contains(rec.Body.String(), b.ID()) {
		t.Errorf("the 502 does not name the member: %s", rec.Body.String())
	}
}

// probeOpts are fastOpts with probing on, judging a peer within a few hundred
// milliseconds.
func probeOpts(path, advertise string) hubcluster.Options {
	o := fastOpts(path)
	o.AdvertiseURL = advertise
	o.ProbeInterval = 40 * time.Millisecond
	o.ProbeTimeout = 100 * time.Millisecond
	o.UnresponsiveAfter = 250 * time.Millisecond
	return o
}

// TestAMemberThatHeartbeatsButDoesNotAnswerIsTreatedAsDown is the member whose
// heartbeat goroutine carries on while nothing serving requests does (Task
// 20419). Its peers judge it unresponsive: what it owns turns up as orphaned —
// adoptable — while its heartbeat still says alive; the request already
// waiting on it fails at once rather than at its timeout; a new one is not
// sent; the membership hooks run without it. Its first answer reverses all of
// that.
func TestAMemberThatHeartbeatsButDoesNotAnswerIsTreatedAsDown(t *testing.T) {
	path := dbPath(t)
	front := newStallingServer(t)
	stuck := newStallingServer(t)

	a := join(t, probeOpts(path, front.srv.URL))
	b := join(t, probeOpts(path, stuck.srv.URL))
	eventually(t, "the members to see each other", func() bool { return a.IsAlive(b.ID()) && b.IsAlive(a.ID()) })

	var mu sync.Mutex
	var lastServing []string
	a.OnMembership(func(live []hubcluster.Member) {
		mu.Lock()
		defer mu.Unlock()
		lastServing = lastServing[:0]
		for _, m := range live {
			lastServing = append(lastServing, m.ID)
		}
	})

	if _, ok, err := b.Claim("run", "/srv/project", map[string]string{"handle": "h-1"}); err != nil || !ok {
		t.Fatalf("b claims the run: ok=%v err=%v", ok, err)
	}
	if o, found, _ := a.Lookup("run", "/srv/project"); !found || !o.Alive {
		t.Fatalf("a sees b's run as %+v (found %v), want owned by a live member", o, found)
	}
	// Answering, b is responsive and nothing it owns is up for adoption.
	time.Sleep(200 * time.Millisecond)
	if !a.Responsive(b.ID()) {
		t.Fatal("a judged a member that answers unresponsive")
	}

	// b stops answering. A request forwarded to it before the verdict is left
	// waiting — the header timeout is the default six minutes.
	stuck.stalled.Store(true)
	waiting := make(chan error, 1)
	go func() {
		rec := httptest.NewRecorder()
		waiting <- a.Forward(rec, httptest.NewRequest(http.MethodGet, "/api/attach", nil), memberOf(t, a, b.ID()), "")
	}()
	eventually(t, "the forwarded request to be held by b", func() bool { return stuck.held.Load() > 0 })

	eventually(t, "a to judge b unresponsive", func() bool { return !a.Responsive(b.ID()) })
	if !a.IsAlive(b.ID()) {
		t.Fatal("b's heartbeat stopped too; this test is about a member that keeps heartbeating")
	}
	if a.Serving(b.ID()) {
		t.Error("a still counts the unresponsive member as serving")
	}
	select {
	case err := <-waiting:
		if !errors.Is(err, hubcluster.ErrMemberUnresponsive) {
			t.Errorf("the request waiting on b failed with %v, want ErrMemberUnresponsive", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the request waiting on b was not failed when b was judged unresponsive")
	}
	if o, found, _ := a.Lookup("run", "/srv/project"); !found || o.Alive {
		t.Errorf("b's run looks owned by a live member (%+v): it would never be adopted", o)
	}
	orphans, err := a.Orphans("run")
	if err != nil || len(orphans) != 1 || orphans[0].Key != "/srv/project" {
		t.Errorf("orphans = %+v (%v), want b's run", orphans, err)
	}
	var listed bool
	for _, m := range a.Members() {
		if m.ID == b.ID() {
			listed = m.Unresponsive && !m.UnresponsiveSince.IsZero() && m.Alive
		}
	}
	if !listed {
		t.Error("the member list does not show b as alive but unresponsive")
	}
	mu.Lock()
	hookSaw := append([]string(nil), lastServing...)
	mu.Unlock()
	for _, id := range hookSaw {
		if id == b.ID() {
			t.Errorf("the membership hook was handed the unresponsive member: %v", hookSaw)
		}
	}
	if len(hookSaw) == 0 {
		t.Error("the membership hook did not run when b was judged unresponsive")
	}

	// A new request is not sent at all.
	rec := httptest.NewRecorder()
	start := time.Now()
	err = a.Forward(rec, httptest.NewRequest(http.MethodGet, "/x", nil), memberOf(t, a, b.ID()), "")
	if !errors.Is(err, hubcluster.ErrMemberUnresponsive) || rec.Code != http.StatusBadGateway {
		t.Errorf("Forward to an unresponsive member = %v with %d, want an immediate 502", err, rec.Code)
	}
	if time.Since(start) > time.Second {
		t.Errorf("Forward waited %s on a member already judged unresponsive", time.Since(start))
	}
	if err := a.Call(context.Background(), memberOf(t, a, b.ID()), http.MethodGet, "/x", nil, nil); !errors.Is(err, hubcluster.ErrMemberUnresponsive) {
		t.Errorf("Call to an unresponsive member = %v, want ErrMemberUnresponsive", err)
	}

	// It answers again: the verdict is cleared, and its run is its own again.
	stuck.stalled.Store(false)
	eventually(t, "a to clear the verdict", func() bool { return a.Responsive(b.ID()) })
	if o, found, _ := a.Lookup("run", "/srv/project"); !found || !o.Alive {
		t.Errorf("after b answered again its run looks orphaned: %+v", o)
	}
}

// TestAnUnresponsiveLeadersRunsAreAdoptedInItsStead: a leader that heartbeats
// without answering keeps its lease — it is renewed in the database — so the
// work of adopting what members that stopped serving leave falls to the
// member serving longest in its stead (Task 20419); without that the leader's
// own runs would be adopted by nobody.
func TestAnUnresponsiveLeadersRunsAreAdoptedInItsStead(t *testing.T) {
	path := dbPath(t)
	leaderSrv := newStallingServer(t)
	a := join(t, probeOpts(path, leaderSrv.srv.URL))
	eventually(t, "the first member to lead", a.IsLeader)
	bSrv := newStallingServer(t)
	b := join(t, probeOpts(path, bSrv.srv.URL))
	cSrv := newStallingServer(t)
	c := join(t, probeOpts(path, cSrv.srv.URL))
	eventually(t, "the members to see each other", func() bool {
		return len(b.Peers()) == 2 && len(c.Peers()) == 2
	})
	if b.LeadsAdoption() || c.LeadsAdoption() || !a.LeadsAdoption() {
		t.Fatal("with an answering leader, only the leader adopts")
	}

	leaderSrv.stalled.Store(true)
	eventually(t, "the others to judge the leader unresponsive", func() bool {
		return !b.Responsive(a.ID()) && !c.Responsive(a.ID())
	})
	if !a.IsLeader() {
		t.Fatal("the stalled leader lost its lease; this test is about one that keeps it")
	}
	if !b.LeadsAdoption() {
		t.Error("the member serving longest does not adopt in the unresponsive leader's stead")
	}
	if c.LeadsAdoption() {
		t.Error("two members adopt in the leader's stead")
	}

	leaderSrv.stalled.Store(false)
	eventually(t, "the leader to answer again", func() bool { return b.Responsive(a.ID()) })
	if b.LeadsAdoption() {
		t.Error("the stand-in kept adopting after the leader answered again")
	}
}
