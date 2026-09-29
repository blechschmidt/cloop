package hubcluster_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type collector struct {
	mu     sync.Mutex
	events []hubcluster.Event
}

func (c *collector) add(ev hubcluster.Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func (c *collector) snapshot() []hubcluster.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]hubcluster.Event(nil), c.events...)
}

func twoMembers(t *testing.T) (a, b *hubcluster.Node, path string) {
	t.Helper()
	path = dbPath(t)
	a = join(t, fastOpts(path))
	b = join(t, fastOpts(path))
	eventually(t, "the members to see each other", func() bool { return a.HasPeers() && b.HasPeers() })
	return a, b, path
}

func TestBusDeliversToPeersNotToTheOrigin(t *testing.T) {
	a, b, _ := twoMembers(t)
	var atA, atB collector
	a.Subscribe("log", atA.add)
	b.Subscribe("log", atB.add)

	for i := 0; i < 20; i++ {
		a.Publish("log", "/proj", map[string]int{"i": i})
	}
	eventually(t, "b to receive all 20 events", func() bool { return len(atB.snapshot()) == 20 })
	got := atB.snapshot()
	for i, ev := range got {
		var p struct{ I int }
		if err := ev.Decode(&p); err != nil || p.I != i {
			t.Fatalf("event %d = %s (%v), want i=%d — the bus must preserve publication order", i, ev.Payload, err, i)
		}
		if ev.Origin != a.ID() || ev.Key != "/proj" || ev.Topic != "log" {
			t.Fatalf("event %d = %+v", i, ev)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(atA.snapshot()); n != 0 {
		t.Fatalf("the origin received %d of its own events", n)
	}
}

func TestBusTargetedEventsReachOnlyTheirTarget(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	b := join(t, fastOpts(path))
	c := join(t, fastOpts(path))
	eventually(t, "three live members", func() bool { return len(a.LiveMembers()) == 3 })

	var atB, atC collector
	b.Subscribe("cmd", atB.add)
	c.Subscribe("cmd", atC.add)
	a.PublishTo(c.ID(), "cmd", "x", "hello")
	eventually(t, "c to receive the targeted event", func() bool { return len(atC.snapshot()) == 1 })
	time.Sleep(60 * time.Millisecond)
	if n := len(atB.snapshot()); n != 0 {
		t.Fatalf("a non-target received %d targeted event(s)", n)
	}
}

func TestBusWildcardSubscriberSeesEveryTopic(t *testing.T) {
	a, b, _ := twoMembers(t)
	var all collector
	b.Subscribe("*", all.add)
	a.Publish("one", "", nil)
	a.Publish("two", "", nil)
	eventually(t, "both topics", func() bool { return len(all.snapshot()) == 2 })
}

// TestBusSkipsWritesWithoutPeers: a single hub must not pay a write per
// broadcast for a bus nobody reads. It writes one row in all: announcing its
// own arrival, in case it is not alone after all.
func TestBusSkipsWritesWithoutPeers(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	for i := 0; i < 5; i++ {
		a.Publish("log", "", i)
	}
	a.FlushBus()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _, issued, err := db.HubEventBounds()
	if err != nil {
		t.Fatal(err)
	}
	if issued != 1 {
		t.Fatalf("a lone member wrote %d bus event(s), want only its arrival", issued)
	}
	if st := a.BusStats(); st.Published != 0 {
		t.Fatalf("published counter = %d", st.Published)
	}
}

// TestAMemberLearnsOfANewcomerWithinAPoll: a member alone publishes nothing,
// so if it learned of a newcomer only at its next heartbeat, the newcomer's
// dashboards would miss everything it produced until then — the first seconds
// of a run's output, the run starting at all. The newcomer announces itself on
// the bus and the others refresh on reading it; a leave is announced the same
// way. The heartbeat here is an hour, so nothing else can explain the result.
func TestAMemberLearnsOfANewcomerWithinAPoll(t *testing.T) {
	path := dbPath(t)
	opts := fastOpts(path)
	opts.Heartbeat = time.Hour
	opts.MemberTTL = 2 * time.Hour
	a := join(t, opts)
	b := join(t, opts)
	var got collector
	b.Subscribe("log", got.add)

	// HasPeers, not IsAlive: it reads only what a already knows, which is what
	// Publish consults. IsAlive would look b up itself.
	eventually(t, "a to learn of b from its announcement", a.HasPeers)
	a.Publish("log", "", "the first line of a run")
	a.FlushBus()
	eventually(t, "b to receive what a published", func() bool { return len(got.snapshot()) == 1 })

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a to learn b left", func() bool { return !a.IsAlive(b.ID()) && !a.HasPeers() })
}

// TestBusGapFromExplicitPrune drives the gap deterministically: three events,
// the middle one deleted.
func TestBusGapFromExplicitPrune(t *testing.T) {
	path := dbPath(t)
	// The events below are backdated an hour so the test's own prune removes
	// them. a is started, and as leader its housekeeping prunes past
	// BusRetention every LeaderInterval — with the default two minutes it could
	// take event 1 before b read it, leaving b a gap and event 3 alone, which
	// is how this failed in CI (2026-09-29). A day's retention leaves the
	// test's prune as the only one that can reach them.
	opts := fastOpts(path)
	opts.BusRetention = 24 * time.Hour
	a := join(t, opts)
	b, err := hubcluster.Join(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	var gaps int
	b.OnBusGap(func() { gaps++ })
	var got collector
	b.Subscribe("t", got.add)
	eventually(t, "a to see b", a.HasPeers)

	old := time.Now().Add(-time.Hour)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Write directly so the timestamps are under the test's control.
	if _, err := db.AppendHubEvents([]statedb.HubEventRow{
		{Origin: a.ID(), Topic: "t", Payload: "1", CreatedAt: old},
	}); err != nil {
		t.Fatal(err)
	}
	b.PollBus() // reads seq 1
	if _, err := db.AppendHubEvents([]statedb.HubEventRow{
		{Origin: a.ID(), Topic: "t", Payload: "2", CreatedAt: old},
		{Origin: a.ID(), Topic: "t", Payload: "3", CreatedAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PruneHubEvents(time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	b.PollBus()
	if gaps != 1 {
		t.Fatalf("gap hook ran %d times, want 1", gaps)
	}
	evs := got.snapshot()
	if len(evs) != 2 || string(evs[1].Payload) != "3" {
		t.Fatalf("delivered %v, want events 1 and 3", evs)
	}
}

// TestBusStartsAtTheHighWaterMark: a member that joins late is not replayed
// the history other members' clients already saw.
func TestBusStartsAtTheHighWaterMark(t *testing.T) {
	a, b, path := twoMembers(t)
	var atB collector
	b.Subscribe("t", atB.add)
	a.Publish("t", "", "before")
	eventually(t, "b to receive the first event", func() bool { return len(atB.snapshot()) == 1 })

	c, err := hubcluster.Join(fastOpts(path))
	if err != nil {
		t.Fatal(err)
	}
	var atC collector
	c.Subscribe("t", atC.add)
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	t.Cleanup(func() { cancel(); _ = c.Close() })
	eventually(t, "a to see c", func() bool { return len(a.LiveMembers()) == 3 })
	a.Publish("t", "", "after")
	eventually(t, "c to receive only the later event", func() bool { return len(atC.snapshot()) == 1 })
	if p := string(atC.snapshot()[0].Payload); p != `"after"` {
		t.Fatalf("c received %s first, want the event published after it joined", p)
	}
}
