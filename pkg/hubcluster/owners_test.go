package hubcluster_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
)

type runMeta struct {
	Executor string `json:"executor"`
	Handle   string `json:"handle"`
}

// TestClaimIsExclusiveAcrossMembers: two members starting the same project's
// run at once — exactly one may dispatch.
func TestClaimIsExclusiveAcrossMembers(t *testing.T) {
	a, b, _ := twoMembers(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		for _, n := range []*hubcluster.Node{a, b} {
			wg.Add(1)
			go func(n *hubcluster.Node) {
				defer wg.Done()
				_, ok, err := n.Claim("run", "/proj", runMeta{Executor: n.ID()})
				if err != nil {
					t.Errorf("Claim: %v", err)
					return
				}
				if ok {
					wins.Add(1)
				}
			}(n)
		}
	}
	wg.Wait()
	o, found, err := a.Lookup("run", "/proj")
	if err != nil || !found {
		t.Fatalf("Lookup = %v, %v", found, err)
	}
	// Every win must have been the same member re-claiming its own key.
	var m runMeta
	if err := o.Meta(&m); err != nil {
		t.Fatal(err)
	}
	if m.Executor != o.InstanceID {
		t.Fatalf("meta names %s but %s owns the key", m.Executor, o.InstanceID)
	}
	loser := a
	if o.InstanceID == a.ID() {
		loser = b
	}
	if _, ok, _ := loser.Claim("run", "/proj", nil); ok {
		t.Fatal("the non-owner won a claim on a key a live member holds")
	}
	if wins.Load() == 0 {
		t.Fatal("nobody won the claim")
	}
}

// TestDeadOwnersKeysAreAdoptableExactlyOnce: when an owner dies, two members
// adopting its orphan race, and one wins.
func TestDeadOwnersKeysAreAdoptableExactlyOnce(t *testing.T) {
	path := dbPath(t)
	crash := fastOpts(path)
	crash.Identity = hublease.Identity{Hostname: "gone", PID: 1, BootID: "x"}
	dead, err := hubcluster.Join(crash)
	if err != nil {
		t.Fatal(err)
	}
	ctx, kill := context.WithCancel(context.Background())
	dead.Start(ctx)
	t.Cleanup(func() { _ = dead.Close() })
	if _, ok, err := dead.Claim("run", "/proj", runMeta{Executor: "container", Handle: "h1"}); err != nil || !ok {
		t.Fatalf("Claim = %v, %v", ok, err)
	}

	b := join(t, fastOpts(path))
	c := join(t, fastOpts(path))
	kill()
	eventually(t, "the owner to be judged dead", func() bool { return !b.IsAlive(dead.ID()) && !c.IsAlive(dead.ID()) })

	orphans, err := b.Orphans("run")
	if err != nil || len(orphans) != 1 {
		t.Fatalf("Orphans = %v, %v", orphans, err)
	}
	var m runMeta
	if err := orphans[0].Meta(&m); err != nil || m.Handle != "h1" {
		t.Fatalf("orphan meta = %+v, %v — an adopter needs it to find the workload", m, err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, n := range []*hubcluster.Node{b, c} {
		wg.Add(1)
		go func(n *hubcluster.Node) {
			defer wg.Done()
			ok, err := n.Adopt(orphans[0], nil)
			if err != nil {
				t.Errorf("Adopt: %v", err)
			}
			if ok {
				wins.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d members adopted the same orphan", wins.Load())
	}
	o, _, _ := b.Lookup("run", "/proj")
	if !o.Alive || (o.InstanceID != b.ID() && o.InstanceID != c.ID()) {
		t.Fatalf("owner after adoption = %+v", o)
	}
	if err := o.Meta(&m); err != nil || m.Handle != "h1" {
		t.Fatal("adoption without new meta must keep the orphan's meta")
	}
}

func TestAssertIsLatestWinsAndReleaseIsFenced(t *testing.T) {
	a, b, _ := twoMembers(t)
	if err := a.Assert("agent", "edge-1", nil); err != nil {
		t.Fatal(err)
	}
	// The agent reconnected to b.
	if err := b.Assert("agent", "edge-1", nil); err != nil {
		t.Fatal(err)
	}
	// a notices its old socket died and releases — it must not free b's.
	if ok, err := a.Release("agent", "edge-1"); err != nil || ok {
		t.Fatalf("a released a key b holds: %v, %v", ok, err)
	}
	o, found, err := a.Lookup("agent", "edge-1")
	if err != nil || !found || o.InstanceID != b.ID() || !o.Alive || o.Self {
		t.Fatalf("owner = %+v found=%v err=%v", o, found, err)
	}
	if !b.Owns("agent", "edge-1") || a.Owns("agent", "edge-1") {
		t.Fatal("Owns disagrees with the row")
	}
	if ok, _ := b.UpdateMeta("agent", "edge-1", map[string]int{"v": 2}); !ok {
		t.Fatal("the owner could not update its meta")
	}
	if ok, _ := a.UpdateMeta("agent", "edge-1", nil); ok {
		t.Fatal("a non-owner updated meta")
	}
	if ok, err := b.Release("agent", "edge-1"); err != nil || !ok {
		t.Fatalf("owner release = %v, %v", ok, err)
	}
	if _, found, _ := a.Lookup("agent", "edge-1"); found {
		t.Fatal("key still owned after release")
	}
}
