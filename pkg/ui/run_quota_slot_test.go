package ui

// A run's concurrency slot goes where the run goes (Task 20452). The upgrade
// rehearsal found a run handed over twice in a rolling update leaving its
// tenant a slot short for good: the member that dispatched it gave the slot
// back only when its own stream closed — never, for a member that stopped —
// and the member that adopted the run did not know it held one.

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// slotTenant is the identity the tests admit runs for.
const slotTenant = "dev@example.com"

// slotMember is one member of a two-member control plane, enforcing quotas
// from the counters the members share.
func slotMember(t *testing.T, dir string) *Server {
	t.Helper()
	s := &Server{WorkDir: dir, Cluster: joinTestNode(t, dir, nil)}
	resolver, err := quota.New(quota.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s.SetQuotaPolicy(resolver)
	return s
}

// concurrentSlots is the tenant's concurrency counter as the members share it.
func concurrentSlots(t *testing.T, dir string) float64 {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListQuotaCounters()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Identity == slotTenant && r.Resource == string(quota.ResConcurrentTasks) && r.Bucket == "" {
			return r.Value
		}
	}
	return 0
}

// dispatchHoldingSlot admits a run for the tenant on s and dispatches it as
// handleRun does: the slot bound to the run when it is recorded, the run
// streamed and settled here unless it moves.
func dispatchHoldingSlot(t *testing.T, s *Server, ex executor.Executor, handleID string) {
	t.Helper()
	if _, err := s.quotas().Admit(quota.SubjectForIdentity(slotTenant), quota.ResConcurrentTasks, 1); err != nil {
		t.Fatalf("admit the run: %v", err)
	}
	slot := s.holdRunSlot(quota.SubjectForIdentity(slotTenant).Label(), quota.ResConcurrentTasks, 1)
	if _, err := s.claimRun(s.WorkDir, "run"); err != nil {
		t.Fatalf("claim the run: %v", err)
	}
	slot.bind(ex.ID(), handleID)
	if err := s.recordRunDispatch(s.WorkDir, "run", ex, handleID); err != nil {
		t.Fatalf("record the run: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lines, err := ex.Stream(ctx, handleID)
	if err != nil {
		t.Fatal(err)
	}
	s.trackRunWithCancel(s.WorkDir, ex, handleID, cancel)
	go s.consumeRunOutput(s.WorkDir, ex, handleID, lines, slot.giveBack)
}

func TestARunsConcurrencySlotGoesWithItToTheMemberThatAdoptsIt(t *testing.T) {
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "slots follow runs", 0); err != nil {
		t.Fatal(err)
	}
	ex := newTakeoverExecutor("edge-slot")
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
	dispatcher, adopter := slotMember(t, dir), slotMember(t, dir)
	waitCluster(t, "the members to see each other", func() bool {
		return dispatcher.Cluster.HasPeers() && adopter.Cluster.HasPeers()
	})
	asProcess(t, dispatcher.Cluster)

	dispatchHoldingSlot(t, dispatcher, ex, "h-slot")
	meta := runOwnerOf(t, dispatcher.Cluster, dir)
	if meta.Slot == nil || meta.Slot.Identity != slotTenant || meta.Slot.Resource != string(quota.ResConcurrentTasks) ||
		meta.Slot.N != 1 {
		t.Fatalf("the run's owner row names slot %+v, want one %s slot of %s", meta.Slot, quota.ResConcurrentTasks, slotTenant)
	}
	// Another run of the same tenant's holds a slot too, so a slot given
	// back twice shows up as one too few, not as a counter clamped at zero.
	if _, err := dispatcher.quotas().Admit(quota.SubjectForIdentity(slotTenant), quota.ResConcurrentTasks, 1); err != nil {
		t.Fatal(err)
	}
	if got := concurrentSlots(t, dir); got != 2 {
		t.Fatalf("the tenant holds %v slots, want the run's and the other one's", got)
	}

	// The run moves: the adopter takes it over, and the dispatcher lets go
	// of it — as it does when the adopter tells it, over the bus.
	o, found, err := adopter.Cluster.Lookup(ownerRun, dir)
	if err != nil || !found {
		t.Fatalf("the run's owner row: %v, %v", found, err)
	}
	asProcess(t, adopter.Cluster)
	adopter.adoptRun(o, meta, "test: the run moves")
	if !dispatcher.detachRun(dir) {
		t.Fatal("the dispatcher was not following the run")
	}
	waitFor(t, 5*time.Second, "the adopter to record the run", func() bool {
		m := runOwnerOf(t, adopter.Cluster, dir)
		return m.Handler == "adopted"
	})
	if m := runOwnerOf(t, adopter.Cluster, dir); m.Slot == nil || *m.Slot != *meta.Slot {
		t.Fatalf("the adopter's owner row names slot %+v, want the run's %+v — a member adopting it next "+
			"would not know to give it back", m.Slot, meta.Slot)
	}
	time.Sleep(100 * time.Millisecond) // the dispatcher's stream consumer has woken and gone
	if got := concurrentSlots(t, dir); got != 2 {
		t.Fatalf("the tenant holds %v slots after the run moved, want 2: the member that let go of the run "+
			"gave its slot back while the run went on", got)
	}

	// The run ends on the adopter, which gives the slot back — once.
	ex.finish()
	waitFor(t, 10*time.Second, "the adopter to give the run's slot back", func() bool {
		return concurrentSlots(t, dir) == 1
	})
	time.Sleep(100 * time.Millisecond)
	if got := concurrentSlots(t, dir); got != 1 {
		t.Fatalf("the tenant holds %v slots after the run ended, want the other run's 1", got)
	}
}

// TestASlotGoesBackOnceAndNotAtAllOnceItMoved pins the held slot's two rules:
// given back at most once, and never by a member its run left.
func TestASlotGoesBackOnceAndNotAtAllOnceItMoved(t *testing.T) {
	dir := statedbtest.Dir(t)
	s := slotMember(t, dir)
	for i := 0; i < 2; i++ {
		if _, err := s.quotas().Admit(quota.SubjectForIdentity(slotTenant), quota.ResConcurrentTasks, 1); err != nil {
			t.Fatal(err)
		}
	}
	label := quota.SubjectForIdentity(slotTenant).Label()
	kept := s.holdRunSlot(label, quota.ResConcurrentTasks, 1)
	kept.bind("edge", "h-kept")
	moved := s.holdRunSlot(label, quota.ResConcurrentTasks, 1)
	moved.bind("edge", "h-moved")
	if rec := s.slots().get("edge", "h-moved"); rec == nil || rec.Identity != label {
		t.Fatalf("the bound slot is not recorded for its run: %+v", rec)
	}

	s.slots().moved("edge", "h-moved")
	moved.giveBack()
	if got := concurrentSlots(t, dir); got != 2 {
		t.Fatalf("a slot whose run moved was given back here: %v held, want 2", got)
	}
	if rec := s.slots().get("edge", "h-moved"); rec != nil {
		t.Fatalf("a moved run's slot is still recorded here: %+v", rec)
	}

	kept.giveBack()
	kept.giveBack()
	if got := concurrentSlots(t, dir); got != 1 {
		t.Fatalf("a slot given back twice: %v held, want 1", got)
	}
	if rec := s.slots().get("edge", "h-kept"); rec != nil {
		t.Fatalf("a slot given back is still recorded for its run: %+v", rec)
	}

	var none *heldSlot
	none.giveBack() // a run that holds no slot
	none.bind("edge", "h-none")
	if s.holdRunSlot("", quota.ResConcurrentTasks, 1) != nil {
		t.Fatal("a slot was held for nobody")
	}
}

// TestReconcileQuotasCountsARunForTheSlotItsOwnerRowNames: a member starting
// alone rebuilds the gauges from what exists, and a run in flight holds the slot
// its owner row names — the identity that started it — rather than one guessed
// from the project's owner, of which a shared project has none (Task 20452).
// Counted for nobody, the slot the adopting member later gives back would
// leave the tenant one under its real usage for the rest of the run.
func TestReconcileQuotasCountsARunForTheSlotItsOwnerRowNames(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Status = "running"
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	srv := New(dir, 0, "")
	srv.Cluster = joinTestNode(t, dir, nil)
	e := installQuotas(t, srv, quota.Config{})
	if _, ok, err := srv.Cluster.Claim(ownerRun, dir, runOwnerMeta{Executor: "edge-slot", Handle: "h-1",
		Slot: &runQuotaSlot{Identity: slotTenant, Resource: string(quota.ResConcurrentTasks), N: 1}}); err != nil || !ok {
		t.Fatalf("claim the run = %v, %v", ok, err)
	}

	srv.ReconcileQuotas()

	if got := e.Usage(slotTenant)[quota.ResConcurrentTasks]; got != 1 {
		t.Fatalf("after the rebuild %s holds %v concurrent-task slots, want the 1 its run's owner row names", slotTenant, got)
	}
}
