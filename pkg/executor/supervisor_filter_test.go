package executor

// WithProbeFilter (Task 20354): on a control plane several hub processes
// serve, an edge agent is observable only from the one holding its socket,
// and every other process would read it as unreachable. The filter keeps
// those processes from probing it at all — so from demoting it, and from
// failing its work over onto another executor.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeFilterKeepsANonHolderFromDemotingAHealthyDevice(t *testing.T) {
	clk := newFakeClock()
	store := newMemHealthStore()
	sink := &memSink{}
	// This process does not hold edge-1's socket: to it, edge-1 looks gone.
	edge := newCapExec("edge-1", fullCaps(nil))
	edge.failWith(errors.New("agent edge-1 has no live session"))
	local := newCapExec("container", fullCaps(nil))

	probed := map[string]int{}
	filter := func(ex Executor) bool {
		probed[ex.ID()]++
		return ex.ID() != "edge-1" // held by another process
	}
	sv, reg := newSupervisorFixture(t, probeTestConfig(),
		WithClock(clk), WithHealthStore(store), WithEventSink(sink), WithProbeFilter(filter))
	for _, ex := range []Executor{edge, local} {
		if err := reg.Register(ex); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		clk.Advance(time.Hour)
		sv.ProbeOnce(context.Background())
	}
	if _, ok := store.get("edge-1"); ok {
		t.Fatal("a process that does not hold the device wrote health for it")
	}
	if n := len(sink.transitionsFor("edge-1")); n != 0 {
		t.Fatalf("the non-holder emitted %d transitions for a device another process holds", n)
	}
	if h, ok := store.get("container"); !ok || h.State != NodeReady {
		t.Fatalf("the executor this process may probe was not probed: %+v %v", h, ok)
	}
	if probed["edge-1"] == 0 {
		t.Fatal("the filter was never consulted about edge-1")
	}
}
