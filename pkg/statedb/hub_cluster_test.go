package statedb_test

// Tests for the hub cluster tables (Task 20354). Each exercises the property a
// multi-member control plane leans on: members are rows that can be fenced out,
// the bus hands every reader a gap-free sequence and never reissues a number,
// and ownership is a compare-and-swap that two adopters cannot both win.

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

func clusterDB(t *testing.T) (*statedb.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func TestHubMembers_JoinHeartbeatLeave(t *testing.T) {
	db, _ := clusterDB(t)
	t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	if err := db.JoinHubMember(statedb.HubMemberRow{
		InstanceID: "hub_a", Hostname: "h", PID: 7, BootID: "b",
		Address: ":8080", AdvertiseURL: "http://10.0.0.1:8080", Version: "v1",
		Meta: `{"gitproxy":"https://10.0.0.1:9443"}`, StartedAt: t0, HeartbeatAt: t0,
	}); err != nil {
		t.Fatalf("JoinHubMember: %v", err)
	}
	ok, err := db.HeartbeatHubMember("hub_a", t0.Add(5*time.Second))
	if err != nil || !ok {
		t.Fatalf("HeartbeatHubMember = %v, %v; want true", ok, err)
	}
	rows, err := db.ListHubMembers()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListHubMembers = %v, %v", rows, err)
	}
	got := rows[0]
	if !got.HeartbeatAt.Equal(t0.Add(5*time.Second)) || got.AdvertiseURL != "http://10.0.0.1:8080" ||
		got.Meta != `{"gitproxy":"https://10.0.0.1:9443"}` || !got.LeftAt.IsZero() {
		t.Fatalf("row = %+v", got)
	}

	if err := db.LeaveHubMember("hub_a", t0.Add(6*time.Second)); err != nil {
		t.Fatalf("LeaveHubMember: %v", err)
	}
	// A member that left, or whose row vanished, must learn it at its next
	// beat — this false is the fencing signal.
	if ok, err := db.HeartbeatHubMember("hub_a", t0.Add(7*time.Second)); err != nil || ok {
		t.Fatalf("heartbeat after leave = %v, %v; want false", ok, err)
	}
	if ok, err := db.HeartbeatHubMember("hub_nobody", t0); err != nil || ok {
		t.Fatalf("heartbeat for an unknown member = %v, %v; want false", ok, err)
	}
	// Re-joining clears the leave.
	if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: "hub_a", StartedAt: t0, HeartbeatAt: t0}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.HeartbeatHubMember("hub_a", t0.Add(8*time.Second)); !ok {
		t.Fatal("heartbeat after re-join was refused")
	}

	n, err := db.PruneHubMembers(t0.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneHubMembers = %d, %v; want 1", n, err)
	}
}

func TestHubBus_SequenceSurvivesPruningEverything(t *testing.T) {
	db, _ := clusterDB(t)
	old := time.Now().Add(-time.Hour)
	last, err := db.AppendHubEvents([]statedb.HubEventRow{
		{Origin: "a", Topic: "t", Key: "k", Payload: `1`, CreatedAt: old},
		{Origin: "a", Topic: "t", Key: "k", Payload: `2`, CreatedAt: old},
	})
	if err != nil || last != 2 {
		t.Fatalf("AppendHubEvents = %d, %v; want 2", last, err)
	}
	if n, err := db.PruneHubEvents(time.Now()); err != nil || n != 2 {
		t.Fatalf("PruneHubEvents = %d, %v", n, err)
	}
	lo, hi, issued, err := db.HubEventBounds()
	if err != nil {
		t.Fatal(err)
	}
	// Empty table, but the high-water mark must still say 2: a reader that
	// starts now must not be handed seq 1 or 2 again.
	if lo != 0 || hi != 0 || issued != 2 {
		t.Fatalf("bounds = %d/%d/%d, want 0/0/2", lo, hi, issued)
	}
	next, err := db.AppendHubEvents([]statedb.HubEventRow{{Origin: "a", Topic: "t", Payload: `3`}})
	if err != nil || next != 3 {
		t.Fatalf("seq after pruning everything = %d, %v; want 3 (never reissued)", next, err)
	}
	evs, err := db.HubEventsAfter(0, 10)
	if err != nil || len(evs) != 1 || evs[0].Seq != 3 || evs[0].Payload != "3" {
		t.Fatalf("HubEventsAfter = %+v, %v", evs, err)
	}
}

// TestHubBus_ConcurrentWritersYieldGapFreeReads is the property the reader's
// gap detection rests on: with several handles writing at once, the numbers a
// reader sees are consecutive, so a jump can only mean pruning.
func TestHubBus_ConcurrentWritersYieldGapFreeReads(t *testing.T) {
	_, path := clusterDB(t)
	const writers, perWriter = 4, 50
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			db, err := statedb.Open(path)
			if err != nil {
				errs <- err
				return
			}
			defer db.Close()
			for i := 0; i < perWriter; i++ {
				if _, err := db.AppendHubEvents([]statedb.HubEventRow{{
					Origin: fmt.Sprintf("w%d", w), Topic: "t", Payload: fmt.Sprint(i),
				}}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("writer: %v", err)
	}
	reader, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var cursor int64
	total := 0
	for {
		evs, err := reader.HubEventsAfter(cursor, 37)
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) == 0 {
			break
		}
		for _, ev := range evs {
			if ev.Seq != cursor+1 {
				t.Fatalf("seq jumped from %d to %d with nothing pruned", cursor, ev.Seq)
			}
			cursor = ev.Seq
			total++
		}
	}
	if total != writers*perWriter {
		t.Fatalf("read %d events, want %d", total, writers*perWriter)
	}
}

func TestHubOwners_ClaimIsACompareAndSwap(t *testing.T) {
	db, _ := clusterDB(t)
	t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	claim := func(inst string, at time.Time, expect statedb.HubOwnerRow) bool {
		t.Helper()
		ok, err := db.ClaimHubOwner(statedb.HubOwnerRow{
			Kind: "run", Key: "/p", InstanceID: inst, Meta: `{"by":"` + inst + `"}`, ClaimedAt: at,
		}, expect)
		if err != nil {
			t.Fatalf("ClaimHubOwner(%s): %v", inst, err)
		}
		return ok
	}

	if !claim("a", t0, statedb.HubOwnerRow{}) {
		t.Fatal("first claim on a free key failed")
	}
	// b saw no owner (a stale read) — the insert must not overwrite a's claim.
	if claim("b", t0.Add(time.Second), statedb.HubOwnerRow{}) {
		t.Fatal("a claim expecting no owner replaced an existing owner")
	}
	cur, err := db.GetHubOwner("run", "/p")
	if err != nil || cur.InstanceID != "a" || cur.Meta != `{"by":"a"}` {
		t.Fatalf("owner = %+v, %v", cur, err)
	}
	// b judged a dead and takes over with the exact row it read.
	if !claim("b", t0.Add(2*time.Second), cur) {
		t.Fatal("takeover with the observed row failed")
	}
	// c raced with the same stale observation and must lose.
	if claim("c", t0.Add(3*time.Second), cur) {
		t.Fatal("two adopters both won the same orphan")
	}
	// a's late release is fenced on its instance id and frees nothing.
	if ok, err := db.ReleaseHubOwner("run", "/p", "a"); err != nil || ok {
		t.Fatalf("stale owner released a key it no longer holds: %v, %v", ok, err)
	}
	if ok, err := db.UpdateHubOwnerMeta("run", "/p", "a", `{}`, t0); err != nil || ok {
		t.Fatalf("stale owner updated meta: %v, %v", ok, err)
	}
	now, _ := db.GetHubOwner("run", "/p")
	if now.InstanceID != "b" {
		t.Fatalf("owner = %q, want b", now.InstanceID)
	}
	// Drop is conditioned on the claim too.
	if ok, _ := db.ReleaseHubOwnerIfClaim(cur); ok {
		t.Fatal("dropped with a stale observation")
	}
	if ok, _ := db.ReleaseHubOwnerIfClaim(now); !ok {
		t.Fatal("drop with the current observation failed")
	}
	if _, err := db.GetHubOwner("run", "/p"); !errors.Is(err, statedb.ErrHubOwnerNotFound) {
		t.Fatalf("after drop: %v, want ErrHubOwnerNotFound", err)
	}
}

func TestHubOwners_PutIsLatestWins(t *testing.T) {
	db, _ := clusterDB(t)
	for _, inst := range []string{"a", "b"} {
		if err := db.PutHubOwner(statedb.HubOwnerRow{Kind: "agent", Key: "edge-1", InstanceID: inst}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.GetHubOwner("agent", "edge-1")
	if err != nil || got.InstanceID != "b" || got.Meta != "{}" {
		t.Fatalf("owner = %+v, %v; want b with empty meta", got, err)
	}
	rows, err := db.ListHubOwners("agent")
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListHubOwners = %v, %v", rows, err)
	}
	if all, _ := db.ListHubOwners(""); len(all) != 1 {
		t.Fatalf("ListHubOwners(all) = %v", all)
	}
}

func TestHubMetaIfAbsent_FirstWriterWins(t *testing.T) {
	db, _ := clusterDB(t)
	got, err := db.SetHubMetaIfAbsent("cluster.k", "first")
	if err != nil || got != "first" {
		t.Fatalf("first = %q, %v", got, err)
	}
	got, err = db.SetHubMetaIfAbsent("cluster.k", "second")
	if err != nil || got != "first" {
		t.Fatalf("second = %q, %v; want the first value kept", got, err)
	}
}
