package hublease_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// These tests are about the four questions an operator ends up asking of a
// fence: can a second hub start while the first is up (no), can it start once
// the first is gone (yes, and how soon), can a crash wedge the control plane
// (no), and does the hub that lost its lease actually stop (yes). Everything
// else here exists to pin one of those.

func leaseDB(t *testing.T) (*statedb.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

// hostA is the identity every test impersonates unless it is specifically
// testing cross-host behaviour. A fixed boot id matters: the same-host liveness
// probe only engages when boot ids match, so a test that forgot one would
// silently exercise the TTL path instead.
var hostA = hublease.Identity{Hostname: "host-a", PID: 100, BootID: "boot-1"}

// baseOpts returns options wired to db with deterministic identity and clock
// inputs. Tests override what they are about.
func baseOpts(db hublease.Store, now time.Time) hublease.Options {
	return hublease.Options{
		Store:        db,
		TTL:          time.Minute,
		Identity:     hostA,
		Now:          func() time.Time { return now },
		ProcessAlive: func(int) bool { return true },
	}
}

func TestAcquire_TakesAFreeLease(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	lease, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("Acquire on a fresh control plane: %v", err)
	}
	defer lease.Release()

	if lease.InstanceID() == "" {
		t.Error("InstanceID is empty")
	}
}

func TestAcquire_RefusesWhileTheFirstHolderIsLive(t *testing.T) {
	db, path := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	first, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer first.Release()

	// Thirty seconds later — inside the one-minute TTL — a second hub starts.
	opts := baseOpts(db, now.Add(30*time.Second))
	opts.DBPath = path
	_, err = hublease.Acquire(opts)
	if err == nil {
		t.Fatal("a second hub started while the first held the lease")
	}

	var conflict *hublease.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error is %T, want *hublease.ConflictError so callers can branch on it", err)
	}
	if conflict.Holder.InstanceID != first.InstanceID() {
		t.Errorf("refusal names %q, want the actual holder %q",
			conflict.Holder.InstanceID, first.InstanceID())
	}

	// The message is the whole user experience of this feature: it is what an
	// operator sees at 3am when a deploy will not come up. Assert it carries
	// the facts needed to act rather than only that it is non-empty.
	msg := err.Error()
	for _, want := range []string{"host-a", "state.db", "cloop hub lease"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message is missing %q; an operator cannot act on it:\n%s", want, msg)
		}
	}
}

func TestAcquire_SucceedsOnceTheLeaseGoesStale(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	first, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	// Deliberately no Release and no Start: this models a holder that vanished
	// without a chance to clean up and never heartbeats again.

	// Still live one second before the TTL.
	early := baseOpts(db, now.Add(59*time.Second))
	if _, err := hublease.Acquire(early); err == nil {
		t.Fatal("took the lease before the TTL elapsed")
	}

	// Free at the TTL.
	late := baseOpts(db, now.Add(time.Minute))
	second, err := hublease.Acquire(late)
	if err != nil {
		t.Fatalf("Acquire after the TTL elapsed: %v", err)
	}
	defer second.Release()

	if second.InstanceID() == first.InstanceID() {
		t.Error("takeover reused the previous instance id")
	}
}

func TestAcquire_TakesOverImmediatelyWhenTheHolderCrashed(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	if _, err := hublease.Acquire(baseOpts(db, now)); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	// One second later the holder is gone — SIGKILL, OOM kill, a panic. Its
	// heartbeat is still fresh, so the TTL alone would lock the successor out
	// for a minute. On a supervised deployment that restarts in seconds, that
	// minute is an outage; the same-host probe is what removes it.
	opts := baseOpts(db, now.Add(time.Second))
	opts.ProcessAlive = func(pid int) bool { return false }

	lease, err := hublease.Acquire(opts)
	if err != nil {
		t.Fatalf("Acquire after the holder crashed: %v — a crashed hub must not "+
			"lock out its own restart for the full TTL", err)
	}
	defer lease.Release()
}

func TestAcquire_DoesNotTrustAPIDFromElsewhere(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	// A pid is only meaningful on the machine and boot that recorded it. On a
	// shared volume the holder may be another node entirely, and after a reboot
	// the number names whatever process inherited it. Trusting it in either
	// case would evict a live hub, so both must fall back to the TTL.
	cases := map[string]hublease.Identity{
		"another host":    {Hostname: "host-b", PID: 100, BootID: "boot-1"},
		"another boot":    {Hostname: "host-a", PID: 100, BootID: "boot-2"},
		"no boot id here": {Hostname: "host-a", PID: 100, BootID: ""},
	}
	for name, self := range cases {
		t.Run(name, func(t *testing.T) {
			db, _ := leaseDB(t)
			if _, err := hublease.Acquire(baseOpts(db, now)); err != nil {
				t.Fatalf("first Acquire: %v", err)
			}

			opts := baseOpts(db, now.Add(time.Second))
			opts.Identity = self
			opts.ProcessAlive = func(int) bool { return false }

			if _, err := hublease.Acquire(opts); err == nil {
				t.Fatal("probed a pid that does not belong to this host and boot, " +
					"and evicted a lease whose heartbeat was fresh")
			}
		})
	}
}

func TestAcquire_TreatsAReleasedLeaseAsFree(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	first, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// A restart one second later must not wait out the TTL: the previous hub
	// said it was done. This is the ordinary `systemctl restart` path.
	second, err := hublease.Acquire(baseOpts(db, now.Add(time.Second)))
	if err != nil {
		t.Fatalf("Acquire after a graceful release: %v", err)
	}
	defer second.Release()
}

func TestLease_StandsDownWhenTakenOver(t *testing.T) {
	db, _ := leaseDB(t)

	opts := hublease.Options{
		Store:    db,
		TTL:      time.Minute,
		Interval: 5 * time.Millisecond,
		Identity: hostA,
	}
	lease, err := hublease.Acquire(opts)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease.Start(ctx)

	// Simulate the case the fencing exists for: this process was paused past
	// the TTL, another hub judged the lease dead and took it, and now this one
	// wakes up. Renewal must report the loss rather than stamping a heartbeat
	// onto the successor's row.
	observed, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	ok, err := db.AcquireHubLease(
		statedb.HubLeaseRow{Scope: statedb.HubScope, InstanceID: "hub_successor"}, observed)
	if err != nil || !ok {
		t.Fatalf("simulated takeover: ok=%v err=%v", ok, err)
	}

	select {
	case <-lease.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the superseded hub never noticed it lost the lease — it would keep " +
			"serving as a second control plane, which is the split-brain this prevents")
	}
	if lease.LostErr() == nil {
		t.Error("LostErr is nil after Lost fired")
	}

	// The successor's claim must survive this lease's Release, which runs on
	// the losing hub's shutdown path.
	if err := lease.Release(); err != nil {
		t.Fatalf("Release after loss: %v", err)
	}
	after, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	if !after.Held() || after.InstanceID != "hub_successor" {
		t.Errorf("successor's lease was damaged by the loser's release: %+v", after)
	}
}

func TestLease_StandsDownWhenRenewalFailsPastTheTTL(t *testing.T) {
	db, _ := leaseDB(t)
	flaky := &flakyStore{Store: db}

	lease, err := hublease.Acquire(hublease.Options{
		Store:    flaky,
		TTL:      120 * time.Millisecond,
		Interval: 5 * time.Millisecond,
		Identity: hostA,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease.Start(ctx)

	// A database we cannot reach is not proof we lost the lease, so brief
	// failures must be ridden out. But once we have been unable to renew for a
	// full TTL another hub is entitled to take over, and serving past that
	// point is the same split-brain by a different route.
	flaky.fail(errors.New("database is locked"))

	select {
	case <-lease.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("kept serving despite being unable to renew for longer than the TTL")
	}
	if got := lease.LostErr(); got == nil || !strings.Contains(got.Error(), "could not renew") {
		t.Errorf("LostErr = %v, want it to name the renewal failure", got)
	}
}

func TestLease_TransientRenewalFailuresDoNotStandDown(t *testing.T) {
	db, _ := leaseDB(t)
	flaky := &flakyStore{Store: db}

	lease, err := hublease.Acquire(hublease.Options{
		Store:    flaky,
		TTL:      2 * time.Second,
		Interval: 5 * time.Millisecond,
		Identity: hostA,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease.Start(ctx)

	// A busy timeout under load must not take the dashboard down.
	flaky.fail(errors.New("database is locked"))
	time.Sleep(100 * time.Millisecond)
	flaky.fail(nil)
	time.Sleep(100 * time.Millisecond)

	select {
	case <-lease.Lost():
		t.Fatalf("stood down over a transient database error (%v); a single busy "+
			"timeout would take the control plane offline", lease.LostErr())
	default:
	}
}

func TestRelease_IsIdempotentAndStopsHeartbeating(t *testing.T) {
	db, _ := leaseDB(t)

	lease, err := hublease.Acquire(hublease.Options{
		Store: db, TTL: time.Minute, Interval: 5 * time.Millisecond, Identity: hostA,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	lease.Start(context.Background())

	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Server.Shutdown and the command's deferred Release both fire on a normal
	// exit; the second must not error or resurrect the heartbeat.
	if err := lease.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}

	row, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	if row.Held() {
		t.Fatal("lease still held after Release")
	}
	// Nothing may write after release — a heartbeat that outlives it would
	// revive the lease under whichever hub started next.
	before := row.HeartbeatAt
	time.Sleep(50 * time.Millisecond)
	after, _ := db.GetHubLease(statedb.HubScope)
	if !after.HeartbeatAt.Equal(before) {
		t.Error("the heartbeat goroutine outlived Release")
	}

	// Lost must not fire for a lease we gave up on purpose: Run selects on it,
	// and a spurious close would report a clean shutdown as a failure.
	select {
	case <-lease.Lost():
		t.Error("Lost fired for a voluntary release")
	default:
	}
}

func TestNilLease_IsInert(t *testing.T) {
	// pkg/ui holds a nil *Lease in every test and embedded use. Each of these
	// is on the server lifecycle path, so a nil panic here would be a crash on
	// shutdown rather than a test failure.
	var lease *hublease.Lease
	lease.Start(context.Background())
	if err := lease.Release(); err != nil {
		t.Errorf("Release on a nil lease: %v", err)
	}
	if lease.Lost() != nil {
		t.Error("Lost on a nil lease must return nil so a select blocks on it forever")
	}
	if lease.LostErr() != nil || lease.InstanceID() != "" {
		t.Error("nil lease reported state")
	}
}

func TestInspect_ReportsTheCountdown(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	st, err := hublease.Inspect(baseOpts(db, now))
	if err != nil {
		t.Fatalf("Inspect on a fresh control plane: %v", err)
	}
	if st.Present || st.Live {
		t.Errorf("fresh control plane reports Present=%v Live=%v", st.Present, st.Live)
	}

	lease, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	st, err = hublease.Inspect(baseOpts(db, now.Add(20*time.Second)))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !st.Present || !st.Live {
		t.Fatalf("held lease reports Present=%v Live=%v", st.Present, st.Live)
	}
	if st.Age != 20*time.Second {
		t.Errorf("Age = %v, want 20s", st.Age)
	}
	if st.Expires != 40*time.Second {
		t.Errorf("Expires = %v, want 40s — this is the countdown an operator waits on", st.Expires)
	}
}

func TestClear_RefusesALiveLeaseAndReleasesALapsedOne(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	lease, err := hublease.Acquire(baseOpts(db, now))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	// The gate is the reason the command is safe to document. Without it an
	// operator could evict a working hub and create the very split-brain the
	// fence prevents — with the newcomer believing it is sole owner.
	if _, err := hublease.Clear(baseOpts(db, now.Add(10*time.Second))); !errors.Is(err, hublease.ErrLeaseLive) {
		t.Fatalf("Clear on a live lease = %v, want ErrLeaseLive", err)
	}
	if row, _ := db.GetHubLease(statedb.HubScope); !row.Held() {
		t.Fatal("a refused Clear released the lease anyway")
	}

	row, err := hublease.Clear(baseOpts(db, now.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("Clear on a lapsed lease: %v", err)
	}
	if row.InstanceID != lease.InstanceID() {
		t.Errorf("Clear reported %q, want the holder it cleared (%q)", row.InstanceID, lease.InstanceID())
	}
	if after, _ := db.GetHubLease(statedb.HubScope); after.Held() {
		t.Error("lease still held after a successful Clear")
	}
}

func TestClear_OnAFreeControlPlaneIsANoOp(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	row, err := hublease.Clear(baseOpts(db, now))
	if err != nil {
		t.Fatalf("Clear with no lease: %v", err)
	}
	if row.InstanceID != "" {
		t.Errorf("Clear invented a holder: %+v", row)
	}
}

// Acquire must serialise even when several hubs start at the same instant, and
// that is the case a sequential test cannot reach: the CAS window between
// reading the row and writing it is microseconds wide. Racing real goroutines
// against one SQLite file is the only way to exercise it, and under -race it
// also covers the lease's own locking.
func TestAcquire_ConcurrentStartsElectExactlyOneWinner(t *testing.T) {
	db, _ := leaseDB(t)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	const starts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []*hublease.Lease
	)
	start := make(chan struct{})
	for i := 0; i < starts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lease, err := hublease.Acquire(baseOpts(db, now))
			if err != nil {
				return // refused, which is the expected outcome for all but one
			}
			mu.Lock()
			winners = append(winners, lease)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("%d of %d simultaneous starts took the lease, want exactly 1", len(winners), starts)
	}
	if err := winners[0].Release(); err != nil {
		t.Errorf("Release: %v", err)
	}
}

// flakyStore wraps a store and can be told to fail renewals, modelling a
// database that is briefly unreachable. Embedding the interface means only the
// method under test is overridden and everything else reaches the real
// database, so the lease is exercised against genuine rows throughout.
type flakyStore struct {
	hublease.Store
	mu  sync.Mutex
	err error
}

func (f *flakyStore) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *flakyStore) RenewHubLease(scope, instanceID string, at time.Time) (bool, error) {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	return f.Store.RenewHubLease(scope, instanceID, at)
}
