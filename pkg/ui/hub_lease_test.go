package ui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The lease is fenced and tested in pkg/hublease. What is only testable here is
// the wiring: that Run actually watches the lease, and that Shutdown actually
// releases it. Both are one line in a large lifecycle function and both fail
// silently if they regress — a hub that ignores a lost lease keeps serving as a
// second control plane, and a hub that forgets to release makes every restart
// wait out the TTL.

func leaseFixture(t *testing.T, dir string) (*statedb.DB, *hublease.Lease) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	lease, err := hublease.Acquire(hublease.Options{
		Store:    db,
		TTL:      time.Minute,
		Interval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("hublease.Acquire: %v", err)
	}
	return db, lease
}

// TestServer_Run_StandsDownWhenTheLeaseIsLost is the integration half of the
// fence. A hub whose lease was taken over has no claim to the control plane:
// its background sweeps, stale-run recovery and stop signals all belong to the
// hub that now holds it. Serving on past that point is the split-brain the
// lease exists to prevent, so Run must return rather than log and continue.
func TestServer_Run_StandsDownWhenTheLeaseIsLost(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := mkdirAllForTest(dir); err != nil {
		t.Fatalf("prepare .cloop: %v", err)
	}
	db, lease := leaseFixture(t, dir)

	port := pickFreePort(t)
	srv := New(dir, port, "")
	srv.Lease = lease

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForServerReady(t, port, 5*time.Second)

	// Another hub judged this one dead and took the lease.
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
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "hub lease lost") {
			t.Fatalf("Run returned %v, want an error naming the lost lease so a "+
				"supervisor reports a failed unit with a reason", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run kept serving after losing the lease — the hub would run on as " +
			"a second control plane against another hub's state")
	}

	// Standing down must not disturb the successor's claim: Shutdown calls
	// Release, and a release fenced on the wrong instance would free the lease
	// the new hub is actively using.
	after, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	if !after.Held() || after.InstanceID != "hub_successor" {
		t.Errorf("successor's lease was damaged when the loser stood down: %+v", after)
	}
}

// TestServer_Shutdown_ReleasesTheLease covers the ordinary restart. Without the
// release every `systemctl restart` would leave a lease with a fresh heartbeat
// behind, and the replacement process would refuse to start until the TTL
// elapsed — turning a restart into an outage.
func TestServer_Shutdown_ReleasesTheLease(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := mkdirAllForTest(dir); err != nil {
		t.Fatalf("prepare .cloop: %v", err)
	}
	db, lease := leaseFixture(t, dir)

	port := pickFreePort(t)
	srv := New(dir, port, "")
	srv.Lease = lease

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForServerReady(t, port, 5*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run after ctx cancel: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	row, err := db.GetHubLease(statedb.HubScope)
	if err != nil {
		t.Fatalf("GetHubLease: %v", err)
	}
	if row.Held() {
		t.Fatal("the lease is still held after a graceful shutdown — the next start " +
			"would refuse until the TTL elapsed")
	}

	// And a replacement starts immediately rather than waiting out the TTL.
	next, err := hublease.Acquire(hublease.Options{Store: db, TTL: time.Minute})
	if err != nil {
		t.Fatalf("restart into a released lease: %v", err)
	}
	_ = next.Release()
}

// TestServer_Run_WithoutALeaseIsUnfenced pins the nil case. Every in-process
// test and embedded use of Server leaves Lease nil, and each of Start, Lost and
// Release sits on the lifecycle path — a nil dereference in any of them would
// be a panic on shutdown rather than a caught regression.
func TestServer_Run_WithoutALeaseIsUnfenced(t *testing.T) {
	t.Parallel()

	port := pickFreePort(t)
	srv := New(t.TempDir(), port, "")
	if srv.Lease != nil {
		t.Fatal("New attached a lease; fencing belongs to `cloop ui`, not the constructor")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForServerReady(t, port, 5*time.Second)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run without a lease: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

// mkdirAllForTest creates the .cloop directory statedb.Open needs. `cloop ui`
// gets this from hublease's own MkdirAll; a test that opens the database
// directly has to do it itself.
func mkdirAllForTest(dir string) error {
	return os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755)
}
