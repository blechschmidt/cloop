package ui

// A cordon, a drain or an agent's revocation made from the CLI takes back what
// the device holds (Task 20424). The CLI's half — record, announce, report —
// and a member's half are driven here against a stand-in device; that the
// commands reach a real agent over the bus is cmd's
// TestCLICordonTakesTheDevicesLeaseBack and TestCLIRevokeDropsTheAgentWithinABound.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// standInDevice is an edge device as far as the hub's revocation paths can
// tell: an executor of the remote kind that holds one lease and records every
// revocation it is asked for.
type standInDevice struct{ *revokeRecordingExec }

func (standInDevice) Kind() string { return executor.KindRemoteAgent }

// deviceWithLease is a control plane in which dev holds a lease recorded as
// issued to it, by a hub process that has since stopped: the lease is in no
// live registry, and its record names a holder that is gone.
func deviceWithLease(t *testing.T, id string) (h *takeoverHub, dev standInDevice, leaseID string, db *statedb.DB) {
	t.Helper()
	dev = standInDevice{&revokeRecordingExec{stubExec: stubExec{id: id, caps: executor.Capabilities{
		Isolation: executor.IsolationRemote, SupportsSecretFiles: true,
	}}}}
	h = newTakeoverHub(t, id)
	sl := h.dispatch(t, dev, "h-"+id)
	leaseID = sl.lease.ID
	dev.mu.Lock()
	dev.held = leaseID
	dev.mu.Unlock()
	liveLeases.removeIf(sl)
	h.holder = "hub_next"

	var err error
	db, err = statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: id, Kind: executor.KindRemoteAgent, Name: "edge"}); err != nil {
		t.Fatal(err)
	}
	return h, dev, leaseID, db
}

// cordonInStore writes the cordon the CLI writes, through the scheduler.
func cordonInStore(t *testing.T, db *statedb.DB, ex executor.Executor, reason string) {
	t.Helper()
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		t.Fatal(err)
	}
	reg := executor.NewRegistry()
	if err := reg.Register(ex); err != nil {
		t.Fatal(err)
	}
	sv := executor.NewSupervisor(reg, executor.DefaultSupervisorConfig(),
		executor.WithHealthStore(sched), executor.WithSessionStore(sched))
	if _, err := sv.Cordon(ex.ID(), reason); err != nil {
		t.Fatalf("Cordon: %v", err)
	}
}

// TestACLICordonWithNoHubServingIsEnforcedByTheNextHub: with no hub serving,
// the CLI's cordon says so and records the device's leases revoked; the next
// hub to start takes them back from the device with its lease janitor, once
// the device is within its reach.
func TestACLICordonWithNoHubServingIsEnforcedByTheNextHub(t *testing.T) {
	h, dev, leaseID, db := deviceWithLease(t, "edge-cli-cordon")
	cordonInStore(t, db, dev, "device stolen")

	rep, err := AnnounceExecutorRevocation(db, "cli-test", ExecutorRevocationAnnouncement{
		ExecutorID: dev.ID(), Op: ExecutorOpCordon, Reason: "device stolen", Actor: "cli:operator",
	}, time.Second)
	if err != nil {
		t.Fatalf("AnnounceExecutorRevocation: %v", err)
	}
	if !rep.NoHub || rep.Device != dev.ID() || len(rep.Recorded) != 1 || rep.Recorded[0] != leaseID {
		t.Fatalf("report = %+v; want no hub, the device, and its one lease recorded", rep)
	}
	if len(rep.Leases) != 1 || !rep.Leases[0].Pending {
		t.Fatalf("lease states = %+v; want the lease pending until a hub reaches the device", rep.Leases)
	}
	if n := len(dev.asked()); n != 0 {
		t.Fatalf("the device was asked %d times with no hub serving", n)
	}
	revs := recordedRevocations(t, h.dir, leaseID)
	if len(revs) != 1 || !strings.Contains(revs[0].Reason, "executor cordoned: device stolen") ||
		revs[0].Actor != "cli:operator" {
		t.Fatalf("the cordon's revocation on record = %+v", revs)
	}

	// The next hub: its lease janitor finds the record and takes the lease
	// back from the device, now that the device is within its reach.
	if err := executor.Register(dev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(dev.ID()) })
	s := &Server{WorkDir: h.dir}
	s.reconcileRecordedRevocations(context.Background(), time.Now())
	if asked := dev.asked(); len(asked) != 1 || asked[0].LeaseID != leaseID {
		t.Fatalf("the device was asked %+v, want its lease revoked once", asked)
	}
	if revs := recordedRevocations(t, h.dir, leaseID); len(revs) != 1 || revs[0].Pending() {
		t.Fatalf("the revocation on record after the janitor = %+v, want it enforced", revs)
	}
}

// TestAnAnnouncedChangeTheStoreDoesNotRecordTakesNothing: the bus is a table
// any process holding the database can write. A cordon the scheduler row does
// not record, or an agent revocation the credential store does not, takes
// nothing back; once the store records the cordon, the same announcement is
// acted on.
func TestAnAnnouncedChangeTheStoreDoesNotRecordTakesNothing(t *testing.T) {
	_, dev, leaseID, db := deviceWithLease(t, "edge-forged")
	if err := executor.Register(dev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(dev.ID()) })
	s := &Server{WorkDir: controlPlaneDir()}

	for _, op := range []string{ExecutorOpCordon, ExecutorOpDrain, ExecutorOpRevoke} {
		rep := s.executorRevocationHere(context.Background(), executorRevocationRequest{
			ExecutorID: dev.ID(), Op: op, Actor: "forger",
		})
		if rep.Refused == "" || rep.Acted {
			t.Errorf("%s the store does not record: %+v, want it refused", op, rep)
		}
	}
	if n := len(dev.asked()); n != 0 {
		t.Fatalf("a forged announcement took %d lease(s) back", n)
	}

	cordonInStore(t, db, dev, "suspected compromise")
	rep := s.executorRevocationHere(context.Background(), executorRevocationRequest{
		ExecutorID: dev.ID(), Op: ExecutorOpCordon, Reason: "suspected compromise", Actor: "cli:operator",
	})
	if rep.Refused != "" || !rep.Acted || len(rep.Leases) != 1 || rep.Leases[0].LeaseID != leaseID ||
		rep.Leases[0].State != executor.RevokeStateRevoked {
		t.Fatalf("a recorded cordon's announcement: %+v, want the lease taken back", rep)
	}
}

// TestACordonOfAnExecutorOnTheHubIsNotAnnounced: an executor the hub runs
// itself — a container runtime here — serves no device. Its cordon takes no
// credential back, as the dashboard's does not, so nothing is recorded or
// announced.
func TestACordonOfAnExecutorOnTheHubIsNotAnnounced(t *testing.T) {
	dir := setupProjectDir(t, "hub-local cordon", nil)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: "local-docker", Kind: executor.KindContainer, Name: "docker"}); err != nil {
		t.Fatal(err)
	}
	_, _, before, err := db.HubEventBounds()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"local-docker", "never-heard-of"} {
		rep, err := AnnounceExecutorRevocation(db, "cli-test", ExecutorRevocationAnnouncement{
			ExecutorID: id, Op: ExecutorOpCordon,
		}, time.Second)
		if err != nil || rep.Device != "" || len(rep.Recorded) != 0 {
			t.Fatalf("cordon of %s: %+v, %v; want nothing taken back", id, rep, err)
		}
	}
	if _, _, after, _ := db.HubEventBounds(); after != before {
		t.Fatal("a cordon of an executor on the hub was announced")
	}
}

// TestAnAnnouncedRevocationNamesASilentMemberAndWhatIsPending: a member the
// control plane believes alive that does not answer is named, and a lease
// nobody took back is reported pending — never as taken back.
func TestAnAnnouncedRevocationNamesASilentMemberAndWhatIsPending(t *testing.T) {
	_, dev, leaseID, db := deviceWithLease(t, "edge-silent")
	cordonInStore(t, db, dev, "decommissioning")
	host, _ := os.Hostname()
	if err := db.JoinHubMember(statedb.HubMemberRow{
		InstanceID: "hub-silent", Hostname: host + "-elsewhere", PID: 1, Meta: "{}",
		StartedAt: time.Now(), HeartbeatAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := AnnounceExecutorRevocation(db, "cli-test", ExecutorRevocationAnnouncement{
		ExecutorID: dev.ID(), Op: ExecutorOpDrain, Reason: "decommissioning", Actor: "cli:operator",
	}, 600*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if rep.NoHub || len(rep.Answered) != 0 || len(rep.Silent) != 1 || rep.Silent[0] != "hub-silent" {
		t.Fatalf("report = %+v; want the silent member named", rep)
	}
	if len(rep.Leases) != 1 || rep.Leases[0].LeaseID != leaseID || !rep.Leases[0].Pending {
		t.Fatalf("lease states = %+v; want the lease pending", rep.Leases)
	}
	// The announcement is on the bus for the member to act on when it reads it.
	evs, err := db.HubEventsAfter(0, 512)
	if err != nil {
		t.Fatal(err)
	}
	var announced bool
	for _, ev := range evs {
		if ev.Key == invalidateExecutorRevocation && strings.Contains(ev.Payload, dev.ID()) {
			announced = true
		}
	}
	if !announced {
		t.Fatal("the drain was not announced on the bus")
	}
}
