package ui

// run_supervision_cluster_test.go covers the parts of Task 20419 that need
// more than one member: a dead member's host-process lease directory wiped
// before its record goes, a grant revocation reporting the lease a dead member
// held as pending, a revocation and a cordon a member cannot be asked about,
// and workload rows adopted by one member only.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// joinTestNode starts a bare member over dir's control plane — a hub process
// for the parts of this file that need no HTTP side.
func joinTestNode(t *testing.T, dir string, edit func(*hubcluster.Options)) *hubcluster.Node {
	t.Helper()
	opts := fastClusterOptions(state.DBPath(dir), "http://127.0.0.1:1")
	if edit != nil {
		edit(&opts)
	}
	node, err := hubcluster.Join(opts)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = node.Close()
	})
	return node
}

// asProcess makes node the cluster membership of this process until the test
// ends, for the package-level plumbing that asks for it.
func asProcess(t *testing.T, node *hubcluster.Node) {
	t.Helper()
	prev := processCluster.Load()
	processCluster.Store(node)
	t.Cleanup(func() { processCluster.Store(prev) })
}

// hostLikeExecutor is a takeoverExecutor whose leases are materialised on the
// hub's own filesystem, as a host process's are.
type hostLikeExecutor struct{ *takeoverExecutor }

func (e hostLikeExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationNone, SupportsSecretFiles: true,
		SecretFilesFromHostPath: true, SharesHostFilesystem: true}
}

// TestADeadMembersHostLeaseDirectoryIsWipedBeforeItsRecordGoes: a host
// process outlives the member that forked it, reading its credential files
// from that member's /dev/shm. The member adopting the run used to retire the
// lease's record saying the files "were wiped" — by a sweep that only runs at
// startup — and the plaintext stayed. It is wiped now, and only then does the
// record go.
func TestADeadMembersHostLeaseDirectoryIsWipedBeforeItsRecordGoes(t *testing.T) {
	ex := hostLikeExecutor{newTakeoverExecutor("host-like")}
	h := newTakeoverHub(t, ex.ID())
	victim := joinTestNode(t, h.dir, nil)
	survivor := joinTestNode(t, h.dir, nil)
	waitCluster(t, "the members to see each other", func() bool { return victim.HasPeers() && survivor.HasPeers() })

	// The victim materialises the run's lease on this host.
	asProcess(t, victim)
	h.holder = victim.ID()
	sl := acquireSecretLease(h.dir, h.dir, ex, "run_host", nil)
	if sl == nil || sl.dir == "" {
		t.Fatalf("no host lease directory was materialised: %+v", sl)
	}
	stopKeepaliveForTest(sl)
	sl.bindHandle(ex.ID(), "h-host")
	leaseID, leaseDir := sl.lease.ID, sl.dir
	liveLeases.removeIf(sl) // its registry dies with it; the directory does not
	if !dirExists(leaseDir) {
		t.Fatal("the lease directory is not on disk")
	}

	// It dies; the survivor adopts the host process's run.
	processCluster.Store(survivor)
	h.holder = survivor.ID()
	if err := victim.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "the survivor to judge the victim gone", func() bool { return !survivor.IsAlive(victim.ID()) })
	s := &Server{WorkDir: h.dir, Cluster: survivor}
	s.takeOverRunLeases(h.dir, ex, "h-host", []string{leaseID})

	if dirExists(leaseDir) {
		t.Fatalf("the dead member's credential directory %s is still on this host", leaseDir)
	}
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListSecretLeaseDirs()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Dir == leaseDir {
			t.Fatalf("the wiped directory's row is still there: %+v", r)
		}
	}
	if _, err := db.GetSecretLease(leaseID); err == nil {
		t.Error("the lease's record was kept after its files were wiped")
	}
}

// TestDeathDetectionWipesOnlyWhatIsProvablyAStoppedMembers: the sweep run when
// a member dies takes that member's directories on this host, and leaves a
// live member's, and a row for a directory out of this member's sight on
// another machine.
func TestDeathDetectionWipesOnlyWhatIsProvablyAStoppedMembers(t *testing.T) {
	dir := setupProjectDir(t, "lease directory sweep", nil)
	withControlPlaneDir(t, dir)
	victim := joinTestNode(t, dir, nil)
	survivor := joinTestNode(t, dir, nil)
	elsewhere := joinTestNode(t, dir, func(o *hubcluster.Options) {
		o.Identity = hublease.Identity{Hostname: "another-machine", PID: 4242, BootID: "another-boot"}
	})
	waitCluster(t, "the members to see each other", func() bool { return len(survivor.Peers()) == 2 })
	asProcess(t, survivor)

	mk := func(owner string) string {
		d, err := os.MkdirTemp("", "cloop-lease-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		if err := os.WriteFile(d+"/token", []byte("canary"), 0o600); err != nil {
			t.Fatal(err)
		}
		return d
	}
	victimDir, survivorDir := mk(victim.ID()), mk(survivor.ID())
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, r := range []statedb.SecretLeaseDirRow{
		{Dir: victimDir, LeaseID: "lease_v", InstanceID: victim.ID()},
		{Dir: survivorDir, LeaseID: "lease_s", InstanceID: survivor.ID()},
		{Dir: "/dev/shm/cloop-lease-on-another-machine", LeaseID: "lease_e", InstanceID: elsewhere.ID()},
	} {
		if err := db.PutSecretLeaseDir(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := victim.Close(); err != nil {
		t.Fatal(err)
	}
	if err := elsewhere.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "both to be judged gone", func() bool {
		return !survivor.IsAlive(victim.ID()) && !survivor.IsAlive(elsewhere.ID())
	})

	res, allGone := wipeDeadMembersLeaseDirs(dir, "")
	if res.Wiped != 1 || dirExists(victimDir) {
		t.Fatalf("the stopped member's directory was not wiped: %+v (exists %v)", res, dirExists(victimDir))
	}
	if !dirExists(survivorDir) {
		t.Fatal("the sweep wiped this member's own directory")
	}
	if allGone {
		t.Error("the sweep claims every directory is gone while one on another machine is out of its sight")
	}
	rows, _ := db.ListSecretLeaseDirs()
	var kept []string
	for _, r := range rows {
		kept = append(kept, r.LeaseID)
	}
	if strings.Join(kept, ",") != "lease_s,lease_e" && strings.Join(kept, ",") != "lease_e,lease_s" {
		t.Fatalf("rows after the sweep = %v, want this member's and the other machine's", kept)
	}
}

// TestAGrantRevocationReportsADeadHoldersLeaseAsPending: revoking a grant
// used to report "revoked" while a workload a dead member started still held
// the material — the cascade skipped leases "held by nobody here", and the
// dead member was not asked. The leader now reports such a lease, as pending,
// with when it takes effect.
func TestAGrantRevocationReportsADeadHoldersLeaseAsPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	ex := newTakeoverExecutor("edge-cascade")
	h := newTakeoverHub(t, ex.ID())
	victim := joinTestNode(t, h.dir, nil)
	leader := newClusterMember(t, h.dir)
	waitCluster(t, "the members to see each other", func() bool { return victim.HasPeers() && leader.node.HasPeers() })

	h.holder = victim.ID()
	sl := h.dispatch(t, ex, "h-cascade")
	leaseID := sl.lease.ID
	grantID := sl.lease.Materials[0].GrantID
	liveLeases.removeIf(sl)
	if err := victim.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "a leader that is not the victim", func() bool {
		return leader.node.IsLeader() && !leader.node.IsAlive(victim.ID())
	})
	h.holder = leader.node.ID()

	broker, closeDB, err := openUIBroker(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if err := broker.Revoke(context.Background(), grantID, "test"); err != nil {
		t.Fatal(err)
	}
	res := leader.srv.grantRevokedHere(context.Background(), clusterGrantRequest{GrantID: grantID, Actor: "test"})
	res.finish()
	if res.State != executor.RevokeStatePending {
		t.Fatalf("the cascade reports %s for a grant a dead member's workload still holds: %+v", res.State, res)
	}
	var found bool
	for _, w := range res.Leases {
		if w.LeaseID == leaseID && len(w.Pending) == 1 && strings.Contains(w.Pending[0].Error, victim.ID()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the dead member's lease is not reported pending: %+v", res.Leases)
	}
}

// TestACordonWhoseAgentsMemberCannotBeAskedIsRecorded: the cordon's lease
// revocation, handed to a member that turned out to be unreachable, used to be
// logged and dropped. Each lease recorded as issued to the agent is recorded
// revoked now — so whoever takes its run over takes the material back — and
// revoked from here.
func TestACordonWhoseAgentsMemberCannotBeAskedIsRecorded(t *testing.T) {
	ex := newTakeoverExecutor("edge-cordoned")
	h := newTakeoverHub(t, ex.ID())
	sl := h.dispatch(t, ex, "h-cordon")
	leaseID := sl.lease.ID
	liveLeases.removeIf(sl)
	h.holder = "hub_other"

	s := &Server{WorkDir: h.dir}
	if got := s.revokeRecordedLeasesOf(context.Background(), ex.ID(), "cordoned: device stolen", "admin", nil); len(got) != 1 ||
		got[0].LeaseID != leaseID {
		t.Fatalf("revoked %+v of the agent's recorded leases, want only %s", got, leaseID)
	}
	revs := recordedRevocations(t, h.dir, leaseID)
	if len(revs) != 1 || revs[0].Reason == "" || !strings.Contains(revs[0].Reason, "device stolen") {
		t.Fatalf("the cordon's revocation was not recorded: %+v", revs)
	}
	if !revs[0].Pending() {
		t.Error("a revocation nothing reached was recorded as enforced")
	}
}

// TestARevocationAMemberCannotBeAskedIsPendingOnRecord: the member holding a
// lease stopped a moment ago and nothing has judged it dead yet, so the
// revocation's fan-out tries it and cannot ask it. That read "unreachable",
// with a note promising delivery "the moment it reconnects", which nothing
// does for a hub member. The revocation is on record and binds the member
// all the same: it answers 202 with the member pending and saying what
// takes the credential back, and the record stays open for whoever does.
// A grant's revocation, which the store records, reports the member the same.
func TestARevocationAMemberCannotBeAskedIsPendingOnRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	ex := newTakeoverExecutor("edge-unasked")
	h := newTakeoverHub(t, ex.ID())
	// It heartbeats, but nothing answers at the address it advertises.
	holder := joinTestNode(t, h.dir, nil)
	survivor := newClusterMember(t, h.dir)
	waitCluster(t, "the members to see each other", func() bool { return holder.HasPeers() && survivor.node.HasPeers() })

	h.holder = holder.ID()
	sl := h.dispatch(t, ex, "h-unasked")
	leaseID, grantID := sl.lease.ID, sl.lease.Materials[0].GrantID
	liveLeases.removeIf(sl)
	h.holder = survivor.node.ID()

	code, out := revokeLease(t, survivor.srv, leaseID, `{"reason":"leaked"}`)
	if code != http.StatusAccepted || out["recorded"] != true || out["state"] != string(remote.RevokeStatePending) {
		t.Fatalf("revoking a lease whose holder cannot be asked = %d %v, want 202, recorded and pending", code, out)
	}
	member := "hub member " + holder.ID()
	var named bool
	for _, p := range asList(out["pending"]) {
		if p["executor_id"] == member && strings.Contains(fmt.Sprint(p["error"]), "could not be asked") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the member that could not be asked is not pending: %v", out["pending"])
	}
	for _, r := range asList(out["remote"]) {
		if r["executor_id"] == member {
			t.Errorf("the member is reported unreachable as well as pending: %v", r)
		}
	}
	if note := fmt.Sprint(out["note"]); strings.Contains(note, "reconnects") || !strings.Contains(note, "could not be asked") {
		t.Errorf("the note does not say what the revocation waits for: %q", note)
	}
	revs := recordedRevocations(t, h.dir, leaseID)
	if len(revs) != 1 || !revs[0].Pending() || !strings.Contains(revs[0].Detail, "could not be asked") {
		t.Fatalf("the revocation on record = %+v, want it pending and saying why", revs)
	}

	res := survivor.srv.cascadeGrantRevocation(context.Background(), secretbroker.GrantRevocation{GrantID: grantID, Actor: "test"})
	if res.State != remote.RevokeStatePending {
		t.Fatalf("the grant revocation reports %s with a member it could not ask: %+v", res.State, res)
	}
	named = false
	for _, w := range res.Leases {
		if w.Member == holder.ID() && len(w.Remote) == 0 && len(w.Pending) == 1 && w.Pending[0].ExecutorID == member {
			named = true
		}
	}
	if !named {
		t.Fatalf("the grant revocation does not report the member pending: %+v", res.Leases)
	}
}

// asList reads a JSON array of objects.
func asList(v any) []map[string]any {
	var out []map[string]any
	items, _ := v.([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// TestAWorkloadRowIsAdoptedByOneMember: a member started after a workload's
// owner died used to adopt its row as well as the member that took the run
// over. The adopter claims the row, and a later member sees it as a live
// member's, and leaves it — to that member, and to its sweep's grace.
func TestAWorkloadRowIsAdoptedByOneMember(t *testing.T) {
	dir := setupProjectDir(t, "one adopter", nil)
	withControlPlaneDir(t, dir)
	dead := joinTestNode(t, dir, nil)
	adopter := joinTestNode(t, dir, nil)
	later := joinTestNode(t, dir, nil)
	waitCluster(t, "the members to see each other", func() bool { return len(adopter.Peers()) == 2 })

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	inner, err := executorstore.NewHandles(db)
	if err != nil {
		t.Fatal(err)
	}
	rec := executor.HandleRecord{HandleID: "c-row", ExecutorID: "ctr", Driver: executor.KindContainer,
		ExternalID: "cloop-p-row", StartedAt: time.Now(), Meta: map[string]string{handleMetaInstance: dead.ID()}}
	if err := inner.PutHandle(rec); err != nil {
		t.Fatal(err)
	}
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	waitCluster(t, "the dead member to be judged gone", func() bool {
		return !adopter.IsAlive(dead.ID()) && !later.IsAlive(dead.ID())
	})
	waitCluster(t, "a leader", func() bool { return adopter.IsLeader() || later.IsLeader() })
	leaderNode, otherNode := adopter, later
	if later.IsLeader() {
		leaderNode, otherNode = later, adopter
	}
	leaderStore := scopeHandleStore(inner, leaderNode).(*clusterHandleStore)
	otherStore := scopeHandleStore(inner, otherNode).(*clusterHandleStore)

	if rows, _ := otherStore.ListHandles("ctr"); len(rows) != 0 {
		t.Fatalf("a member that does not adopt for stopped members sees their row: %+v", rows)
	}
	rows, _ := leaderStore.ListHandles("ctr")
	if len(rows) != 1 {
		t.Fatalf("the leader does not see the stopped member's row: %+v", rows)
	}
	if !executor.ClaimHandle(leaderStore, rows[0]) {
		t.Fatal("the leader could not claim the row")
	}
	if executor.ClaimHandle(otherStore, rows[0]) {
		t.Fatal("a second member claimed a row from the same reading")
	}
	if rows, _ := otherStore.ListHandles("ctr"); len(rows) != 0 {
		t.Fatalf("after the claim another member sees the row as its to adopt: %+v", rows)
	}
	if foreign, _ := otherStore.ListForeignHandles("ctr"); len(foreign) != 1 {
		t.Fatalf("another member's sweep would not spare the adopted row: %+v", foreign)
	}
	if owner, found := handleOwner("c-row"); !found || owner != leaderNode.ID() {
		t.Fatalf("the row names %q (found %v) as its owner, want the adopter", owner, found)
	}
}
