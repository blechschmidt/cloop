package hubcluster_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fastOpts returns options that make a cluster converge in milliseconds, so
// tests wait on conditions rather than on production intervals.
func fastOpts(dbPath string) hubcluster.Options {
	return hubcluster.Options{
		DBPath:         dbPath,
		Heartbeat:      40 * time.Millisecond,
		MemberTTL:      400 * time.Millisecond,
		BusPoll:        15 * time.Millisecond,
		BusFlush:       5 * time.Millisecond,
		Campaign:       30 * time.Millisecond,
		LeaderTTL:      500 * time.Millisecond,
		LeaderInterval: 50 * time.Millisecond,
	}
}

func dbPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".cloop", "state.db")
}

// join starts a member and stops it at the end of the test.
func join(t *testing.T, opts hubcluster.Options) *hubcluster.Node {
	t.Helper()
	n, err := hubcluster.Join(opts)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = n.Close()
	})
	return n
}

// eventually polls cond until it holds or the deadline passes, and fails
// naming what it was waiting for.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTwoMembersSeeEachOtherAndElectOneLeader(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	b := join(t, fastOpts(path))

	eventually(t, "both members to see two live members", func() bool {
		return len(a.LiveMembers()) == 2 && len(b.LiveMembers()) == 2
	})
	eventually(t, "exactly one leader", func() bool {
		return a.IsLeader() != b.IsLeader()
	})
	leader, follower := a, b
	if b.IsLeader() {
		leader, follower = b, a
	}
	eventually(t, "the follower to name the leader", func() bool {
		return follower.LeaderID() == leader.ID()
	})
	if !a.HasPeers() || !b.HasPeers() {
		t.Fatal("HasPeers is false with two live members")
	}
}

// TestLeaderDutiesRunOnceAndMoveOnFailover is the property every leader-only
// sweep depends on: a duty runs on exactly one member at a time, and a
// graceful leave hands it to a survivor.
func TestLeaderDutiesRunOnceAndMoveOnFailover(t *testing.T) {
	path := dbPath(t)
	var running atomic.Int32
	var maxConcurrent atomic.Int32
	var starts atomic.Int32
	duty := func(ctx context.Context) {
		starts.Add(1)
		n := running.Add(1)
		for {
			m := maxConcurrent.Load()
			if n <= m || maxConcurrent.CompareAndSwap(m, n) {
				break
			}
		}
		<-ctx.Done()
		running.Add(-1)
	}

	a, err := hubcluster.Join(fastOpts(path))
	if err != nil {
		t.Fatal(err)
	}
	a.WhileLeader("sweep", duty)
	ctxA, cancelA := context.WithCancel(context.Background())
	a.Start(ctxA)

	b := join(t, fastOpts(path))
	b.WhileLeader("sweep", duty)

	eventually(t, "a leader to start the duty", func() bool { return running.Load() == 1 })
	if !a.IsLeader() {
		t.Fatalf("a joined first and should lead; leader is %q", b.LeaderID())
	}

	// Graceful leave: a releases leadership, b must take the duty over.
	cancelA()
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	eventually(t, "b to take leadership", b.IsLeader)
	eventually(t, "the duty to run on b", func() bool { return starts.Load() == 2 && running.Load() == 1 })
	if m := maxConcurrent.Load(); m != 1 {
		t.Fatalf("the duty ran on %d members at once", m)
	}
	eventually(t, "b to see a as gone", func() bool { return len(b.LiveMembers()) == 1 })
}

// TestCrashedLeaderIsReplacedAfterTheTTL: a leader that stops heartbeating
// without releasing (SIGKILL on another machine) loses leadership to a peer
// once the lease lapses, and its member row goes dead after the member TTL.
func TestCrashedLeaderIsReplacedAfterTheTTL(t *testing.T) {
	path := dbPath(t)
	crashOpts := fastOpts(path)
	// Pretend to be on another machine so the same-host pid probe cannot
	// short-cut the TTL — this test is about the TTL.
	crashOpts.Identity = hublease.Identity{Hostname: "elsewhere", PID: 99999, BootID: "other-boot"}
	a, err := hubcluster.Join(crashOpts)
	if err != nil {
		t.Fatal(err)
	}
	ctxA, crashA := context.WithCancel(context.Background())
	a.Start(ctxA)
	t.Cleanup(func() { _ = a.Close() })
	eventually(t, "a to lead", a.IsLeader)

	b := join(t, fastOpts(path))
	eventually(t, "b to see a", func() bool { return len(b.LiveMembers()) == 2 })

	// Crash: stop every loop, write nothing more. No Close.
	crashA()
	eventually(t, "b to take over once a's lease lapses", b.IsLeader)
	eventually(t, "b to judge a dead", func() bool { return !b.IsAlive(a.ID()) })
}

// TestSameHostCrashIsNoticedWithoutWaitingForTheTTL: a member on this machine
// and pid namespace whose pid is gone is dead now, not in twenty seconds.
func TestSameHostCrashIsNoticedWithoutWaitingForTheTTL(t *testing.T) {
	path := dbPath(t)
	ident := hublease.Identity{Hostname: "box", PID: 4242, BootID: "boot+pid:[1]"}
	dead := map[int]bool{}
	var mu sync.Mutex
	alive := func(pid int) bool {
		mu.Lock()
		defer mu.Unlock()
		return !dead[pid]
	}
	opts := fastOpts(path)
	opts.MemberTTL = time.Hour // the TTL must not be what notices
	opts.LeaderTTL = time.Hour
	opts.Identity = ident
	opts.ProcessAlive = alive
	a, err := hubcluster.Join(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctxA, crashA := context.WithCancel(context.Background())
	a.Start(ctxA)
	t.Cleanup(func() { _ = a.Close() })
	eventually(t, "a to lead", a.IsLeader)

	optsB := opts
	optsB.Identity = hublease.Identity{Hostname: "box", PID: 5151, BootID: "boot+pid:[1]"}
	b := join(t, optsB)
	eventually(t, "b to see a alive", func() bool { return b.IsAlive(a.ID()) && len(b.LiveMembers()) == 2 })

	crashA()
	mu.Lock()
	dead[4242] = true
	mu.Unlock()
	eventually(t, "b to judge a dead from its pid", func() bool { return !b.IsAlive(a.ID()) })
	eventually(t, "b to take leadership despite an hour-long lease TTL", b.IsLeader)
}

// TestAPidInAnotherNamespaceIsNeverProbed: the same hostname and kernel boot
// but a different pid namespace means the pid is meaningless here, and a
// probe that found nothing must not evict a live member.
func TestAPidInAnotherNamespaceIsNeverProbed(t *testing.T) {
	path := dbPath(t)
	probed := atomic.Int32{}
	optsA := fastOpts(path)
	optsA.MemberTTL = time.Hour
	optsA.Identity = hublease.Identity{Hostname: "replica", PID: 1, BootID: "boot+pid:[111]"}
	optsA.ProcessAlive = func(int) bool { probed.Add(1); return false }
	a := join(t, optsA)

	optsB := optsA
	optsB.Identity = hublease.Identity{Hostname: "replica", PID: 1, BootID: "boot+pid:[222]"}
	b := join(t, optsB)

	eventually(t, "the members to see each other", func() bool {
		return len(a.LiveMembers()) == 2 && len(b.LiveMembers()) == 2
	})
	if probed.Load() != 0 {
		t.Fatalf("probed a pid from another namespace %d time(s)", probed.Load())
	}
}

// TestJoinRefusesBesideAPreClusterHub: a live lease holder that is not a
// member is an older hub that would neither forward nor read the bus.
func TestJoinRefusesBesideAPreClusterHub(t *testing.T) {
	path := dbPath(t)
	opts := fastOpts(path)
	// Generous against a loaded test machine: the legacy hub below renews
	// every LeaderInterval, and only a lease left unrenewed this long lapses.
	opts.LeaderTTL = 10 * time.Second
	legacy, err := hublease.Acquire(hublease.Options{
		DBPath:   path,
		Identity: hublease.Identity{Hostname: "old-box", PID: 1, BootID: "x"},
		TTL:      opts.LeaderTTL,
		Interval: opts.LeaderInterval,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer legacy.Release()
	// Renewing, as a serving hub does. One that stopped renewing is waited
	// out instead — TestJoinWaitsOutASilentPreClusterHub.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	legacy.Start(ctx)

	_, err = hubcluster.Join(opts)
	if !errors.Is(err, hubcluster.ErrLegacyHub) {
		t.Fatalf("Join beside a legacy hub = %v, want ErrLegacyHub", err)
	}

	// Once it releases, joining works.
	cancel()
	if err := legacy.Release(); err != nil {
		t.Fatal(err)
	}
	n := join(t, opts)
	eventually(t, "the new member to lead", n.IsLeader)
}

// TestJoinWaitsOutASilentPreClusterHub: a pre-cluster holder that stopped
// renewing — the old build's last process, killed rather than stopped, during
// an upgrade — is waited out rather than refused, and never evicted early.
func TestJoinWaitsOutASilentPreClusterHub(t *testing.T) {
	path := dbPath(t)
	opts := fastOpts(path)
	// Long enough that creating the database below cannot use it all up.
	opts.LeaderTTL = 1500 * time.Millisecond
	// Silent for four renewals.
	lastBeat := time.Now().Add(-4 * opts.LeaderInterval)
	lapse := lastBeat.Add(opts.LeaderTTL)
	if _, err := hublease.Acquire(hublease.Options{
		DBPath:   path,
		Identity: hublease.Identity{Hostname: "old-box", PID: 1, BootID: "x"},
		Now:      func() time.Time { return lastBeat },
	}); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	// Never released: it died.
	if !time.Now().Before(lapse) {
		t.Skip("setting up took longer than the lease; nothing left to wait for")
	}

	n := join(t, opts)
	if early := time.Until(lapse); early > 0 {
		t.Fatalf("joined %s before the silent holder's lease lapsed", early)
	}
	eventually(t, "the new member to lead", n.IsLeader)
}

// TestFencedMemberRejoins: a member whose row was removed while it was still
// serving (pruned as dead after a long pause) puts itself back.
func TestFencedMemberRejoins(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.LeaveHubMember(a.ID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a to re-join", func() bool {
		rows, err := db.ListHubMembers()
		if err != nil {
			return false
		}
		for _, r := range rows {
			if r.InstanceID == a.ID() && r.LeftAt.IsZero() {
				return true
			}
		}
		return false
	})
}

func TestMembershipHookSeesJoinsAndLeaves(t *testing.T) {
	path := dbPath(t)
	a := join(t, fastOpts(path))
	var mu sync.Mutex
	var sizes []int
	a.OnMembership(func(live []hubcluster.Member) {
		mu.Lock()
		sizes = append(sizes, len(live))
		mu.Unlock()
	})
	b, err := hubcluster.Join(fastOpts(path))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.Start(ctx)
	eventually(t, "a to see b join", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sizes) > 0 && sizes[len(sizes)-1] == 2
	})
	cancel()
	_ = b.Close()
	eventually(t, "a to see b leave", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sizes[len(sizes)-1] == 1
	})
}

// TestLiveMemberRowsJudgesLikeAMember: the view of who is serving that the
// CLI refuses on — `cloop db maintain`, `cloop hub quota set` — agrees with the
// members' own. A member that left, one silent past the TTL, and one on this
// machine whose process is gone are not serving; a fresh heartbeat from
// anywhere else, or from a process here that is still running, is.
func TestLiveMemberRowsJudgesLikeAMember(t *testing.T) {
	path := dbPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Skipf("cannot run a short-lived process: %v", err)
	}
	self := hublease.LocalIdentity()
	now := time.Now()
	rows := []statedb.HubMemberRow{
		{InstanceID: "hub_elsewhere", Hostname: "other-node", PID: 1, BootID: "b", HeartbeatAt: now},
		{InstanceID: "hub_here", Hostname: self.Hostname, PID: os.Getpid(), BootID: self.BootID, HeartbeatAt: now},
		{InstanceID: "hub_crashed_here", Hostname: self.Hostname, PID: gone.ProcessState.Pid(), BootID: self.BootID, HeartbeatAt: now},
		{InstanceID: "hub_silent", Hostname: "other-node", PID: 2, BootID: "b", HeartbeatAt: now.Add(-time.Minute)},
		{InstanceID: "hub_left", Hostname: "other-node", PID: 3, BootID: "b", HeartbeatAt: now},
	}
	for _, r := range rows {
		if err := db.JoinHubMember(r); err != nil {
			t.Fatalf("JoinHubMember(%s): %v", r.InstanceID, err)
		}
	}
	if err := db.LeaveHubMember("hub_left", now); err != nil {
		t.Fatal(err)
	}

	live, err := hubcluster.LiveMemberRows(path, now)
	if err != nil {
		t.Fatalf("LiveMemberRows: %v", err)
	}
	var got []string
	for _, r := range live {
		got = append(got, r.InstanceID)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "hub_elsewhere" || got[1] != "hub_here" {
		t.Fatalf("live members = %v, want [hub_elsewhere hub_here]", got)
	}
}
