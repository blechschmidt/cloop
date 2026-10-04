package runprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// hubRig is a control plane served by a stand-in hub process, and a project
// that hub may be running.
type hubRig struct {
	hubDir  string
	project string
	db      *statedb.DB
	src     sources
}

func newHubRig(t *testing.T) *hubRig {
	t.Helper()
	r := &hubRig{hubDir: statedbtest.Dir(t), project: t.TempDir()}
	db, err := statedb.Open(state.DBPath(r.hubDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	r.db = db
	r.src = sources{
		runPIDs:      func(string) []int { return nil },
		hubs:         func() []multiui.HubProcess { return []multiui.HubProcess{{PID: 7, Dir: r.hubDir}} },
		controlPlane: state.DBPath,
		claims:       hubcluster.PeekRunClaims,
		grace:        hubcluster.DefaultOrphanRunGrace,
	}
	return r
}

// member records a hub member last seen at heartbeat. Its host is not this
// one, so liveness is judged by the heartbeat alone.
func (r *hubRig) member(t *testing.T, id string, heartbeat time.Time) {
	t.Helper()
	if err := r.db.JoinHubMember(statedb.HubMemberRow{
		InstanceID: id, Hostname: "elsewhere", PID: 4242,
		StartedAt: heartbeat.Add(-time.Hour), HeartbeatAt: heartbeat,
	}); err != nil {
		t.Fatal(err)
	}
}

func (r *hubRig) claim(t *testing.T, key, owner, meta string, at time.Time) {
	t.Helper()
	ok, err := r.db.ClaimHubOwner(statedb.HubOwnerRow{
		Kind: hubcluster.OwnerKindRun, Key: key, InstanceID: owner, Meta: meta, ClaimedAt: at,
	}, statedb.HubOwnerRow{})
	if err != nil || !ok {
		t.Fatalf("claim %s: %v %v", key, ok, err)
	}
}

func TestProbeSeesALocalRunProcess(t *testing.T) {
	r := newHubRig(t)
	r.src.runPIDs = func(dir string) []int {
		if dir == r.project {
			return []int{4711}
		}
		return nil
	}
	ev := probe(r.project, r.src, time.Now())
	if !ev.Live || !strings.Contains(ev.Reason, "pid 4711") {
		t.Fatalf("probe = %+v, want live with the run's pid", ev)
	}
}

func TestProbeSeesALiveMembersClaimInAHubsControlPlane(t *testing.T) {
	r := newHubRig(t)
	now := time.Now()
	r.member(t, "m1", now)
	r.claim(t, r.project, "m1", `{"handler":"run"}`, now)

	ev := probe(r.project, r.src, now)
	if !ev.Live || !strings.Contains(ev.Reason, "m1") || !strings.Contains(ev.Reason, state.DBPath(r.hubDir)) {
		t.Fatalf("probe = %+v, want live, naming member m1 and the control plane", ev)
	}

	// The same rig, with the hub process gone from this host: its control
	// plane is not found, and nothing else shows the run.
	r.src.hubs = func() []multiui.HubProcess { return nil }
	if ev := probe(r.project, r.src, now); ev.Live {
		t.Fatalf("probe without the hub = %+v, want not live", ev)
	}
}

// A hub serving its own directory — the deployment where the project and the
// control plane are one database — needs no hub process to be found.
func TestProbeReadsTheProjectsOwnControlPlane(t *testing.T) {
	r := newHubRig(t)
	now := time.Now()
	r.member(t, "m1", now)
	r.claim(t, r.hubDir, "m1", `{}`, now)
	r.src.hubs = func() []multiui.HubProcess { return nil }

	if ev := probe(r.hubDir, r.src, now); !ev.Live {
		t.Fatalf("probe = %+v, want live", ev)
	}
}

// The rule is hubcluster.RunClaimLive's, the one the hub's members apply: a
// dead owner's claim counts for the grace after it was last seen, unless it
// was taken before anything was dispatched.
func TestProbeJudgesADeadOwnersClaimAsTheHubDoes(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		lastSeen time.Duration
		meta     string
		live     bool
	}{
		{"within the grace", 30 * time.Second, `{"executor":"ex1","handle":"h1"}`, true},
		{"past the grace", 3 * time.Minute, `{"executor":"ex1","handle":"h1"}`, false},
		{"still dispatching", 30 * time.Second, `{"dispatching":true}`, false},
		{"undecodable meta fails closed", 30 * time.Second, `not json`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newHubRig(t)
			r.member(t, "gone", now.Add(-tc.lastSeen))
			r.claim(t, r.project, "gone", tc.meta, now.Add(-time.Hour))
			ev := probe(r.project, r.src, now)
			if ev.Live != tc.live {
				t.Fatalf("probe = %+v, want live=%v", ev, tc.live)
			}
			if ev.Live && !strings.Contains(ev.Reason, "last seen") {
				t.Errorf("reason %q does not say the owner is gone", ev.Reason)
			}
		})
	}
}

func TestProbeMatchesTheClaimByDirectoryNotSpelling(t *testing.T) {
	r := newHubRig(t)
	now := time.Now()
	r.member(t, "m1", now)
	link := filepath.Join(t.TempDir(), "via-link")
	if err := os.Symlink(r.project, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	r.claim(t, link, "m1", `{}`, now)
	r.claim(t, filepath.Join(t.TempDir(), "someone-else"), "m1", `{}`, now)

	if ev := probe(r.project, r.src, now); !ev.Live {
		t.Fatalf("a claim recorded under a symlink to the project was not matched: %+v", ev)
	}
	other := t.TempDir()
	if ev := probe(other, r.src, now); ev.Live {
		t.Fatalf("another project's claim was matched: %+v", ev)
	}
}

// A control plane that exists and cannot be read may be the one holding the
// claim, so the probe says live rather than guessing.
func TestProbeFailsClosedOnAnUnreadableControlPlane(t *testing.T) {
	r := newHubRig(t)
	broken := t.TempDir()
	if err := os.MkdirAll(filepath.Join(broken, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.DBPath(broken), []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	r.src.hubs = func() []multiui.HubProcess { return []multiui.HubProcess{{PID: 9, Dir: broken}} }

	ev := probe(r.project, r.src, time.Now())
	if !ev.Live || !strings.Contains(ev.Reason, "could not be read") {
		t.Fatalf("probe = %+v, want live because the control plane could not be read", ev)
	}
}

func TestProbeWithNothingRunning(t *testing.T) {
	r := newHubRig(t)
	if ev := probe(r.project, r.src, time.Now()); ev.Live || ev.Reason != "" {
		t.Fatalf("probe = %+v, want not live", ev)
	}
}
