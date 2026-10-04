// Package runprobe answers, for a process that is not a hub, whether a run of a
// project is executing (Task 20374).
//
// The hub asks itself the same question before it repairs what a dead run left
// behind (projectExecuting in pkg/ui), and answers it from four sources. Two are
// the hub's own memory — the handles of the workloads it dispatched, and the
// flag it keeps while it streams one — and no other process can see them. The
// other two are on disk, and this package reads exactly those two, the way the
// hub reads them:
//
//   - a `cloop run` process executing in the project (pkg/multiui). That is
//     how a run on this host shows, whether a user started it in a terminal or
//     a hub dispatched it to the host executor; and
//   - the run's claim in a hub's control plane, judged by the rule hub members
//     judge each other's claims by (hubcluster.RunClaimLive). A clustered hub
//     claims a run before it dispatches it, whatever executor the run goes to,
//     so this is how a run in a container or on a remote device shows.
//
// A claim is recorded in the control plane of the hub that dispatched the run,
// which lives in the hub's working directory rather than in the project's. The
// control planes read are therefore the project's own — a hub serving the
// directory it runs in — and those of the `cloop ui` processes on this host.
//
// What it cannot see it says nothing about: a hub started with
// ui.cluster.exclusive publishes no claims, and a hub on another machine has no
// process here. Each recovers its own dead runs. A persisted "running" status is
// not evidence in either direction; it is precisely what a dead run leaves.
//
// Reading fails closed. A control plane that exists and cannot be read may hold
// the claim that would have said "live", and acting on a live run is the one
// mistake a caller cannot take back.
package runprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Evidence is the probe's answer.
type Evidence struct {
	// Live reports that a run is, or may still be, executing the project.
	Live bool
	// Reason says what showed it, as a clause a message can embed — "a `cloop
	// run` process (pid 4242) is executing in /srv/p". Empty when not Live.
	Reason string
}

// Project reports whether a run of the project at dir is live.
func Project(dir string) Evidence {
	return probe(dir, hostSources(), time.Now())
}

// sources are where the probe looks, so tests can stand in for /proc and for
// the hubs on this host.
type sources struct {
	// runPIDs returns the pids of `cloop run` processes executing in dir.
	runPIDs func(dir string) []int
	// hubs returns the `cloop ui` processes on this host.
	hubs func() []multiui.HubProcess
	// controlPlane returns the path of the control plane a hub running in dir
	// serves, and of dir's own project database.
	controlPlane func(dir string) string
	// claims reads the run claims recorded in the control plane at dbPath.
	claims func(dbPath string, now time.Time) ([]hubcluster.Owner, error)
	// grace is how long a dead owner's claim still counts.
	grace time.Duration
}

func hostSources() sources {
	return sources{
		runPIDs:      multiui.CloopRunPIDsInDir,
		hubs:         multiui.HubProcesses,
		controlPlane: state.DBPath,
		claims:       hubcluster.PeekRunClaims,
		grace:        hubcluster.DefaultOrphanRunGrace,
	}
}

func probe(dir string, src sources, now time.Time) Evidence {
	if pids := src.runPIDs(dir); len(pids) > 0 {
		return Evidence{Live: true, Reason: fmt.Sprintf(
			"a `cloop run` process (pid %d) is executing in %s", pids[0], dir)}
	}

	want := canonical(dir)
	for _, dbPath := range controlPlanes(dir, src) {
		claims, err := src.claims(dbPath, now)
		if err != nil {
			return Evidence{Live: true, Reason: fmt.Sprintf(
				"the hub control plane %s could not be read (%v), so a run claimed there cannot be ruled out",
				dbPath, err)}
		}
		for _, o := range claims {
			if canonical(o.Key) != want || !hubcluster.RunClaimLive(o, now, src.grace) {
				continue
			}
			return Evidence{Live: true, Reason: describeClaim(o, dbPath, now)}
		}
	}
	return Evidence{}
}

// controlPlanes lists the control planes that may hold a claim on dir's run:
// dir's own database, then those of the hubs on this host, each once and only
// if it exists.
func controlPlanes(dir string, src sources) []string {
	var out []string
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" {
			return
		}
		key := canonical(path)
		if seen[key] {
			return
		}
		seen[key] = true
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return
		}
		out = append(out, path)
	}
	add(src.controlPlane(dir))
	for _, h := range src.hubs() {
		add(src.controlPlane(h.Dir))
	}
	return out
}

// describeClaim says who holds a live claim, in the terms an operator can act
// on: which member, and where it runs.
func describeClaim(o hubcluster.Owner, dbPath string, now time.Time) string {
	who := o.InstanceID
	if o.Member.Hostname != "" || o.Member.PID > 0 {
		who = fmt.Sprintf("%s (pid %d on %s)", o.InstanceID, o.Member.PID, o.Member.Hostname)
	}
	if o.Alive {
		return fmt.Sprintf("hub member %s holds the run's claim in %s", who, dbPath)
	}
	since := o.Member.HeartbeatAt
	if since.IsZero() {
		since = o.ClaimedAt()
	}
	return fmt.Sprintf("hub member %s, which holds the run's claim in %s, was last seen %s ago, "+
		"and another member may still adopt the run", who, dbPath, now.Sub(since).Round(time.Second))
}

// canonical resolves p to an absolute, symlink-free path where it can, so a
// claim recorded under one spelling of a directory matches another — the
// comparison the hub's own stale-run recovery makes (sameDir in pkg/ui).
func canonical(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}
