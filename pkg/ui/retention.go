package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/janitor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// retentionCheckInterval is how often the sweep wakes to ask "is any project
// due?", not how often a project is cleaned — each project's own
// retention.interval_hours governs that, and the janitor records when it last
// ran so the cadence survives a hub restart.
//
// One hour, matching watchAutoBackup: short enough to honour the one-hour
// minimum interval config allows, long enough that the wake-up itself costs
// nothing measurable.
const retentionCheckInterval = time.Hour

// retentionStartupDelay defers the first sweep so a hub restart does not walk
// every project's .cloop while it is still registering routes and scanning
// projects. Same 30 seconds watchAutoBackup uses, for the same reason.
const retentionStartupDelay = 30 * time.Second

// watchRetention runs the disk-retention janitor for every registered project
// (Task 20229).
//
// Before this existed, cloop had three retention mechanisms and ran none of
// them unprompted: `cloop compact`, `cloop db maintain` and `cloop hub audit
// prune` are all operator-invoked. A hosted hub therefore grew until its disk
// filled — this repository's own control plane reached 4.9 GB — which is an
// availability defect rather than housekeeping, and so belongs in the server
// process.
//
// Designed to be invoked as `go s.watchRetention(ctx)` from Run(). Returns
// when ctx is cancelled.
func (s *Server) watchRetention(ctx context.Context) {
	defer recoverGoroutine("watchRetention")

	// Installed here rather than in New() so it is bound to the same lifetime
	// as the sweep it belongs to, and so a Server constructed for a test does
	// not silently acquire process-global pruning behaviour.
	installSnapshotRetentionResolver()

	startupDelay := time.NewTimer(retentionStartupDelay)
	defer startupDelay.Stop()
	select {
	case <-ctx.Done():
		return
	case <-startupDelay.C:
	}

	s.runRetentionSweep()

	ticker := time.NewTicker(retentionCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runRetentionSweep()
		}
	}
}

// runRetentionSweep visits every known project and runs a janitor pass on the
// ones that are due. A failure in one project is logged and skipped so it
// cannot stall the rest.
func (s *Server) runRetentionSweep() {
	defer recoverGoroutine("runRetentionSweep")

	s.expireGrantRequests()

	// One /proc walk for the whole sweep, consulted per project below. The
	// hub's own runStates map is not enough here: it records runs *this hub*
	// dispatched, and a `cloop run` started from a shell against a registered
	// project is invisible to it while being exactly as fatal to a step prune.
	running := multiui.ScanRunningDirs()

	for _, e := range s.allProjectEntries() {
		s.maybeRunRetention(e.Path, running)
	}
}

// expireGrantRequests lapses access requests nobody decided in time
// (Task 20271).
//
// It rides the retention sweep rather than getting its own goroutine because it
// is the same kind of work — bounded, hub-global, best-effort housekeeping —
// and an hourly cadence is right for a deadline measured in days.
//
// Expiry is not merely tidying. A request that sits pending forever is the one
// that gets approved in a batch six weeks later by someone who no longer
// remembers the incident it was filed for, and the justification on it has
// silently stopped being true. Lapsing it means the ask has to be made again,
// with a current reason — which is the point of requiring a reason at all.
//
// The broker refuses to decide a request past its deadline regardless of whether
// this has run (see checkDecidable), so a hub where this sweep never fires is
// still safe. What the sweep adds is the audit event and the visible state
// change: without it a requester would see "pending" forever and never learn
// that the answer was no.
func (s *Server) expireGrantRequests() {
	bs, err := s.openBrokers()
	if err != nil {
		return
	}
	defer bs.close()
	if bs.secret == nil {
		// No CLOOP_SECRET_KEY on this hub, so there is no secret broker and no
		// requests to expire. Not a fault; see brokerUnavailableReason.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	lapsed, err := bs.secret.ExpireRequests(ctx)
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "retention: expire access requests",
			map[string]interface{}{"error": err.Error()})
		return
	}
	if len(lapsed) == 0 {
		return
	}
	s.log().Info(logger.EventAuthz, 0, "retention: access requests lapsed undecided",
		map[string]interface{}{"count": len(lapsed)})
	// One broadcast for the batch: the envelope carries an event verb and an id
	// and nothing else, and the panel re-reads through the gated route.
	s.broadcastSecretsUpdate("request_expired", "")
}

// maybeRunRetention runs one project's pass if its policy is enabled and its
// interval has elapsed. running is the sweep-wide snapshot of where cloop run
// processes are executing.
func (s *Server) maybeRunRetention(workDir string, running multiui.RunningDirs) {
	// Nothing to retain, and stopping here matters because MarkRun below
	// creates the directory it writes into: without this, a sweep would
	// manufacture a .cloop in every registered path that does not have one.
	if _, err := os.Stat(filepath.Join(workDir, ".cloop")); err != nil {
		return
	}

	cfg, err := config.Load(workDir)
	if err != nil {
		// A project whose config will not parse still grows on disk, and the
		// default policy is the safe one — it prunes derived data only. Say so
		// and proceed rather than letting one bad file exempt a project from
		// retention forever.
		s.logRetention(workDir, "load config (using defaults): "+err.Error())
		cfg = nil
	}
	pol := janitor.PolicyFromConfig(cfg)
	if !pol.Enabled {
		return
	}
	if !janitor.Due(workDir, pol.Interval, time.Now()) {
		return
	}

	opts := janitor.Options{WorkDir: workDir, Policy: pol}

	// Only the control-plane directory's lease is ours. For every other
	// project, an empty InstanceID makes the janitor refuse to vacuum if any
	// hub holds that project's lease — which is the right answer, because
	// that hub is not this process.
	//
	// The explicit non-empty test is load-bearing: sameDir treats an empty
	// first argument as a match, so passing an unset path through would hand
	// this hub's lease identity to a project it does not own.
	if workDir != "" && s.WorkDir != "" && sameDir(workDir, s.WorkDir) {
		opts.InstanceID = s.Lease.InstanceID()
	}

	// Never rewrite a database underneath a live run, and never prune its step
	// history — a run holds every step in memory and upserts all of them on
	// each save, so deleted rows would simply come back. Everything else still
	// applies: plan snapshots, audit seals and the append-only row tables are
	// all safe to prune while a task writes.
	//
	// Both signals are consulted because they answer different questions. The
	// hub's own belief covers a run it dispatched; the /proc snapshot covers one
	// started anywhere else, including in a task worktree beneath the project.
	if s.projectRunning(workDir) || running.Contains(workDir) {
		opts.SkipVacuum = true
		opts.SkipVacuumReason = "a task is running; a rewrite would stall its writes"
		opts.RunActive = true
		opts.RunActiveReason = "a task is running"
	}

	// Stamp the attempt, not the success. A pass that dies partway — the hub
	// killed, the process OOMed, a VACUUM that outlasts the lease — would
	// otherwise leave no stamp, so the next startup would be "due" again and
	// retry the same failing work 30 seconds after every restart. Recording
	// the attempt first turns a crash loop into one failure per interval.
	if err := janitor.MarkRun(workDir, time.Now()); err != nil {
		s.logRetention(workDir, err.Error())
	}

	rep, err := janitor.RunOnce(opts)
	if err != nil {
		s.logRetention(workDir, "retention pass failed: "+err.Error())
		return
	}
	for _, e := range rep.Errs() {
		s.logRetention(workDir, e.Error())
	}

	if rep.BytesFreed() > 0 || rep.Vacuum.Ran {
		s.logRetentionResult(workDir, rep.Summary())
	}
}

// retentionKeepCache memoises per-project keep-counts for the snapshot
// resolver below. SaveSnapshot runs on every plan mutation, and config.Load
// reads and parses a YAML file — far too expensive to repeat per write.
var retentionKeepCache sync.Map // workDir -> retentionKeepEntry

type retentionKeepEntry struct {
	keep int
	at   time.Time
}

// retentionKeepTTL is how long a cached keep-count is trusted. Short enough
// that an operator editing config.yaml sees it take effect without a restart,
// long enough that a burst of task updates parses the file once.
const retentionKeepTTL = 30 * time.Second

// installSnapshotRetentionResolver makes the plan-history keep-count a
// property of the project being written rather than of this process.
//
// The hub is the one writer that serves many projects at once: pkg/state's
// Save calls pm.SaveSnapshot for whichever project a request touched. Without
// this, the control plane's own retention.keep_snapshots would govern every
// tenant — so a project that set `retention.enabled: false` to preserve its
// full history would still have it pruned on the next UI edit, which is silent
// data loss against explicit configuration.
func installSnapshotRetentionResolver() {
	pm.SetSnapshotRetentionResolver(func(workDir string) int {
		if workDir == "" {
			return pm.SnapshotRetention()
		}
		now := time.Now()
		if v, ok := retentionKeepCache.Load(workDir); ok {
			if e, ok := v.(retentionKeepEntry); ok && now.Sub(e.at) < retentionKeepTTL {
				return e.keep
			}
		}
		// A project whose config will not parse falls back to the process
		// default rather than to "unbounded": the failure that brought this
		// package into being was a directory nothing bounded.
		cfg, err := config.Load(workDir)
		if err != nil {
			cfg = nil
		}
		pol := janitor.PolicyFromConfig(cfg)
		keep := pol.KeepSnapshots
		if !pol.Enabled {
			keep = 0 // the operator asked for their history to be kept
		}
		retentionKeepCache.Store(workDir, retentionKeepEntry{keep: keep, at: now})
		return keep
	})
}

// projectRunning reports whether the hub believes a task is executing for this
// project. Read under the same mutex broadcastRunState writes it with.
func (s *Server) projectRunning(workDir string) bool {
	s.runStateMu.Lock()
	defer s.runStateMu.Unlock()
	return s.runStates[workDir]
}

// logRetention records a retention problem against a project. Mirrors
// logAutoBackup: warn-level, tagged with the component, and falling back to
// stderr on a Server that has no logger (which the background sweeps can
// legitimately be, since they run behind a recover()).
func (s *Server) logRetention(workDir, msg string) {
	line := fmt.Sprintf("retention [%s] %s", workDir, msg)
	if s != nil && s.Log != nil {
		s.Log.Warn(logger.EventStep, 0, line, map[string]interface{}{
			"work_dir":  workDir,
			"component": "retention",
		})
		return
	}
	fmt.Fprintln(os.Stderr, line)
}

// logRetentionResult records a pass that actually reclaimed something. Kept
// separate from logRetention so a healthy hub's log says "freed 2.1 GB" at
// info level rather than warning about nothing.
func (s *Server) logRetentionResult(workDir, summary string) {
	line := fmt.Sprintf("retention [%s] %s", workDir, summary)
	if s != nil && s.Log != nil {
		s.Log.Info(logger.EventStep, 0, line, map[string]interface{}{
			"work_dir":  workDir,
			"component": "retention",
		})
		return
	}
	fmt.Fprintln(os.Stderr, line)
}
