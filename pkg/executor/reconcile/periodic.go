package reconcile

// periodic.go runs the orphan sweep on a timer instead of only at startup.
//
// # Why startup-only was not enough
//
// The sweep answers "what did the process I am replacing leave behind?", and
// for a long time that was the only question worth asking, because the only way
// to orphan a workload was for the control plane to die. It is not the only
// way. A node can be evicted or lost, a Pod can be deleted out from under the
// driver, a cluster upgrade can drain a node mid-run — and each of those leaves
// an object the hub is no longer tracking, with the hub still running. A hub
// that stays up for weeks accumulated those until someone restarted it, which
// is the one operation a healthy deployment never performs.
//
// So the same sweep runs again every SweepInterval. It is the identical code
// path — there is deliberately no second implementation to drift — and it is
// safe to repeat by construction: a tracked workload is never touched, and an
// untracked one is only removed once it is past the grace period.
//
// # What this does not do
//
// It does not look for Secrets. It cannot: finding them needs `list secrets`
// and this driver holds no read access to Secrets at all, by design. That half
// of Task 20281 is solved in the other direction, by ownerReferences, so that
// deleting a Pod here takes its credentials with it without anything ever
// having to enumerate them. The two fixes are complementary and neither is
// sufficient alone — this one reaches Pods and NetworkPolicies the cluster's
// garbage collector has no reason to touch, and the ownerReferences reach
// Secrets this one cannot see.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// DefaultSweepInterval is how often the orphan sweep repeats when a deployment
// does not choose.
//
// Fifteen minutes is chosen against the cost of being wrong in each direction.
// Too long and an evicted Pod burns a node's CPU and a ResourceQuota slot for
// that much longer; too short and every hub adds steady list traffic to its
// cluster's API server for a condition that is rare. A sweep is two list calls
// per executor, so four an hour is negligible, and fifteen minutes bounds the
// lifetime of a leaked workload at something an operator would describe as
// "shortly" rather than "eventually".
const DefaultSweepInterval = 15 * time.Minute

// MinSweepInterval floors a configured interval.
//
// A misconfigured `orphan_sweep_interval_minutes: 0.1` equivalent — or a unit
// confusion that produced seconds — would turn a background tidy-up into a
// hot loop against the cluster's API server, which is a much more damaging
// failure than never sweeping at all. Zero still means disabled; this floors
// only values that asked for something positive and unreasonable.
const MinSweepInterval = time.Minute

// sweepInterval resolves the configured interval. Zero disables.
func (o Options) sweepInterval() time.Duration {
	switch {
	case o.SweepInterval < 0:
		return 0
	case o.SweepInterval == 0:
		return DefaultSweepInterval
	case o.SweepInterval < MinSweepInterval:
		return MinSweepInterval
	default:
		return o.SweepInterval
	}
}

// ExecutorSweep is one driver's result from one pass.
type ExecutorSweep struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Removed counts the objects collected. For Kubernetes that is Pods plus
	// the NetworkPolicies that governed them; for the container driver it is
	// sandbox containers.
	Removed int `json:"removed"`
	// Objects names what went, newest-format "namespace/name", capped so a
	// pathological sweep cannot put an unbounded slice into an HTTP response.
	Objects []string `json:"objects,omitempty"`
	// Error is the driver's failure, if the pass could not complete. A sweep
	// that failed is reported rather than hidden: an operator whose RBAC lost
	// the list verb should find out from the fleet panel, not from a namespace
	// slowly filling with Pods.
	Error string `json:"error,omitempty"`
}

// SweepReport is the result of one periodic pass across every driver.
type SweepReport struct {
	At        time.Time       `json:"at"`
	Removed   int             `json:"removed"`
	Executors []ExecutorSweep `json:"executors,omitempty"`
}

// maxSweepObjects caps Objects per executor. The count stays exact; only the
// listing is truncated, because the number is what a dashboard shows and the
// names are a debugging aid.
const maxSweepObjects = 50

var (
	sweepMu     sync.Mutex
	lastSweep   *SweepReport
	sweepCancel context.CancelFunc
	// sweepRunning counts live sweeper goroutines.
	//
	// It exists to make "a second Start replaced the first" observable. Without
	// it the only evidence is a cancel func, and Go cannot compare two closures
	// — so a test could assert nothing stronger than that a sweeper exists,
	// which is equally true of the bug where two of them do. Two tickers double
	// the API traffic and race to delete the same Pod, and Bootstrap runs two
	// passes by design, so this is a real state to be able to rule out.
	sweepRunning atomic.Int64
)

// LastSweep returns the most recent periodic sweep and whether one has run.
//
// The copy is deliberate, for the reason LastReport's is: callers marshal it
// into HTTP responses from other goroutines while a later pass may be running.
func LastSweep() (SweepReport, bool) {
	sweepMu.Lock()
	defer sweepMu.Unlock()
	if lastSweep == nil {
		return SweepReport{}, false
	}
	return cloneSweep(*lastSweep), true
}

func cloneSweep(r SweepReport) SweepReport {
	if r.Executors == nil {
		return r
	}
	execs := make([]ExecutorSweep, len(r.Executors))
	copy(execs, r.Executors)
	for i := range execs {
		if execs[i].Objects != nil {
			objs := make([]string, len(execs[i].Objects))
			copy(objs, execs[i].Objects)
			execs[i].Objects = objs
		}
	}
	r.Executors = execs
	return r
}

func publishSweep(r SweepReport) {
	cp := cloneSweep(r)
	sweepMu.Lock()
	lastSweep = &cp
	sweepMu.Unlock()
}

// StartPeriodicSweep runs SweepOrphansOnce every interval until ctx is done.
//
// It replaces any sweeper already running in this process: a hub reconciles
// more than once — Bootstrap does two passes by design, and tests construct
// many servers — and two tickers would double the API traffic while racing to
// delete the same objects. Calling it with a disabled interval stops the
// current sweeper and starts nothing, so toggling the setting off takes effect
// without a restart of anything but the reconciliation.
//
// The first pass is deliberately one interval away, not immediate: the startup
// sweep has just run or is running, and repeating it in the same second would
// only race it.
func StartPeriodicSweep(ctx context.Context, opts Options) {
	StopPeriodicSweep()

	interval := opts.sweepInterval()
	if interval <= 0 {
		// Said out loud, because it is the setting whose absence is invisible:
		// an operator who disabled it and then wonders why a namespace is
		// filling with Pods has one line in the startup log that explains it.
		opts.logf("executor: periodic orphan sweep is %s — orphaned workloads will be "+
			"collected only at the next restart", describeSweepInterval(opts))
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// The parent's cancellation is honoured. It would be easy to detach here
	// instead — the startup sweep does, because a one-shot tidy-up must finish
	// even if the pass that triggered it is cancelled — but a *loop* that
	// ignores its context is a goroutine with no owner, and the ctx parameter
	// would be a lie. Callers that need it to outlive their own context say so
	// at the call site with context.WithoutCancel, where the decision is
	// visible; see FromConfig.
	ctx, cancel := context.WithCancel(ctx)

	sweepMu.Lock()
	sweepCancel = cancel
	sweepMu.Unlock()

	sweepRunning.Add(1)
	go func() {
		defer sweepRunning.Add(-1)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				opts.logf("executor: panic in the periodic orphan sweep: %v", r)
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				SweepOrphansOnce(ctx, opts)
			}
		}
	}()
}

// StopPeriodicSweep halts the process's sweeper. Safe to call when none runs,
// and safe to call twice — a server shutting down does both.
func StopPeriodicSweep() {
	sweepMu.Lock()
	cancel := sweepCancel
	sweepCancel = nil
	sweepMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SweepOrphansOnce runs one pass across every driver in the registry that can
// collect its own orphans, records it, and returns it.
//
// Exported because it is also the honest implementation of "sweep now" for an
// operator who does not want to wait out the interval, and because a test that
// cannot trigger a pass deterministically would have to sleep.
func SweepOrphansOnce(ctx context.Context, opts Options) SweepReport {
	defer func() {
		if r := recover(); r != nil {
			opts.logf("executor: panic during the orphan sweep: %v", r)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()

	report := SweepReport{At: time.Now()}
	for _, ex := range opts.registry().List() {
		var res ExecutorSweep
		switch drv := ex.(type) {
		case *kubernetes.Executor:
			res = sweepOne(ctx, drv.ID(), "kubernetes", drv.ReconcileOrphans)
		case *container.Executor:
			res = sweepOne(ctx, drv.ID(), "container", drv.ReapOrphans)
		default:
			// Every other driver either cannot orphan anything (localprocess
			// workloads die with the process that spawned them) or is a remote
			// agent that reconciles its own device.
			continue
		}
		report.Executors = append(report.Executors, res)
		report.Removed += res.Removed
	}
	sort.Slice(report.Executors, func(i, j int) bool {
		return report.Executors[i].ID < report.Executors[j].ID
	})

	logSweep(report, opts)
	publishSweep(report)
	return report
}

// sweepOne runs a single driver's reaper and normalises the result.
//
// A partial success is kept rather than discarded: the container driver reports
// the exited half's real removals alongside an error from the running half, and
// an operator debugging a vanished sandbox needs to know it was collected even
// though the pass also failed.
func sweepOne(ctx context.Context, id, kind string,
	reap func(context.Context) ([]string, error)) ExecutorSweep {

	res := ExecutorSweep{ID: id, Kind: kind}
	removed, err := reap(ctx)
	if err != nil {
		res.Error = err.Error()
	}
	res.Removed = len(removed)
	if len(removed) > maxSweepObjects {
		removed = removed[:maxSweepObjects]
	}
	res.Objects = append([]string(nil), removed...)
	return res
}

// logSweep says something only when there is something to say.
//
// A sweep that found nothing is the expected outcome on a healthy hub, and
// emitting a line for it four times an hour is how an operator learns to filter
// the component out — taking the lines that matter with it.
func logSweep(r SweepReport, opts Options) {
	for _, e := range r.Executors {
		if e.Error != "" {
			opts.logf("executor %s: periodic orphan sweep failed: %s", e.ID, e.Error)
		}
		if e.Removed == 0 {
			continue
		}
		opts.logf("executor %s: periodic sweep collected %d orphaned object(s): %s",
			e.ID, e.Removed, strings.Join(e.Objects, ", "))
	}
}

// resetSweepForTest clears the published sweep and stops any sweeper, so one
// test's pass is not visible to the next. It waits for the goroutine to
// actually exit, because a leak detector that runs while the previous test's
// sweeper is still unwinding reports a leak that is really a race.
func resetSweepForTest() {
	StopPeriodicSweep()
	waitSweepersStopped(2 * time.Second)
	sweepMu.Lock()
	lastSweep = nil
	sweepMu.Unlock()
}

// waitSweepersStopped blocks until no sweeper goroutine is live, or d elapses.
// It reports whether they stopped.
func waitSweepersStopped(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if sweepRunning.Load() == 0 {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return sweepRunning.Load() == 0
}

// describeSweepInterval renders the configured cadence for an operator-facing
// message.
func describeSweepInterval(opts Options) string {
	d := opts.sweepInterval()
	if d <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("every %s", d)
}
