package knowledge

// runner.go: the hub's knowledge sync scheduler (Task 20470).
//
// A Runner runs two kinds of sync. The schedule — every enabled source, on its
// own interval — is a leader duty: only the hub-cluster member that leads runs
// Schedule, so a cluster of three syncs each source once, not three times. A
// manual sync — a person asking for one now — runs on whichever member they
// asked. Either way the sync first takes its source's lease in the shared
// database, so a manual sync on one member and the leader's scheduled one, or
// two manual ones, never run at once: the second is refused and told which
// member holds the source.
//
// A sync's lease is renewed while it runs, and every write that moves the sync
// forward checks it, so a process that stalled past its lease writes nothing
// more once another sync has taken over. Each sync opens its own database
// handle and the secret store for its length — the credential is opened inside
// the sync and wiped at its end — and a panic in one source's connector fails
// that source's sync and no other. Stopping the runner, or its leader duty
// ending, interrupts every sync it runs: each records itself interrupted, to
// resume from its cursor, and releases its lease before the runner returns.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Runner defaults.
const (
	// DefaultSyncConcurrency bounds the scheduled syncs one process runs at
	// once.
	DefaultSyncConcurrency = 4
	// DefaultScheduleTick is how often the schedule is read.
	DefaultScheduleTick = time.Minute
	// DefaultSyncLeaseTTL is how long a sync's lease lasts unless renewed; it
	// is renewed every third of that.
	DefaultSyncLeaseTTL = 2 * time.Minute
	// DefaultSyncBudget bounds how long one sync lists; a source with more
	// resumes from its cursor at once, so one large source cannot hold a
	// slot for hours while the others wait.
	DefaultSyncBudget = 20 * time.Minute
	// DefaultScheduleDelay is how long a newly elected leader waits before
	// its first pass, so a hub that just started is not also syncing every
	// source at once.
	DefaultScheduleDelay = 30 * time.Second
	// resumeAfter is how soon a sync that stopped short — interrupted, out of
	// its budget, or overtaken by a change to its source — is followed by the
	// next.
	resumeAfter = time.Minute
	// purgeBudget bounds the purge of deleted sources' rows each pass runs.
	purgeBudget = 5 * time.Second
)

// ErrRunnerStopped reports a sync asked of a runner that has stopped.
var ErrRunnerStopped = errors.New("knowledge: the hub is stopping and starts no more syncs")

// errHubStopping is the cause a stopping runner interrupts its syncs with.
var errHubStopping = fmt.Errorf("%w: the hub process running it stopped", ErrSyncInterrupted)

// errNoLongerLeading is the cause a schedule interrupts its syncs with when
// its leader duty ends.
var errNoLongerLeading = fmt.Errorf("%w: the hub process running it stopped leading its cluster", ErrSyncInterrupted)

// BusyError is a sync refused because another sync of the source runs: on
// this hub process or another. It matches statedb.ErrKnowledgeSyncLeaseHeld.
type BusyError struct {
	Running RunningSync
}

func (e *BusyError) Error() string {
	return fmt.Sprintf("knowledge: a %s sync of this source is already running on %s, since %s",
		e.Running.Origin, e.Running.Member, e.Running.Since.UTC().Format(time.RFC3339))
}

// Is makes errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld) match.
func (e *BusyError) Is(target error) bool { return target == statedb.ErrKnowledgeSyncLeaseHeld }

// RunnerOptions configures a Runner.
type RunnerOptions struct {
	// Member is the hub process's instance id, as a sync's lease records it.
	Member string
	// Open opens the Service one sync runs with — its own database handle,
	// and the secret store — and close releases them. It is called once per
	// sync and once per pass of the schedule, so what it opens is held for
	// that long and no longer.
	Open func() (svc *Service, close func(), err error)
	// Concurrency bounds the scheduled syncs this process runs at once
	// (DefaultSyncConcurrency). Manual syncs are not counted against it: each
	// is one person's request, and the lease bounds them to one per source.
	Concurrency int
	// Tick is how often the schedule is read (DefaultScheduleTick).
	Tick time.Duration
	// StartDelay is how long a schedule waits before its first pass
	// (DefaultScheduleDelay); negative means no wait.
	StartDelay time.Duration
	// LeaseTTL is how long a sync's lease lasts unless renewed
	// (DefaultSyncLeaseTTL).
	LeaseTTL time.Duration
	// Budget bounds how long one sync lists (DefaultSyncBudget).
	Budget time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Logf logs what the runner did and what failed; nil discards it. Every
	// error it is given was scrubbed of credentials.
	Logf func(format string, args ...any)
	// OnSync, when set, is told every sync's end — for the hub to tell the
	// dashboards that may read the source.
	OnSync func(SyncResult)
}

// SyncResult is how one sync went.
type SyncResult struct {
	SourceID int64
	// Kind is the source's connector kind, or KnowledgeKindUnknown's value
	// for one this build cannot read.
	Kind   string
	Origin string
	// Status is StatusOK, StatusError or StatusInterrupted, or "" when
	// there was nothing to sync: the source was disabled or deleted after its
	// lease was taken.
	Status   string
	Report   SyncReport
	Duration time.Duration
	// Err is the sync's error, scrubbed; nil when it ended ok.
	Err error
}

// Runner runs a hub process's knowledge syncs.
type Runner struct {
	o RunnerOptions

	mu      sync.Mutex
	stopped bool
	// running holds every sync this process runs, by its lease holder: one
	// that lapsed and is still unwinding and the sync that took its source
	// over are two entries, so stopping the runner reaches both.
	running map[string]runningEntry
	// dispatched holds the sources a pass of the schedule handed a sync to
	// until that sync ends, so the next pass — reading the schedule before
	// the sync has recorded anything — does not hand it a second.
	dispatched map[int64]bool
	wg         sync.WaitGroup
	// lastPassErr is the last error a pass of the schedule could not read
	// it with, so a lasting one is logged once rather than every tick.
	lastPassErr string
}

// runningEntry is one sync this process runs.
type runningEntry struct {
	sourceID int64
	cancel   context.CancelCauseFunc
}

// NewRunner returns a Runner. Its options' zero values take the defaults.
func NewRunner(o RunnerOptions) *Runner {
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultSyncConcurrency
	}
	if o.Tick <= 0 {
		o.Tick = DefaultScheduleTick
	}
	if o.StartDelay == 0 {
		o.StartDelay = DefaultScheduleDelay
	}
	if o.LeaseTTL <= 0 {
		o.LeaseTTL = DefaultSyncLeaseTTL
	}
	if o.Budget <= 0 {
		o.Budget = DefaultSyncBudget
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return &Runner{o: o, running: map[string]runningEntry{}, dispatched: map[int64]bool{}}
}

// Member is the hub process this runner names in the leases it takes.
func (r *Runner) Member() string { return r.o.Member }

// Schedule runs the schedule until ctx ends: after StartDelay and then every
// Tick, it syncs each enabled source that is due — on its interval since its
// last sync, at once if that one stopped short — the most overdue first, at
// most Concurrency at a time, and purges what deleted sources left. When ctx
// ends it interrupts the syncs it started and returns once they have recorded
// that and released their leases.
//
// It is a leader duty: run it only while this process leads its hub cluster.
// A second schedule elsewhere would still never sync a source twice at once —
// the lease sees to that — but would sync each source twice as often.
func (r *Runner) Schedule(ctx context.Context) {
	defer func() {
		if v := recover(); v != nil {
			r.o.Logf("knowledge: the sync schedule panicked: %s", redact.Scrub(fmt.Sprint(v)))
		}
	}()
	slots := make(chan struct{}, r.o.Concurrency)
	var mine sync.WaitGroup
	defer mine.Wait()
	// Its syncs end when the duty does, and say why: a context derived from
	// ctx would end with ctx's own cause, which says nothing.
	parent := ctx
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	defer cancel(errNoLongerLeading)
	stopAfter := context.AfterFunc(parent, func() { cancel(errNoLongerLeading) })
	defer stopAfter()

	if r.o.StartDelay > 0 {
		t := time.NewTimer(r.o.StartDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	ticker := time.NewTicker(r.o.Tick)
	defer ticker.Stop()
	for {
		r.pass(ctx, slots, &mine)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pass starts a sync of every due source a slot is free for.
func (r *Runner) pass(ctx context.Context, slots chan struct{}, mine *sync.WaitGroup) {
	defer func() {
		if v := recover(); v != nil {
			r.o.Logf("knowledge: a pass of the sync schedule panicked: %s", redact.Scrub(fmt.Sprint(v)))
		}
	}()
	if ctx.Err() != nil {
		return
	}
	svc, closeSvc, err := r.o.Open()
	if err != nil {
		r.passFailed(err)
		return
	}
	defer closeSvc()
	now := r.o.Now()
	due, err := r.dueSources(svc, now)
	if err != nil {
		r.passFailed(err)
		return
	}
	r.passFailed(nil)
	for _, id := range due {
		if r.isRunning(id) {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			// Every slot is busy: the rest wait for the next pass, most
			// overdue first again.
			return
		}
		r.mu.Lock()
		r.dispatched[id] = true
		r.mu.Unlock()
		mine.Add(1)
		go func(id int64) {
			defer mine.Done()
			defer func() { <-slots }()
			defer func() {
				r.mu.Lock()
				delete(r.dispatched, id)
				r.mu.Unlock()
			}()
			if _, err := r.SyncNow(ctx, id, OriginSchedule, ""); err != nil && !errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld) &&
				!errors.Is(err, ErrRunnerStopped) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrDisabled) {
				r.o.Logf("knowledge: scheduled sync of source %d: %v", id, err)
			}
		}(id)
	}
	// What deleted sources left — a deletion's own purge cut short — goes
	// within a pass, not at the janitor's next.
	pctx, cancel := context.WithTimeout(ctx, purgeBudget)
	defer cancel()
	if res, err := svc.db.PurgeKnowledge(pctx, time.Time{}, false); err != nil && pctx.Err() == nil {
		r.o.Logf("knowledge: purge what deleted sources left: %v", err)
	} else if res.Rows() > 0 {
		r.o.Logf("knowledge: purged %d documents and %d chunks deleted sources left", res.Documents, res.Chunks)
	}
}

// passFailed logs why a pass could not read the schedule, once for each new
// reason; nil records that one could.
func (r *Runner) passFailed(err error) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	r.mu.Lock()
	same := text == r.lastPassErr
	r.lastPassErr = text
	r.mu.Unlock()
	if err != nil && !same {
		r.o.Logf("knowledge: read the sync schedule: %v", err)
	}
}

// dueSources lists the sources due a scheduled sync at now, most overdue
// first, leaving out those another sync holds.
func (r *Runner) dueSources(svc *Service, now time.Time) ([]int64, error) {
	rows, err := svc.db.ListKnowledgeSources()
	if err != nil {
		return nil, err
	}
	leases, err := svc.db.LiveKnowledgeSyncLeases(now)
	if err != nil {
		return nil, err
	}
	type dueSource struct {
		id      int64
		overdue time.Duration
	}
	var due []dueSource
	for _, row := range rows {
		if _, held := leases[row.ID]; held {
			continue
		}
		next := nextSync(row)
		if next.IsZero() || now.Before(next) {
			continue
		}
		due = append(due, dueSource{row.ID, now.Sub(next)})
	}
	sort.SliceStable(due, func(i, j int) bool { return due[i].overdue > due[j].overdue })
	out := make([]int64, len(due))
	for i, d := range due {
		out[i] = d.id
	}
	return out, nil
}

// nextSync is when the schedule next syncs a source: zero for a disabled one,
// and for one never synced, the moment it was created.
func nextSync(row statedb.KnowledgeSourceRow) time.Time {
	if !row.Enabled {
		return time.Time{}
	}
	last := row.SyncedAt
	if last.IsZero() {
		if row.CreatedAt.IsZero() {
			return time.Unix(0, 1)
		}
		return row.CreatedAt
	}
	interval := time.Duration(row.SyncIntervalMin) * time.Minute
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	switch {
	case row.SyncStatus == StatusInterrupted,
		row.SyncStatus == StatusOK && row.SyncMore,
		// Changed since the last sync began — reconfigured, re-enabled, or
		// mid-sync, which that sync refused to write past.
		row.UpdatedAt.After(row.SyncStartedAt):
		return last.Add(resumeAfter)
	}
	return last.Add(interval)
}

// SyncNow runs one sync of source id in the caller's goroutine: it takes the
// source's lease — a *BusyError when another sync holds it — runs the sync,
// records it and releases the lease.
func (r *Runner) SyncNow(ctx context.Context, id int64, origin, actor string) (SyncResult, error) {
	if !r.enter() {
		return SyncResult{}, ErrRunnerStopped
	}
	defer r.wg.Done()
	svc, closeSvc, err := r.o.Open()
	if err != nil {
		return SyncResult{}, err
	}
	defer closeSvc()
	lease, err := r.acquire(svc, id, origin, actor)
	if err != nil {
		return SyncResult{}, err
	}
	if origin == OriginSchedule && !stillDue(svc, id, r.o.Now()) {
		// Synced since the schedule was read — by this member's last sync,
		// or by another member's before it stepped down: due again only at
		// its next interval.
		if err := svc.db.ReleaseKnowledgeSyncLease(id, lease.Holder); err != nil {
			r.o.Logf("knowledge: release the sync lease of source %d: %v", id, err)
		}
		return SyncResult{SourceID: id, Origin: origin}, nil
	}
	res := r.run(ctx, svc, lease)
	return res, res.Err
}

// stillDue reports whether source id is due a scheduled sync at now, read
// again once its lease is held: the schedule that chose it was read before.
func stillDue(svc *Service, id int64, now time.Time) bool {
	row, err := svc.db.GetKnowledgeSource(id)
	if err != nil {
		// Let the sync find out, and say, what is wrong.
		return true
	}
	next := nextSync(row)
	return !next.IsZero() && !now.Before(next)
}

// Start begins a sync of source id in the background, for actor. It takes the
// source's lease before it returns, so a source another sync holds — on this
// hub process or another — is refused at once with a *BusyError naming that
// sync. The sync runs until it ends or the runner stops.
func (r *Runner) Start(id int64, origin, actor string) (RunningSync, error) {
	if !r.enter() {
		return RunningSync{}, ErrRunnerStopped
	}
	svc, closeSvc, err := r.o.Open()
	if err != nil {
		r.wg.Done()
		return RunningSync{}, err
	}
	lease, err := r.acquire(svc, id, origin, actor)
	if err != nil {
		closeSvc()
		r.wg.Done()
		return RunningSync{}, err
	}
	go func() {
		defer r.wg.Done()
		defer closeSvc()
		r.run(context.Background(), svc, lease)
	}()
	return RunningSync{Member: lease.Member, Origin: lease.Origin, Actor: lease.Actor, Since: lease.AcquiredAt}, nil
}

// Stop interrupts every sync the runner runs and waits up to wait for them to
// record that and release their leases. It starts no more.
func (r *Runner) Stop(wait time.Duration) {
	r.mu.Lock()
	r.stopped = true
	for _, e := range r.running {
		e.cancel(errHubStopping)
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(wait):
		r.o.Logf("knowledge: syncs still running %s after the hub began stopping; their leases lapse in %s",
			wait, r.o.LeaseTTL)
	}
}

// enter counts a sync in, unless the runner has stopped.
func (r *Runner) enter() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.wg.Add(1)
	return true
}

func (r *Runner) isRunning(id int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dispatched[id] {
		return true
	}
	for _, e := range r.running {
		if e.sourceID == id {
			return true
		}
	}
	return false
}

// acquire takes source id's lease for a new sync.
func (r *Runner) acquire(svc *Service, id int64, origin, actor string) (statedb.KnowledgeSyncLease, error) {
	now := r.o.Now()
	lease, err := svc.db.AcquireKnowledgeSyncLease(statedb.KnowledgeSyncLease{
		SourceID: id, Holder: r.o.Member + "/" + randomID(), Member: r.o.Member, Origin: origin, Actor: actor,
		ExpiresAt: now.Add(r.o.LeaseTTL),
	}, now)
	switch {
	case errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld):
		return lease, &BusyError{Running: RunningSync{Member: lease.Member, Origin: lease.Origin, Actor: lease.Actor,
			Since: lease.AcquiredAt}}
	case errors.Is(err, statedb.ErrKnowledgeSourceNotFound):
		return lease, fmt.Errorf("%w: source %d", ErrNotFound, id)
	}
	return lease, err
}

// run runs the sync lease was taken for, renewing the lease while it runs and
// releasing it after, and reports it.
func (r *Runner) run(parent context.Context, svc *Service, lease statedb.KnowledgeSyncLease) (res SyncResult) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	r.mu.Lock()
	r.running[lease.Holder] = runningEntry{sourceID: lease.SourceID, cancel: cancel}
	stopped := r.stopped
	r.mu.Unlock()
	if stopped {
		cancel(errHubStopping)
	}
	res = SyncResult{SourceID: lease.SourceID, Origin: lease.Origin, Kind: hubmetrics.KnowledgeKindUnknown}
	if row, err := svc.db.GetKnowledgeSource(lease.SourceID); err == nil {
		if _, ok := svc.registry.Lookup(row.Kind); ok {
			res.Kind = row.Kind
		}
	}
	keepalive := r.keepalive(ctx, cancel, svc, lease)
	started := r.o.Now()
	defer func() {
		// A panic the sync did not recover itself — in the runner's own
		// work around it — fails this sync, not the process.
		if v := recover(); v != nil {
			res.Status = StatusError
			res.Err = fmt.Errorf("knowledge: sync of source %d panicked: %s", lease.SourceID, redact.Scrub(fmt.Sprint(v)))
		}
		cancel(nil)
		<-keepalive
		if err := svc.db.ReleaseKnowledgeSyncLease(lease.SourceID, lease.Holder); err != nil {
			r.o.Logf("knowledge: release the sync lease of source %d: %v", lease.SourceID, err)
		}
		r.mu.Lock()
		delete(r.running, lease.Holder)
		r.mu.Unlock()
		res.Duration = r.o.Now().Sub(started)
		r.record(res)
	}()
	report, err := svc.SyncWith(ctx, lease.SourceID, SyncOptions{Holder: lease.Holder, Origin: lease.Origin,
		Budget: r.o.Budget})
	res.Report, res.Err, res.Status = report, err, SyncStatusOf(err)
	if errors.Is(err, ErrDisabled) || errors.Is(err, ErrNotFound) {
		// Disabled or deleted between its lease and its start: there was
		// nothing to sync, and nothing failed.
		res.Status = ""
	}
	return res
}

// keepalive renews lease every third of its TTL until ctx ends, and cancels
// the sync with ErrLeaseLost when it cannot: another sync holds the source, or
// renewing failed until the lease lapsed. The channel closes when it returns.
func (r *Runner) keepalive(ctx context.Context, cancel context.CancelCauseFunc, svc *Service,
	lease statedb.KnowledgeSyncLease) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if v := recover(); v != nil {
				r.o.Logf("knowledge: renewing the sync lease of source %d panicked: %s", lease.SourceID,
					redact.Scrub(fmt.Sprint(v)))
				cancel(ErrLeaseLost)
			}
		}()
		expires := lease.ExpiresAt
		ticker := time.NewTicker(r.o.LeaseTTL / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			now := r.o.Now()
			until := now.Add(r.o.LeaseTTL)
			err := svc.db.RenewKnowledgeSyncLease(lease.SourceID, lease.Holder, until, now)
			switch {
			case err == nil:
				expires = until
			case errors.Is(err, statedb.ErrKnowledgeSyncLeaseLost):
				r.o.Logf("knowledge: the sync of source %d lost its lease; stopping it", lease.SourceID)
				cancel(ErrLeaseLost)
				return
			default:
				r.o.Logf("knowledge: renew the sync lease of source %d: %v", lease.SourceID, err)
				if !now.Before(expires) {
					cancel(ErrLeaseLost)
					return
				}
			}
		}
	}()
	return done
}

// record counts a sync into the hub's metrics, logs a failure, and tells
// OnSync. A run that found nothing to sync — its source disabled or deleted
// before it began — is none of those.
func (r *Runner) record(res SyncResult) {
	if res.Status == "" {
		return
	}
	hubmetrics.KnowledgeSyncDuration.Observe(res.Duration.Seconds(), res.Kind, res.Status)
	for change, n := range map[string]int{
		hubmetrics.KnowledgeChangeCreated:   res.Report.Created,
		hubmetrics.KnowledgeChangeUpdated:   res.Report.Updated,
		hubmetrics.KnowledgeChangeUnchanged: res.Report.Unchanged,
		hubmetrics.KnowledgeChangeDeleted:   res.Report.Deleted,
		hubmetrics.KnowledgeChangeRemoved:   res.Report.Swept + res.Report.Removed,
		hubmetrics.KnowledgeChangeRejected:  res.Report.Rejected,
	} {
		if n > 0 {
			hubmetrics.KnowledgeDocumentsIndexed.Add(float64(n), res.Kind, change)
		}
	}
	if res.Status == StatusError {
		reason := FailureReason(res.Err)
		if reason == "" {
			reason = ReasonStorage
		}
		hubmetrics.KnowledgeSyncErrors.Inc(res.Kind, reason)
		r.o.Logf("knowledge: %s sync of source %d failed (%s): %v", res.Origin, res.SourceID, reason, res.Err)
		var pe *PanicError
		if errors.As(res.Err, &pe) {
			r.o.Logf("knowledge: the panic in source %d's sync:\n%s", res.SourceID, redact.Scrub(string(pe.Stack)))
		}
	}
	if r.o.OnSync != nil {
		func() {
			defer func() { _ = recover() }()
			r.o.OnSync(res)
		}()
	}
}

// randomID is a sync's own id, unique among every sync of every member.
func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
