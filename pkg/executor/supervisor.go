package executor

// supervisor.go drives the liveness probes that health.go's state machine folds
// in, and reacts to the one transition that needs action: a node going
// unreachable while it still holds work.
//
// The design constraints, in the order they shaped the code:
//
//   - Never block a workload. Probing is bookkeeping; if it stalls, Start must
//     still return. So probes run in their own goroutines, every one is bounded
//     by a context deadline, and the supervisor holds no lock while probing.
//   - Back off on failure. A node that is down will be down for the next probe
//     too. Probing an unreachable device every 30s for an hour is a good way to
//     keep a cellular link awake and a battery flat, so failures back off
//     exponentially, capped.
//   - Jitter everything. A control plane that restarts and probes forty edge
//     devices on the same tick creates a thundering herd against whatever
//     shared infrastructure they sit behind. Every delay carries ±jitter.
//   - Be safe to run twice. Control planes get restarted, and briefly there may
//     be two supervisors. Nothing here assumes exclusivity; the exactly-once
//     guarantee for failover lives in a conditional UPDATE in the session
//     store, not in a mutex here.
//
// Testability comes from splitting the loop into a pure-ish step: ProbeOnce
// does exactly one round and returns the transitions it caused, so the whole
// state machine can be exercised without timers, and Start is a thin loop
// around it.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// Clock abstracts time so tests can drive a supervisor without sleeping.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// After returns a channel that fires once after d.
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// SystemClock is the production Clock.
var SystemClock Clock = realClock{}

// HealthStore persists the supervisor's view across control-plane restarts.
//
// It is an interface, not a *statedb.DB, for the same reason the rest of this
// package avoids storage: pkg/executor is linked into the agent binary that
// runs on edge devices, and an executor driver has no business pulling in a
// SQLite engine. pkg/executorstore implements this over statedb.
type HealthStore interface {
	// LoadHealth returns the persisted health for an executor. An unknown
	// executor yields the zero Health and a nil error — "never probed" is a
	// normal state, not a lookup failure.
	LoadHealth(executorID string) (Health, error)
	// SaveHealth persists a health record, creating it if absent.
	SaveHealth(h Health) error
	// ListHealth returns every persisted health record.
	ListHealth() ([]Health, error)
}

// Session is one workload dispatched to an executor, as the scheduler sees it.
//
// It is deliberately thinner than a Handle: failover needs to know what to
// re-run and who currently owns the right to re-run it, not how to stream its
// output.
type Session struct {
	// ID is unique across the control plane.
	ID string `json:"id"`
	// ExecutorID is the node the session was dispatched to.
	ExecutorID string `json:"executor_id"`
	// HandleID is the driver-side handle, when one was obtained.
	HandleID string `json:"handle_id,omitempty"`
	// ProjectPath and TaskID identify the work, so failover can mark the
	// task failed-with-retry and re-dispatch it.
	ProjectPath string `json:"project_path,omitempty"`
	TaskID      int    `json:"task_id,omitempty"`
	// ClaimToken is the exactly-once guard. Requeueing a session requires
	// presenting the token the session currently carries; the store rotates
	// it atomically, so a second requeue attempt — from a concurrent
	// supervisor, or from this one after a restart — finds a token that no
	// longer matches and is refused with ErrSessionClaimLost.
	ClaimToken string `json:"claim_token"`
	// Attempt counts dispatches, starting at 1.
	Attempt   int       `json:"attempt"`
	StartedAt time.Time `json:"started_at"`
	// Spec is the workload the session was dispatched with, so a failover
	// can re-dispatch it verbatim. It is persisted rather than held in
	// memory precisely because the control plane that requeues a session is
	// often not the one that started it.
	Spec Spec `json:"spec"`
}

// SessionStore tracks in-flight work per executor and arbitrates requeues.
type SessionStore interface {
	// RunningSessions returns the sessions currently in flight on an
	// executor. Passing "" returns every running session.
	RunningSessions(executorID string) ([]Session, error)
	// ClaimRequeue atomically transfers ownership of a session away from its
	// current claim token, returning the session with its new token.
	//
	// It must be a single conditional write ("UPDATE ... WHERE id = ? AND
	// claim_token = ?"): that is the entire double-execution guard. It
	// returns ErrSessionClaimLost when the token no longer matches.
	ClaimRequeue(sessionID, claimToken string, at time.Time) (Session, error)
	// CountRunning returns the number of in-flight sessions on an executor,
	// which drain waits on and the UI displays.
	CountRunning(executorID string) (int, error)
}

// EventSink receives supervisor observations for the event log and the UI.
// Implementations must not block: they are called from the probe goroutines.
type EventSink interface {
	// ExecutorTransition is called once per state change.
	ExecutorTransition(t Transition)
	// ExecutorFailover is called once per session moved off a dead node,
	// including when no replacement could be found (ev.Err is then set).
	ExecutorFailover(ev FailoverEvent)
}

// FailoverEvent describes one session being moved off an unreachable node.
type FailoverEvent struct {
	// Session is the claimed session, carrying its *new* claim token.
	Session Session `json:"session"`
	// From is the executor that went unreachable.
	From string `json:"from"`
	// To is the replacement executor, or "" when none was found.
	To string `json:"to,omitempty"`
	// Err is set when placement or re-dispatch failed. The task is still
	// marked failed-with-retry; it just has nowhere to go right now.
	Err error `json:"-"`
	// Reason renders Err for the event payload.
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// FailoverHandler re-dispatches a claimed session. It is supplied by the
// control plane (pkg/ui) because only that layer knows how to mark a task
// failed-with-retry and start a fresh run.
//
// It is called *after* the claim succeeds, so it is guaranteed to run at most
// once per session per failure. Returning an error records the failover as
// unplaced; it does not release the claim, because releasing it would re-arm
// the double-execution risk the claim exists to prevent.
type FailoverHandler func(ctx context.Context, ev FailoverEvent) error

// SupervisorConfig tunes probing. The zero value is usable; DefaultSupervisorConfig
// spells out the defaults.
type SupervisorConfig struct {
	// Interval is the probe period for a healthy node.
	Interval time.Duration
	// ProbeTimeout bounds one HealthCheck call. It must be well under
	// Interval so a hung probe cannot stack up rounds.
	ProbeTimeout time.Duration
	// BackoffBase is the first retry delay after a failure; each subsequent
	// consecutive failure doubles it up to BackoffMax.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// JitterFraction is the proportional jitter applied to every delay
	// (0.2 = ±20%). Clamped to [0, 0.9].
	JitterFraction float64
	// MaxConcurrentProbes bounds how many nodes are probed at once.
	MaxConcurrentProbes int
	// Policy sets the degrade/unreachable thresholds.
	Policy HealthPolicy
	// Rand returns a value in [0,1) for jitter. Nil uses a package-level
	// source; tests inject a deterministic one.
	Rand func() float64
}

// DefaultSupervisorConfig returns production defaults: probe every 30s, give up
// after three consecutive failures (~90s), back off from 5s to 5m while down.
func DefaultSupervisorConfig() SupervisorConfig {
	return SupervisorConfig{
		Interval:            30 * time.Second,
		ProbeTimeout:        10 * time.Second,
		BackoffBase:         5 * time.Second,
		BackoffMax:          5 * time.Minute,
		JitterFraction:      0.2,
		MaxConcurrentProbes: 8,
		Policy:              DefaultHealthPolicy(),
	}
}

func (c SupervisorConfig) normalize() SupervisorConfig {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 10 * time.Second
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = 5 * time.Second
	}
	if c.BackoffMax < c.BackoffBase {
		c.BackoffMax = c.BackoffBase
	}
	if c.JitterFraction < 0 {
		c.JitterFraction = 0
	}
	if c.JitterFraction > 0.9 {
		c.JitterFraction = 0.9
	}
	if c.MaxConcurrentProbes <= 0 {
		c.MaxConcurrentProbes = 8
	}
	c.Policy = c.Policy.normalize()
	return c
}

// Supervisor probes registered executors, maintains their scheduling state,
// and fails work over when a node dies holding it.
type Supervisor struct {
	registry *Registry
	cfg      SupervisorConfig
	clock    Clock

	health   HealthStore
	sessions SessionStore
	sink     EventSink
	failover FailoverHandler

	// candidates supplies the placement pool for failover. Nil falls back to
	// the registry's own executors with their persisted health.
	candidates func() []Candidate

	mu        sync.Mutex
	nextProbe map[string]time.Time // executor ID → earliest next probe
	running   bool
	stop      context.CancelFunc
	done      chan struct{}
}

// SupervisorOption configures a Supervisor.
type SupervisorOption func(*Supervisor)

// WithHealthStore persists health across restarts. Without one the supervisor
// keeps state only in the store's absence — that is, nowhere — and every
// restart re-learns the fleet.
func WithHealthStore(s HealthStore) SupervisorOption {
	return func(sv *Supervisor) { sv.health = s }
}

// WithSessionStore enables failover. Without one, an unreachable node still
// transitions and emits events, but no work is moved.
func WithSessionStore(s SessionStore) SupervisorOption {
	return func(sv *Supervisor) { sv.sessions = s }
}

// WithEventSink routes transitions and failovers to the event log.
func WithEventSink(s EventSink) SupervisorOption {
	return func(sv *Supervisor) { sv.sink = s }
}

// WithFailoverHandler installs the re-dispatch callback.
func WithFailoverHandler(h FailoverHandler) SupervisorOption {
	return func(sv *Supervisor) { sv.failover = h }
}

// WithClock injects a clock, for tests.
func WithClock(c Clock) SupervisorOption {
	return func(sv *Supervisor) {
		if c != nil {
			sv.clock = c
		}
	}
}

// WithCandidateSource overrides how the failover placement pool is assembled.
func WithCandidateSource(fn func() []Candidate) SupervisorOption {
	return func(sv *Supervisor) { sv.candidates = fn }
}

// NewSupervisor builds a supervisor over reg. A nil registry uses
// DefaultRegistry.
func NewSupervisor(reg *Registry, cfg SupervisorConfig, opts ...SupervisorOption) *Supervisor {
	if reg == nil {
		reg = DefaultRegistry
	}
	sv := &Supervisor{
		registry:  reg,
		cfg:       cfg.normalize(),
		clock:     SystemClock,
		nextProbe: make(map[string]time.Time),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(sv)
		}
	}
	return sv
}

// Start launches the probe loop and returns immediately.
//
// The returned stop function cancels the loop and waits for in-flight probes to
// finish, so a caller shutting down does not race a probe writing to a closed
// store. Calling Start twice is a no-op on the second call.
func (sv *Supervisor) Start(ctx context.Context) (stop func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	sv.mu.Lock()
	if sv.running {
		existing := sv.stop
		done := sv.done
		sv.mu.Unlock()
		return func() {
			if existing != nil {
				existing()
			}
			if done != nil {
				<-done
			}
		}
	}
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	sv.running = true
	sv.stop = cancel
	sv.done = done
	sv.mu.Unlock()

	go func() {
		defer close(done)
		defer func() {
			sv.mu.Lock()
			sv.running = false
			sv.mu.Unlock()
		}()
		// A panic in a probe must not take the control plane down with it.
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("executor: supervisor loop panic: %v\n", r)
			}
		}()
		sv.loop(loopCtx)
	}()

	return func() {
		cancel()
		<-done
	}
}

// loop probes on Interval until ctx is cancelled. The tick is the *scan*
// period; each executor has its own due time, so a backed-off node is simply
// skipped on ticks it is not due for.
func (sv *Supervisor) loop(ctx context.Context) {
	// Probe immediately on start rather than waiting a full interval: a
	// control plane that just came up should learn its fleet's state now,
	// not in 30 seconds.
	sv.ProbeOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sv.clock.After(sv.scanDelay()):
			sv.ProbeOnce(ctx)
		}
	}
}

// scanDelay is the jittered gap between scans.
func (sv *Supervisor) scanDelay() time.Duration {
	return sv.jitter(sv.cfg.Interval)
}

// ProbeOnce probes every executor that is currently due and returns the
// transitions it caused, ordered by executor ID.
//
// It is exported because it is the whole supervisor minus the timer: tests
// drive fleets through arbitrary state sequences by calling it, and `cloop
// executor ls` uses it to refresh before printing rather than showing an
// operator a stale table.
func (sv *Supervisor) ProbeOnce(ctx context.Context) []Transition {
	if ctx == nil {
		ctx = context.Background()
	}
	executors := sv.registry.List()
	now := sv.clock.Now()

	due := make([]Executor, 0, len(executors))
	sv.mu.Lock()
	live := make(map[string]bool, len(executors))
	for _, ex := range executors {
		id := ex.ID()
		live[id] = true
		if next, ok := sv.nextProbe[id]; ok && now.Before(next) {
			continue
		}
		due = append(due, ex)
	}
	// Forget schedule entries for executors that have been unregistered, so
	// a long-lived control plane that churns edge devices does not grow this
	// map without bound.
	for id := range sv.nextProbe {
		if !live[id] {
			delete(sv.nextProbe, id)
		}
	}
	sv.mu.Unlock()

	if len(due) == 0 {
		return nil
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []Transition
		sem     = make(chan struct{}, sv.cfg.MaxConcurrentProbes)
	)
	for _, ex := range due {
		// Stop dispatching new probes once the caller has given up, but let
		// already-running ones finish under their own deadline.
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ex Executor) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// A driver that panics in HealthCheck is a broken
					// driver, not a reason to lose the whole round.
					fmt.Printf("executor: probe panic for %s: %v\n", ex.ID(), r)
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			if tr := sv.probe(ctx, ex); tr != nil {
				mu.Lock()
				results = append(results, *tr)
				mu.Unlock()
			}
		}(ex)
	}
	wg.Wait()

	sortTransitions(results)
	return results
}

// probe runs one health check, folds the result into the state machine,
// persists it, and reacts to any transition.
func (sv *Supervisor) probe(ctx context.Context, ex Executor) *Transition {
	id := ex.ID()

	current := sv.loadHealth(id)
	current.ExecutorID = id

	// Every probe is bounded. A driver that hangs — a remote agent whose TCP
	// connection is black-holed is the common case — must cost one timeout,
	// not one goroutine forever.
	probeCtx, cancel := context.WithTimeout(ctx, sv.cfg.ProbeTimeout)
	err := ex.HealthCheck(probeCtx)
	cancel()

	// A cancelled *parent* context means the control plane is shutting down,
	// not that the node is sick. Recording that as a failure would have every
	// restart nudge the whole fleet toward unreachable.
	if err != nil && ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}

	now := sv.clock.Now()
	updated, tr := ObserveProbe(current, err, now, sv.cfg.Policy)
	sv.scheduleNext(id, updated, err != nil, now)
	sv.saveHealth(updated)

	if tr == nil {
		return nil
	}
	if sv.sink != nil {
		sv.sink.ExecutorTransition(*tr)
	}
	if tr.To == NodeUnreachable {
		sv.failOver(ctx, *tr)
	}
	return tr
}

// scheduleNext sets when this executor is next due, applying exponential
// backoff while it is failing.
func (sv *Supervisor) scheduleNext(id string, h Health, failed bool, now time.Time) {
	delay := sv.cfg.Interval
	if failed {
		delay = sv.backoff(h.ConsecutiveFailures)
	}
	sv.mu.Lock()
	sv.nextProbe[id] = now.Add(sv.jitter(delay))
	sv.mu.Unlock()
}

// backoff returns BackoffBase * 2^(failures-1), capped at BackoffMax.
func (sv *Supervisor) backoff(failures int) time.Duration {
	if failures <= 1 {
		return sv.cfg.BackoffBase
	}
	// Cap the shift before it overflows: 2^62 nanoseconds is already
	// centuries, and a device that has been down for a million probes must
	// not wrap into a negative delay and get hammered.
	shift := failures - 1
	if shift > 32 {
		return sv.cfg.BackoffMax
	}
	d := time.Duration(math.Min(
		float64(sv.cfg.BackoffBase)*math.Pow(2, float64(shift)),
		float64(sv.cfg.BackoffMax),
	))
	if d < sv.cfg.BackoffBase {
		return sv.cfg.BackoffBase
	}
	return d
}

// jitter spreads a delay by ±JitterFraction.
func (sv *Supervisor) jitter(d time.Duration) time.Duration {
	if d <= 0 || sv.cfg.JitterFraction == 0 {
		return d
	}
	r := sv.cfg.Rand
	if r == nil {
		r = defaultRandFloat
	}
	// r() in [0,1) → factor in [1-f, 1+f)
	factor := 1 + sv.cfg.JitterFraction*(2*r()-1)
	out := time.Duration(float64(d) * factor)
	if out < 0 {
		return d
	}
	return out
}

// failOver moves every in-flight session off a node that just went unreachable.
//
// The ordering is the important part: the claim happens *before* the handler
// runs. If it were the other way round, two supervisors racing on the same dead
// node would both re-dispatch the task and only afterwards discover that one of
// them should not have — and by then the task is running twice, which for a
// cloop task means two agents editing the same repository.
func (sv *Supervisor) failOver(ctx context.Context, tr Transition) {
	if sv.sessions == nil {
		return
	}
	sessions, err := sv.sessions.RunningSessions(tr.ExecutorID)
	if err != nil {
		fmt.Printf("executor: list sessions for %s: %v\n", tr.ExecutorID, err)
		return
	}
	for _, sess := range sessions {
		sv.failOverSession(ctx, tr, sess)
	}
}

func (sv *Supervisor) failOverSession(ctx context.Context, tr Transition, sess Session) {
	now := sv.clock.Now()

	claimed, err := sv.sessions.ClaimRequeue(sess.ID, sess.ClaimToken, now)
	if err != nil {
		// ErrSessionClaimLost is the normal outcome of a race and is not
		// worth logging: it means the guard worked.
		if !errors.Is(err, ErrSessionClaimLost) {
			fmt.Printf("executor: claim session %s: %v\n", sess.ID, err)
		}
		return
	}

	ev := FailoverEvent{Session: claimed, From: tr.ExecutorID, At: now}

	target, placeErr := sv.placeReplacement(tr.ExecutorID, claimed)
	if placeErr != nil {
		ev.Err = placeErr
		ev.Reason = placeErr.Error()
	} else {
		ev.To = target.ID()
	}

	if ev.Err == nil && sv.failover != nil {
		if err := sv.failover(ctx, ev); err != nil {
			ev.Err = err
			ev.Reason = err.Error()
		}
	}
	if sv.sink != nil {
		sv.sink.ExecutorFailover(ev)
	}
}

// placeReplacement picks a healthy node for a requeued session, excluding the
// one that just died.
func (sv *Supervisor) placeReplacement(deadID string, sess Session) (Candidate, error) {
	pool := sv.candidatePool()
	filtered := make([]Candidate, 0, len(pool))
	for _, c := range pool {
		if c.ID() == deadID {
			continue
		}
		filtered = append(filtered, c)
	}
	return Select(filtered, sv.requirementsFor(sess))
}

// requirementsFor derives placement requirements for a requeued session.
//
// A requeue inherits only the constraints the control plane can prove: the
// isolation posture demanded by policy. It deliberately does not inherit the
// dead node's labels — "it ran on edge-1, so put it on something exactly like
// edge-1" would make a single-device fleet unable to fail over at all, which is
// the opposite of the point.
func (sv *Supervisor) requirementsFor(Session) Requirements {
	return Requirements{RequireIsolation: !HostExecutionAllowed()}
}

// candidatePool assembles the placement pool, defaulting to the registry with
// persisted health attached.
func (sv *Supervisor) candidatePool() []Candidate {
	if sv.candidates != nil {
		return sv.candidates()
	}
	executors := sv.registry.List()
	out := make([]Candidate, 0, len(executors))
	for _, ex := range executors {
		c := Candidate{Executor: ex, Health: sv.loadHealth(ex.ID())}
		if sv.sessions != nil {
			if n, err := sv.sessions.CountRunning(ex.ID()); err == nil {
				c.InFlight, c.InFlightKnown = n, true
			}
		}
		out = append(out, c)
	}
	return out
}

// Health returns the current health of one executor.
func (sv *Supervisor) Health(executorID string) Health {
	h := sv.loadHealth(executorID)
	h.ExecutorID = executorID
	return h.Normalize()
}

// Cordon takes an executor out of rotation, persisting and announcing it.
func (sv *Supervisor) Cordon(executorID, reason string) (Health, error) {
	return sv.adminSet(executorID, reason, Cordon)
}

// Drain takes an executor out of rotation and marks it for retirement.
func (sv *Supervisor) Drain(executorID, reason string) (Health, error) {
	return sv.adminSet(executorID, reason, Drain)
}

// Uncordon returns an executor to the state its probe history justifies.
func (sv *Supervisor) Uncordon(executorID string) (Health, error) {
	if _, err := sv.registry.Get(executorID); err != nil {
		return Health{}, err
	}
	h := sv.loadHealth(executorID)
	h.ExecutorID = executorID
	updated, tr := Uncordon(h, sv.clock.Now(), sv.cfg.Policy)
	if err := sv.persistAdmin(updated, tr); err != nil {
		return Health{}, err
	}
	// An uncordoned node should be re-probed promptly rather than waiting
	// out whatever backoff it accumulated while it was held.
	sv.mu.Lock()
	delete(sv.nextProbe, executorID)
	sv.mu.Unlock()
	return updated, nil
}

func (sv *Supervisor) adminSet(executorID, reason string, fn func(Health, string, time.Time) (Health, *Transition)) (Health, error) {
	if _, err := sv.registry.Get(executorID); err != nil {
		return Health{}, err
	}
	h := sv.loadHealth(executorID)
	h.ExecutorID = executorID
	updated, tr := fn(h, reason, sv.clock.Now())
	if err := sv.persistAdmin(updated, tr); err != nil {
		return Health{}, err
	}
	return updated, nil
}

func (sv *Supervisor) persistAdmin(h Health, tr *Transition) error {
	if sv.health != nil {
		if err := sv.health.SaveHealth(h); err != nil {
			return fmt.Errorf("executor: persist health for %s: %w", h.ExecutorID, err)
		}
	}
	if tr != nil && sv.sink != nil {
		sv.sink.ExecutorTransition(*tr)
	}
	return nil
}

// WaitForDrain blocks until an executor has no in-flight sessions, ctx fires,
// or timeout elapses. A zero timeout waits indefinitely (bounded by ctx).
//
// It returns ErrDrainTimeout with the remaining count when work is still in
// flight at the deadline, so `cloop executor drain --timeout` can tell an
// operator how many sessions they would be abandoning with --force.
func (sv *Supervisor) WaitForDrain(ctx context.Context, executorID string, timeout, poll time.Duration) (int, error) {
	if sv.sessions == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Time{}
	if timeout > 0 {
		deadline = sv.clock.Now().Add(timeout)
	}

	for {
		n, err := sv.sessions.CountRunning(executorID)
		if err != nil {
			return 0, fmt.Errorf("executor: count in-flight sessions on %s: %w", executorID, err)
		}
		if n == 0 {
			return 0, nil
		}
		if !deadline.IsZero() && !sv.clock.Now().Before(deadline) {
			return n, fmt.Errorf("%w: %d session(s) still running on %s", ErrDrainTimeout, n, executorID)
		}
		select {
		case <-ctx.Done():
			return n, ctx.Err()
		case <-sv.clock.After(poll):
		}
	}
}

func (sv *Supervisor) loadHealth(id string) Health {
	if sv.health == nil {
		return Health{ExecutorID: id}.Normalize()
	}
	h, err := sv.health.LoadHealth(id)
	if err != nil {
		// A health store that cannot be read must not stop probing. The
		// worst case is that a transition is recomputed from a zero value,
		// which re-emits an event — noisy, not harmful.
		return Health{ExecutorID: id}.Normalize()
	}
	h.ExecutorID = id
	return h.Normalize()
}

func (sv *Supervisor) saveHealth(h Health) {
	if sv.health == nil {
		return
	}
	if err := sv.health.SaveHealth(h); err != nil {
		fmt.Printf("executor: persist health for %s: %v\n", h.ExecutorID, err)
	}
}

// defaultRandFloat is the jitter source. math/rand's global source is
// goroutine-safe and jitter has no security requirement whatsoever, so there is
// no reason to carry a seeded generator and a mutex around for it.
func defaultRandFloat() float64 { return rand.Float64() }

func sortTransitions(ts []Transition) {
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j].ExecutorID < ts[j-1].ExecutorID; j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
}
