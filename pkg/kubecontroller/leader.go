package kubecontroller

// leader.go is the leader election: a coordination.k8s.io/v1 Lease that one
// replica holds and renews, so two replicas never both scale a pool.
//
// It follows client-go's leaderelection on the two points that make it safe:
//
//   - A rival's lease is judged expired by this replica's own clock, from when
//     it last saw the lease change — never from the renewTime the rival wrote,
//     which is the rival's clock. Clock skew between nodes therefore cannot
//     make a live lease look expired.
//   - The leader stops leading at renewDeadline, which is shorter than the
//     lease's duration: a leader that cannot renew cancels its own work before
//     any rival could take the lease over, and waits for that work to stop
//     before it counts itself a follower.
//
// Every write is guarded by the Lease's resourceVersion, so two replicas that
// both judge the lease free race on the API server, and one of them loses
// with a conflict.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// LeaderElection configures the Lease.
type LeaderElection struct {
	// Namespace and Name locate the Lease.
	Namespace string
	Name      string
	// Identity is this replica's holder identity: its Pod name and a random
	// suffix, so a restarted Pod is a new holder.
	Identity string
	// LeaseDuration is how long a lease nobody renews stays held; zero is 15s.
	LeaseDuration time.Duration
	// RenewDeadline is how long the leader keeps trying to renew before it
	// stops leading; zero is 10s. Must be below LeaseDuration.
	RenewDeadline time.Duration
	// RetryPeriod is the interval between attempts; zero is 2s.
	RetryPeriod time.Duration
}

func (le LeaderElection) withDefaults() LeaderElection {
	if le.LeaseDuration <= 0 {
		le.LeaseDuration = 15 * time.Second
	}
	if le.RenewDeadline <= 0 {
		le.RenewDeadline = 10 * time.Second
	}
	if le.RetryPeriod <= 0 {
		le.RetryPeriod = 2 * time.Second
	}
	return le
}

// Validate checks the timings.
func (le LeaderElection) Validate() error {
	le = le.withDefaults()
	switch {
	case le.Namespace == "" || le.Name == "":
		return fmt.Errorf("kubecontroller: leader election needs a Lease namespace and name")
	case le.Identity == "":
		return fmt.Errorf("kubecontroller: leader election needs an identity")
	case le.RenewDeadline >= le.LeaseDuration:
		return fmt.Errorf("kubecontroller: the renew deadline (%s) must be shorter than the lease duration (%s)",
			le.RenewDeadline, le.LeaseDuration)
	case le.RetryPeriod >= le.RenewDeadline:
		return fmt.Errorf("kubecontroller: the retry period (%s) must be shorter than the renew deadline (%s)",
			le.RetryPeriod, le.RenewDeadline)
	}
	return nil
}

// elector runs one replica's candidacy.
type elector struct {
	api  *kubeAPI
	cfg  LeaderElection
	logf func(string, ...any)
	now  func() time.Time

	mu sync.Mutex
	// observed is the lease as last read, and observedAt when this replica
	// saw it change.
	observed   *Lease
	observedAt time.Time
	leading    bool
}

func newElector(api *kubeAPI, cfg LeaderElection, logf func(string, ...any)) *elector {
	return &elector{api: api, cfg: cfg.withDefaults(), logf: logf, now: time.Now}
}

// IsLeader reports whether this replica leads now.
func (e *elector) IsLeader() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leading
}

// run campaigns until ctx ends. Each term calls lead with a context that ends
// when the term does; run waits for lead to return before campaigning again,
// and releases the lease on its way out.
func (e *elector) run(ctx context.Context, lead func(context.Context)) {
	for ctx.Err() == nil {
		if !e.acquire(ctx) {
			return
		}
		e.logf("leader election: %s leads (Lease %s/%s)", e.cfg.Identity, e.cfg.Namespace, e.cfg.Name)
		termCtx, endTerm := context.WithCancel(ctx)
		led := make(chan struct{})
		go func() {
			defer close(led)
			lead(termCtx)
		}()
		e.renew(termCtx)
		endTerm()
		<-led
		e.setLeading(false)
		if ctx.Err() != nil {
			e.release()
			return
		}
		e.logf("leader election: %s lost the lease; campaigning again", e.cfg.Identity)
	}
}

func (e *elector) setLeading(v bool) {
	e.mu.Lock()
	e.leading = v
	e.mu.Unlock()
}

// acquire tries every RetryPeriod until this replica holds the lease, or ctx
// ends (false).
func (e *elector) acquire(ctx context.Context) bool {
	for {
		if ok, err := e.tryAcquireOrRenew(ctx); err != nil && ctx.Err() == nil {
			e.logf("leader election: %v", err)
		} else if ok {
			e.setLeading(true)
			return true
		}
		if !sleep(ctx, jitter(e.cfg.RetryPeriod)) {
			return false
		}
	}
}

// renew keeps the lease until a renewal has failed for RenewDeadline, or ctx
// ends.
func (e *elector) renew(ctx context.Context) {
	lastRenew := e.now()
	for {
		if !sleep(ctx, e.cfg.RetryPeriod) {
			return
		}
		attempt, cancel := context.WithTimeout(ctx, e.cfg.RenewDeadline)
		ok, err := e.tryAcquireOrRenew(attempt)
		cancel()
		switch {
		case ok:
			lastRenew = e.now()
		case ctx.Err() != nil:
			return
		default:
			if err != nil {
				e.logf("leader election: renew: %v", err)
			}
			if e.now().Sub(lastRenew) >= e.cfg.RenewDeadline || err == nil {
				// err == nil and not ok: someone else holds it now.
				return
			}
		}
	}
}

// tryAcquireOrRenew takes or renews the lease once.
func (e *elector) tryAcquireOrRenew(ctx context.Context) (bool, error) {
	now := e.now()
	dur := int32(e.cfg.LeaseDuration / time.Second)
	cur, err := e.api.getLease(ctx, e.cfg.Namespace, e.cfg.Name)
	if kubernetes.IsNotFound(err) {
		lease := &Lease{Metadata: ObjectMeta{Name: e.cfg.Name, Namespace: e.cfg.Namespace},
			Spec: LeaseSpec{HolderIdentity: ptr(e.cfg.Identity), LeaseDurationSeconds: ptr(dur),
				AcquireTime: microTime(now), RenewTime: microTime(now), LeaseTransitions: ptr(int32(0))}}
		created, err := e.api.createLease(ctx, lease)
		if err != nil {
			if kubernetes.IsConflict(err) {
				return false, nil
			}
			return false, fmt.Errorf("create Lease %s/%s: %w", e.cfg.Namespace, e.cfg.Name, err)
		}
		e.observe(created, now)
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read Lease %s/%s: %w", e.cfg.Namespace, e.cfg.Name, err)
	}
	e.observe(cur, now)

	holder := ""
	if cur.Spec.HolderIdentity != nil {
		holder = *cur.Spec.HolderIdentity
	}
	if holder != "" && holder != e.cfg.Identity && !e.expired(now, cur) {
		return false, nil
	}
	next := *cur
	next.Spec.HolderIdentity = ptr(e.cfg.Identity)
	next.Spec.LeaseDurationSeconds = ptr(dur)
	next.Spec.RenewTime = microTime(now)
	if holder != e.cfg.Identity {
		next.Spec.AcquireTime = microTime(now)
		transitions := int32(0)
		if cur.Spec.LeaseTransitions != nil {
			transitions = *cur.Spec.LeaseTransitions
		}
		next.Spec.LeaseTransitions = ptr(transitions + 1)
	}
	updated, err := e.api.updateLease(ctx, &next)
	if err != nil {
		if kubernetes.IsConflict(err) {
			return false, nil
		}
		return false, fmt.Errorf("update Lease %s/%s: %w", e.cfg.Namespace, e.cfg.Name, err)
	}
	e.observe(updated, now)
	return true, nil
}

// observe records the lease as read at now, restarting the expiry clock when
// it changed.
func (e *elector) observe(l *Lease, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.observed == nil || e.observed.Metadata.ResourceVersion != l.Metadata.ResourceVersion {
		e.observedAt = now
	}
	e.observed = l
}

// expired reports whether a rival's lease has gone unrenewed, by this
// replica's clock, for its duration.
func (e *elector) expired(now time.Time, l *Lease) bool {
	e.mu.Lock()
	seen := e.observedAt
	e.mu.Unlock()
	dur := e.cfg.LeaseDuration
	if l.Spec.LeaseDurationSeconds != nil && *l.Spec.LeaseDurationSeconds > 0 {
		dur = time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second
	}
	return now.Sub(seen) > dur
}

// release gives the lease up on shutdown, so a successor need not wait out
// its duration. Best effort.
func (e *elector) release() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cur, err := e.api.getLease(ctx, e.cfg.Namespace, e.cfg.Name)
	if err != nil || cur.Spec.HolderIdentity == nil || *cur.Spec.HolderIdentity != e.cfg.Identity {
		return
	}
	next := *cur
	next.Spec.HolderIdentity = ptr("")
	next.Spec.LeaseDurationSeconds = ptr(int32(1))
	next.Spec.RenewTime = microTime(e.now())
	if _, err := e.api.updateLease(ctx, &next); err != nil {
		e.logf("leader election: release the lease: %v", err)
	}
}
