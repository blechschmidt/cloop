package diskwatch

import (
	"context"
	"time"
)

// Policy is a Watchdog's sampling schedule.
//
// The interval adapts in both directions and is bounded below by the cost of
// the last walk. A walk that took a second waits at least CostFactor seconds
// before the next, so a tree that is expensive to measure is measured less
// often rather than measured continuously — the sampler's share of one thread
// stays under 1/CostFactor however large the tree grows. Within that bound it
// samples sooner the closer the tree gets to its limit: at the observed growth
// rate, the next sample is due by half the time the tree would take to reach
// it.
type Policy struct {
	// MinInterval is the shortest wait between two samples.
	MinInterval time.Duration
	// MaxInterval is the longest wait when nothing calls for a sooner one. A
	// walk costlier than MaxInterval/CostFactor still waits CostFactor times
	// its cost: the cost bound wins.
	MaxInterval time.Duration
	// FirstInterval is the wait after a sample with no growth history behind
	// it — the one taken at the start — when the tree is not near its limit.
	// Shorter than MaxInterval because until a second sample there is no rate
	// to schedule by, and the start of a run is when a workload that writes
	// fast has the most room to overshoot.
	FirstInterval time.Duration
	// CostFactor is how many times the last walk's duration the next sample
	// waits at least.
	CostFactor int
	// Deadline bounds one walk. A walk that misses it is unknown.
	Deadline time.Duration
}

// DefaultPolicy is the schedule the container driver samples on.
var DefaultPolicy = Policy{
	MinInterval:   5 * time.Second,
	MaxInterval:   2 * time.Minute,
	FirstInterval: 15 * time.Second,
	CostFactor:    10,
	Deadline:      time.Minute,
}

// headroomNear is the fraction of the limit past which a tree with no growth
// history yet is sampled at the shortest interval.
const headroomNear = 0.9

func (p Policy) normalize() Policy {
	if p.MinInterval <= 0 {
		p.MinInterval = DefaultPolicy.MinInterval
	}
	if p.MaxInterval < p.MinInterval {
		p.MaxInterval = p.MinInterval
	}
	if p.FirstInterval <= 0 || p.FirstInterval > p.MaxInterval {
		p.FirstInterval = p.MaxInterval
	}
	if p.CostFactor <= 0 {
		p.CostFactor = DefaultPolicy.CostFactor
	}
	return p
}

// Sample is one completed measurement, as the schedule sees it.
type Sample struct {
	Bytes int64
	At    time.Time
	// Cost is how long the walk took.
	Cost time.Duration
}

// Next returns how long to wait after cur before sampling again. prev is the
// sample before it, or nil; limit is the limit in bytes.
func (p Policy) Next(cur Sample, prev *Sample, limit int64) time.Duration {
	p = p.normalize()
	wait := p.MaxInterval
	switch {
	case limit > 0 && float64(cur.Bytes) >= headroomNear*float64(limit):
		wait = p.MinInterval
	case prev == nil:
		wait = p.FirstInterval
	case limit > 0 && cur.At.After(prev.At) && cur.Bytes > prev.Bytes:
		// In float seconds, and compared before converting: a large limit
		// and a slow trickle put the arrival years out, past what a
		// time.Duration holds.
		rate := float64(cur.Bytes-prev.Bytes) / cur.At.Sub(prev.At).Seconds()
		half := float64(limit-cur.Bytes) / rate / 2
		if half < wait.Seconds() {
			wait = time.Duration(half * float64(time.Second))
		}
	}
	return p.costBound(wait, cur.Cost)
}

// AfterUnknown returns how long to wait after a walk that did not complete.
// Its cost is what it spent before it gave up, which for a missed deadline is
// the whole deadline: the next attempt waits CostFactor deadlines, so a tree
// too large to measure is not measured back to back.
func (p Policy) AfterUnknown(cost time.Duration) time.Duration {
	p = p.normalize()
	return p.costBound(p.MaxInterval, cost)
}

// costBound raises wait to at least MinInterval and CostFactor × cost.
func (p Policy) costBound(wait, cost time.Duration) time.Duration {
	if wait < p.MinInterval {
		wait = p.MinInterval
	}
	if floor := time.Duration(p.CostFactor) * cost; floor > wait {
		wait = floor
	}
	return wait
}

// Watchdog samples a workload's workspace until it is cancelled or the
// workspace is over its limit.
type Watchdog struct {
	// Roots are the trees measured together.
	Roots []Root
	// LimitBytes is the limit; a non-positive one makes Run return at once.
	LimitBytes int64
	// Walker measures; its Deadline is set from Policy.Deadline when zero.
	Walker Walker
	// Policy is the schedule; its zero value is DefaultPolicy.
	Policy Policy
	// Initial is the measurement taken before the workload started, which
	// schedules the first sample. Nil schedules it at MinInterval.
	Initial *Sample

	// Now and Sleep are the loop's clock. Sleep returns false when ctx ended
	// first. Nil means the real ones.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) bool
	// Measure takes one measurement; nil walks Roots with Walker on a
	// low-priority thread (LowPriority).
	Measure func(ctx context.Context) (Usage, error)

	// OnBreach is called with a measurement over the limit. It returns
	// whether the workload was stopped: Run returns if so, and samples again
	// at MinInterval if not — a stop that failed is a workload still writing.
	OnBreach func(u Usage, at time.Time) bool
	// OnUnknown is called for a measurement that did not complete and is not
	// already over the limit, with the wait before the next attempt. It is
	// the caller's to log: the sample is unknown, and never counts as under.
	OnUnknown func(err error, u Usage, next time.Duration)
}

// Run samples until ctx ends or a breach stops the workload.
func (w *Watchdog) Run(ctx context.Context) {
	if w.LimitBytes <= 0 {
		return
	}
	policy := w.Policy
	if policy == (Policy{}) {
		policy = DefaultPolicy
	}
	policy = policy.normalize()
	now := w.Now
	if now == nil {
		now = time.Now
	}
	sleep := w.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	measure := w.Measure
	if measure == nil {
		walker := w.Walker
		if walker.Deadline == 0 {
			walker.Deadline = policy.Deadline
		}
		measure = func(ctx context.Context) (Usage, error) {
			var (
				u   Usage
				err error
			)
			if perr := LowPriority(func() { u, err = walker.Measure(ctx, w.Roots...) }); perr != nil {
				return u, perr
			}
			return u, err
		}
	}

	prev := w.Initial
	wait := policy.MinInterval
	if prev != nil {
		wait = policy.Next(*prev, nil, w.LimitBytes)
	}
	for {
		if !sleep(ctx, wait) {
			return
		}
		u, err := measure(ctx)
		if ctx.Err() != nil {
			return
		}
		at := now()
		// Over is over even when the walk did not finish: an incomplete count
		// is a lower bound, and a lower bound past the limit settles it.
		if u.Bytes > w.LimitBytes {
			if w.OnBreach == nil || w.OnBreach(u, at) {
				return
			}
			wait = policy.MinInterval
			continue
		}
		if err != nil {
			wait = policy.AfterUnknown(u.Elapsed)
			if w.OnUnknown != nil {
				w.OnUnknown(err, u, wait)
			}
			// prev is kept: an unknown sample says nothing about growth.
			continue
		}
		cur := Sample{Bytes: u.Bytes, At: at, Cost: u.Elapsed}
		wait = policy.Next(cur, prev, w.LimitBytes)
		prev = &cur
	}
}

// sleepCtx waits d or until ctx ends, reporting whether the wait completed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
