package diskwatch

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

const mb = int64(1 << 20)

var testPolicy = Policy{MinInterval: 5 * time.Second, MaxInterval: 2 * time.Minute, FirstInterval: 15 * time.Second,
	CostFactor: 10, Deadline: time.Minute}

func TestPolicyIsBoundedByTheCostOfTheLastWalk(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	cheap := testPolicy.Next(Sample{Bytes: 1 * mb, At: t0, Cost: 10 * time.Millisecond}, nil, 64*mb)
	if cheap != testPolicy.FirstInterval {
		t.Fatalf("a first cheap walk far from the limit waits %s, want FirstInterval %s", cheap, testPolicy.FirstInterval)
	}
	prev := Sample{Bytes: 1 * mb, At: t0}
	steady := testPolicy.Next(Sample{Bytes: 1 * mb, At: t0.Add(time.Minute), Cost: 10 * time.Millisecond}, &prev, 64*mb)
	if steady != testPolicy.MaxInterval {
		t.Fatalf("a tree that is not growing waits %s, want MaxInterval %s", steady, testPolicy.MaxInterval)
	}
	// A walk costing 30s waits at least 300s — longer than MaxInterval: the
	// cost bound wins, so an expensive tree is measured less often, not
	// continuously.
	costly := testPolicy.Next(Sample{Bytes: 1 * mb, At: t0, Cost: 30 * time.Second}, nil, 64*mb)
	if costly != 300*time.Second {
		t.Fatalf("a 30s walk waits %s, want 5m0s", costly)
	}
	// Even right at the limit.
	near := testPolicy.Next(Sample{Bytes: 63 * mb, At: t0, Cost: 30 * time.Second}, nil, 64*mb)
	if near != 300*time.Second {
		t.Fatalf("a 30s walk near the limit waits %s, want the cost bound 5m0s", near)
	}
}

func TestPolicySamplesSoonerAsTheTreeApproachesItsLimit(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	// Near the limit with no growth history: the shortest interval.
	if got := testPolicy.Next(Sample{Bytes: 60 * mb, At: t0}, nil, 64*mb); got != testPolicy.MinInterval {
		t.Fatalf("at 94%% of the limit waits %s, want MinInterval", got)
	}
	// Growing 1 MB/s with 40 MB to go: due in 40s, sampled within half that.
	prev := Sample{Bytes: 14 * mb, At: t0}
	cur := Sample{Bytes: 24 * mb, At: t0.Add(10 * time.Second)}
	if got := testPolicy.Next(cur, &prev, 64*mb); got != 20*time.Second {
		t.Fatalf("growing toward the limit waits %s, want 20s", got)
	}
	// Faster growth cannot push it below MinInterval.
	fast := Sample{Bytes: 54 * mb, At: t0.Add(time.Second)}
	if got := testPolicy.Next(fast, &prev, 64*mb); got != testPolicy.MinInterval {
		t.Fatalf("fast growth waits %s, want MinInterval", got)
	}
	// A trickle into a huge limit puts the arrival centuries out — past what
	// a time.Duration holds. It must read as "not soon", not overflow into a
	// negative wait.
	huge := int64(900) << 30
	slow := Sample{Bytes: 1 * mb, At: t0}
	trickle := Sample{Bytes: 1*mb + 4096, At: t0.Add(2 * time.Minute)}
	if got := testPolicy.Next(trickle, &slow, huge); got != testPolicy.MaxInterval {
		t.Fatalf("a trickle into a 900 GiB limit waits %s, want MaxInterval", got)
	}
	// A shrinking tree is not on its way to the limit.
	shrunk := Sample{Bytes: 4 * mb, At: t0.Add(10 * time.Second)}
	if got := testPolicy.Next(shrunk, &prev, 64*mb); got != testPolicy.MaxInterval {
		t.Fatalf("a shrinking tree waits %s, want MaxInterval", got)
	}
}

func TestPolicyAfterAnUnknownWalkWaitsForItsCost(t *testing.T) {
	// A walk that missed a one-minute deadline cost a minute.
	if got := testPolicy.AfterUnknown(time.Minute); got != 10*time.Minute {
		t.Fatalf("after a missed deadline waits %s, want 10m0s", got)
	}
	if got := testPolicy.AfterUnknown(0); got != testPolicy.MaxInterval {
		t.Fatalf("after an unknown that cost nothing waits %s, want MaxInterval", got)
	}
}

// loop drives a Watchdog with a scripted series of measurements and a clock
// that only moves when the loop sleeps.
type loop struct {
	now     time.Time
	waits   []time.Duration
	results []result
	calls   int
}

type result struct {
	u   Usage
	err error
}

func (l *loop) watchdog(limit int64) *Watchdog {
	return &Watchdog{
		LimitBytes: limit,
		Policy:     testPolicy,
		Now:        func() time.Time { return l.now },
		Sleep: func(ctx context.Context, d time.Duration) bool {
			if ctx.Err() != nil {
				return false
			}
			l.waits = append(l.waits, d)
			l.now = l.now.Add(d)
			return true
		},
		Measure: func(ctx context.Context) (Usage, error) {
			if l.calls >= len(l.results) {
				panic(fmt.Sprintf("measured %d times, scripted %d", l.calls+1, len(l.results)))
			}
			r := l.results[l.calls]
			l.calls++
			return r.u, r.err
		},
	}
}

func TestWatchdogStopsTheWorkloadOnceItIsOverTheLimit(t *testing.T) {
	l := &loop{now: time.Unix(1_700_000_000, 0), results: []result{
		{u: Usage{Bytes: 10 * mb}},
		{u: Usage{Bytes: 30 * mb}},
		{u: Usage{Bytes: 65 * mb, Elapsed: time.Second}},
	}}
	w := l.watchdog(64 * mb)
	var breaches []Usage
	w.OnBreach = func(u Usage, at time.Time) bool {
		breaches = append(breaches, u)
		return true
	}
	w.OnUnknown = func(err error, u Usage, next time.Duration) { t.Fatalf("unexpected unknown: %v", err) }
	w.Run(context.Background())
	if len(breaches) != 1 || breaches[0].Bytes != 65*mb {
		t.Fatalf("breaches = %+v, want one at 65 MB", breaches)
	}
	if l.calls != 3 {
		t.Fatalf("measured %d times after the breach stopped it, want 3", l.calls)
	}
	// No start measurement, so the first sample comes at MinInterval; with no
	// growth behind it the second at FirstInterval; then 10 MB → 30 MB in
	// 15s, with 34 MB to go, is due in 25.5s, so the third came within half.
	if len(l.waits) != 3 || l.waits[0] != testPolicy.MinInterval || l.waits[1] != testPolicy.FirstInterval ||
		l.waits[2] != 12750*time.Millisecond {
		t.Fatalf("waits = %v", l.waits)
	}
}

func TestWatchdogNeverCountsAnUnknownWalkAsUnderTheLimit(t *testing.T) {
	l := &loop{now: time.Unix(1_700_000_000, 0), results: []result{
		// Missed its deadline at 20 MB: unknown, not "20 MB, under".
		{u: Usage{Bytes: 20 * mb, Elapsed: time.Minute}, err: ErrDeadline},
		// Unreadable directories at 30 MB: unknown too.
		{u: Usage{Bytes: 30 * mb, Elapsed: time.Second}, err: fmt.Errorf("%w: 1 directory", ErrIncomplete)},
		// Missed its deadline already past the limit: that lower bound settles it.
		{u: Usage{Bytes: 70 * mb, Elapsed: time.Minute}, err: ErrDeadline},
	}}
	w := l.watchdog(64 * mb)
	var unknown []error
	var nexts []time.Duration
	w.OnUnknown = func(err error, u Usage, next time.Duration) {
		unknown = append(unknown, err)
		nexts = append(nexts, next)
	}
	stopped := false
	w.OnBreach = func(u Usage, at time.Time) bool {
		stopped = u.Bytes == 70*mb
		return true
	}
	w.Run(context.Background())
	if len(unknown) != 2 || !errors.Is(unknown[0], ErrDeadline) || !errors.Is(unknown[1], ErrIncomplete) {
		t.Fatalf("unknown = %v", unknown)
	}
	// After a missed one-minute deadline the next attempt waits ten.
	if nexts[0] != 10*time.Minute || nexts[1] != 2*time.Minute {
		t.Fatalf("waits after unknown = %v", nexts)
	}
	if !stopped {
		t.Fatal("a walk over the limit was not a breach because it missed its deadline")
	}
}

func TestWatchdogKeepsSamplingWhenAStopFails(t *testing.T) {
	l := &loop{now: time.Unix(1_700_000_000, 0), results: []result{
		{u: Usage{Bytes: 70 * mb}},
		{u: Usage{Bytes: 80 * mb}},
	}}
	w := l.watchdog(64 * mb)
	attempts := 0
	w.OnBreach = func(u Usage, at time.Time) bool {
		attempts++
		return attempts == 2
	}
	w.Run(context.Background())
	if attempts != 2 || l.waits[1] != testPolicy.MinInterval {
		t.Fatalf("attempts = %d, waits = %v: a failed stop must be retried at the shortest interval", attempts, l.waits)
	}
}

func TestWatchdogEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &loop{now: time.Unix(1_700_000_000, 0), results: []result{{u: Usage{Bytes: mb}}}}
	w := l.watchdog(64 * mb)
	w.Measure = func(context.Context) (Usage, error) {
		l.calls++
		cancel()
		return Usage{Bytes: 100 * mb}, nil
	}
	w.OnBreach = func(Usage, time.Time) bool { t.Fatal("a sample taken as the workload ended was acted on"); return true }
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestWatchdogSchedulesItsFirstSampleFromTheStartMeasurement(t *testing.T) {
	l := &loop{now: time.Unix(1_700_000_000, 0), results: []result{{u: Usage{Bytes: 65 * mb}}}}
	w := l.watchdog(64 * mb)
	w.Initial = &Sample{Bytes: 62 * mb, At: l.now, Cost: 2 * time.Second}
	w.OnBreach = func(Usage, time.Time) bool { return true }
	w.Run(context.Background())
	// Near the limit, so as soon as the start walk's cost allows: 10 × 2s.
	if len(l.waits) != 1 || l.waits[0] != 20*time.Second {
		t.Fatalf("waits = %v, want [20s]", l.waits)
	}
}

func TestWatchdogWithoutALimitDoesNothing(t *testing.T) {
	l := &loop{now: time.Unix(1_700_000_000, 0)}
	w := l.watchdog(0)
	w.Run(context.Background())
	if l.calls != 0 || len(l.waits) != 0 {
		t.Fatalf("a watchdog with no limit measured %d times", l.calls)
	}
}

func TestWatchdogMeasuresARealTreeOnALowPriorityThread(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root+"/big", 2<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got := make(chan Usage, 1)
	w := &Watchdog{
		Roots:      []Root{{Path: root}},
		LimitBytes: 1 << 20,
		Policy:     Policy{MinInterval: time.Millisecond, MaxInterval: time.Millisecond, CostFactor: 1, Deadline: 10 * time.Second},
		OnBreach: func(u Usage, at time.Time) bool {
			got <- u
			return true
		},
	}
	go w.Run(ctx)
	select {
	case u := <-got:
		if u.Bytes < 2<<20 {
			t.Fatalf("breach at %d bytes, want at least the 2 MiB written", u.Bytes)
		}
	case <-ctx.Done():
		t.Fatal("no breach reported for a tree twice its limit")
	}
}
