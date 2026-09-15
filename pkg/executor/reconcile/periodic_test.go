package reconcile

// periodic_test.go covers the second half of Task 20281: the orphan sweep has
// to keep running, not run once at startup and never again.
//
// The tests are mostly about the *decision* logic — how an interval is
// resolved, when a sweeper is running, what gets published — rather than about
// driving a real driver, because the pass itself is the same code path the
// startup sweep already exercises against a fake API server. What was new here
// is everything around it: a default that has to survive an unset field, an
// operator's explicit "off" having to survive a round trip through a Go zero
// value, and a ticker that must not be able to exist twice.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

func TestSweepInterval_ResolvesTheThreeIntentions(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset uses the default", 0, DefaultSweepInterval},
		{"explicit negative disables", -1, 0},
		{"a chosen cadence is honoured", 30 * time.Minute, 30 * time.Minute},
		{"an unreasonably small cadence is floored", time.Second, MinSweepInterval},
		{"exactly the floor is kept", MinSweepInterval, MinSweepInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Options{SweepInterval: tc.in}).sweepInterval(); got != tc.want {
				t.Errorf("sweepInterval(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestOrphanSweepInterval_ConfigRoundTrip is the translation that is easy to
// get backwards: an operator's 0 means "off", while a Go zero value has to mean
// "default". A bug here disables the sweep on every deployment that never set
// the field, which is every existing deployment, and nothing would report it.
func TestOrphanSweepInterval_ConfigRoundTrip(t *testing.T) {
	minutes := func(n int) *int { return &n }

	cases := []struct {
		name     string
		cfg      config.ExecutorsConfig
		wantEff  time.Duration
		disabled bool
	}{
		{
			name:    "absent from the file gets the default",
			cfg:     config.ExecutorsConfig{},
			wantEff: DefaultSweepInterval,
		},
		{
			name:     "an explicit 0 disables",
			cfg:      config.ExecutorsConfig{OrphanSweepIntervalMinutes: minutes(0)},
			disabled: true,
		},
		{
			name:     "a negative in the file also disables",
			cfg:      config.ExecutorsConfig{OrphanSweepIntervalMinutes: minutes(-5)},
			disabled: true,
		},
		{
			name:    "a chosen cadence survives",
			cfg:     config.ExecutorsConfig{OrphanSweepIntervalMinutes: minutes(45)},
			wantEff: 45 * time.Minute,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (Options{SweepInterval: tc.cfg.OrphanSweepInterval()}).sweepInterval()
			if tc.disabled {
				if got != 0 {
					t.Errorf("effective interval = %v, want disabled (0)", got)
				}
				return
			}
			if got != tc.wantEff {
				t.Errorf("effective interval = %v, want %v", got, tc.wantEff)
			}
		})
	}
}

// TestSweepOrphansOnce_PublishesWhatEachDriverRemoved covers the reporting
// path, including a driver whose pass failed.
//
// A failing sweep has to be visible. An operator whose Role lost its list rule
// sees a namespace slowly filling with Pods, and the only place that can
// explain it is the fleet panel — so an error is recorded rather than swallowed
// by the same recover that keeps the loop alive.
func TestSweepOrphansOnce_PublishesWhatEachDriverRemoved(t *testing.T) {
	t.Cleanup(resetSweepForTest)
	resetSweepForTest()

	// No orphan-capable drivers registered: the pass still completes and still
	// publishes, because "ran, found nothing" and "never ran" are different
	// answers to the operator's question.
	opts := Options{Registry: executor.NewRegistry(), Logf: func(string, ...any) {}}
	report := SweepOrphansOnce(context.Background(), opts)
	if report.At.IsZero() {
		t.Error("the report carries no timestamp; the panel renders it as the zero date")
	}
	if report.Removed != 0 {
		t.Errorf("removed = %d, want 0 from an empty registry", report.Removed)
	}
	got, ok := LastSweep()
	if !ok {
		t.Fatal("LastSweep reports nothing after a completed pass")
	}
	if !got.At.Equal(report.At) {
		t.Errorf("published At = %v, want %v", got.At, report.At)
	}
}

// unreachableCredentials is a kubernetes.CredentialSource pointing at an
// address nothing listens on, so a driver built with it registers and
// preflights like any other but fails the moment it talks to a cluster.
type unreachableCredentials struct{}

func (unreachableCredentials) Acquire(context.Context, string) (*kubernetes.Credentials, error) {
	return &kubernetes.Credentials{
		Rest: &kubernetes.RESTConfig{
			// 127.0.0.1:1 refuses immediately rather than hanging, which keeps
			// the test fast and the failure unambiguous.
			Server:      "https://127.0.0.1:1",
			BearerToken: "not-a-real-token",
			Namespace:   "cloop",
			Insecure:    true,
		},
		LeaseID: "lease-unreachable",
	}, nil
}
func (unreachableCredentials) Renew(context.Context, string) (*kubernetes.Credentials, error) {
	return nil, errors.New("not used")
}
func (unreachableCredentials) Release(string) {}
func (unreachableCredentials) Describe() string {
	return "unreachable cluster (test)"
}

// TestSweepOrphansOnce_ReachesARealKubernetesDriver closes the hole every other
// test in this file leaves open.
//
// They all run against an empty registry, which exercises the loop, the report
// and the publishing — and would every one of them still pass if the type
// switch in SweepOrphansOnce matched nothing at all. That is not a hypothetical
// failure mode: the switch is on concrete pointer types, so a driver moved to a
// new package or wrapped in a decorator stops matching silently, and the
// symptom is a sweep that reports success while collecting nothing forever.
//
// The cluster is deliberately unreachable. What is being proven is that the
// driver is *found* and *called*, which its error proves as well as a success
// would — and better, because it also pins the reporting path for a failing
// sweep, which is the case an operator actually has to be told about.
func TestSweepOrphansOnce_ReachesARealKubernetesDriver(t *testing.T) {
	t.Cleanup(resetSweepForTest)
	resetSweepForTest()

	reg := executor.NewRegistry()
	ex, err := kubernetes.New(kubernetes.Options{
		ID:          "k8s-periodic",
		Namespace:   "cloop",
		Image:       "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Credentials: unreachableCredentials{},
	})
	if err != nil {
		t.Fatalf("kubernetes.New: %v", err)
	}
	t.Cleanup(ex.Close)
	if err := reg.Register(ex); err != nil {
		t.Fatalf("register: %v", err)
	}

	report := SweepOrphansOnce(context.Background(),
		Options{Registry: reg, Logf: func(string, ...any) {}})

	if len(report.Executors) != 1 {
		t.Fatalf("the sweep produced %d per-executor results, want 1 — the type switch in "+
			"SweepOrphansOnce did not match the registered Kubernetes driver: %+v",
			len(report.Executors), report.Executors)
	}
	got := report.Executors[0]
	if got.ID != "k8s-periodic" {
		t.Errorf("swept executor ID = %q, want %q", got.ID, "k8s-periodic")
	}
	if got.Kind != "kubernetes" {
		t.Errorf("swept executor kind = %q, want %q", got.Kind, "kubernetes")
	}
	if got.Error == "" {
		t.Error("an unreachable cluster produced no error; a failing sweep must be reported, " +
			"because a Role that lost its list rule looks exactly like this")
	}
	// And it is published, so the fleet panel can render the failure.
	published, ok := LastSweep()
	if !ok || len(published.Executors) != 1 || published.Executors[0].Error == "" {
		t.Errorf("the failing sweep was not published: ok=%v report=%+v", ok, published)
	}
}

// TestSweepOne_KeepsAPartialSuccess: the container driver returns real removals
// alongside an error from the half that failed, and discarding those would tell
// an operator debugging a vanished sandbox that nothing collected it.
func TestSweepOne_KeepsAPartialSuccess(t *testing.T) {
	res := sweepOne(context.Background(), "ctr", "container",
		func(context.Context) ([]string, error) {
			return []string{"a", "b"}, errors.New("could not list running containers")
		})

	if res.Removed != 2 {
		t.Errorf("removed = %d, want 2 — a partial success is still a removal", res.Removed)
	}
	if res.Error == "" {
		t.Error("the error was dropped; a sweep that half-failed must say so")
	}
	if len(res.Objects) != 2 {
		t.Errorf("objects = %v, want both names", res.Objects)
	}
}

// TestSweepOne_CapsTheObjectListButNotTheCount. The count is what a dashboard
// renders and has to stay exact; the names are a debugging aid and must not be
// able to put an unbounded slice into an HTTP response.
func TestSweepOne_CapsTheObjectListButNotTheCount(t *testing.T) {
	many := make([]string, maxSweepObjects+25)
	for i := range many {
		many[i] = "ns/pod"
	}
	res := sweepOne(context.Background(), "k8s", "kubernetes",
		func(context.Context) ([]string, error) { return many, nil })

	if res.Removed != len(many) {
		t.Errorf("removed = %d, want the true count %d", res.Removed, len(many))
	}
	if len(res.Objects) != maxSweepObjects {
		t.Errorf("objects = %d, want capped at %d", len(res.Objects), maxSweepObjects)
	}
}

// TestStartPeriodicSweep_ReplacesRatherThanAccumulates.
//
// Bootstrap reconciles twice by design and a process may construct several
// servers, so this is reachable in normal operation rather than only in tests.
// Two tickers would double the API traffic and race each other to delete the
// same Pod.
func TestStartPeriodicSweep_ReplacesRatherThanAccumulates(t *testing.T) {
	t.Cleanup(resetSweepForTest)
	resetSweepForTest()

	opts := Options{
		Registry:      executor.NewRegistry(),
		SweepInterval: MinSweepInterval,
		Logf:          func(string, ...any) {},
	}

	StartPeriodicSweep(context.Background(), opts)
	if currentSweepCancel() == nil {
		t.Fatal("no sweeper is running after StartPeriodicSweep")
	}

	// Five more, as a hub that reconciles repeatedly would do. The count is the
	// assertion: one live loop, not six.
	for range 5 {
		StartPeriodicSweep(context.Background(), opts)
	}
	if !waitSweeperCount(1, 2*time.Second) {
		t.Errorf("after six StartPeriodicSweep calls %d sweeper goroutines are live, want 1 — "+
			"each extra one doubles the API traffic and races the others to delete the same Pod",
			sweepRunning.Load())
	}

	StopPeriodicSweep()
	if currentSweepCancel() != nil {
		t.Error("a sweeper is still registered after StopPeriodicSweep")
	}
	if !waitSweepersStopped(2 * time.Second) {
		t.Errorf("%d sweeper goroutines outlived StopPeriodicSweep", sweepRunning.Load())
	}
	// Idempotent: a server shutting down stops it, and so does the next
	// StartPeriodicSweep.
	StopPeriodicSweep()
}

// waitSweeperCount blocks until exactly n sweeper goroutines are live.
func waitSweeperCount(n int64, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if sweepRunning.Load() == n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return sweepRunning.Load() == n
}

// TestStartPeriodicSweep_DisabledStartsNothingAndSaysSo.
func TestStartPeriodicSweep_DisabledStartsNothingAndSaysSo(t *testing.T) {
	t.Cleanup(resetSweepForTest)
	resetSweepForTest()

	var mu sync.Mutex
	var lines []string
	opts := Options{
		Registry:      executor.NewRegistry(),
		SweepInterval: -1,
		Logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, format)
		},
	}
	StartPeriodicSweep(context.Background(), opts)

	if currentSweepCancel() != nil {
		t.Error("a sweeper is running despite the interval being disabled")
	}
	mu.Lock()
	joined := strings.Join(lines, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "periodic orphan sweep is") {
		t.Errorf("nothing was logged about the sweep being off; the operator has no way to "+
			"connect a filling namespace to this setting. logged: %q", joined)
	}
	if got := describeSweepInterval(opts); got != "disabled" {
		t.Errorf("describeSweepInterval = %q, want %q", got, "disabled")
	}
}

// TestStartPeriodicSweep_StopsWhenItsContextIsCancelled keeps the loop from
// outliving the server that started it — the package has a goroutine-leak
// detector, and a ticker nobody can stop would trip it.
func TestStartPeriodicSweep_StopsWhenItsContextIsCancelled(t *testing.T) {
	t.Cleanup(resetSweepForTest)
	resetSweepForTest()

	ctx, cancel := context.WithCancel(context.Background())
	StartPeriodicSweep(ctx, Options{
		Registry:      executor.NewRegistry(),
		SweepInterval: MinSweepInterval,
		Logf:          func(string, ...any) {},
	})
	if currentSweepCancel() == nil {
		t.Fatal("no sweeper is running")
	}
	cancel()

	// Cancelling the caller's context must be enough on its own: a server that
	// shuts down by cancelling and never calls StopPeriodicSweep would
	// otherwise leave the ticker running for the life of the process.
	if !waitSweepersStopped(2 * time.Second) {
		t.Errorf("%d sweeper goroutines survived their context being cancelled",
			sweepRunning.Load())
	}
	StopPeriodicSweep()
}

// currentSweepCancel reads the registered canceller under the lock.
func currentSweepCancel() context.CancelFunc {
	sweepMu.Lock()
	defer sweepMu.Unlock()
	return sweepCancel
}
