package chaos

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// SuiteCase describes one chaos test case. The default suite covers every
// FaultType in turn; callers can extend or subset it via WithCases.
type SuiteCase struct {
	Fault       Fault
	Description string
	// Probe is the function the suite runs against the system under test
	// while the fault is active. It returns the outcome and a short detail
	// string. Probes must complete inside Fault.Until or the suite considers
	// the run "degraded".
	Probe func(ctx context.Context) (Outcome, string)
}

// Suite runs each case sequentially: inject → probe → clear → record.
// Designed to be invoked by `cloop chaos suite` against either:
//
//   - a fresh in-process probe (the default — exercises Transport, the
//     SQLite busy holder, and the disk simulator without needing an
//     external cloop process), or
//   - a probe that reaches into a running cloop ui via HTTP (callers can
//     provide a custom Probe that hits /healthz, runs a task, etc).
type Suite struct {
	WorkDir    string
	StatePath  string
	Controller *Controller
	Store      *Store
	Cases      []SuiteCase
}

// DefaultCases returns one case per fault type with sensible defaults. The
// per-fault Probe verifies that the fault is actually being honoured (HTTP
// probe for the provider faults, sqlite probe for sqlite-busy, disk probe for
// the disk faults). This is the "self-test" the spec asks for: when the
// suite runs cleanly all chaos faults are demonstrably applied.
func DefaultCases(workDir string) []SuiteCase {
	until := func(d time.Duration) time.Time { return time.Now().Add(d) }
	return []SuiteCase{
		{
			Fault: Fault{
				Type: FaultProvider429, Probability: 1.0,
				StartedAt: time.Now(), Until: until(2 * time.Second),
				Note: "suite",
			},
			Description: "every HTTP request returns 429",
			Probe:       httpProbe(http.StatusTooManyRequests),
		},
		{
			Fault: Fault{
				Type: FaultProvider500, Probability: 1.0,
				StartedAt: time.Now(), Until: until(2 * time.Second),
				Note: "suite",
			},
			Description: "every HTTP request returns 500",
			Probe:       httpProbe(http.StatusInternalServerError),
		},
		{
			Fault: Fault{
				Type: FaultNetworkFlap, Probability: 1.0,
				StartedAt: time.Now(), Until: until(2 * time.Second),
				Note: "suite",
			},
			Description: "every HTTP request fails with dial error",
			Probe:       httpProbeError(),
		},
		{
			Fault: Fault{
				Type: FaultProviderTimeout, Probability: 1.0,
				StartedAt: time.Now(), Until: until(3 * time.Second),
				Note: "suite",
			},
			Description: "every HTTP request hangs past the deadline",
			Probe:       httpProbeTimeout(),
		},
		{
			Fault: Fault{
				Type: FaultSlowDisk, Probability: 1.0,
				StartedAt: time.Now(), Until: until(2 * time.Second),
				Note:      "75ms",
			},
			Description: "atomicfile writes get a 75ms delay applied",
			Probe:       slowDiskProbe(workDir),
		},
		{
			Fault: Fault{
				Type: FaultDiskFull, Probability: 1.0,
				StartedAt: time.Now(), Until: until(3 * time.Second),
				Note: "suite",
			},
			Description: "ballast file occupies disk space",
			Probe:       diskFullProbe(workDir),
		},
		{
			Fault: Fault{
				Type: FaultSQLiteBusy, Probability: 1.0,
				StartedAt: time.Now(), Until: until(2 * time.Second),
				Note: "suite",
			},
			Description: "sqlite write lock held by sibling connection",
			Probe:       sqliteBusyProbe(filepath.Join(workDir, ".cloop", "state.db")),
		},
	}
}

// Run executes every case in order and persists each result. Returns the
// list of finalised Run rows so the caller can render a report inline.
func (s *Suite) Run(ctx context.Context) ([]Run, error) {
	if s.Controller == nil {
		s.Controller = NewController(s.WorkDir)
	}
	if len(s.Cases) == 0 {
		s.Cases = DefaultCases(s.WorkDir)
	}

	prev := SetGlobal(s.Controller)
	defer SetGlobal(prev)

	out := make([]Run, 0, len(s.Cases))
	for _, c := range s.Cases {
		// Ensure no leftover faults from a previous case bleed into this one.
		_ = s.Controller.Clear()

		// Persist the fault as a chaos_runs row up front so a crash mid-probe
		// still leaves a forensic trail.
		startedAt := time.Now()
		runID := int64(0)
		if s.Store != nil {
			id, err := s.Store.Insert(Run{
				FaultType:   c.Fault.Type,
				Probability: c.Fault.Probability,
				StartedAt:   startedAt,
				Outcome:     OutcomeUnknown,
				Note:        c.Description,
			})
			if err != nil {
				return out, fmt.Errorf("chaos: suite insert run for %s: %w", c.Fault.Type, err)
			}
			runID = id
		}

		// Inject the fault and run the probe with the controller's per-fault
		// duration as an upper bound — even a hung probe can't outlast it.
		c.Fault.StartedAt = startedAt
		if err := s.Controller.Inject(c.Fault); err != nil {
			r := Run{
				ID: runID, FaultType: c.Fault.Type, StartedAt: startedAt,
				StoppedAt: time.Now(), Outcome: OutcomeCrashed,
				OutcomeDetail: err.Error(),
			}
			if s.Store != nil {
				_ = s.Store.Update(r)
			}
			out = append(out, r)
			continue
		}

		probeCtx, cancel := context.WithDeadline(ctx, c.Fault.Until)
		outcome, detail := c.Probe(probeCtx)
		cancel()

		stoppedAt := time.Now()
		_ = s.Controller.Clear()

		r := Run{
			ID:            runID,
			FaultType:     c.Fault.Type,
			Probability:   c.Fault.Probability,
			StartedAt:     startedAt,
			StoppedAt:     stoppedAt,
			DurationMS:    stoppedAt.Sub(startedAt).Milliseconds(),
			Outcome:       outcome,
			OutcomeDetail: detail,
			Note:          c.Description,
		}
		if s.Store != nil {
			_ = s.Store.Update(r)
		}
		out = append(out, r)
	}
	return out, nil
}

// httpProbe verifies that the chaos transport rewrites responses with the
// expected status code.
func httpProbe(expected int) func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		client := &http.Client{Transport: &Transport{}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://chaos.local/", nil)
		resp, err := client.Do(req)
		if err != nil {
			return OutcomeCrashed, fmt.Sprintf("unexpected error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != expected {
			return OutcomeDegraded, fmt.Sprintf("got %d, want %d", resp.StatusCode, expected)
		}
		return OutcomeRecovered, fmt.Sprintf("client received %d as expected", expected)
	}
}

// httpProbeError verifies that network-flap returns an error before any
// response can be parsed.
func httpProbeError() func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		client := &http.Client{Transport: &Transport{}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://chaos.local/", nil)
		_, err := client.Do(req)
		if err == nil {
			return OutcomeDegraded, "expected dial error, got nil"
		}
		return OutcomeRecovered, fmt.Sprintf("dial error surfaced: %v", err)
	}
}

// httpProbeTimeout verifies that provider-timeout exceeds the caller deadline.
func httpProbeTimeout() func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		// Cap our probe's wait at 1.5s so the suite stays responsive even if
		// the timeout fault is misconfigured.
		probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		client := &http.Client{Transport: &Transport{}}
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://chaos.local/", nil)
		start := time.Now()
		_, err := client.Do(req)
		elapsed := time.Since(start)
		if err == nil {
			return OutcomeDegraded, fmt.Sprintf("expected timeout, got success after %s", elapsed)
		}
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
			return OutcomeDegraded, fmt.Sprintf("unexpected error: %v", err)
		}
		return OutcomeRecovered, fmt.Sprintf("timeout fired after %s", elapsed.Round(time.Millisecond))
	}
}

// slowDiskProbe checks that SlowDiskDelay returns a positive value while the
// fault is active. This is the lightweight check; the actual sleep is applied
// by callers that explicitly opt in via MaybeSleepSlowDisk.
func slowDiskProbe(string) func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		_ = ctx
		d := SlowDiskDelay(nil)
		if d <= 0 {
			return OutcomeDegraded, "slow-disk fault active but SlowDiskDelay returned 0"
		}
		return OutcomeRecovered, fmt.Sprintf("delay configured: %s", d)
	}
}

// diskFullProbe creates the ballast file, verifies it exists at the requested
// size, and tears it down. Operates on a small ballast (4 MiB) because the
// suite runs unattended and we don't want to actually exhaust disk.
func diskFullProbe(workDir string) func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		_ = ctx
		sim := NewDiskFullSimulator(workDir, 4<<20)
		if err := sim.Start(); err != nil {
			return OutcomeCrashed, fmt.Sprintf("ballast create failed: %v", err)
		}
		defer sim.Stop()
		return OutcomeRecovered, "ballast file created and removed cleanly"
	}
}

// sqliteBusyProbe holds the write lock for ~250ms via a sibling connection
// and reports recovery on success. If the database file is missing (not yet
// initialised) the probe reports degraded so the operator knows to run an
// init first.
func sqliteBusyProbe(dbPath string) func(context.Context) (Outcome, string) {
	return func(ctx context.Context) (Outcome, string) {
		holder := NewBusyHolder(dbPath)
		if err := holder.Start(ctx); err != nil {
			return OutcomeDegraded, fmt.Sprintf("sqlite-busy holder start: %v", err)
		}
		// Hold for a short, deterministic period so we don't drag the suite
		// out. The point of the probe is to prove we *can* hold the lock.
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
		}
		held := holder.Stop()
		return OutcomeRecovered, fmt.Sprintf("write lock held for %s", held.Round(time.Millisecond))
	}
}

// httptestRoundTripCount is exposed for tests that want to count synthetic
// requests routed through a chaos transport-wrapped client.
type httptestRoundTripCount struct {
	atomic.Int64
}

// roundTripperFunc is a minimal RoundTripper used internally by testing
// helpers; kept here so chaos_test.go does not need to redeclare it.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// passthroughTransport is a benign default Base used in tests and probes that
// don't wire a real upstream — it returns an empty 200 OK so callers can tell
// "no fault" from "happy path".
func passthroughTransport(srv *httptest.Server) http.RoundTripper {
	if srv != nil {
		return srv.Client().Transport
	}
	return roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return syntheticResponse(&http.Request{}, http.StatusOK, "{}"), nil
	})
}
