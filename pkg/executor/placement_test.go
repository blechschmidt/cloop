package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// capExec is a configurable Executor for the placement and supervisor tests.
//
// registry_test.go's fakeExecutor hard-codes Capabilities{Isolation:
// IsolationNone} and a nil HealthCheck error, which are precisely the two
// things the scheduling layer needs to vary, so this is a separate type rather
// than a change to that one.
//
// caps is set at construction and never mutated, so it needs no lock; healthFn
// is swapped by the supervisor tests while probes are in flight, so it does.
type capExec struct {
	id   string
	kind string
	caps Capabilities

	mu       sync.Mutex
	healthFn func(context.Context) error
	probes   int
}

func newCapExec(id string, caps Capabilities) *capExec {
	return &capExec{id: id, kind: KindLocalProcess, caps: caps}
}

func (c *capExec) ID() string                 { return c.id }
func (c *capExec) Kind() string               { return c.kind }
func (c *capExec) Capabilities() Capabilities { return c.caps }

func (c *capExec) Start(context.Context, Spec) (Handle, error) {
	return Handle{ID: "h-" + c.id, ExecutorID: c.id, StartedAt: baseTime}, nil
}
func (c *capExec) Signal(context.Context, string, Signal) error { return nil }
func (c *capExec) Status(context.Context, string) (Status, error) {
	return Status{State: StateExited}, nil
}
func (c *capExec) Stream(context.Context, string) (<-chan LogLine, error) {
	ch := make(chan LogLine)
	close(ch)
	return ch, nil
}

func (c *capExec) HealthCheck(ctx context.Context) error {
	c.mu.Lock()
	fn := c.healthFn
	c.probes++
	c.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx)
}

// setHealth swaps the probe behaviour, safely with respect to in-flight probes.
func (c *capExec) setHealth(fn func(context.Context) error) {
	c.mu.Lock()
	c.healthFn = fn
	c.mu.Unlock()
}

func (c *capExec) failWith(err error) {
	c.setHealth(func(context.Context) error { return err })
}

func (c *capExec) probeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probes
}

// fullCaps is a node that can do everything, so each table row below can show
// only the one capability it is actually about.
func fullCaps(fn func(*Capabilities)) Capabilities {
	c := Capabilities{
		Isolation:              IsolationContainer,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: true,
		SharesHostFilesystem:   false,
		NetworkEgress:          true,
		MaxConcurrent:          4,
		Platform:               "linux",
		Arch:                   "amd64",
	}
	if fn != nil {
		fn(&c)
	}
	return c
}

// wantPlacementError asserts the three things every placement failure has to
// deliver: the sentinel callers match on, the typed error the UI renders, and
// the named constraint that tells an operator what to fix.
func wantPlacementError(t *testing.T, err error, want Constraint) *PlacementError {
	t.Helper()
	if err == nil {
		t.Fatalf("Select succeeded, want a rejection naming %s", want)
	}
	if !errors.Is(err, ErrNoPlacement) {
		t.Fatalf("errors.Is(err, ErrNoPlacement) = false for %v — callers match the sentinel", err)
	}
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *PlacementError; the structured detail is what the CLI and UI render", err)
	}
	if want != "" && pe.Constraint != want {
		t.Fatalf("headline constraint = %q, want %q (rejections: %+v)", pe.Constraint, want, pe.Rejections)
	}
	return pe
}

// TestSelectFiltersOnHealth: the two admin-held states and unreachable take no
// new work; ready and degraded do.
func TestSelectFiltersOnHealth(t *testing.T) {
	cases := []struct {
		state       NodeState
		schedulable bool
	}{
		{NodeReady, true},
		{NodeDegraded, true},
		{NodeUnreachable, false},
		{NodeCordoned, false},
		{NodeDraining, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			c := Candidate{
				Executor: newCapExec("edge-1", fullCaps(nil)),
				Health:   Health{ExecutorID: "edge-1", State: tc.state},
			}
			got, err := Select([]Candidate{c}, Requirements{})
			if tc.schedulable {
				if err != nil {
					t.Fatalf("Select on a %s node = %v, want it chosen", tc.state, err)
				}
				if got.ID() != "edge-1" {
					t.Fatalf("Select = %q, want edge-1", got.ID())
				}
				return
			}
			pe := wantPlacementError(t, err, ConstraintHealth)
			if len(pe.Rejections) != 1 || !strings.Contains(pe.Rejections[0].Detail, string(tc.state)) {
				t.Fatalf("rejections = %+v, want one naming %q", pe.Rejections, tc.state)
			}
		})
	}

	// An unset health record normalizes to ready rather than to "unknown, do
	// not schedule": a caller with no health store still gets placement.
	if got, err := Select([]Candidate{{Executor: newCapExec("edge-1", fullCaps(nil))}}, Requirements{}); err != nil || got.ID() != "edge-1" {
		t.Fatalf("Select with zero Health = (%q, %v), want edge-1", got.ID(), err)
	}

	// ForbidDegraded tightens it for callers that would rather fail than run
	// on a node whose probes are missing.
	degraded := Candidate{
		Executor: newCapExec("edge-1", fullCaps(nil)),
		Health:   Health{State: NodeDegraded},
	}
	pe := wantPlacementError(t, mustFail(Select([]Candidate{degraded}, Requirements{ForbidDegraded: true})), ConstraintHealth)
	if !strings.Contains(pe.Rejections[0].Detail, "forbidden") {
		t.Errorf("detail = %q, want it to say degraded placement was forbidden", pe.Rejections[0].Detail)
	}
}

// mustFail adapts Select's two-value return for the one-liner assertions above.
func mustFail(_ Candidate, err error) error { return err }

// TestSelectCapabilityMatrix is the constraint table: every requirement gets a
// candidate that fails exactly that requirement and one that satisfies it, and
// the reported Constraint has to name the right one — "no executor available"
// sends an operator reading logs, "no executor satisfies harness=claude" sends
// them to the fix.
func TestSelectCapabilityMatrix(t *testing.T) {
	cases := []struct {
		name string
		cand Candidate
		req  Requirements
		want Constraint // "" means the candidate must be selected
	}{
		{
			name: "fully capable node satisfies every requirement at once",
			cand: Candidate{
				Executor:          newCapExec("node", fullCaps(nil)),
				Harnesses:         []string{"claude", "codex"},
				ContainerRuntimes: []string{"podman"},
				MemoryMB:          8192,
				Labels:            map[string]string{"region": "eu"},
			},
			req: Requirements{
				ExecutorID: "node", Labels: map[string]string{"region": "eu"},
				Harnesses: []string{"claude"}, Platform: "linux", Arch: "amd64",
				MinMemoryMB: 4096, RequireIsolation: true,
				AllowedIsolations:       []Isolation{IsolationContainer, IsolationRemote},
				RequireContainerRuntime: true, RequireNetworkEgress: true,
				RequireResourceLimits: true, RequireStream: true, RequireSignal: true,
			},
		},

		// --- isolation -------------------------------------------------
		{
			name: "isolation required, node shares the host",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.Isolation = IsolationNone }))},
			req:  Requirements{RequireIsolation: true},
			want: ConstraintIsolation,
		},
		{
			name: "isolation kind not in the allowed set",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))}, // container
			req:  Requirements{AllowedIsolations: []Isolation{IsolationRemote, IsolationVM}},
			want: ConstraintIsolation,
		},
		{
			name: "isolation kind in the allowed set",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{AllowedIsolations: []Isolation{IsolationRemote, IsolationContainer}},
		},

		// --- platform / arch -------------------------------------------
		{
			name: "platform mismatch",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{Platform: "darwin"},
			want: ConstraintPlatform,
		},
		{
			name: "platform match is case-insensitive",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{Platform: "LINUX"},
		},
		{
			name: "node that does not report a platform is not rejected for it",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.Platform = "" }))},
			req:  Requirements{Platform: "darwin"},
		},
		{
			name: "arch mismatch",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{Arch: "arm64"},
			want: ConstraintArch,
		},
		{
			name: "node that does not report an arch is not rejected for it",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.Arch = "" }))},
			req:  Requirements{Arch: "arm64"},
		},

		// --- harness ----------------------------------------------------
		{
			name: "harness not among those advertised",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), Harnesses: []string{"codex", "cloop"}},
			req:  Requirements{Harnesses: []string{"claude"}},
			want: ConstraintHarness,
		},
		{
			name: "one of several required harnesses is missing",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), Harnesses: []string{"claude"}},
			req:  Requirements{Harnesses: []string{"claude", "codex"}},
			want: ConstraintHarness,
		},
		{
			name: "harness match is case-insensitive",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), Harnesses: []string{"Claude"}},
			req:  Requirements{Harnesses: []string{"claude"}},
		},

		// --- container runtime ------------------------------------------
		{
			name: "container runtime required, none advertised",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{RequireContainerRuntime: true},
			want: ConstraintContainerRuntime,
		},
		{
			name: "container runtime advertised",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), ContainerRuntimes: []string{"docker"}},
			req:  Requirements{RequireContainerRuntime: true},
		},

		// --- driver capabilities ----------------------------------------
		{
			name: "network egress required, node has none",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.NetworkEgress = false }))},
			req:  Requirements{RequireNetworkEgress: true},
			want: ConstraintNetworkEgress,
		},
		{
			name: "resource limits required, driver ignores them",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.SupportsResourceLimits = false }))},
			req:  Requirements{RequireResourceLimits: true},
			want: ConstraintResourceLimits,
		},
		{
			name: "live output required, driver cannot stream",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.SupportsStream = false }))},
			req:  Requirements{RequireStream: true},
			want: ConstraintStream,
		},
		{
			name: "stop button required, driver cannot signal",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.SupportsSignal = false }))},
			req:  Requirements{RequireSignal: true},
			want: ConstraintSignal,
		},

		// --- memory ------------------------------------------------------
		{
			name: "node reports less memory than required",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), MemoryMB: 512},
			req:  Requirements{MinMemoryMB: 1024},
			want: ConstraintMemory,
		},
		{
			name: "unknown memory is never treated as too small",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), MemoryMB: 0},
			req:  Requirements{MinMemoryMB: 1024},
		},
		{
			name: "memory exactly at the minimum",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), MemoryMB: 1024},
			req:  Requirements{MinMemoryMB: 1024},
		},

		// --- capacity -----------------------------------------------------
		{
			name: "node is at its advertised ceiling",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), InFlight: 4, InFlightKnown: true},
			req:  Requirements{},
			want: ConstraintCapacity,
		},
		{
			name: "node is over its advertised ceiling",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), InFlight: 9, InFlightKnown: true},
			req:  Requirements{},
			want: ConstraintCapacity,
		},
		{
			name: "capacity is not enforced when load is unknown",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), InFlight: 99, InFlightKnown: false},
			req:  Requirements{},
		},
		{
			name: "capacity check can be waived",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), InFlight: 4, InFlightKnown: true},
			req:  Requirements{IgnoreCapacity: true},
		},
		{
			name: "unbounded driver is never at capacity",
			cand: Candidate{Executor: newCapExec("node", fullCaps(func(c *Capabilities) { c.MaxConcurrent = 0 })), InFlight: 99, InFlightKnown: true},
			req:  Requirements{},
		},

		// --- executor pin --------------------------------------------------
		{
			name: "pinned to a different executor",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{ExecutorID: "somewhere-else"},
			want: ConstraintExecutorID,
		},
		{
			name: "pinned to this executor",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil))},
			req:  Requirements{ExecutorID: "node"},
		},
		{
			name: "a pin is not a license to run on a dead node",
			cand: Candidate{Executor: newCapExec("node", fullCaps(nil)), Health: Health{State: NodeUnreachable}},
			req:  Requirements{ExecutorID: "node"},
			want: ConstraintHealth,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Select([]Candidate{tc.cand}, tc.req)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Select = %v, want the candidate chosen", err)
				}
				if got.ID() != tc.cand.ID() {
					t.Fatalf("Select = %q, want %q", got.ID(), tc.cand.ID())
				}
				return
			}
			pe := wantPlacementError(t, err, tc.want)
			if len(pe.Rejections) != 1 {
				t.Fatalf("rejections = %+v, want exactly one", pe.Rejections)
			}
			r := pe.Rejections[0]
			if r.ExecutorID != tc.cand.ID() {
				t.Errorf("rejection names %q, want %q", r.ExecutorID, tc.cand.ID())
			}
			if r.Constraint != tc.want {
				t.Errorf("per-candidate constraint = %q, want %q", r.Constraint, tc.want)
			}
			if strings.TrimSpace(r.Detail) == "" {
				t.Error("rejection carries no detail; the operator-facing message would be empty")
			}
			if pe.Considered != 1 {
				t.Errorf("Considered = %d, want 1", pe.Considered)
			}
		})
	}
}

// TestSelectLabelSelector covers the three outcomes of a selector key.
func TestSelectLabelSelector(t *testing.T) {
	cases := []struct {
		name       string
		labels     map[string]string
		req        map[string]string
		want       Constraint
		wantDetail string
	}{
		{
			name:       "key absent",
			labels:     map[string]string{"tier": "gold"},
			req:        map[string]string{"region": "eu"},
			want:       ConstraintLabels,
			wantDetail: `has no label "region"`,
		},
		{
			name:       "value differs",
			labels:     map[string]string{"region": "us"},
			req:        map[string]string{"region": "eu"},
			want:       ConstraintLabels,
			wantDetail: `has label region="us", want "eu"`,
		},
		{
			name:   "exact match",
			labels: map[string]string{"region": "eu", "tier": "gold"},
			req:    map[string]string{"region": "eu"},
		},
		{
			name:   "every required key must match",
			labels: map[string]string{"region": "eu"},
			req:    map[string]string{"region": "eu", "tier": "gold"},
			want:   ConstraintLabels,
		},
		{
			name:   "empty selector matches anything",
			labels: nil,
			req:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Candidate{Executor: newCapExec("node", fullCaps(nil)), Labels: tc.labels}
			got, err := Select([]Candidate{c}, Requirements{Labels: tc.req})
			if tc.want == "" {
				if err != nil || got.ID() != "node" {
					t.Fatalf("Select = (%q, %v), want node", got.ID(), err)
				}
				return
			}
			pe := wantPlacementError(t, err, tc.want)
			if tc.wantDetail != "" && !strings.Contains(pe.Rejections[0].Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", pe.Rejections[0].Detail, tc.wantDetail)
			}
		})
	}
}

// TestHasHarnessBestEffortDetection pins the deliberate asymmetry: capability
// detection degrades to an empty list, so "we detected nothing" must not mean
// "it has nothing" — otherwise an agent on an unusual filesystem layout becomes
// permanently unschedulable. A node that reports a list is taken at its word.
func TestHasHarnessBestEffortDetection(t *testing.T) {
	undetected := Candidate{Executor: newCapExec("undetected", fullCaps(nil))} // Harnesses nil
	got, err := Select([]Candidate{undetected}, Requirements{Harnesses: []string{"claude", "codex", "anything"}})
	if err != nil {
		t.Fatalf("a node advertising no harnesses was rejected: %v — detection is best-effort", err)
	}
	if got.ID() != "undetected" {
		t.Fatalf("Select = %q, want undetected", got.ID())
	}

	// Explicitly empty (non-nil) is the same signal as nil: nothing detected.
	empty := Candidate{Executor: newCapExec("empty", fullCaps(nil)), Harnesses: []string{}}
	if _, err := Select([]Candidate{empty}, Requirements{Harnesses: []string{"claude"}}); err != nil {
		t.Fatalf("a node advertising an empty harness list was rejected: %v", err)
	}

	// But a node that does report a list is held to it.
	partial := Candidate{Executor: newCapExec("partial", fullCaps(nil)), Harnesses: []string{"codex"}}
	wantPlacementError(t, mustFail(Select([]Candidate{partial}, Requirements{Harnesses: []string{"claude"}})), ConstraintHarness)

	// Direct unit coverage of the helper's truth table.
	for _, tc := range []struct {
		advertised []string
		want       string
		ok         bool
	}{
		{nil, "claude", true},
		{[]string{}, "claude", true},
		{[]string{"claude"}, "claude", true},
		{[]string{"CLAUDE"}, "claude", true},
		{[]string{"codex", "cloop"}, "claude", false},
		{[]string{"codex"}, "", false},
	} {
		if got := hasHarness(tc.advertised, tc.want); got != tc.ok {
			t.Errorf("hasHarness(%v, %q) = %v, want %v", tc.advertised, tc.want, got, tc.ok)
		}
	}
}

// TestSelectRanking checks the documented preference order, each tier proven by
// making the *losing* candidate win on every lower tiebreak (ID included).
func TestSelectRanking(t *testing.T) {
	t.Run("ready beats degraded", func(t *testing.T) {
		degraded := Candidate{
			Executor: newCapExec("a-degraded", fullCaps(func(c *Capabilities) { c.MaxConcurrent = 0 })),
			Health:   Health{State: NodeDegraded},
		}
		ready := Candidate{
			Executor: newCapExec("z-ready", fullCaps(func(c *Capabilities) { c.MaxConcurrent = 0 })),
			Health:   Health{State: NodeReady},
		}
		got, err := Select([]Candidate{degraded, ready}, Requirements{})
		if err != nil || got.ID() != "z-ready" {
			t.Fatalf("Select = (%q, %v), want z-ready — a node whose probes land is the better bet", got.ID(), err)
		}
	})

	t.Run("health outranks free capacity", func(t *testing.T) {
		idleButDegraded := Candidate{
			Executor: newCapExec("a-idle", fullCaps(nil)),
			Health:   Health{State: NodeDegraded}, InFlight: 0, InFlightKnown: true,
		}
		busyButReady := Candidate{
			Executor: newCapExec("z-busy", fullCaps(nil)),
			Health:   Health{State: NodeReady}, InFlight: 3, InFlightKnown: true,
		}
		got, _ := Select([]Candidate{idleButDegraded, busyButReady}, Requirements{})
		if got.ID() != "z-busy" {
			t.Fatalf("Select = %q, want z-busy — health ranks above capacity", got.ID())
		}
	})

	t.Run("more free capacity wins", func(t *testing.T) {
		busy := Candidate{Executor: newCapExec("a-busy", fullCaps(nil)), InFlight: 3, InFlightKnown: true}
		idle := Candidate{Executor: newCapExec("z-idle", fullCaps(nil)), InFlight: 0, InFlightKnown: true}
		got, _ := Select([]Candidate{busy, idle}, Requirements{})
		if got.ID() != "z-idle" {
			t.Fatalf("Select = %q, want z-idle — a fleet should fill evenly", got.ID())
		}
	})

	t.Run("unknown load sorts as plenty, not as saturated", func(t *testing.T) {
		nearlyFull := Candidate{Executor: newCapExec("a-known", fullCaps(nil)), InFlight: 3, InFlightKnown: true}
		unknown := Candidate{Executor: newCapExec("z-unknown", fullCaps(nil))}
		got, _ := Select([]Candidate{nearlyFull, unknown}, Requirements{})
		if got.ID() != "z-unknown" {
			t.Fatalf("Select = %q, want z-unknown — a driver that cannot enumerate must not be starved", got.ID())
		}
	})

	t.Run("isolated beats un-isolated", func(t *testing.T) {
		host := Candidate{Executor: newCapExec("a-host", fullCaps(func(c *Capabilities) {
			c.Isolation = IsolationNone
			c.MaxConcurrent = 0
		}))}
		sandbox := Candidate{Executor: newCapExec("z-sandbox", fullCaps(func(c *Capabilities) {
			c.Isolation = IsolationContainer
			c.MaxConcurrent = 0
		}))}
		got, _ := Select([]Candidate{host, sandbox}, Requirements{})
		if got.ID() != "z-sandbox" {
			t.Fatalf("Select = %q, want z-sandbox — a deployment that permits host execution "+
				"should still prefer a sandbox when one is free", got.ID())
		}
	})

	t.Run("executor ID is the final deterministic tiebreak", func(t *testing.T) {
		mk := func(id string) Candidate {
			return Candidate{Executor: newCapExec(id, fullCaps(func(c *Capabilities) { c.MaxConcurrent = 0 }))}
		}
		in := []Candidate{mk("c"), mk("a"), mk("b")}
		for i := 0; i < 20; i++ {
			got, err := Select(in, Requirements{})
			if err != nil || got.ID() != "a" {
				t.Fatalf("Select = (%q, %v), want a on every call", got.ID(), err)
			}
		}
	})
}

// TestSelectDeniesByDefault: if nothing satisfies the requirements, placement
// errors. It never widens the search and never falls back to the host.
func TestSelectDeniesByDefault(t *testing.T) {
	t.Run("no candidates at all", func(t *testing.T) {
		for _, in := range [][]Candidate{nil, {}} {
			_, err := Select(in, Requirements{})
			pe := wantPlacementError(t, err, ConstraintNoCandidates)
			if pe.Considered != 0 || len(pe.Rejections) != 0 {
				t.Fatalf("PlacementError = %+v, want considered=0 with no rejections", pe)
			}
			if !strings.Contains(err.Error(), "none registered") {
				t.Errorf("Error() = %q, want it to say nothing is registered", err.Error())
			}
		}
	})

	t.Run("every candidate rejected", func(t *testing.T) {
		candidates := []Candidate{
			{ // rejected for health
				Executor: newCapExec("edge-dead", fullCaps(nil)),
				Health:   Health{State: NodeUnreachable},
			},
			{ // rejected for harness
				Executor: newCapExec("edge-1", fullCaps(nil)), Harnesses: []string{"codex"},
			},
			{ // rejected for harness
				Executor: newCapExec("edge-2", fullCaps(nil)), Harnesses: []string{"cloop"},
			},
		}
		_, err := Select(candidates, Requirements{Harnesses: []string{"claude"}})

		// The headline is the constraint that eliminated the most candidates,
		// which is nearly always the one to fix.
		pe := wantPlacementError(t, err, ConstraintHarness)
		if pe.Considered != 3 {
			t.Errorf("Considered = %d, want 3", pe.Considered)
		}
		if len(pe.Rejections) != 3 {
			t.Fatalf("rejections = %+v, want one per candidate", pe.Rejections)
		}
		// Ordered by executor ID so the CLI table and the API body are stable.
		wantOrder := []string{"edge-1", "edge-2", "edge-dead"}
		byID := map[string]Rejection{}
		for i, r := range pe.Rejections {
			if r.ExecutorID != wantOrder[i] {
				t.Errorf("rejection[%d] = %q, want %q (must be ordered by ID)", i, r.ExecutorID, wantOrder[i])
			}
			byID[r.ExecutorID] = r
		}
		if got := byID["edge-dead"].Constraint; got != ConstraintHealth {
			t.Errorf("edge-dead rejected for %q, want %q — per-candidate detail must be specific", got, ConstraintHealth)
		}
		if got := byID["edge-1"].Constraint; got != ConstraintHarness {
			t.Errorf("edge-1 rejected for %q, want %q", got, ConstraintHarness)
		}
		if !strings.Contains(byID["edge-1"].Detail, "claude") {
			t.Errorf("edge-1 detail = %q, want it to name the missing harness", byID["edge-1"].Detail)
		}

		// The rendered message has to carry the same information: an operator
		// reading it should not need to go to the logs.
		msg := err.Error()
		for _, want := range []string{string(ConstraintHarness), "edge-1", "edge-2", "edge-dead", "3 candidate(s)"} {
			if !strings.Contains(msg, want) {
				t.Errorf("Error() = %q, want it to contain %q", msg, want)
			}
		}
	})

	t.Run("malformed candidates are skipped, not selected", func(t *testing.T) {
		got, err := Select([]Candidate{{Executor: nil}, {Executor: newCapExec("real", fullCaps(nil))}}, Requirements{})
		if err != nil || got.ID() != "real" {
			t.Fatalf("Select = (%q, %v), want real", got.ID(), err)
		}
		// A pool of nothing but malformed entries still denies rather than
		// returning a zero Candidate with a nil error.
		_, err = Select([]Candidate{{Executor: nil}}, Requirements{})
		pe := wantPlacementError(t, err, ConstraintNoCandidates)
		if pe.Considered != 1 {
			t.Errorf("Considered = %d, want 1", pe.Considered)
		}
		if (Candidate{}).ID() != "" {
			t.Error("Candidate.ID() on a nil executor should be empty, not panic")
		}
	})
}

// TestSelectHonoursHostExecutionPolicy: the process-wide no-host-execution
// switch is enforced at placement as well as at Resolve. A security control
// with one enforcement point is a security control with a bypass.
func TestSelectHonoursHostExecutionPolicy(t *testing.T) {
	prev := SetAllowHostExecution(false)
	defer SetAllowHostExecution(prev)

	host := Candidate{Executor: newCapExec("host", fullCaps(func(c *Capabilities) { c.Isolation = IsolationNone }))}
	sandbox := Candidate{Executor: newCapExec("sandbox", fullCaps(func(c *Capabilities) { c.Isolation = IsolationContainer }))}

	// With an isolated node available, placement simply avoids the host.
	got, err := Select([]Candidate{host, sandbox}, Requirements{})
	if err != nil || got.ID() != "sandbox" {
		t.Fatalf("Select = (%q, %v), want sandbox", got.ID(), err)
	}

	// With only the host available it must fail rather than fall back —
	// silently running an isolated workload on the host is precisely the
	// failure this subsystem exists to prevent.
	_, err = Select([]Candidate{host}, Requirements{})
	pe := wantPlacementError(t, err, ConstraintHostPolicy)
	if len(pe.Rejections) != 1 || !strings.Contains(pe.Rejections[0].Detail, "policy forbids") {
		t.Fatalf("rejections = %+v, want one naming the host policy", pe.Rejections)
	}

	// Policy is checked ahead of the task's own requirements, so the operator
	// is told about the deployment-wide switch rather than a red herring.
	_, err = Select([]Candidate{host}, Requirements{Harnesses: []string{"claude"}, RequireIsolation: true})
	wantPlacementError(t, err, ConstraintHostPolicy)

	// Restoring the flag restores host placement, which proves the rejection
	// above came from the policy and not from something sticky in the fixture.
	SetAllowHostExecution(true)
	if got, err := Select([]Candidate{host}, Requirements{}); err != nil || got.ID() != "host" {
		t.Fatalf("Select with host execution allowed = (%q, %v), want host", got.ID(), err)
	}
	// ...and RequireIsolation still rejects it, now naming the task's
	// constraint rather than the deployment's.
	wantPlacementError(t, mustFail(Select([]Candidate{host}, Requirements{RequireIsolation: true})), ConstraintIsolation)
}

// TestHeadlineConstraintIsDeterministic guards the tiebreak in the reported
// headline: a flapping error message is a support ticket generator.
func TestHeadlineConstraintIsDeterministic(t *testing.T) {
	rejections := []Rejection{
		{ExecutorID: "a", Constraint: ConstraintHarness},
		{ExecutorID: "b", Constraint: ConstraintHealth},
		{ExecutorID: "c", Constraint: ConstraintHarness},
		{ExecutorID: "d", Constraint: ConstraintMemory},
	}
	for i := 0; i < 50; i++ {
		if got := headlineConstraint(rejections); got != ConstraintHarness {
			t.Fatalf("headlineConstraint = %q, want %q (the most common cause)", got, ConstraintHarness)
		}
	}
	// A tie is broken by constraint name so the message is still stable.
	tied := []Rejection{
		{ExecutorID: "a", Constraint: ConstraintMemory},
		{ExecutorID: "b", Constraint: ConstraintHealth},
	}
	first := headlineConstraint(tied)
	for i := 0; i < 50; i++ {
		if got := headlineConstraint(tied); got != first {
			t.Fatalf("headlineConstraint flapped between %q and %q on a tie", first, got)
		}
	}
	if got := headlineConstraint(nil); got != ConstraintNoCandidates {
		t.Errorf("headlineConstraint(nil) = %q, want %q", got, ConstraintNoCandidates)
	}
}

// TestSelectIsPureUnderConcurrentUse: placement runs on every dispatch, from
// HTTP handlers and from supervisor failover at the same time.
func TestSelectIsPureUnderConcurrentUse(t *testing.T) {
	candidates := []Candidate{
		{Executor: newCapExec("a", fullCaps(nil)), InFlight: 2, InFlightKnown: true},
		{Executor: newCapExec("b", fullCaps(nil)), Health: Health{State: NodeDegraded}},
		{Executor: newCapExec("c", fullCaps(nil)), InFlight: 1, InFlightKnown: true},
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				got, err := Select(candidates, Requirements{})
				if err != nil || got.ID() != "c" {
					t.Errorf("Select = (%q, %v), want c", got.ID(), err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Select must not have reordered the caller's slice underneath it.
	for i, want := range []string{"a", "b", "c"} {
		if candidates[i].ID() != want {
			t.Errorf("candidates[%d] = %q after Select, want %q — the input slice was mutated",
				i, candidates[i].ID(), want)
		}
	}
}
