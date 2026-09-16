package executor

import (
	"errors"
	"strings"
	"testing"
)

// TestBoundLimitClosesTheUnstatedCase is the property the whole design turns
// on, tested at the layer that actually owns it.
//
// In ResourceLimits a zero means *no limit*, so the cheapest way to defeat a cap
// that only lowers stated numbers is to state none — which is also the state of
// every project that has never heard of sandbox specs. BoundLimit is what the
// drivers call after resolving a request against their own configured default,
// and it is where that hole is closed.
func TestBoundLimitClosesTheUnstatedCase(t *testing.T) {
	tests := []struct {
		name           string
		effective, cap int
		want           int
	}{
		{"nothing bounded it yet, so the ceiling does", 0, 2048, 2048},
		{"a resolved value above the ceiling is lowered", 65536, 2048, 2048},
		{"a resolved value below the ceiling is kept", 512, 2048, 512},
		{"a resolved value at the ceiling is kept", 2048, 2048, 2048},
		{"no ceiling leaves the resolved value alone", 65536, 0, 65536},
		{"no ceiling and nothing resolved stays unbounded", 0, 0, 0},
		// -1 is the runtimes' "unlimited" sentinel, which an operator may set
		// on an executor. A ceiling must still override it.
		{"an explicit unlimited is still capped", -1, 2048, 2048},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := BoundLimit(tc.effective, tc.cap); got != tc.want {
				t.Errorf("BoundLimit(%d, %d) = %d, want %d", tc.effective, tc.cap, got, tc.want)
			}
		})
	}
}

// TestBoundCPUsMatchesBoundLimit covers the fractional-core variant the
// container runtimes take.
func TestBoundCPUs(t *testing.T) {
	tests := []struct {
		effective float64
		capMillis int
		want      float64
	}{
		{0, 2000, 2.0},   // unbounded becomes the ceiling
		{8, 2000, 2.0},   // above is lowered
		{1, 2000, 1.0},   // below is kept
		{8, 0, 8.0},      // no ceiling
		{0.5, 2000, 0.5}, // a fraction below the cap survives as itself
		{2.5, 2000, 2.0}, // and above it is lowered
	}
	for _, tc := range tests {
		if got := BoundCPUs(tc.effective, tc.capMillis); got != tc.want {
			t.Errorf("BoundCPUs(%v, %d) = %v, want %v", tc.effective, tc.capMillis, got, tc.want)
		}
	}
}

// TestCeilingNeverRaisesAnUnstatedRequestOnTheSpec is the bug this design was
// corrected for, and it is worth stating as its own test because the obvious
// implementation has it.
//
// Writing the ceiling into a limit the project left unset looks like closing the
// hole above. It is not: the drivers treat a *stated* request as more specific
// than their own configured default, so a spec carrying a ceiling-derived 8 GB
// would beat a `memory: 4g` executor default — and the ceiling would have raised
// the allowance of a project that asked for nothing. The spec-level clamp
// therefore only lowers what was actually stated.
func TestCeilingNeverRaisesAnUnstatedRequestOnTheSpec(t *testing.T) {
	ceiling := ResourceCeiling{CPUMillis: 2000, MemoryMB: 8192, DiskMB: 10240, PIDs: 512}

	got, clamps := ceiling.applyStated(ResourceLimits{}, CeilingSourceFleet)

	if !got.IsZero() {
		t.Fatalf("an unstated request was materialised onto the spec as %+v; the driver must "+
			"resolve it against its own default first", got)
	}
	if len(clamps) != 0 {
		t.Errorf("want nothing reported for a request that was never made, got %+v", clamps)
	}
}

func TestCeilingApply(t *testing.T) {
	tests := []struct {
		name       string
		ceiling    ResourceCeiling
		request    ResourceLimits
		want       ResourceLimits
		wantClamps int
	}{
		{
			name:    "a zero ceiling changes nothing",
			ceiling: ResourceCeiling{},
			request: ResourceLimits{MemoryMB: 999999},
			want:    ResourceLimits{MemoryMB: 999999},
		},
		{
			name:    "a request below the ceiling passes through untouched",
			ceiling: ResourceCeiling{MemoryMB: 2048},
			request: ResourceLimits{MemoryMB: 512},
			want:    ResourceLimits{MemoryMB: 512},
		},
		{
			name:       "a request above the ceiling is lowered to it",
			ceiling:    ResourceCeiling{MemoryMB: 2048},
			request:    ResourceLimits{MemoryMB: 921600}, // the 900g a repo could name
			want:       ResourceLimits{MemoryMB: 2048},
			wantClamps: 1,
		},
		{
			name:    "a request exactly at the ceiling is not a clamp",
			ceiling: ResourceCeiling{MemoryMB: 2048},
			request: ResourceLimits{MemoryMB: 2048},
			want:    ResourceLimits{MemoryMB: 2048},
		},
		{
			name:       "a ceiling constrains only the resources it names",
			ceiling:    ResourceCeiling{MemoryMB: 2048},
			request:    ResourceLimits{MemoryMB: 4096, CPUMillis: 8000},
			want:       ResourceLimits{MemoryMB: 2048, CPUMillis: 8000},
			wantClamps: 1,
		},
		{
			// The two resources under the ceiling keep the smaller value they
			// asked for: a ceiling is a bound, so it never raises a stated
			// request up to itself.
			name:       "every resource is bounded independently",
			ceiling:    ResourceCeiling{CPUMillis: 1000, MemoryMB: 1024, DiskMB: 2048, PIDs: 256},
			request:    ResourceLimits{CPUMillis: 4000, MemoryMB: 512, DiskMB: 8192, PIDs: 128},
			want:       ResourceLimits{CPUMillis: 1000, MemoryMB: 512, DiskMB: 2048, PIDs: 128},
			wantClamps: 2,
		},
		{
			// Stated once as its own case, because it is the invariant that
			// separates a ceiling from a default and the one a future edit is
			// most likely to break.
			name:    "a ceiling never raises a stated request",
			ceiling: ResourceCeiling{CPUMillis: 8000, MemoryMB: 65536, DiskMB: 65536, PIDs: 4096},
			request: ResourceLimits{CPUMillis: 500, MemoryMB: 256, DiskMB: 512, PIDs: 32},
			want:    ResourceLimits{CPUMillis: 500, MemoryMB: 256, DiskMB: 512, PIDs: 32},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, clamps := tc.ceiling.applyStated(tc.request, CeilingSourceFleet)
			if got != tc.want {
				t.Errorf("effective limits:\n got %+v\nwant %+v", got, tc.want)
			}
			if len(clamps) != tc.wantClamps {
				t.Errorf("want %d clamps, got %d: %+v", tc.wantClamps, len(clamps), clamps)
			}
		})
	}
}

// TestCeilingsComposeToTheMinimum checks the property the two-ceiling design
// rests on: applying them in sequence is the same as taking the minimum, and
// the tighter one wins regardless of which was applied first.
func TestCeilingsComposeToTheMinimum(t *testing.T) {
	fleet := ResourceCeiling{MemoryMB: 8192, CPUMillis: 8000}
	project := ResourceCeiling{MemoryMB: 1024}
	request := ResourceLimits{MemoryMB: 65536, CPUMillis: 16000}

	// Fleet first, then project — the order the dispatch path uses.
	step, first := fleet.applyStated(request, CeilingSourceFleet)
	forward, second := project.applyStated(step, CeilingSourceProject)

	// And the reverse, to show the effective value does not depend on order.
	step2, _ := project.applyStated(request, CeilingSourceProject)
	reverse, _ := fleet.applyStated(step2, CeilingSourceFleet)

	want := ResourceLimits{MemoryMB: 1024, CPUMillis: 8000}
	if forward != want {
		t.Errorf("fleet-then-project:\n got %+v\nwant %+v", forward, want)
	}
	if reverse != want {
		t.Errorf("project-then-fleet:\n got %+v\nwant %+v", reverse, want)
	}

	// The clamp on CPU could only have come from the fleet ceiling, and the
	// final clamp on memory from the project's — attribution is what makes the
	// result explainable to whoever has to ask for more.
	if len(first) != 2 {
		t.Fatalf("want the fleet ceiling to clamp both resources, got %+v", first)
	}
	if len(second) != 1 || second[0].Resource != "memory" || second[0].Source != CeilingSourceProject {
		t.Fatalf("want a single project-sourced memory clamp, got %+v", second)
	}
	if second[0].Requested != 8192 {
		t.Errorf("want the project clamp to report the post-fleet value 8192, got %d", second[0].Requested)
	}
}

// TestProjectCeilingCannotRaiseTheFleetCeiling is the containment property: a
// per-project cap is a second bound, never a waiver. An operator who widens one
// project must not thereby hand it more than the hub allows anyone.
func TestProjectCeilingCannotRaiseTheFleetCeiling(t *testing.T) {
	fleet := ResourceCeiling{MemoryMB: 2048}
	project := ResourceCeiling{MemoryMB: 65536} // far above the fleet's

	step, _ := fleet.applyStated(ResourceLimits{MemoryMB: 65536}, CeilingSourceFleet)
	got, _ := project.applyStated(step, CeilingSourceProject)

	if got.MemoryMB != 2048 {
		t.Fatalf("a project ceiling raised the effective limit past the fleet's: got %d MB, want 2048", got.MemoryMB)
	}
}

func TestCeilingTighten(t *testing.T) {
	tests := []struct {
		name string
		a, b ResourceCeiling
		want ResourceCeiling
	}{
		{
			name: "zero is silence, not a bound of nothing",
			a:    ResourceCeiling{MemoryMB: 2048},
			b:    ResourceCeiling{CPUMillis: 4000},
			want: ResourceCeiling{MemoryMB: 2048, CPUMillis: 4000},
		},
		{
			name: "the smaller cap wins",
			a:    ResourceCeiling{MemoryMB: 2048},
			b:    ResourceCeiling{MemoryMB: 1024},
			want: ResourceCeiling{MemoryMB: 1024},
		},
		{
			name: "and wins from either side",
			a:    ResourceCeiling{MemoryMB: 1024},
			b:    ResourceCeiling{MemoryMB: 2048},
			want: ResourceCeiling{MemoryMB: 1024},
		},
		{
			name: "tightening against nothing keeps the ceiling",
			a:    ResourceCeiling{MemoryMB: 1024, PIDs: 64},
			b:    ResourceCeiling{},
			want: ResourceCeiling{MemoryMB: 1024, PIDs: 64},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Tighten(tc.b); got != tc.want {
				t.Errorf("Tighten:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestCeilingTightenIsARatchet states the ApplyMinAgentBuild property in this
// type's terms: a hub reads many projects' config.yaml, and no one of them may
// loosen a cap already in force for everyone else.
func TestCeilingTightenIsARatchet(t *testing.T) {
	inForce := ResourceCeiling{MemoryMB: 2048}
	tenant := ResourceCeiling{MemoryMB: 1 << 20} // a tenant file asking for 1 TiB

	if got := inForce.Tighten(tenant); got.MemoryMB != 2048 {
		t.Fatalf("a tenant config loosened a fleet-wide ceiling: got %d MB, want 2048", got.MemoryMB)
	}
}

// TestBoundSpecAppliesBothCeilings covers the function every dispatch site
// calls, including the per-project lookup hook that lets pkg/executor consult a
// SQLite table it cannot import.
func TestBoundSpecAppliesBothCeilings(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 8192, CPUMillis: 4000})
	SetProjectCeilingLookup(func(path string) (ResourceCeiling, bool) {
		if path == "/srv/noisy" {
			return ResourceCeiling{MemoryMB: 1024}, true
		}
		return ResourceCeiling{}, false
	})

	// The capped project gets the tighter of the two, per resource.
	spec := Spec{ResourceLimits: ResourceLimits{MemoryMB: 65536, CPUMillis: 32000}}
	clamps := BoundSpec(&spec, "/srv/noisy")
	if spec.ResourceLimits.MemoryMB != 1024 {
		t.Errorf("memory: got %d MB, want the project's 1024", spec.ResourceLimits.MemoryMB)
	}
	if spec.ResourceLimits.CPUMillis != 4000 {
		t.Errorf("cpu: got %d, want the fleet's 4000 (the project named none)", spec.ResourceLimits.CPUMillis)
	}
	if len(clamps) != 3 {
		t.Errorf("want fleet memory+cpu and project memory recorded, got %+v", clamps)
	}

	// Another project sees the fleet ceiling only.
	other := Spec{ResourceLimits: ResourceLimits{MemoryMB: 65536}}
	BoundSpec(&other, "/srv/quiet")
	if other.ResourceLimits.MemoryMB != 8192 {
		t.Errorf("memory: got %d MB, want the fleet's 8192", other.ResourceLimits.MemoryMB)
	}
}

// TestBoundSpecLeavesAnUnstatedRequestToTheDriver states the division of labour
// between this function and the drivers.
//
// A Spec that names no limits is left alone here — materialising the ceiling
// onto it would turn "stated nothing" into "requested the ceiling" and beat a
// tighter executor default. The bound is still applied, one layer down, and
// CeilingFor is the channel: the driver reads it after resolving the request
// against its own configuration.
func TestBoundSpecLeavesAnUnstatedRequestToTheDriver(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 2048})

	spec := Spec{WorkDir: "/srv/proj", Argv: []string{"cloop", "run"}}
	clamps := BoundSpec(&spec, spec.WorkDir)

	if spec.ResourceLimits.MemoryMB != 0 {
		t.Fatalf("the spec was given an explicit %d MB request it never made",
			spec.ResourceLimits.MemoryMB)
	}
	if len(clamps) != 0 {
		t.Errorf("want nothing reported for a request that was never made, got %+v", clamps)
	}

	// The ceiling is nonetheless reachable to whoever runs the workload, and
	// bounds a driver that resolved no limit of its own.
	if got := CeilingFor(spec.WorkDir); got.MemoryMB != 2048 {
		t.Fatalf("CeilingFor lost the ceiling: got %+v", got)
	}
	if got := BoundLimit(0, CeilingFor(spec.WorkDir).MemoryMB); got != 2048 {
		t.Fatalf("an unbounded driver default was left at %d MB, want 2048", got)
	}
}

// TestCeilingForTightensBothSources covers the accessor the drivers use.
func TestCeilingForTightensBothSources(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 8192, CPUMillis: 4000})
	SetProjectCeilingLookup(func(string) (ResourceCeiling, bool) {
		return ResourceCeiling{MemoryMB: 1024}, true
	})

	got := CeilingFor("/srv/proj")
	if got.MemoryMB != 1024 {
		t.Errorf("memory: got %d, want the project's tighter 1024", got.MemoryMB)
	}
	if got.CPUMillis != 4000 {
		t.Errorf("cpu: got %d, want the fleet's 4000 preserved", got.CPUMillis)
	}
}

// TestBoundSpecWithoutALookupUsesFleetOnly covers the CLI and every test
// process: no lookup installed means no per-project ceiling, not a panic and not
// a guess.
func TestBoundSpecWithoutALookupUsesFleetOnly(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 2048})

	spec := Spec{ResourceLimits: ResourceLimits{MemoryMB: 65536}}
	if clamps := BoundSpec(&spec, "/srv/proj"); len(clamps) != 1 {
		t.Fatalf("want exactly the fleet clamp, got %+v", clamps)
	}
	if spec.ResourceLimits.MemoryMB != 2048 {
		t.Errorf("got %d MB, want 2048", spec.ResourceLimits.MemoryMB)
	}
	if _, ok := ProjectResourceCeiling("/srv/proj"); ok {
		t.Error("want no project ceiling when no lookup is installed")
	}
}

// TestBoundSpecIsSafeOnNil keeps a defensive call from panicking a dispatch.
func TestBoundSpecIsSafeOnNil(t *testing.T) {
	if clamps := BoundSpec(nil, "/srv/proj"); clamps != nil {
		t.Errorf("want no clamps for a nil spec, got %+v", clamps)
	}
}

// TestApplyResourceCeilingRatchets pins the process-wide switch's one-way
// behaviour — the property that stops one tenant's config.yaml relaxing a cap
// for everybody else in the process.
func TestApplyResourceCeilingRatchets(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 2048})
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 1 << 20}) // a tenant asking for 1 TiB
	if got := FleetResourceCeiling().MemoryMB; got != 2048 {
		t.Fatalf("a later config loosened the ceiling to %d MB; it must only tighten", got)
	}

	// Tightening is allowed, and a second resource is added rather than
	// replacing the first.
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 512, PIDs: 64})
	got := FleetResourceCeiling()
	if got.MemoryMB != 512 || got.PIDs != 64 {
		t.Fatalf("want memory tightened to 512 and pids added at 64, got %+v", got)
	}

	// An invalid ceiling is ignored rather than installed: "I cannot understand
	// this rule" must not become "refuse every workload on the fleet".
	ApplyResourceCeiling(ResourceCeiling{MemoryMB: -1})
	if FleetResourceCeiling().MemoryMB != 512 {
		t.Error("an invalid ceiling changed the switch")
	}
}

func TestCeilingValidate(t *testing.T) {
	if err := (ResourceCeiling{}).Validate(); err != nil {
		t.Errorf("the zero ceiling must be valid, got %v", err)
	}
	if err := (ResourceCeiling{MemoryMB: 2048}).Validate(); err != nil {
		t.Errorf("a positive ceiling must be valid, got %v", err)
	}
	for _, c := range []ResourceCeiling{
		{CPUMillis: -1}, {MemoryMB: -1}, {DiskMB: -1}, {PIDs: -1},
	} {
		err := c.Validate()
		if err == nil {
			t.Errorf("%+v: want a negative cap rejected", c)
			continue
		}
		if !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%+v: want ErrInvalidSpec, got %v", c, err)
		}
	}
}

// TestClampStringDistinguishesUnstated guards the wording. Reporting an
// unstated request as "requested 0" misdescribes what the project asked for —
// it asked for nothing, which meant everything.
func TestClampStringDistinguishesUnstated(t *testing.T) {
	unstated := Clamp{Resource: "memory", Requested: 0, Effective: 2048, Source: CeilingSourceFleet}
	if got := unstated.String(); !strings.Contains(got, "unbounded") {
		t.Errorf("want an unstated clamp described as unbounded, got %q", got)
	}
	if got := unstated.String(); strings.Contains(got, "0 MB") {
		t.Errorf("want the misleading %q avoided, got %q", "0 MB", got)
	}

	stated := Clamp{Resource: "memory", Requested: 65536, Effective: 2048, Source: CeilingSourceProject}
	got := stated.String()
	if !strings.Contains(got, "65536") || !strings.Contains(got, "2048") {
		t.Errorf("want both the request and the effective value named, got %q", got)
	}
	if !strings.Contains(got, CeilingSourceProject) {
		t.Errorf("want the binding ceiling named so the reader knows who to ask, got %q", got)
	}
}

// TestClampWarningsDeduplicate covers the case both ceilings clamp the same
// resource to the same number: that is one fact, not two.
func TestClampWarningsDeduplicate(t *testing.T) {
	clamps := []Clamp{
		{Resource: "memory", Requested: 0, Effective: 2048, Source: CeilingSourceFleet},
		{Resource: "memory", Requested: 0, Effective: 2048, Source: CeilingSourceFleet},
		{Resource: "cpu", Requested: 4000, Effective: 2000, Source: CeilingSourceProject},
	}
	got := ClampWarnings(clamps)
	if len(got) != 2 {
		t.Fatalf("want 2 deduplicated warnings, got %d: %q", len(got), got)
	}
	if ClampWarnings(nil) != nil {
		t.Error("want no warnings for no clamps")
	}
}

func TestFormatHelpers(t *testing.T) {
	tests := []struct{ got, want string }{
		{FormatMB(0), "unlimited"},
		{FormatMB(512), "512 MB"},
		{FormatMB(2048), "2 GB"},
		{FormatCPUMillis(0), "unlimited"},
		{FormatCPUMillis(2000), "2"},
		{FormatCPUMillis(1500), "1.50"},
		{ResourceCeiling{}.Describe(), "unlimited"},
		{ResourceCeiling{MemoryMB: 2048, PIDs: 64}.Describe(), "memory 2 GB, pids 64"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}
