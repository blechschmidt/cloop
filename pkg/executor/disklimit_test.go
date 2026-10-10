package executor

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDiskLimitBreachDescribesBothSizes(t *testing.T) {
	b := DiskLimitBreach{UsedBytes: 64<<20 + 1, LimitMB: 64, Source: DiskLimitFromSpec}
	if !b.Over() {
		t.Fatal("one byte over is over")
	}
	// Rounded up: one byte over a 64 MB limit must not read "64 MB, over its
	// disk limit of 64 MB".
	if got := b.Describe(); got != "the workspace grew to 65 MB, over its disk limit of 64 MB "+
		"(from .cloop/sandbox.yaml resources.disk)" {
		t.Fatalf("Describe() = %q", got)
	}
	// Never rounded to gigabytes: 20 MB over a 20 GB limit must not read as
	// "20.0 GB, over its disk limit of 20 GB".
	big := DiskLimitBreach{UsedBytes: 20<<30 + 20<<20, LimitMB: 20480, Source: DiskLimitFromCeiling}
	if got := big.Describe(); !strings.Contains(got, "20500 MB, over its disk limit of 20 GB (an operator's disk ceiling)") {
		t.Fatalf("Describe() = %q", got)
	}
	if got := (DiskLimitBreach{UsedBytes: 1<<62 + 1, LimitMB: 64}).UsedMB(); got <= 0 {
		t.Fatalf("UsedMB() of a huge measurement = %d, overflowed", got)
	}
	if !strings.Contains(big.Remedy(), "ask an admin to raise the disk ceiling") ||
		strings.Contains(big.Remedy(), "sandbox.yaml") {
		t.Fatalf("a ceiling's remedy = %q, want the admin, not the project's file", big.Remedy())
	}
	if (DiskLimitBreach{UsedBytes: 64 << 20, LimitMB: 64}).Over() {
		t.Fatal("exactly at the limit is not over it")
	}
}

func TestDiskLimitErrorIsMatchableAndNamesTheRemedy(t *testing.T) {
	err := fmt.Errorf("start: %w", &DiskLimitError{Executor: "container", Breach: DiskLimitBreach{
		UsedBytes: 70 << 20, LimitMB: 64, Source: DiskLimitFromSpec, Path: "/srv/proj"}})
	if !errors.Is(err, ErrDiskLimit) {
		t.Fatal("errors.Is(err, ErrDiskLimit) is false")
	}
	var de *DiskLimitError
	if !errors.As(err, &de) || de.Breach.LimitMB != 64 {
		t.Fatal("errors.As does not find the DiskLimitError")
	}
	for _, want := range []string{"executor container", "/srv/proj", "already holds 70 MB",
		"disk limit of 64 MB", "raise resources.disk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not name %q", err, want)
		}
	}
}

func TestSanitizeDiskOutcomeBoundsADevicesAccount(t *testing.T) {
	if o, b := SanitizeDiskOutcome("", nil); o != "" || b != nil {
		t.Fatal("an empty outcome grew one")
	}
	if o, b := SanitizeDiskOutcome("evicted", &DiskLimitBreach{UsedBytes: 2 << 20, LimitMB: 1}); o != "" || b != nil {
		t.Fatal("an outcome the hub does not know was kept")
	}
	// A stop "at the limit" with the tree under it is not one.
	if o, _ := SanitizeDiskOutcome(OutcomeDiskLimit, &DiskLimitBreach{UsedBytes: 1 << 20, LimitMB: 64}); o != "" {
		t.Fatal("a breach under its limit was believed")
	}
	long := "/w/\u202edlrow\u0085" + strings.Repeat("é", 4096) + "\x1b[31m\n"
	o, b := SanitizeDiskOutcome(OutcomeDiskLimit, &DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64,
		Source: "made-up", Path: long})
	if o != OutcomeDiskLimit || b == nil {
		t.Fatal("a genuine breach was dropped")
	}
	if len(b.Path) > maxBreachPath || strings.ContainsAny(b.Path, "\x1b\n\u202e\u0085") || b.Source != "" ||
		!utf8.ValidString(b.Path) {
		t.Fatalf("sanitized breach = path %d bytes %q source %q", len(b.Path), b.Path[:16], b.Source)
	}
	// Numbers no hub ever sends, or that would overflow what is done with
	// them, are not believed.
	for _, bad := range []DiskLimitBreach{
		{UsedBytes: 70 << 20, LimitMB: 1 << 44},
		{UsedBytes: 70 << 20, LimitMB: -1},
	} {
		if o, _ := SanitizeDiskOutcome(OutcomeDiskLimit, &bad); o != "" {
			t.Errorf("breach %+v was believed", bad)
		}
	}
	if _, b := SanitizeDiskOutcome(OutcomeDiskLimit, &DiskLimitBreach{UsedBytes: math.MaxInt64, LimitMB: 64}); b == nil ||
		b.UsedMB() <= 0 {
		t.Fatalf("a huge measurement = %+v", b)
	}
}

func TestDiskLimitSourceOf(t *testing.T) {
	spec := Spec{ResourceLimits: ResourceLimits{DiskMB: 1024}}
	if got := DiskLimitSourceOf(spec, 1024, ResourceCeiling{}); got != DiskLimitFromSpec {
		t.Fatalf("a stated request with no ceiling = %q", got)
	}
	if got := DiskLimitSourceOf(spec, 512, ResourceCeiling{DiskMB: 512}); got != DiskLimitFromCeiling {
		t.Fatalf("a request the ceiling lowered = %q", got)
	}
	if got := DiskLimitSourceOf(Spec{}, 0, ResourceCeiling{DiskMB: 512}); got != "" {
		t.Fatalf("no limit at all = %q", got)
	}
	labels := map[string]string{"task_id": "7"}
	marked := Spec{Labels: labels, ResourceLimits: ResourceLimits{DiskMB: 2048}}
	MarkDiskLimitFromCeiling(&marked)
	if got := DiskLimitSourceOf(marked, 2048, ResourceCeiling{}); got != DiskLimitFromCeiling {
		t.Fatalf("a spec the hub marked = %q", got)
	}
	if _, wrote := labels[LabelDiskLimitSource]; wrote || marked.Labels["task_id"] != "7" {
		t.Fatal("marking wrote through the caller's label map, or dropped its labels")
	}
}

func TestBoundSpecMarksADiskRequestItLowered(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)
	ApplyResourceCeiling(ResourceCeiling{DiskMB: 2048})

	spec := Spec{ResourceLimits: ResourceLimits{DiskMB: 921600}}
	clamps := BoundSpec(&spec, "/srv/proj", "")
	if spec.ResourceLimits.DiskMB != 2048 || spec.Labels[LabelDiskLimitSource] != DiskLimitFromCeiling {
		t.Fatalf("spec = %+v labels %v", spec.ResourceLimits, spec.Labels)
	}
	if len(clamps) != 1 || clamps[0].Resource != "disk" {
		t.Fatalf("clamps = %+v", clamps)
	}

	within := Spec{ResourceLimits: ResourceLimits{DiskMB: 1024}}
	BoundSpec(&within, "/srv/proj", "")
	if within.Labels[LabelDiskLimitSource] != "" {
		t.Fatal("a request within the ceiling was labelled the ceiling's")
	}
}

// capsExec is an executor that advertises exactly caps.
type capsExec struct {
	Executor
	caps Capabilities
}

func (c capsExec) ID() string                 { return "x" }
func (c capsExec) Kind() string               { return "x" }
func (c capsExec) Capabilities() Capabilities { return c.caps }

func TestCeilingUnenforceableNamesADiskCeilingOnADriverThatHoldsNone(t *testing.T) {
	disk := ResourceCeiling{DiskMB: 20480}
	host := capsExec{caps: Capabilities{}}
	if !CeilingUnenforceable(host, disk, nil) {
		t.Fatal("a disk ceiling on the host-process driver is not reported, though nothing holds it")
	}
	if CeilingUnenforceable(host, ResourceCeiling{MemoryMB: 1024}, nil) {
		t.Fatal("a memory ceiling with no clamp is reported: that one waits for a clamp")
	}
	if !CeilingUnenforceable(host, ResourceCeiling{MemoryMB: 1024}, []Clamp{{Resource: "memory"}}) {
		t.Fatal("a clamp on a driver that enforces nothing is not reported")
	}
	// Limits enforced, disk not: an agent older than protocol v20.
	older := capsExec{caps: Capabilities{SupportsResourceLimits: true}}
	if !CeilingUnenforceable(older, disk, nil) {
		t.Fatal("a disk ceiling on a driver that holds the other limits but not disk is not reported")
	}
	for _, mode := range []DiskEnforcement{DiskEnforcementSampled, DiskEnforcementEviction} {
		held := capsExec{caps: Capabilities{SupportsResourceLimits: true, DiskEnforcement: mode}}
		if CeilingUnenforceable(held, disk, nil) {
			t.Fatalf("a disk ceiling on a %s driver is reported as unenforced", mode)
		}
	}
	if CeilingUnenforceable(nil, disk, nil) {
		t.Fatal("no executor reported an unenforced ceiling")
	}
}

func TestPlacementRequiresDiskEnforcementForADiskLimitedSpec(t *testing.T) {
	spec := Spec{ResourceLimits: ResourceLimits{DiskMB: 1024}}
	req := spec.SandboxRequirements()
	if !req.RequireDiskLimit || !req.RequireResourceLimits {
		t.Fatalf("requirements = %+v, want a disk limit required", req)
	}
	if (Spec{ResourceLimits: ResourceLimits{MemoryMB: 1024}}).SandboxRequirements().RequireDiskLimit {
		t.Fatal("a memory-only spec requires disk enforcement")
	}

	limitsOnly := capsExec{caps: Capabilities{SupportsResourceLimits: true, SupportsStream: true, SupportsSignal: true,
		Isolation: IsolationContainer}}
	err := CheckSandboxSupport(limitsOnly, req, "/srv/proj")
	var perr *PlacementError
	if !errors.As(err, &perr) || perr.Constraint != ConstraintDiskLimit {
		t.Fatalf("CheckSandboxSupport = %v, want a disk_limit refusal", err)
	}
	sampled := limitsOnly
	sampled.caps.DiskEnforcement = DiskEnforcementSampled
	if err := CheckSandboxSupport(sampled, req, "/srv/proj"); err != nil {
		t.Fatalf("a sampling executor was refused: %v", err)
	}
}

func TestDiskEnforcementDescribe(t *testing.T) {
	for mode, want := range map[DiskEnforcement]string{
		DiskEnforcementNone:     "not supported",
		DiskEnforcementSampled:  "enforced (sampled)",
		DiskEnforcementEviction: "enforced (eviction)",
	} {
		if got := mode.Describe(); got != want {
			t.Errorf("%q.Describe() = %q, want %q", mode, got, want)
		}
	}
}
