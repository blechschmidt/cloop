package executor

// Tests for HostMount (Task 20187) — the one mount primitive whose source may
// leave the workspace.
//
// The type exists because a local_repo grant has to hand a driver an absolute
// path on the control-plane host, and SpecMount deliberately cannot express
// that. What these tests pin down is the boundary that makes the wider
// primitive safe to have: that a path cannot be re-parsed into something else
// between validation and the runtime flag, and that a driver which cannot
// honour the field is refused rather than silently ignoring it.

import (
	"errors"
	"strings"
	"testing"
)

func TestHostMountValidateAcceptsAbsoluteCleanPaths(t *testing.T) {
	m := HostMount{Name: "api", Source: "/home/dev/src/api", Target: "/repos/api", ReadOnly: true}
	if err := m.Validate(); err != nil {
		t.Fatalf("rejected a well-formed host mount: %v", err)
	}
}

func TestHostMountValidateRejectsReinterpretablePaths(t *testing.T) {
	cases := map[string]HostMount{
		// The colon is the sharp one: the runtimes' -v flag is
		// colon-separated, so a path carrying one appends mount options — or
		// a third path — to a flag the operator believed they controlled.
		"colon in source":   {Source: "/src:/etc", Target: "/repos/api"},
		"colon in target":   {Source: "/src/api", Target: "/repos/api:ro"},
		"NUL in source":     {Source: "/src/a\x00b", Target: "/repos/api"},
		"newline in target": {Source: "/src/api", Target: "/repos/a\nb"},
		"backslash":         {Source: `/src\api`, Target: "/repos/api"},
		"relative source":   {Source: "src/api", Target: "/repos/api"},
		"relative target":   {Source: "/src/api", Target: "repos/api"},
		"empty source":      {Target: "/repos/api"},
		"empty target":      {Source: "/src/api"},
		"unclean source":    {Source: "/src/../etc", Target: "/repos/api"},
		"unclean target":    {Source: "/src/api", Target: "/repos/./api"},
		"trailing slash":    {Source: "/src/api/", Target: "/repos/api"},
		"target is root":    {Source: "/src/api", Target: "/"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			err := m.Validate()
			if err == nil {
				t.Fatalf("accepted %+v", m)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("error %v does not chain ErrInvalidSpec, so callers cannot classify it", err)
			}
		})
	}
}

func TestValidateHostMountsRejectsDuplicateTargets(t *testing.T) {
	// Two grants both opening a repository called "api" would otherwise
	// shadow each other in an order nobody chose: the runtimes take the last
	// -v, the kubelet refuses the Pod.
	err := ValidateHostMounts([]HostMount{
		{Name: "api", Source: "/a/api", Target: "/repos/api"},
		{Name: "api", Source: "/b/api", Target: "/repos/api"},
	})
	if err == nil {
		t.Fatal("accepted two host mounts claiming the same target")
	}
	if !strings.Contains(err.Error(), "/repos/api") {
		t.Errorf("error %q does not name the contested target", err)
	}
}

func TestValidateHostMountsBoundsListLength(t *testing.T) {
	many := make([]HostMount, 0, MaxHostMounts+1)
	for i := 0; i <= MaxHostMounts; i++ {
		many = append(many, HostMount{
			Source: "/src/r" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Target: "/repos/r" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
		})
	}
	if err := ValidateHostMounts(many); err == nil {
		t.Fatalf("accepted %d host mounts; the cap is %d", len(many), MaxHostMounts)
	}
}

func TestValidateHostMountsAcceptsAWellFormedList(t *testing.T) {
	err := ValidateHostMounts([]HostMount{
		{Name: "api", Source: "/src/api", Target: "/repos/api", ReadOnly: true},
		{Name: "web", Source: "/src/web", Target: "/repos/web", ReadOnly: true},
	})
	if err != nil {
		t.Fatalf("rejected a well-formed list: %v", err)
	}
}

func TestSpecWithHostMountsRequiresAnExecutorThatBinds(t *testing.T) {
	spec := Spec{
		WorkDir:    "/srv/app",
		Argv:       []string{"cloop", "run"},
		HostMounts: []HostMount{{Name: "api", Source: "/src/api", Target: "/repos/api"}},
	}
	if !spec.SandboxRequirements().RequireHostMounts {
		t.Fatal("RequireHostMounts not set — a driver that ignores HostMounts would " +
			"start the harness against an empty /repos and look like it worked")
	}
	// And the converse: a spec with no host mounts must not demand the
	// capability, or every project would suddenly be unplaceable on
	// Kubernetes.
	plain := Spec{WorkDir: "/srv/app", Argv: []string{"cloop", "run"}}
	if plain.SandboxRequirements().RequireHostMounts {
		t.Error("RequireHostMounts set on a spec with no host mounts")
	}
}

// TestHostMountPlacementRefusesDriversThatCannotBind is the property that makes
// "local repositories" and "remote sandbox" an honest either/or. A project
// holding a local_repo grant and bound to a machine that has never seen those
// files must be refused, naming both facts — not placed and left to report an
// empty directory.
func TestHostMountPlacementRefusesDriversThatCannotBind(t *testing.T) {
	binds := Capabilities{
		Isolation: IsolationContainer, SupportsStream: true, SupportsSignal: true,
		SupportsHostMounts: true,
	}
	cannot := Capabilities{
		Isolation: IsolationRemote, SupportsStream: true, SupportsSignal: true,
		SupportsHostMounts: false,
	}
	req := Requirements{RequireHostMounts: true}

	if _, err := Select([]Candidate{{Executor: &capExecutor{id: "container-1", caps: binds}}}, req); err != nil {
		t.Fatalf("refused a driver that advertises SupportsHostMounts: %v", err)
	}

	_, err := Select([]Candidate{{Executor: &capExecutor{id: "edge-1", caps: cannot}}}, req)
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("Select = %v, want a *PlacementError — placing a host-mount spec on a "+
			"driver that cannot bind host paths yields an empty /repos", err)
	}
	if pe.Constraint != ConstraintHostMounts {
		t.Errorf("constraint = %q, want %q", pe.Constraint, ConstraintHostMounts)
	}
	// The message is the whole value of refusing here rather than failing at
	// runtime, so it has to say what to do about it.
	if !strings.Contains(err.Error(), "local_repo") {
		t.Errorf("error %q does not name the grant kind that caused it", err)
	}
}

// TestDriversAdvertiseHostMountsHonestly is a guard against the capability
// drifting away from the truth. It is a compile-time-ish check written as a
// test because the cost of getting it wrong is silent: a driver that claims the
// capability and ignores the field produces a sandbox that starts, runs, and
// cannot find the repositories the developer granted it.
func TestHostMountCapabilityIsNotImpliedBySharedFilesystem(t *testing.T) {
	// localprocess is the case that makes this a separate flag: it shares the
	// hub's filesystem, so the repositories are already reachable, but it has
	// no mount namespace to bind them into. Anything deriving one field from
	// the other would get this backwards in one direction or the other.
	shares := Capabilities{SharesHostFilesystem: true, SupportsHostMounts: false}
	if _, err := Select([]Candidate{{Executor: &capExecutor{id: "host", caps: shares}}},
		Requirements{RequireHostMounts: true}); err == nil {
		t.Error("a driver sharing the host filesystem was treated as able to bind; " +
			"the caller must instead point the environment at the source paths")
	}
}
