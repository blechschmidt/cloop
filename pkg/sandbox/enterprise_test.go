package sandbox

// Tests for the three capability keys added by Task 20236: kernel_isolated,
// egress and devices.
//
// The theme they share is the package's one invariant — a repo-committed file
// may narrow what the operator granted and may never widen it — so most of these
// are about what the schema *refuses*.

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func parseOrFatal(t *testing.T, yaml string) *Spec {
	t.Helper()
	spec, _, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse(%q): %v", yaml, err)
	}
	return spec
}

// TestKernelIsolatedBecomesAPlacementRequirement is the gVisor case: a project
// asking that its syscalls stay off the host kernel must be refused an executor
// that cannot provide it, and must *not* be forced to demand a hypervisor.
func TestKernelIsolatedBecomesAPlacementRequirement(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  kernel_isolated: true\n")
	res := &Resolved{Spec: spec}
	req := res.Requirements()

	if !req.RequireKernelIsolation {
		t.Fatal("kernel_isolated: true implies no RequireKernelIsolation, so the project " +
			"could be placed on a runc executor and told it succeeded")
	}
	if req.RequireVirtualization {
		t.Error("kernel_isolated also demanded virtualization, which would refuse every " +
			"gVisor executor in the fleet — the ones that satisfy the request exactly")
	}
}

// TestVirtualizedStillImpliesItsOwnRequirement guards against the new, weaker
// key being wired in place of the stronger one.
func TestVirtualizedStillImpliesItsOwnRequirement(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  virtualized: true\n")
	req := (&Resolved{Spec: spec}).Requirements()
	if !req.RequireVirtualization {
		t.Error("virtualized: true no longer requires a hypervisor")
	}
}

// TestEgressScopeIsAppliedAndNarrows covers the field reaching the Spec, which
// is the only way a driver ever sees it.
func TestEgressScopeIsAppliedAndNarrows(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  egress: public\n  network: corp-proxy\n")
	res := &Resolved{Spec: spec}

	var out executor.Spec
	if err := res.ApplyTo(&out, "/srv/p", allowAllGrants{}); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if out.EgressScope != executor.EgressScopePublic {
		t.Fatalf("EgressScope = %q, want %q", out.EgressScope, executor.EgressScopePublic)
	}
	req := res.Requirements()
	if !req.RequireEgressScope || !req.RequireNetworkEgress {
		t.Error("a filtering scope does not imply both RequireEgressScope and " +
			"RequireNetworkEgress, so it could be placed somewhere that ignores it")
	}
}

// TestEgressScopeSurvivesAMissingNetworkGrant is the ordering bug this is here to
// prevent. ApplyTo returns early when no network grant is named, and a scope
// written after that return would be a confinement the author asked for and
// silently did not get.
func TestEgressScopeSurvivesAMissingNetworkGrant(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  egress: public\n")
	res := &Resolved{Spec: spec}

	var out executor.Spec
	if err := res.ApplyTo(&out, "/srv/p", allowAllGrants{}); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if out.EgressScope != executor.EgressScopePublic {
		t.Errorf("EgressScope = %q; the scope was dropped by the no-grant early return",
			out.EgressScope)
	}
	if !out.DisableNetwork {
		t.Error("no network grant was named but DisableNetwork is false")
	}
}

// TestEgressRefusesAnUnknownScope keeps the enum closed. A typo must not parse as
// "no opinion", which would leave the project on the executor's default policy
// while its author believed it was confined.
func TestEgressRefusesAnUnknownScope(t *testing.T) {
	for _, val := range []string{"internet", "all", "private", "true", "10.0.0.0/8"} {
		if _, _, err := Parse([]byte("capabilities:\n  egress: " + val + "\n")); err == nil {
			t.Errorf("accepted capabilities.egress: %q", val)
		}
	}
}

// TestEgressHasNoCIDRKey is the widening test. If a future edit adds an address
// list to this schema, this fails — the whole point is that a pull request
// cannot name the operator's network.
func TestEgressHasNoCIDRKey(t *testing.T) {
	for _, key := range []string{"allow_cidrs", "allow_ports", "allow_public_internet"} {
		_, _, err := Parse([]byte("capabilities:\n  " + key + ": [\"10.0.0.0/8\"]\n"))
		if err == nil {
			t.Errorf("the schema accepts capabilities.%s; a repo-committed file must not "+
				"be able to name address space, only to renounce it", key)
		}
	}
}

// TestEgressNoneConflictsWithANetworkGrant catches a file that says two opposite
// things. Both keys are one-directional so the outcome is well defined, but the
// author plainly did not mean it.
func TestEgressNoneConflictsWithANetworkGrant(t *testing.T) {
	_, _, err := Parse([]byte("capabilities:\n  egress: none\n  network: corp-proxy\n"))
	if err == nil {
		t.Fatal("accepted egress: none alongside a network grant")
	}
	if !strings.Contains(err.Error(), "drop one") {
		t.Errorf("error %q does not tell the author what to do", err)
	}
}

// TestDevicesSelectFromGrantsAndCannotAdd is the device invariant: the list
// narrows what a host_device grant already delivered.
func TestDevicesSelectFromGrantsAndCannotAdd(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  devices: [serial0]\n  network: corp\n")
	res := &Resolved{Spec: spec}

	granted := executor.Spec{Devices: []executor.HostDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Permissions: executor.DeviceReadWrite},
		{Name: "gpu0", Source: "/dev/nvidia0", Permissions: executor.DeviceReadWrite},
	}}
	if err := res.ApplyTo(&granted, "/srv/p", allowAllGrants{}); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if len(granted.Devices) != 1 || granted.Devices[0].Name != "serial0" {
		t.Fatalf("Devices = %+v, want only serial0 — the selector did not narrow the grant",
			granted.Devices)
	}
}

// TestDevicesRefuseAnUngrantedName is the asymmetry with `env`, and it is
// deliberate: a missing variable degrades a run, a missing device node makes the
// task meaningless.
func TestDevicesRefuseAnUngrantedName(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  devices: [serial0, gpu0]\n  network: corp\n")
	res := &Resolved{Spec: spec}

	granted := executor.Spec{Devices: []executor.HostDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0"},
	}}
	err := res.ApplyTo(&granted, "/srv/p", allowAllGrants{})
	if err == nil {
		t.Fatal("accepted a spec naming gpu0, which the project holds no grant for; the " +
			"task would start without the hardware it exists to drive")
	}
	var denied *DeviceNotGrantedError
	if !errors.As(err, &denied) {
		t.Fatalf("error is %T, want *DeviceNotGrantedError so callers can map it to a 409", err)
	}
	if len(denied.Names) != 1 || denied.Names[0] != "gpu0" {
		t.Errorf("Names = %v, want [gpu0]", denied.Names)
	}
	if !strings.Contains(denied.Remediation(), "secret grant") {
		t.Errorf("remediation %q does not name the command that fixes it", denied.Remediation())
	}
}

// TestDevicesEmptySelectorKeepsEveryGrant: saying nothing is not the same as
// selecting nothing, exactly as with `env`.
func TestDevicesEmptySelectorKeepsEveryGrant(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  network: corp\n")
	res := &Resolved{Spec: spec}

	granted := executor.Spec{Devices: []executor.HostDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0"},
		{Name: "gpu0", Source: "/dev/nvidia0"},
	}}
	if err := res.ApplyTo(&granted, "/srv/p", allowAllGrants{}); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if len(granted.Devices) != 2 {
		t.Errorf("a spec with no devices key dropped grants: %+v", granted.Devices)
	}
}

// TestDevicesHasNoPathKey is the device equivalent of TestEgressHasNoCIDRKey, and
// the single most important refusal in this file. A `path:` here would let a pull
// request hand itself the hardware.
func TestDevicesHasNoPathKey(t *testing.T) {
	for _, doc := range []string{
		"capabilities:\n  devices:\n    - path: /dev/mem\n",
		"capabilities:\n  device_paths: [/dev/mem]\n",
		"capabilities:\n  devices: [\"/dev/mem\"]\n",
	} {
		if _, _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("the schema accepted %q; a repo-committed file must select granted "+
				"devices by name and must never name a host path", doc)
		}
	}
}

// TestDevicesBecomeAPlacementRequirement is the device counterpart of
// TestKernelIsolatedBecomesAPlacementRequirement, and it closes the last gap
// between this schema and placement.
//
// Selecting a device is a demand on the executor: only a driver advertising
// SupportsDevices can honour one. Every other capability key that needs
// something of the node says so here, and leaving this one out made
// Requirements() disagree with its own doc comment — "every entry is a
// capability the executor must genuinely have".
//
// The dispatch path does refuse these runs today, at applyDeviceGrants and at
// DeviceNotGrantedError, so this is not the difference between confined and
// unconfined. It is the difference between a refusal that names the constraint
// at placement and one that arrives later from a different layer, which is the
// distinction CheckSandboxSupport exists to draw.
func TestDevicesBecomeAPlacementRequirement(t *testing.T) {
	spec := parseOrFatal(t, "capabilities:\n  devices: [serial0]\n")
	req := (&Resolved{Spec: spec}).Requirements()

	if !req.RequireDevices {
		t.Fatal("capabilities.devices names a device but implies no RequireDevices, so " +
			"CheckSandboxSupport would pass an executor that cannot expose one")
	}
}

// TestNoDeviceSelectorImpliesNoDeviceRequirement is the other half, and the
// reason the rule is keyed on the selector rather than on "might have devices".
//
// An empty selector means "every device this project was granted", which may
// well be none. Requiring the capability for it would refuse ordinary projects
// on ordinary executors for hardware they never asked for. The grant path
// carries that case instead: Spec.SandboxRequirements sets RequireDevices from
// the devices actually attached.
func TestNoDeviceSelectorImpliesNoDeviceRequirement(t *testing.T) {
	spec := parseOrFatal(t, "image: alpine:3.20\n")
	if (&Resolved{Spec: spec}).Requirements().RequireDevices {
		t.Error("a spec naming no devices demands SupportsDevices, which would refuse " +
			"every executor that cannot expose hardware to projects not asking for any")
	}
}

// TestCapabilityKeysAreHashed keeps the audit trail honest. SandboxHash is what
// ties a running container back to the spec that shaped it, so two runs with
// materially different boundaries must not share an identity.
func TestCapabilityKeysAreHashed(t *testing.T) {
	base := parseOrFatal(t, "image: alpine:3.20\n")
	variants := map[string]string{
		"kernel_isolated": "image: alpine:3.20\ncapabilities:\n  kernel_isolated: true\n",
		"virtualized":     "image: alpine:3.20\ncapabilities:\n  virtualized: true\n",
		"egress":          "image: alpine:3.20\ncapabilities:\n  egress: none\n",
		"devices":         "image: alpine:3.20\ncapabilities:\n  devices: [serial0]\n",
	}
	baseHash := base.Hash()
	for name, doc := range variants {
		if got := parseOrFatal(t, doc).Hash(); got == baseHash {
			t.Errorf("capabilities.%s does not change the sandbox hash, so the audit trail "+
				"cannot tell a confined run from an unconfined one", name)
		}
	}
}

// TestNewCapabilityKeysAreNotZero keeps IsZero in step with the struct. A spec
// that only sets one of these is not an empty spec, and treating it as one would
// skip applying it entirely.
func TestNewCapabilityKeysAreNotZero(t *testing.T) {
	for name, doc := range map[string]string{
		"kernel_isolated": "capabilities:\n  kernel_isolated: true\n",
		"egress":          "capabilities:\n  egress: none\n",
		"devices":         "capabilities:\n  devices: [serial0]\n",
	} {
		if parseOrFatal(t, doc).IsZero() {
			t.Errorf("a spec setting only capabilities.%s reports IsZero, so it would never "+
				"be applied", name)
		}
	}
}

// allowAllGrants satisfies GrantChecker for the tests that are not about egress
// grants. It is permissive on purpose: the narrowing asserted above must hold
// whatever the grant store says.
type allowAllGrants struct{}

func (allowAllGrants) HasEgressGrant(string, string) bool { return true }
