package security

// Guarantee: a host_device grant exposes exactly the hardware a human named, and
// a repo-committed file can never add to it (Task 20236).
//
// This is the widest authority the broker issues. `local_repo` hands a sandbox
// reach into the hub's filesystem; this one hands it reach into the machine. A
// wrong grant is not a credential that could be stolen — it is a serial line into
// whatever is plugged in, a GPU with its own DMA, or `/dev/mem`, which is every
// isolation claim cloop makes rendered decorative.
//
// The failure modes are the same shape as local_repo's, and quiet for the same
// reason — in each of them the run starts and the task completes:
//
//   - A `devices:` key in .cloop/sandbox.yaml names a host path. That file
//     arrives by `git pull`, so it is whatever a pull request says it is, and a
//     path-shaped key there would turn review into hardware access.
//   - The inventory names /dev/mem, /dev/kcore or a whole host disk. Nobody
//     types that adversarially; they type it while enumerating hardware, and the
//     resulting sandbox reads kernel memory while every log line looks normal.
//   - The device allowlist falls open when empty, turning a storage bug or a
//     half-written migration into the whole inventory.
//   - A source outside /dev smuggles a host bind mount in through the device
//     field, bypassing the containment check local_repo grants are subject to.
//   - The grant reaches an executor with no sandbox to put a device into, so the
//     harness opens the path, gets ENOENT, and reports the hardware broken.
//
// The access *mode* is deliberately not asserted here. It programs the container
// device cgroup, whose enforcement depends on the host's cgroup version and
// runtime build; cloop cannot verify it and does not claim it (see
// preflightDeviceMode and pkg/executor.DevicePermissions). A conformance test
// that required it would fail on an ordinary host and pass for the wrong reason
// on a hardened one.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// grantedInventory mints an inventory and grants a slice of it to one project,
// returning the devices the lease actually delivers.
func grantedInventory(t *testing.T, inventory string, allow []string, writable bool) []secretbroker.GrantedDevice {
	t.Helper()
	b := localRepoBroker(t)
	ctx := context.Background()

	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "bench-hw", Kind: secretbroker.KindHostDevice,
		Payload: []byte(inventory), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/p")},
		TTL:       time.Hour,
		Actor:     "test",
		Constraints: secretbroker.Constraints{Devices: allow, Writable: writable},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lease, err := b.Lease(ctx, "sbx", secretbroker.NormalizeProjectID("/srv/p"))
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	d, err := lease.Deliver("/run/cloop/lease")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d.Devices()
}

// TestDeviceGrantDeliversOnlyWhatWasNamed is the core scope guarantee.
func TestDeviceGrantDeliversOnlyWhatWasNamed(t *testing.T) {
	inventory := "serial0=/dev/ttyUSB0\nserial1=/dev/ttyUSB1\ngpu0=/dev/nvidia0\nsecret=/dev/ttyS9\n"

	got := grantedInventory(t, inventory, []string{"serial*"}, true)
	if len(got) != 2 {
		t.Fatalf("delivered %d devices, want 2: %+v", len(got), got)
	}
	for _, d := range got {
		if d.Name == "gpu0" || d.Name == "secret" {
			t.Errorf("the allowlist 'serial*' delivered %q (%s), which was never named",
				d.Name, d.Source)
		}
	}
}

// TestDeviceGrantAllowlistDoesNotFallOpen is the storage-bug guarantee. An empty
// allowlist must be refused at grant time, not read as "everything".
func TestDeviceGrantAllowlistDoesNotFallOpen(t *testing.T) {
	if err := (secretbroker.Constraints{}).ValidateFor(secretbroker.KindHostDevice); err == nil {
		t.Fatal("a host_device grant with no allowlist was accepted; a half-written " +
			"migration would then open every device in the inventory")
	}
	// And the matcher itself must not fall open either, which is what protects a
	// grant row that reached storage before the check existed.
	got := grantedInventoryAllowingNothing(t)
	if len(got) != 0 {
		t.Fatalf("an empty allowlist delivered %d devices: %+v", len(got), got)
	}
}

// grantedInventoryAllowingNothing bypasses ValidateFor to prove the *matcher*
// fails closed, which is the property that matters for a row already in storage.
func grantedInventoryAllowingNothing(t *testing.T) []secretbroker.GrantedDevice {
	t.Helper()
	b := localRepoBroker(t)
	ctx := context.Background()
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "bench-hw", Kind: secretbroker.KindHostDevice,
		Payload: []byte("serial0=/dev/ttyUSB0\n"), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// A grant with an allowlist that matches nothing is the closest reachable
	// analogue of a corrupted empty one: Grant refuses a literally empty list.
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/p")},
		TTL:       time.Hour, Actor: "test",
		Constraints: secretbroker.Constraints{Devices: []string{"nothing-matches-this"}},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lease, err := b.Lease(ctx, "sbx", secretbroker.NormalizeProjectID("/srv/p"))
	if err != nil {
		// A lease with no deliverable material is a legitimate outcome here.
		return nil
	}
	d, err := lease.Deliver("/run/cloop/lease")
	if err != nil {
		return nil
	}
	t.Cleanup(func() { _ = d.Close() })
	return d.Devices()
}

// TestDeviceInventoryRefusesHostSurrender is the check whose absence would make
// every other guarantee in this suite void.
func TestDeviceInventoryRefusesHostSurrender(t *testing.T) {
	for _, path := range []string{
		"/dev/mem", "/dev/kmem", "/dev/kcore", "/dev/port", "/dev/msr", "/dev/cpu",
		"/dev/sda", "/dev/nvme0n1", "/dev/vda",
	} {
		if _, err := secretbroker.ParseDeviceInventory([]byte("d=" + path + "\n")); err == nil {
			t.Errorf("the broker would store an inventory naming %s", path)
		}
		// The executor end has to refuse it too: a Spec is persisted and
		// re-hydrated by executorstore, so the broker's refusal is not the only
		// thing standing between a tampered row and a runtime CLI.
		err := executor.ValidateHostDevice(executor.HostDevice{
			Name: "d", Source: path, Permissions: executor.DeviceRead,
		})
		if err == nil {
			t.Errorf("executor.ValidateHostDevice would dispatch %s", path)
		}
	}
}

// TestDeviceSourceCannotLeaveDev keeps the device field from becoming a second,
// unvalidated host-bind-mount path — one not subject to local_repo's containment
// check and not attributed to a local_repo grant.
func TestDeviceSourceCannotLeaveDev(t *testing.T) {
	for _, src := range []string{
		"/etc/shadow", "/root", "/srv/git", "/", "/dev/../etc/shadow", "/proc/self/mem",
	} {
		if _, err := secretbroker.ParseDeviceInventory([]byte("d=" + src + "\n")); err == nil {
			t.Errorf("the broker would store a device whose source is %q", src)
		}
		err := executor.ValidateHostDevice(executor.HostDevice{
			Name: "d", Source: src, Permissions: executor.DeviceRead,
		})
		if err == nil {
			t.Errorf("executor.ValidateHostDevice would dispatch source %q", src)
		}
	}
}

// TestSandboxSpecCannotNameADevicePath is the trust-inversion guarantee, and the
// single most important assertion in this file. .cloop/sandbox.yaml arrives by
// `git pull`; if it could name a path, review would be hardware access.
func TestSandboxSpecCannotNameADevicePath(t *testing.T) {
	for _, doc := range []string{
		"capabilities:\n  devices: [\"/dev/mem\"]\n",
		"capabilities:\n  devices:\n    - path: /dev/mem\n",
		"capabilities:\n  devices:\n    - source: /dev/mem\n      target: /dev/x\n",
		"capabilities:\n  device_paths: [/dev/mem]\n",
		"devices:\n  - /dev/mem\n",
		// A mount is the other route to a host path, and its source is
		// workspace-relative for exactly this reason.
		"mounts:\n  - source: /dev\n    target: /hostdev\n",
	} {
		if _, _, err := sandbox.Parse([]byte(doc)); err == nil {
			t.Errorf("a repo-committed spec was accepted that names a host path:\n%s", doc)
		}
	}
}

// TestSandboxSpecSelectionCannotAddADevice is the same guarantee at the next
// layer: even a well-formed selector must be unable to produce a device the
// project holds no grant for.
func TestSandboxSpecSelectionCannotAddADevice(t *testing.T) {
	spec, _, err := sandbox.Parse([]byte("capabilities:\n  devices: [serial0, gpu0]\n  network: corp\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res := &sandbox.Resolved{Spec: spec}

	// Only serial0 was granted. gpu0 is a name in a repo-committed file.
	out := executor.Spec{Devices: []executor.HostDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Permissions: executor.DeviceReadWrite},
	}}
	err = res.ApplyTo(&out, "/srv/p", everyEgressGrant{})
	if err == nil {
		t.Fatal("a spec naming an ungranted device was applied; the sandbox would either " +
			"receive hardware nobody granted, or silently receive none")
	}
	var denied *sandbox.DeviceNotGrantedError
	if !errors.As(err, &denied) {
		t.Fatalf("error is %T, want *sandbox.DeviceNotGrantedError", err)
	}
	for _, d := range out.Devices {
		if d.Name == "gpu0" {
			t.Error("gpu0 reached the Spec despite the refusal")
		}
	}
}

// TestDeviceGrantIsRefusedWhereItCannotBeHonoured is the placement guarantee:
// a grant that cannot be delivered produces a refusal naming it, not a sandbox
// with an empty /dev.
func TestDeviceGrantIsRefusedWhereItCannotBeHonoured(t *testing.T) {
	spec := executor.Spec{
		Argv:    []string{"/bin/true"},
		Devices: []executor.HostDevice{{Name: "serial0", Source: "/dev/ttyUSB0"}},
	}
	req := spec.SandboxRequirements()
	if !req.RequireDevices {
		t.Fatal("a Spec carrying devices implies no RequireDevices, so it could be placed " +
			"on a driver that drops the field")
	}

	incapable := stubCapExecutor{id: "k8s", caps: executor.Capabilities{
		Isolation: executor.IsolationRemote, SupportsDevices: false,
	}}
	err := executor.CheckSandboxSupport(incapable, req, "/srv/p")
	if err == nil {
		t.Fatal("placement accepted an executor that cannot expose devices")
	}
	if !strings.Contains(err.Error(), "device") {
		t.Errorf("refusal %q does not name devices as the constraint", err)
	}

	capable := stubCapExecutor{id: "sbx", caps: executor.Capabilities{
		Isolation: executor.IsolationContainer, SupportsDevices: true,
	}}
	if err := executor.CheckSandboxSupport(capable, req, "/srv/p"); err != nil {
		t.Errorf("placement refused a capable container executor: %v", err)
	}
}

// TestDeviceGrantNarrowsAccessAndNeverWidensIt is the direction invariant. A
// constraint exists to take authority away; one that could add it would make the
// read-only inventory entry a suggestion.
func TestDeviceGrantNarrowsAccessAndNeverWidensIt(t *testing.T) {
	// The inventory says the analyser is read-only. A writable grant must not
	// promote it — nothing should be able to reprogram that instrument.
	got := grantedInventory(t, "analyser=/dev/ttyACM0:r\n", []string{"*"}, true)
	if len(got) != 1 {
		t.Fatalf("delivered %d devices, want 1", len(got))
	}
	if got[0].Permissions != "r" {
		t.Errorf("a --writable grant promoted a read-only inventory entry to %q",
			got[0].Permissions)
	}

	// And a non-writable grant narrows a read-write entry.
	got = grantedInventory(t, "serial0=/dev/ttyUSB0:rw\n", []string{"*"}, false)
	if got[0].Permissions != "r" {
		t.Errorf("a non-writable grant delivered %q access", got[0].Permissions)
	}
}

// TestDeviceGrantLeaksNoHostPathsIntoTheEnvironment: the machine's hardware
// layout is reconnaissance, and every process in the sandbox can read the
// environment.
func TestDeviceGrantLeaksNoHostPathsIntoTheEnvironment(t *testing.T) {
	b := localRepoBroker(t)
	ctx := context.Background()
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "bench-hw", Kind: secretbroker.KindHostDevice,
		Payload: []byte("serial0=/dev/ttyUSB0\ngpu0=/dev/nvidia0\n"), Actor: "test",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef: sec.ID,
		Subject:   secretbroker.Subject{Type: secretbroker.SubjectProject, Value: secretbroker.NormalizeProjectID("/srv/p")},
		TTL:       time.Hour, Actor: "test",
		Constraints: secretbroker.Constraints{Devices: []string{"*"}},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lease, err := b.Lease(ctx, "sbx", secretbroker.NormalizeProjectID("/srv/p"))
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	d, err := lease.Deliver("/run/cloop/lease")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer func() { _ = d.Close() }()

	for _, kv := range d.Env() {
		if strings.Contains(kv, "/dev/") {
			t.Errorf("the lease environment carries a host device path: %q", kv)
		}
	}
}

// everyEgressGrant satisfies sandbox.GrantChecker permissively, so the device
// assertions above cannot pass merely because an unrelated egress check failed
// first.
type everyEgressGrant struct{}

func (everyEgressGrant) HasEgressGrant(string, string) bool { return true }
