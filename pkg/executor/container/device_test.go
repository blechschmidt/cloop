package container

// Real-runtime tests for Spec.Devices (Task 20236): the host hardware a
// host_device grant carries into a sandbox.
//
// They run an actual container for the same reason hostmount_test.go does. The
// argv is not the guarantee — the guarantee is that the device node is present
// and usable inside the sandbox at the granted path, and that a read-only grant
// cannot be written to. A test that only inspected the command line would pass
// happily while the cgroup device rule denied every access.
//
// /dev/zero and /dev/null are the devices under test because they are the two
// that exist on every Linux host, need no hardware, and have observable
// behaviour: reading /dev/zero yields NULs, writing to /dev/null succeeds. A
// test that needed /dev/ttyUSB0 would be a test that never ran.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// requireHostDevice skips when the host has no such device node, which is the
// honest outcome in a container-in-container CI sandbox with a minimal /dev.
func requireHostDevice(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("host has no %s (%v), so there is nothing to pass through", path, err)
	}
}

// TestDeviceReachesTheSandbox is the end-to-end proof of the scenario: a device
// node on the executor's host is usable inside an isolated container, at the
// path the grant named.
func TestDeviceReachesTheSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	requireHostDevice(t, "/dev/zero")
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// A granted device at a *remapped* path, which proves two things at once:
	// that the node arrives, and that Target is honoured rather than ignored in
	// favour of Source. A project told it has /dev/granted0 must find it there.
	res, err := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "head -c 4 /dev/granted0 | wc -c"},
		Devices: []executor.HostDevice{{
			Name:        "zero",
			Source:      "/dev/zero",
			Target:      "/dev/granted0",
			Permissions: executor.DeviceRead,
		}},
	})
	if err != nil {
		t.Fatalf("running with a granted device: %v (output %q)", err, res.Output)
	}
	if !strings.Contains(string(res.Output), "4") {
		t.Fatalf("output %q does not show 4 bytes read from the granted device; the "+
			"--device flag did not produce a usable node at /dev/granted0", res.Output)
	}
}

// TestDeviceAbsentWithoutAGrant is the control. Without it, every assertion
// above could be satisfied by an image that happened to ship the node itself,
// and the test would prove nothing about the grant.
func TestDeviceAbsentWithoutAGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, _ := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", "test -e /dev/granted0 && echo PRESENT || echo ABSENT"},
	})
	if !strings.Contains(string(res.Output), "ABSENT") {
		t.Fatalf("output %q: /dev/granted0 exists in a sandbox that was granted no device, "+
			"so the passthrough test above proves nothing", res.Output)
	}
}

// TestDeviceReadOnlyGrantDeliversAReadableNode pins what a read-only grant
// actually guarantees, which is narrower than it first appears and is worth a
// test that says so.
//
// The guarantee is that the node arrives and is readable. Whether the *write* is
// refused depends on the container's device cgroup, and on cgroup v2 that is an
// eBPF program whose attachment depends on the kernel, the runtime build and
// cgroup delegation — none of which cloop can interrogate. On this development
// host neither podman nor docker enforces it: a device granted "w" is still
// readable, which proves the rule is absent rather than merely permissive.
//
// So the test asserts the guarantee and *reports* the rest. Requiring
// WRITE_DENIED would make the suite fail on a correct cloop running on an
// ordinary host, and asserting WRITE_OK would fail on a hardened one. Logging
// which of the two happened is the honest thing a test can do about an
// environmental property, and it is why preflightDeviceMode warns rather than
// claiming the boundary.
func TestDeviceReadOnlyGrantDeliversAReadableNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container; skipped under -short")
	}
	requireHostDevice(t, "/dev/zero")
	ex := newTestExecutor(t, "alpine:3.20", nil)
	requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, _ := executor.Run(ctx, ex, executor.Spec{
		WorkDir: t.TempDir(),
		Argv: []string{"/bin/sh", "-c",
			"head -c 1 /dev/granted0 >/dev/null && echo READ_OK; " +
				"if echo x > /dev/granted0 2>/dev/null; then echo WRITE_OK; else echo WRITE_DENIED; fi"},
		Devices: []executor.HostDevice{{
			Name:        "zero",
			Source:      "/dev/zero",
			Target:      "/dev/granted0",
			Permissions: executor.DeviceRead,
		}},
	})
	out := string(res.Output)
	if !strings.Contains(out, "READ_OK") {
		t.Fatalf("output %q: a read-only device grant did not deliver a readable node", out)
	}
	switch {
	case strings.Contains(out, "WRITE_DENIED"):
		t.Log("this host enforces the device cgroup: the read-only grant is a real boundary")
	case strings.Contains(out, "WRITE_OK"):
		t.Log("this host does not enforce the device cgroup, so the read-only grant is " +
			"advisory here — preflight's devices warning is the one that applies, and the " +
			"enforceable control is the host node's own file mode")
	default:
		t.Errorf("output %q reported neither WRITE_OK nor WRITE_DENIED; the probe did not run", out)
	}
}

// TestDeviceModePreflightWarns is the guard on the honesty above. If someone
// later removes the warning because "read-only grants work on my machine", this
// fails and points at why it is there.
func TestDeviceModePreflightWarns(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	var found *Finding
	ex.preflightDeviceMode(func(name, level, msg, fix string) {
		if name == "devices" {
			found = &Finding{Name: name, Level: level, Message: msg, Fix: fix}
		}
	})
	if found == nil {
		t.Fatal("preflight reports nothing about device access modes, so an operator would " +
			"read \"read-only device grant\" as a boundary cloop cannot promise")
	}
	if found.Level != LevelWarn {
		t.Errorf("devices finding is %q, want %q", found.Level, LevelWarn)
	}
	if found.Fix == "" {
		t.Error("the devices warning names no remedy; the enforceable control is the host " +
			"node's own ownership and mode, and preflight is where that belongs")
	}
}

// --- validation, which does not need a runtime -------------------------------

// TestDeviceRefusesForbiddenSource is the guard that matters most. An operator
// who grants /dev/mem has handed over all of physical memory, and no downstream
// layer can recover from that.
func TestDeviceRefusesForbiddenSource(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	for _, path := range []string{"/dev/mem", "/dev/kmem", "/dev/kcore", "/dev/port"} {
		_, err := ex.buildRequest(executor.Spec{
			WorkDir: t.TempDir(),
			Argv:    []string{"/bin/true"},
			Devices: []executor.HostDevice{{Name: "d", Source: path}},
		}, t.TempDir(), nil)
		if err == nil {
			t.Errorf("accepted a device grant for %s, which waives every isolation "+
				"guarantee the sandbox advertises", path)
		}
	}
}

// TestDeviceRefusesNonDevSource keeps the field from becoming a second,
// unvalidated host-bind-mount path. Files have HostMount, which is attributed to
// a local_repo grant and containment-checked; this one is for hardware.
func TestDeviceRefusesNonDevSource(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	_, err := ex.buildRequest(executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
		Devices: []executor.HostDevice{{Name: "etc", Source: "/etc/shadow"}},
	}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("accepted a device whose source is a regular file; that is a host bind " +
			"mount wearing a device's name and bypasses HostMount's own checks")
	}
	if !strings.Contains(err.Error(), "/dev") {
		t.Errorf("error %q does not explain the /dev requirement", err)
	}
}

// TestDeviceRejectsTraversalSource covers the path shapes that would mean
// something other than what an operator reviewed.
func TestDeviceRejectsTraversalSource(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	for _, src := range []string{
		"/dev/../etc/shadow", // non-canonical
		"dev/zero",           // relative
		"/dev/zero:rw",       // a colon would re-split the runtime's triple
	} {
		_, err := ex.buildRequest(executor.Spec{
			WorkDir: t.TempDir(),
			Argv:    []string{"/bin/true"},
			Devices: []executor.HostDevice{{Name: "d", Source: src}},
		}, t.TempDir(), nil)
		if err == nil {
			t.Errorf("accepted device source %q", src)
		}
	}
}

// TestDeviceRejectsDuplicateTargets keeps two grants that both land on one
// sandbox path from being resolved by argv order, where the workload cannot tell
// which piece of hardware it holds.
func TestDeviceRejectsDuplicateTargets(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)

	_, err := ex.buildRequest(executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/true"},
		Devices: []executor.HostDevice{
			{Name: "a", Source: "/dev/zero", Target: "/dev/shared"},
			{Name: "b", Source: "/dev/null", Target: "/dev/shared"},
		},
	}, t.TempDir(), nil)
	if err == nil {
		t.Fatal("accepted two devices claiming /dev/shared")
	}
}

// TestDeviceStillBlockedViaExtraArgs is the regression guard on the whole
// design. Adding a typed field must not have opened the untyped route: a device
// passed as a raw runtime flag is attributed to no lease, recorded in no Spec,
// and applies to every workload on the executor rather than the project that was
// granted it.
func TestDeviceStillBlockedViaExtraArgs(t *testing.T) {
	if err := ValidateExtraArgs([]string{"--device=/dev/zero"}); err == nil {
		t.Fatal("extra_args accepted --device; the typed Spec.Devices field is the only " +
			"route to host hardware precisely so that it is revocable, recorded and scoped")
	}
}

// TestDeviceArgvCarriesPermissions pins the rendered flag, because the runtime's
// default when the mode is omitted is rwm — so a missing field is a silent
// widening rather than a visible error.
func TestDeviceArgvCarriesPermissions(t *testing.T) {
	cmd, err := buildRunArgs(runRequest{
		Runtime:   Runtime{Name: RuntimePodman, Path: "/usr/bin/podman"},
		Image:     "alpine:3.20",
		Name:      "c",
		Workspace: mount{HostPath: "/tmp/x", TargetPath: ContainerWorkspace},
		Argv:      []string{"/bin/true"},
		AllowRoot: true,
		Devices: []executor.HostDevice{
			{Name: "ro", Source: "/dev/zero", Permissions: executor.DeviceRead},
			// Permissions left empty: the default must be rw, not the
			// runtime's rwm, so mknod is never granted by omission.
			{Name: "dflt", Source: "/dev/null"},
		},
	})
	if err != nil {
		t.Fatalf("buildRunArgs: %v", err)
	}
	joined := strings.Join(cmd.Args, " ")
	for _, want := range []string{"--device /dev/zero:/dev/zero:r", "--device /dev/null:/dev/null:rw"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q does not contain %q", joined, want)
		}
	}
	if strings.Contains(joined, ":rwm") {
		t.Error("argv grants rwm, which allows mknod on the device's major:minor — a " +
			"second handle on the same hardware that nobody asked for")
	}
}

func TestDeviceCapabilityIsAdvertised(t *testing.T) {
	ex := newTestExecutor(t, "alpine:3.20", nil)
	if !ex.Capabilities().SupportsDevices {
		t.Error("the container driver does not advertise SupportsDevices, so placement " +
			"would refuse every project holding a host_device grant")
	}
}
