package ui

// Tests for applyDeviceGrants (Task 20236): the seam where a broker grant becomes
// a Spec field.
//
// This package is where secretbroker.GrantedDevice and executor.HostDevice meet,
// so it is also the only place that can check the two duplicated definitions
// still agree. They are duplicated on purpose — pkg/secretbroker does not import
// pkg/executor, so that the broker stays a statement about authority and the
// executor package a statement about execution — and duplication that nothing
// checks is duplication that drifts.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// deviceCapsExecutor is a stub whose only job is to answer Capabilities(), which
// is the one thing applyDeviceGrants branches on.
type deviceCapsExecutor struct {
	executor.Executor
	id   string
	kind string
	caps executor.Capabilities
}

func (e *deviceCapsExecutor) ID() string                          { return e.id }
func (e *deviceCapsExecutor) Kind() string                        { return e.kind }
func (e *deviceCapsExecutor) Capabilities() executor.Capabilities { return e.caps }

func sandboxExecutor() *deviceCapsExecutor {
	return &deviceCapsExecutor{
		id: "sbx", kind: executor.KindContainer,
		caps: executor.Capabilities{
			Isolation:       executor.IsolationContainer,
			SupportsDevices: true,
		},
	}
}

// TestApplyDeviceGrantsCarriesTheGrantOntoTheSpec is the happy path, and it
// checks the fields individually because a conversion that dropped Permissions
// would silently widen every grant to the driver's default.
func TestApplyDeviceGrantsCarriesTheGrantOntoTheSpec(t *testing.T) {
	granted := []secretbroker.GrantedDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rw"},
		{Name: "meter", Source: "/dev/ttyUSB1", Target: "/dev/meter0", Permissions: "r"},
	}
	spec, err := applyDeviceGrantsFor(executor.Spec{Env: []string{}}, sandboxExecutor(), granted)
	if err != nil {
		t.Fatalf("applyDeviceGrants: %v", err)
	}
	if len(spec.Devices) != 2 {
		t.Fatalf("Devices = %+v, want 2", spec.Devices)
	}
	want := []executor.HostDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: executor.DeviceReadWrite},
		{Name: "meter", Source: "/dev/ttyUSB1", Target: "/dev/meter0", Permissions: executor.DeviceRead},
	}
	for i := range want {
		if spec.Devices[i] != want[i] {
			t.Errorf("device %d = %+v, want %+v", i, spec.Devices[i], want[i])
		}
	}
	var names string
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "CLOOP_HOST_DEVICES=") {
			names = strings.TrimPrefix(kv, "CLOOP_HOST_DEVICES=")
		}
	}
	if names != "serial0,meter" {
		t.Errorf("CLOOP_HOST_DEVICES = %q, want %q", names, "serial0,meter")
	}
	for _, kv := range spec.Env {
		if strings.Contains(kv, "/dev/") {
			t.Errorf("the environment leaks a host device path: %q", kv)
		}
	}
}

// TestApplyDeviceGrantsRefusesAnIncapableExecutor is the refusal that turns a
// silently-missing device node into a message naming both the grant and the
// binding.
func TestApplyDeviceGrantsRefusesAnIncapableExecutor(t *testing.T) {
	ex := &deviceCapsExecutor{
		id: "k8s", kind: executor.KindKubernetes,
		caps: executor.Capabilities{Isolation: executor.IsolationRemote},
	}
	granted := []secretbroker.GrantedDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rw"},
	}
	_, err := applyDeviceGrantsFor(executor.Spec{}, ex, granted)
	if err == nil {
		t.Fatal("accepted a device grant on an executor that cannot expose devices; the " +
			"harness would open the path, get ENOENT, and report the hardware broken")
	}
	for _, want := range []string{"serial0", "k8s"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestApplyDeviceGrantsWarnsOnTheHostExecutor: the host driver has no sandbox to
// put a device into, so the grant is satisfied in the weakest possible sense.
// That must not be an error (the access genuinely is there) and must not be
// silent (the dashboard would show a scoped grant on a workload holding all of
// /dev).
func TestApplyDeviceGrantsWarnsOnTheHostExecutor(t *testing.T) {
	ex := &deviceCapsExecutor{
		id: "host", kind: executor.KindLocalProcess,
		caps: executor.Capabilities{
			Isolation:            executor.IsolationNone,
			SharesHostFilesystem: true,
		},
	}
	granted := []secretbroker.GrantedDevice{
		{Name: "serial0", Source: "/dev/ttyUSB0", Target: "/dev/ttyUSB0", Permissions: "rw"},
	}
	spec, err := applyDeviceGrantsFor(executor.Spec{}, ex, granted)
	if err != nil {
		t.Fatalf("the host executor refused a device grant: %v", err)
	}
	if len(spec.Devices) != 0 {
		t.Errorf("Devices = %+v on a driver that cannot honour them; the field would be "+
			"rejected by Spec validation downstream", spec.Devices)
	}
}

// TestApplyDeviceGrantsRejectsCollidingGrants: two grants can legitimately name
// different hardware that lands on one sandbox path, and which one won would
// otherwise be decided by argv order.
func TestApplyDeviceGrantsRejectsCollidingGrants(t *testing.T) {
	granted := []secretbroker.GrantedDevice{
		{Name: "a", Source: "/dev/ttyUSB0", Target: "/dev/shared", Permissions: "rw"},
		{Name: "b", Source: "/dev/ttyUSB1", Target: "/dev/shared", Permissions: "rw"},
	}
	if _, err := applyDeviceGrantsFor(executor.Spec{}, sandboxExecutor(), granted); err == nil {
		t.Fatal("accepted two grants claiming /dev/shared")
	}
}

// TestDevicePermissionVocabulariesAgree is the divergence guard the duplicated
// types need. secretbroker writes these strings; executor.DevicePermissions has
// to accept exactly them and nothing more.
func TestDevicePermissionVocabulariesAgree(t *testing.T) {
	// Every mode the broker can emit must be one the executor accepts. The
	// broker's constants are unexported, so these are the literals its parser
	// produces — which is the contract being pinned.
	for _, mode := range []string{"r", "rw", "rwm"} {
		inv := []byte("d=/dev/ttyUSB0:" + mode + "\n")
		got, err := secretbroker.ParseDeviceInventory(inv)
		if err != nil {
			t.Fatalf("the broker rejected mode %q, which executor.DevicePermissions "+
				"defines: %v", mode, err)
		}
		if !executor.DevicePermissions(got[0].Permissions).Valid() {
			t.Errorf("the broker emits mode %q but executor.DevicePermissions rejects it; "+
				"a grant would be minted and then refused at dispatch", got[0].Permissions)
		}
	}
	// And the reverse, so the executor does not quietly accept something the
	// broker cannot express.
	for _, p := range []executor.DevicePermissions{
		executor.DeviceRead, executor.DeviceReadWrite, executor.DeviceReadWriteMknod,
	} {
		if _, err := secretbroker.ParseDeviceInventory([]byte("d=/dev/ttyUSB0:" + string(p) + "\n")); err != nil {
			t.Errorf("executor defines mode %q but the broker cannot parse it: %v", p, err)
		}
	}
}

// TestForbiddenDevicesAgreeAtBothEnds pins the other duplicated list. Both copies
// exist for a reason — the broker's catches the mistake in the operator's dialog,
// the executor's holds against a tampered Spec — and a path refused by only one
// of them is a hole in whichever end is missing it.
func TestForbiddenDevicesAgreeAtBothEnds(t *testing.T) {
	surrender := []string{
		"/dev/mem", "/dev/kmem", "/dev/port", "/dev/kcore", "/dev/msr", "/dev/cpu",
		"/dev/sda", "/dev/nvme0n1", "/dev/vda",
	}
	for _, path := range surrender {
		if _, err := secretbroker.ParseDeviceInventory([]byte("d=" + path + "\n")); err == nil {
			t.Errorf("the broker accepts an inventory entry for %s", path)
		}
		err := executor.ValidateHostDevice(executor.HostDevice{
			Name: "d", Source: path, Permissions: executor.DeviceRead,
		})
		if err == nil {
			t.Errorf("executor.ValidateHostDevice accepts %s, so a Spec carrying it would "+
				"reach a runtime even though the broker would never mint it", path)
		}
	}
}

// applyDeviceGrantsFor is applyDeviceGrants with the lease's device list injected
// directly.
//
// A real *secretLease wraps either a broker Mount or a Delivery, and building
// either needs a sealed store, a keyring and a materialised tmpfs directory —
// none of which these tests are about. The indirection is deliberately thin: it
// calls the same function under test with the same arguments, and only replaces
// the accessor whose value is being varied.
func applyDeviceGrantsFor(spec executor.Spec, ex executor.Executor, granted []secretbroker.GrantedDevice) (executor.Spec, error) {
	return applyDeviceGrantsList(spec, ex, granted)
}
