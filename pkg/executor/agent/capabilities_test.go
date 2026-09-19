package agent

// Tests for the device-side virtualization probe (Task 20312).
//
// The hub cannot answer this question. Whether a payload sent to an edge device
// ends up behind a hypervisor depends on hardware the control plane never sees,
// and before this probe existed the hub inferred it from the runtime name an
// admin had typed — which is a statement of intent, not of ability. On a device
// without nested virtualization the two disagree, and the hub's version was the
// wrong one.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectReportsNoVirtualizationWithoutTheDevice is the case that motivated
// the probe: a cloud instance whose hypervisor does not expose vmx/svm has no
// /dev/kvm at all, so Kata cannot start QEMU and the device must say so.
func TestDetectReportsNoVirtualizationWithoutTheDevice(t *testing.T) {
	caps := Detect(DetectOptions{
		KVMDevice: filepath.Join(t.TempDir(), "definitely-absent"),
		MemoryMB:  -1,
		LookPath:  func(string) (string, error) { return "", os.ErrNotExist },
	})
	if caps.Virtualization {
		t.Error("device with no KVM device reported that it can start a VM")
	}
}

// TestDetectReportsVirtualizationWhenTheDeviceOpens is the positive case. The
// probe must not be a constant false, or every Kata executor loses the
// placements it exists for.
func TestDetectReportsVirtualizationWhenTheDeviceOpens(t *testing.T) {
	// A regular file stands in for /dev/kvm: the probe's question is "can this
	// process open it read-write", and a temp file answers it the same way the
	// character device would.
	path := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	caps := Detect(DetectOptions{
		KVMDevice: path,
		MemoryMB:  -1,
		LookPath:  func(string) (string, error) { return "", os.ErrNotExist },
	})
	if !caps.Virtualization {
		t.Error("device with an openable KVM device reported that it cannot start a VM")
	}
}

// TestDetectReportsNoVirtualizationWhenTheDeviceIsUnopenable is why the probe
// opens rather than stats.
//
// /dev/kvm is mode 0660 root:kvm on most distributions, so a stat succeeds for
// a user who cannot use it — and an agent running as a non-root service user is
// exactly the deployment that would then advertise a hypervisor it cannot
// start. Skipped as root, which can open anything and so cannot observe the
// distinction this test exists for.
func TestDetectReportsNoVirtualizationWhenTheDeviceIsUnopenable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so an unopenable file cannot be staged")
	}
	path := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(path, nil, 0o000); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	caps := Detect(DetectOptions{
		KVMDevice: path,
		MemoryMB:  -1,
		LookPath:  func(string) (string, error) { return "", os.ErrNotExist },
	})
	if caps.Virtualization {
		t.Error("a device file this process cannot open must not be reported as virtualization")
	}
}

// TestDetectProbesTheRealDeviceByDefault keeps the override a test seam rather
// than the mechanism: an agent in the field passes no KVMDevice, and must still
// probe something.
func TestDetectProbesTheRealDeviceByDefault(t *testing.T) {
	caps := Detect(DetectOptions{
		MemoryMB: -1,
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
	})
	_, err := os.OpenFile(KVMDevice, os.O_RDWR, 0)
	if want := err == nil; caps.Virtualization != want {
		t.Errorf("Detect reported Virtualization=%v; opening %s says %v",
			caps.Virtualization, KVMDevice, want)
	}
}
