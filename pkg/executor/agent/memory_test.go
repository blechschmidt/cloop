package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDetectMemoryWithoutProcMeminfo: the unit the installer renders sets
// ProcSubset=pid, so an installed agent has no /proc/meminfo. It must still
// report the device's memory — before Task 20512 every installed agent
// reported it as unknown, and the hub could not say how small a device was.
func TestDetectMemoryWithoutProcMeminfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("memory is detected on Linux only")
	}
	withMeminfo := detectMemoryMB()
	if withMeminfo <= 0 {
		t.Fatalf("detectMemoryMB() = %d with /proc/meminfo, want the machine's memory", withMeminfo)
	}

	prev := procMeminfo
	procMeminfo = filepath.Join(t.TempDir(), "meminfo") // hidden, as ProcSubset=pid hides it
	t.Cleanup(func() { procMeminfo = prev })

	without := detectMemoryMB()
	if without <= 0 {
		t.Fatalf("detectMemoryMB() = %d without /proc/meminfo, want the machine's memory from sysinfo(2)", without)
	}
	// Both read the kernel's total RAM; MemTotal and sysinfo's totalram are
	// the same page count, so the two must agree to the megabyte.
	if without != withMeminfo {
		t.Errorf("sysinfo says %d MB and /proc/meminfo %d MB", without, withMeminfo)
	}
	caps := Detect(DetectOptions{
		LookPath:  func(string) (string, error) { return "", os.ErrNotExist },
		KVMDevice: filepath.Join(t.TempDir(), "kvm"),
	})
	if caps.MemoryMB != withMeminfo {
		t.Errorf("Detect reported MemoryMB=%d without /proc/meminfo, want %d", caps.MemoryMB, withMeminfo)
	}
}
