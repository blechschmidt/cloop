package executor

import "testing"

// TestIsVirtualizedRuntime pins the matcher that decides whether cloop tells
// an operator a workload runs behind a hypervisor.
//
// The false cases matter more than the true ones. Each name below that must
// report false is a name someone could plausibly expect to qualify — a
// stronger-than-runc sandbox (runsc), a substring match (kataloger), a
// hypervisor that is not Kata (crun-vm) — and a matcher that said yes to any
// of them would place a workload requiring virtualization onto something that
// does not provide it. See virtualization.go on why the error is asymmetric.
func TestIsVirtualizedRuntime(t *testing.T) {
	cases := []struct {
		name string
		want bool
		why  string
	}{
		// The names Kata is actually registered under.
		{"kata", true, "the canonical RuntimeClass and containers.conf name"},
		{"kata-runtime", true, "the binary name"},
		{"kata-qemu", true, "the default hypervisor variant"},
		{"kata-clh", true, "cloud-hypervisor variant"},
		{"kata-fc", true, "firecracker variant"},
		{"katacontainers", true, "the project's own name, seen in some charts"},
		{"io.containerd.kata.v2", true, "the containerd shim spelling"},
		{"kata.v2", true, "shim spelling without the domain prefix"},

		// Case and whitespace: a YAML value carries whatever the operator
		// typed, and a capitalised name is still the same runtime.
		{"Kata", true, "case-insensitive"},
		{"KATA-QEMU", true, "case-insensitive"},
		{"  kata  ", true, "surrounding whitespace is not significant"},

		// Everything that shares the host kernel.
		{"", false, "unset means the CLI default, which is runc"},
		{"   ", false, "whitespace-only is unset"},
		{"runc", false, "the default OCI runtime"},
		{"crun", false, "a faster runc, same boundary"},
		{"youki", false, "a Rust runc, same boundary"},

		// gVisor. Deliberately false: a userspace kernel is a stronger
		// boundary than runc but it is not a virtual machine, and calling it
		// one would misstate what an escape reaches.
		{"runsc", false, "gVisor intercepts syscalls; it is not a VM"},
		{"io.containerd.runsc.v1", false, "gVisor shim, still not a VM"},

		// Names that merely contain the letters.
		{"kataloger", false, "substring match must not qualify"},
		{"my-kata", false, "a suffix is not the kata naming convention"},
		{"notkata", false, "substring match must not qualify"},
		{"karate", false, "unrelated"},

		// A hypervisor-backed runtime that is not Kata. It may well be a VM,
		// but this matcher recognises Kata and claims nothing about others.
		{"crun-vm", false, "not recognised; the matcher is Kata-only by design"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsVirtualizedRuntime(tc.name); got != tc.want {
				t.Errorf("IsVirtualizedRuntime(%q) = %v, want %v — %s", tc.name, got, tc.want, tc.why)
			}
		})
	}
}

// TestCapabilitiesVirtualizedDefaultsFalse guards the direction the zero value
// must fail in. A driver that never sets the field — one written before it
// existed, or a Capabilities built by a caller who did not know about it —
// must be read as "not virtualized", because the alternative is placing a
// workload that requires a hypervisor onto a driver that never claimed one.
func TestCapabilitiesVirtualizedDefaultsFalse(t *testing.T) {
	var caps Capabilities
	if caps.Virtualized {
		t.Error("zero-value Capabilities reports Virtualized — silence must mean 'no hypervisor claimed'")
	}
}

// TestIsolationVMIsolatesFromHost guards the strict no-host-execution path
// against the strongest sandbox cloop offers.
//
// isolatesFromHost allow-lists isolation levels rather than denying
// IsolationNone, which is the right default for an *unknown* level but means a
// level missing from the list is treated as no boundary at all. A local Kata
// executor is the first driver to report IsolationVM, so without this the
// failure mode would be strict mode evicting the one executor that isolates
// most — and the message would say it "runs on the control-plane host".
func TestIsolationVMIsolatesFromHost(t *testing.T) {
	for _, iso := range []Isolation{IsolationContainer, IsolationVM, IsolationRemote} {
		ex := newCapExec("e", Capabilities{Isolation: iso})
		if !isolatesFromHost(ex) {
			t.Errorf("isolatesFromHost(isolation=%q) = false, want true", iso)
		}
	}
	if isolatesFromHost(newCapExec("e", Capabilities{Isolation: IsolationNone})) {
		t.Error("isolatesFromHost(isolation=none) = true, want false")
	}
	// An undeclared level must read as "no boundary claimed", never as one.
	if isolatesFromHost(newCapExec("e", Capabilities{})) {
		t.Error("isolatesFromHost(unset isolation) = true — silence must not be read as isolation")
	}
}
