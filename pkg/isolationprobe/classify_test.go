package isolationprobe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is one capture in testdata: what a probe read inside a sandbox, what
// the executing host read about itself, and what the capture is known to be.
type fixture struct {
	About        string          `json:"about"`
	Runtime      string          `json:"runtime"`
	EngineKernel string          `json:"engine_kernel"`
	Source       ReferenceSource `json:"source"`
	Host         Evidence        `json:"host"`
	Probe        Evidence        `json:"probe"`
	Want         Kind            `json:"want"`
}

func (f fixture) reference() Reference {
	h := f.Host
	return Reference{Kernel: &h, Source: f.Source, EngineKernel: f.EngineKernel}
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// claimFor mirrors executor.IsolationClaim, which this package cannot import:
// what each fixture's runtime name claims.
func claimFor(runtime string) Kind {
	switch {
	case strings.HasPrefix(runtime, "kata"):
		return KindVM
	case runtime == "runsc":
		return KindUserspaceKernel
	}
	return KindHostKernel
}

// TestClassifyCapturedEvidence classifies every capture in testdata: runc and
// runsc on sgx, the hub host's docker, and two genuine QEMU q35 guests standing
// in for Kata, which neither machine can run (no /dev/kvm). Each must come out
// as what it is, and each runtime's own claim must be verified by it.
func TestClassifyCapturedEvidence(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(names) < 5 {
		t.Fatalf("want at least five captures in testdata, found %d (%v)", len(names), err)
	}
	for _, path := range names {
		name := filepath.Base(path)
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			f := loadFixture(t, name)
			v := Classify(f.Probe, f.reference())
			if v.Kind != f.Want {
				t.Fatalf("Classify = %s (%s), want %s\n%s", v.Kind, v.Detail, f.Want, f.About)
			}
			if v.Detail == "" {
				t.Error("a verdict must name its evidence")
			}
			if got := Judge(claimFor(f.Runtime), v.Kind); got != StatusVerified {
				t.Errorf("Judge(%s claim, %s) = %s, want verified", claimFor(f.Runtime), v.Kind, got)
			}
		})
	}
}

// TestRuncRegisteredAsKataIsCaught is the case the probe exists for: a runtime
// named kata that is runc. The evidence is the real runc capture on sgx; only
// the name differs, and the name is all the old claim rested on.
func TestRuncRegisteredAsKataIsCaught(t *testing.T) {
	f := loadFixture(t, "sgx-docker-runc.json")
	v := Classify(f.Probe, f.reference())
	if v.Kind != KindHostKernel {
		t.Fatalf("Classify = %s, want host-kernel", v.Kind)
	}
	for _, claim := range []Kind{KindVM, KindUserspaceKernel} {
		if got := Judge(claim, v.Kind); got != StatusContradicted {
			t.Errorf("Judge(%s, host-kernel) = %s, want contradicted", claim, got)
		}
	}
	// The detail names what gave it away, so the refusal can quote it.
	for _, want := range []string{"host's boot ID", "2d725fb0", "6.8.0-79-generic"} {
		if !strings.Contains(v.Detail, want) {
			t.Errorf("detail %q does not mention %q", v.Detail, want)
		}
	}
}

// TestGVisorIsNotAVM: gVisor passes the host's DMI product name and the CPU's
// hypervisor flag through to the sandbox, so evidence read naively says "VM".
// It must classify as a userspace kernel, which contradicts a Kata name and
// verifies a gVisor one.
func TestGVisorIsNotAVM(t *testing.T) {
	f := loadFixture(t, "sgx-docker-runsc.json")
	if !f.Probe.Hypervisor || f.Probe.DMIProduct == "" {
		t.Fatal("the capture no longer shows the pass-through this test is about")
	}
	v := Classify(f.Probe, f.reference())
	if v.Kind != KindUserspaceKernel {
		t.Fatalf("Classify = %s (%s), want userspace-kernel", v.Kind, v.Detail)
	}
	if got := Judge(KindVM, v.Kind); got != StatusContradicted {
		t.Errorf("a runtime named kata found to be gVisor: Judge = %s, want contradicted", got)
	}
	// gVisor's markers are self-evident: no reference is needed to say so.
	if v := Classify(f.Probe, Reference{}); v.Kind != KindUserspaceKernel {
		t.Errorf("without a reference, Classify = %s, want userspace-kernel", v.Kind)
	}
}

// TestAVMBootingTheHostsOwnKernelImage: a guest booting the host's very kernel
// image matches it in release, build string and /proc/version. The boot ID is
// what tells the two kernels apart; without it the build match must read as
// the host's kernel — under-describing a VM, never inventing one.
func TestAVMBootingTheHostsOwnKernelImage(t *testing.T) {
	f := loadFixture(t, "sgx-qemu-q35-guest-host-kernel-image.json")
	if !sameBuild(f.Probe, f.Host) {
		t.Fatal("the capture's guest kernel no longer matches the host's build")
	}
	if v := Classify(f.Probe, f.reference()); v.Kind != KindVM {
		t.Fatalf("with both boot IDs, Classify = %s (%s), want vm", v.Kind, v.Detail)
	}
	noID := f.Probe
	noID.BootID = ""
	v := Classify(noID, f.reference())
	if v.Kind != KindHostKernel {
		t.Fatalf("without the guest's boot ID, Classify = %s, want host-kernel", v.Kind)
	}
	if !strings.Contains(v.Detail, "sandbox's side") {
		t.Errorf("detail %q should say which side's boot ID was missing", v.Detail)
	}
}

// TestHypervisorMarksAreNotEvidenceAlone: every capture here was made on a VM,
// so a runc container shows a hypervisor flag and a cloud's DMI vendor. With
// nothing to compare against, that must stay unknown rather than become vm.
func TestHypervisorMarksAreNotEvidenceAlone(t *testing.T) {
	f := loadFixture(t, "sgx-docker-runc.json")
	if !f.Probe.Hypervisor || f.Probe.DMIVendor == "" {
		t.Fatal("the capture no longer shows the cloud's marks this test is about")
	}
	v := Classify(f.Probe, Reference{})
	if v.Kind != KindUnknown {
		t.Fatalf("Classify with no reference = %s, want unknown", v.Kind)
	}
	if got := Judge(KindVM, v.Kind); got != StatusUnverified {
		t.Errorf("Judge(vm, unknown) = %s, want unverified", got)
	}
}

// TestReferencesThatDescribeTheWrongKernel: a reference the comparison cannot
// rest on must never turn a host kernel into isolation.
func TestReferencesThatDescribeTheWrongKernel(t *testing.T) {
	runc := loadFixture(t, "sgx-docker-runc.json")
	runsc := loadFixture(t, "sgx-docker-runsc.json")
	hub := loadFixture(t, "hub-docker-runc.json")

	t.Run("an engine on another machine", func(t *testing.T) {
		// The hub on one host, its engine's containers on sgx: the hub's
		// kernel is not the one those containers share, and the engine says so.
		ref := Reference{Kernel: &hub.Host, Source: SourceHub, EngineKernel: runc.EngineKernel}
		v := Classify(runc.Probe, ref)
		if v.Kind != KindUnknown {
			t.Fatalf("Classify = %s (%s), want unknown", v.Kind, v.Detail)
		}
		if !strings.Contains(v.Detail, "container engine reports kernel 6.8.0-79-generic") {
			t.Errorf("detail %q should name the engine's kernel", v.Detail)
		}
	})
	t.Run("a reference that is itself gVisor", func(t *testing.T) {
		ref := Reference{Kernel: &runsc.Probe, Source: SourceAgent}
		if v := Classify(runc.Probe, ref); v.Kind != KindUnknown {
			t.Fatalf("Classify = %s, want unknown", v.Kind)
		}
	})
	t.Run("a node reference booted moments ago", func(t *testing.T) {
		// A cluster whose default runtime is itself a VM hands the reference
		// Pod a fresh kernel; the host kernel the probe Pod saw must not be
		// read as "different from the host's, so a VM".
		fresh := loadFixture(t, "sgx-qemu-q35-guest.json").Probe
		ref := Reference{Kernel: &fresh, Source: SourceClusterNode}
		if v := Classify(runc.Probe, ref); v.Kind != KindUnknown {
			t.Fatalf("Classify = %s (%s), want unknown", v.Kind, v.Detail)
		}
		// A long-lived node reference is fine.
		ref = Reference{Kernel: &runc.Host, Source: SourceClusterNode}
		if v := Classify(runc.Probe, ref); v.Kind != KindHostKernel {
			t.Fatalf("with the node's own kernel, Classify = %s, want host-kernel", v.Kind)
		}
	})
	t.Run("no host kernel reported", func(t *testing.T) {
		v := Classify(runc.Probe, Reference{Source: SourceAgent})
		if v.Kind != KindUnknown || !strings.Contains(v.Detail, "not reported") {
			t.Fatalf("Classify = %s (%s), want unknown naming the missing reference", v.Kind, v.Detail)
		}
	})
}

// TestADifferentKernelWithoutMarksIsUnknown: a kernel other than the host's
// with no hypervisor or gVisor marker is not given a kind it did not show.
func TestADifferentKernelWithoutMarksIsUnknown(t *testing.T) {
	f := loadFixture(t, "sgx-qemu-q35-guest.json")
	p := f.Probe
	p.Hypervisor, p.DMIVendor, p.DMIProduct = false, "", ""
	if v := Classify(p, f.reference()); v.Kind != KindUnknown {
		t.Fatalf("Classify = %s, want unknown", v.Kind)
	}
	if v := Classify(Evidence{}, f.reference()); v.Kind != KindUnknown {
		t.Fatalf("empty evidence: Classify = %s, want unknown", v.Kind)
	}
}

func TestJudge(t *testing.T) {
	cases := []struct {
		claim, verdict Kind
		want           Status
	}{
		{KindVM, KindVM, StatusVerified},
		{KindVM, KindHostKernel, StatusContradicted},
		{KindVM, KindUserspaceKernel, StatusContradicted},
		{KindVM, KindUnknown, StatusUnverified},
		{KindUserspaceKernel, KindUserspaceKernel, StatusVerified},
		// A guest kernel keeps syscalls off the host kernel too.
		{KindUserspaceKernel, KindVM, StatusVerified},
		{KindUserspaceKernel, KindHostKernel, StatusContradicted},
		{KindUserspaceKernel, KindUnknown, StatusUnverified},
		// A plain container promised nothing a verdict could break.
		{KindHostKernel, KindHostKernel, StatusVerified},
		{KindHostKernel, KindVM, StatusVerified},
		{KindHostKernel, KindUnknown, StatusUnverified},
		{KindVM, Kind("nonsense"), StatusUnverified},
	}
	for _, c := range cases {
		if got := Judge(c.claim, c.verdict); got != c.want {
			t.Errorf("Judge(%s, %s) = %s, want %s", c.claim, c.verdict, got, c.want)
		}
	}
}
