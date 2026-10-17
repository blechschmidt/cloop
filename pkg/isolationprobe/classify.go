package isolationprobe

import (
	"fmt"
	"strings"
)

// Kind is what a probe found serving a sandbox's system calls.
type Kind string

const (
	// KindHostKernel: the executing host's own kernel — the sandbox is a
	// container, whatever its runtime is called.
	KindHostKernel Kind = "host-kernel"
	// KindUserspaceKernel: gVisor's Sentry, a kernel implemented in a host
	// process.
	KindUserspaceKernel Kind = "userspace-kernel"
	// KindVM: a guest kernel of the sandbox's own, behind a hypervisor.
	KindVM Kind = "vm"
	// KindUnknown: nothing the probe saw settles it. Never read as isolation.
	KindUnknown Kind = "unknown"
)

// Valid reports whether k is one of the four kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindHostKernel, KindUserspaceKernel, KindVM, KindUnknown:
		return true
	}
	return false
}

// Phrase renders k as the object of "runs on" or "runs in": "the host kernel",
// "gVisor's userspace kernel", "a virtual machine", "an unidentified kernel".
func (k Kind) Phrase() string {
	switch k {
	case KindHostKernel:
		return "the host kernel"
	case KindUserspaceKernel:
		return "a userspace kernel (gVisor)"
	case KindVM:
		return "a virtual machine"
	}
	return "an unidentified kernel"
}

// ReferenceSource says where the host's own kernel evidence came from.
type ReferenceSource string

const (
	// SourceHub: the hub read its own kernel, for a container engine on the
	// hub's machine.
	SourceHub ReferenceSource = "hub"
	// SourceAgent: a device's agent read the kernel of the machine it runs on.
	SourceAgent ReferenceSource = "agent"
	// SourceClusterNode: a Pod on the same node, under the cluster's default
	// runtime, read the node's kernel. Within the executor Role's verbs a hub
	// cannot read a Node object, so this is how it learns a node's kernel —
	// and it is the one reference that could itself be a sandbox, if the
	// cluster's default runtime is one. Classify's uptime rule is what keeps
	// such a reference from making the host kernel look like a VM.
	SourceClusterNode ReferenceSource = "node"
)

// Reference is the executing host's own kernel, which a probe's evidence is
// compared with.
type Reference struct {
	// Kernel is the host's evidence. Nil when there is none.
	Kernel *Evidence `json:"kernel,omitempty"`
	// Source says who read it.
	Source ReferenceSource `json:"source,omitempty"`
	// EngineKernel is the kernel release the container engine reports for its
	// own machine (`docker info`'s KernelVersion), when it was asked. It must
	// match Kernel's release: an engine on another machine — DOCKER_HOST at a
	// remote daemon — runs its containers on a kernel the reference does not
	// describe.
	EngineKernel string `json:"engine_kernel,omitempty"`
}

// usable reports whether the reference can stand for the kernel the sandbox's
// runtime runs on, and why not when it cannot.
func (r Reference) usable() (bool, string) {
	k := r.Kernel
	switch {
	case k == nil || (k.Release == "" && k.BootID == ""):
		return false, "the executing host's own kernel was not reported"
	case len(k.GVisor) > 0:
		return false, "the host's own evidence is itself a gVisor sandbox's (" + k.Kernel() + ")"
	case r.EngineKernel != "" && k.Release != "" && r.EngineKernel != k.Release:
		return false, fmt.Sprintf("the container engine reports kernel %s while the host reference is %s, "+
			"so the engine runs on a machine the reference does not describe", r.EngineKernel, k.Release)
	}
	return true, ""
}

// Verdict is what Classify concluded and the evidence it rests on.
type Verdict struct {
	Kind Kind `json:"kind"`
	// Detail names the evidence in a sentence an operator can act on.
	Detail string `json:"detail"`
}

// Classify decides what served the probe, from its evidence and the host's.
//
// The order is the argument:
//
//  1. The same boot ID as the host is the same kernel instance. Nothing else
//     produces it, so this wins over every marker — a host kernel someone
//     built and named "gvisor" is still the host's.
//  2. Without boot IDs on both sides, the host's exact build (release, build
//     string, /proc/version) is read as the host's kernel. That under-describes
//     a VM booting the host's own kernel image — the safe direction: a refusal
//     an operator can investigate, never isolation that is not there.
//  3. gVisor's markers. The Sentry's boot log and build string are not
//     something a Linux kernel writes, so they need no reference.
//  4. A kernel other than the host's, with a hypervisor's mark on it — the
//     CPU's hypervisor flag, a hypervisor's DMI vendor, /sys/hypervisor — and
//     younger than the host's kernel is a VM. Only here, once the kernel is
//     known to differ: on its own the flag says only that *some* hypervisor
//     is underneath, and on a cloud VM a runc container sees the cloud's. And
//     only younger: a VM serving a sandbox booted after the machine it runs
//     on, so a "different" kernel that has been up longer than the reference
//     is the reference that is wrong — a cluster whose default runtime is
//     itself a VM hands its reference Pod one, and an agent inside a VM that
//     drives an outer host's engine reads its own guest kernel. Either would
//     otherwise make the outer host kernel look like isolation.
//  5. Anything else is unknown.
//
// Nothing here asks how long the reference has been up in absolute terms: a
// node an autoscaler — or a CI runner — booted minutes ago is still the host,
// and the boot ID still says so.
func Classify(p Evidence, ref Reference) Verdict {
	p = p.Sanitize()
	if p.IsZero() {
		return Verdict{KindUnknown, "the probe reported no kernel at all" + unreadableSuffix(p)}
	}
	ok, why := ref.usable()
	var h Evidence
	if ok {
		h = ref.Kernel.Sanitize()
	}

	if ok && p.BootID != "" && p.BootID == h.BootID {
		return Verdict{KindHostKernel, fmt.Sprintf("the sandbox's kernel is the host's own: it reports the "+
			"host's boot ID (%s) and its kernel, %s", shortID(p.BootID), p.Kernel())}
	}
	if ok && (p.BootID == "" || h.BootID == "") && sameBuild(p, h) {
		return Verdict{KindHostKernel, fmt.Sprintf("the sandbox reports the host's own kernel build, %s, and "+
			"no boot ID on %s could tell a separate instance of it apart, so it is read as the host's kernel",
			p.Kernel(), missingBootID(p, h))}
	}
	if len(p.GVisor) > 0 {
		return Verdict{KindUserspaceKernel, fmt.Sprintf("gVisor's userspace kernel served the probe: it "+
			"reports %s (%s)", p.Kernel(), strings.Join(p.GVisor, "; "))}
	}
	if !ok {
		return Verdict{KindUnknown, fmt.Sprintf("the sandbox reports %s, and there is nothing to compare it "+
			"with: %s", p.Kernel(), why)}
	}
	if marks := hypervisorMarks(p); len(marks) > 0 {
		if p.UptimeSeconds <= 0 || h.UptimeSeconds <= 0 || p.UptimeSeconds >= h.UptimeSeconds {
			return Verdict{KindUnknown, fmt.Sprintf("the sandbox runs a kernel other than the host reference's "+
				"(%s, against %s) with %s, but it has been up %s against the reference's %s, so it was not "+
				"booted for the sandbox — a sandbox's VM boots after its host — and the reference may itself be "+
				"a sandbox's kernel", p.Kernel(), h.Kernel(), strings.Join(marks, " and "),
				uptime(p.UptimeSeconds), uptime(h.UptimeSeconds))}
		}
		own := "a boot ID of its own (" + shortID(p.BootID) + ")"
		if p.BootID == "" || h.BootID == "" {
			own = "a build other than the host's"
		}
		return Verdict{KindVM, fmt.Sprintf("a kernel of the sandbox's own, behind a hypervisor: it reports "+
			"%s with %s and %s, up %s where the host has been up %s, and the host runs %s", p.Kernel(), own,
			strings.Join(marks, " and "), uptime(p.UptimeSeconds), uptime(h.UptimeSeconds), h.Kernel())}
	}
	return Verdict{KindUnknown, fmt.Sprintf("the sandbox runs a kernel other than the host's (%s, against "+
		"the host's %s) and shows no hypervisor or gVisor marker cloop recognises", p.Kernel(), h.Kernel())}
}

// sameBuild reports whether two kernels are the same build: the same release,
// build string and, where both read it, /proc/version.
func sameBuild(a, b Evidence) bool {
	if a.Release == "" || a.Release != b.Release || a.Version != b.Version {
		return false
	}
	return a.ProcVersion == "" || b.ProcVersion == "" || a.ProcVersion == b.ProcVersion
}

// hypervisorMarks lists what in the evidence says a hypervisor is underneath.
func hypervisorMarks(e Evidence) []string {
	var marks []string
	if v := vmmVendor(e.DMIVendor, e.DMIProduct); v != "" {
		marks = append(marks, "DMI vendor "+v)
	}
	if e.Hypervisor {
		marks = append(marks, "the CPU's hypervisor flag")
	}
	if e.HypervisorType != "" {
		marks = append(marks, "a "+e.HypervisorType+" hypervisor in /sys/hypervisor")
	}
	return marks
}

// vmmNames are DMI strings virtual machine monitors and the clouds built on
// them put in their guests' firmware tables. Matching one says a hypervisor
// presented the machine; it says nothing about whose kernel runs on it, which
// is why Classify consults this only once the kernel is known to differ.
var vmmNames = []string{
	"qemu", "kvm", "cloud hypervisor", "firecracker", "xen", "vmware", "virtualbox",
	"innotek", "bochs", "bhyve", "parallels", "acrn", "virtual machine", "openstack",
	"amazon ec2", "google compute engine", "alibaba cloud", "hetzner", "digitalocean",
}

// vmmVendor returns the DMI string naming a hypervisor, or "".
func vmmVendor(vendor, product string) string {
	for _, s := range []string{vendor, product} {
		l := strings.ToLower(s)
		for _, n := range vmmNames {
			if strings.Contains(l, n) {
				return s
			}
		}
	}
	return ""
}

// uptime renders a kernel's uptime, "unknown" when it was not read.
func uptime(sec float64) string {
	switch {
	case sec <= 0:
		return "an unknown time"
	case sec < 120:
		return fmt.Sprintf("%.1f s", sec)
	case sec < 2*86400:
		return fmt.Sprintf("%.0f min", sec/60)
	}
	return fmt.Sprintf("%.0f days", sec/86400)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

func missingBootID(p, h Evidence) string {
	switch {
	case p.BootID == "" && h.BootID == "":
		return "either side"
	case p.BootID == "":
		return "the sandbox's side"
	}
	return "the host's side"
}

func unreadableSuffix(e Evidence) string {
	if len(e.Unreadable) == 0 {
		return ""
	}
	return " (" + strings.Join(e.Unreadable, "; ") + ")"
}

// Status is how a runtime's claim stands against the evidence.
type Status string

const (
	// StatusVerified: the evidence shows at least the isolation claimed.
	StatusVerified Status = "verified"
	// StatusContradicted: the evidence shows less than the claim — a runtime
	// named for a VM serving from the host kernel or from gVisor, one named
	// for gVisor serving from the host kernel.
	StatusContradicted Status = "contradicted"
	// StatusUnverified: nothing settles it — never probed, or an unknown
	// verdict.
	StatusUnverified Status = "unverified"
)

// Judge compares what a runtime claims with what a probe found.
//
// "At least the isolation claimed" is the rule, so the comparison is not
// symmetric: a runtime named for gVisor found to be a VM is verified, because
// a guest kernel keeps syscalls off the host kernel too, while a runtime named
// for a VM found to be gVisor is contradicted, because there is no hypervisor.
// A runtime that claims nothing — a plain container — is verified by any
// verdict but unknown: it promised nothing a verdict could break.
func Judge(claim, verdict Kind) Status {
	if verdict == KindUnknown || !verdict.Valid() {
		return StatusUnverified
	}
	switch claim {
	case KindVM:
		if verdict == KindVM {
			return StatusVerified
		}
		return StatusContradicted
	case KindUserspaceKernel:
		if verdict == KindHostKernel {
			return StatusContradicted
		}
		return StatusVerified
	}
	return StatusVerified
}
