package executor

// virtualization.go decides, from a runtime's *name*, whether that runtime
// puts a workload behind a hypervisor.
//
// It lives here rather than in a driver because two drivers ask it about two
// different things and must agree on the answer. The container driver asks
// about an OCI runtime passed to `--runtime` (kata, kata-qemu); the Kubernetes
// driver asks about a RuntimeClass name (kata, kata-clh). Both are naming the
// same technology through their own ecosystem's vocabulary, and both use the
// answer to set the same field — Capabilities.Virtualized — which a placement
// requirement is then checked against. Two copies of this matcher would be two
// chances for the same executor to be described differently depending on which
// driver was asked.
//
// # Why it is deliberately narrow
//
// Being wrong here is asymmetric. A false negative under-describes a sandbox:
// a Kata executor registered under an unrecognised name is called a container,
// and a project requiring virtualization is refused placement on an executor
// that would in fact have satisfied it. The operator sees a refusal and can
// rename the class.
//
// A false positive is the dangerous direction. It tells an operator a workload
// runs behind a hypervisor when it shares the host kernel, and places work that
// was required to be virtualized onto something that is not. So only names that
// are unambiguously Kata qualify. gVisor's runsc is a genuinely stronger
// boundary than runc and still reports false here: it is a userspace kernel, not
// a virtual machine, and describing it as one would misstate what an escape
// reaches.
//
// That last point used to end the discussion, and it left a gap. An operator who
// runs gVisor got a sandbox described as a plain container — indistinguishable
// from runc — so a project that needed its syscalls kept off the host kernel had
// no way to ask for one, and `virtualized: true` actively refused the gVisor
// executor that would have satisfied the intent. Hence the second predicate
// below. The two are deliberately not the same question:
//
//	IsVirtualizedRuntime      — is there a hypervisor? (Kata only)
//	IsKernelIsolatedRuntime   — are the workload's syscalls served by something
//	                            other than the host kernel? (Kata *and* gVisor)
//
// Virtualization implies kernel isolation and not the reverse, so the second is
// a superset of the first. Keeping both means an operator is told what they
// actually deployed, and a project can require the weaker-but-sufficient
// property without being forced to demand a VM it does not need.
//
// The name is all we have to go on, and that is a real limit: an operator can
// register runc under the name "kata" and be believed. That is not a hole these
// functions can close — the name is the only thing the OCI and RuntimeClass APIs
// expose to a client — and it is why Preflight separately proves the sandbox
// can start a VM at all by checking for /dev/kvm.

import "strings"

// IsVirtualizedRuntime reports whether name identifies a Kata Containers
// runtime, in either the OCI-runtime or the Kubernetes RuntimeClass spelling.
//
// Recognised: "kata", "katacontainers", any "kata-*" or "kata.*" name
// (kata-runtime, kata-qemu, kata-clh, kata-fc), and the containerd shim
// spelling "io.containerd.kata.v2". Everything else, including an empty name,
// reports false.
func IsVirtualizedRuntime(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return false
	case n == "kata", n == "katacontainers":
		return true
	case strings.HasPrefix(n, "kata-"), strings.HasPrefix(n, "kata."):
		return true
	case strings.Contains(n, ".kata."):
		return true
	}
	return false
}

// IsUserspaceKernelRuntime reports whether name identifies gVisor, in either
// the OCI-runtime or the Kubernetes RuntimeClass spelling.
//
// Recognised: "runsc" (the binary's own name, which is what both `--runtime
// runsc` and a RuntimeClass called runsc use), "gvisor", any "runsc-*" or
// "gvisor-*" variant an operator has registered with different Sentry flags
// (runsc-ptrace, runsc-kvm are the two in the wild), and the containerd shim
// spelling "io.containerd.runsc.v1".
//
// gVisor is not a hypervisor and this never claims it is; see
// IsKernelIsolatedRuntime for what it is used to assert.
func IsUserspaceKernelRuntime(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return false
	case n == "runsc", n == "gvisor":
		return true
	case strings.HasPrefix(n, "runsc-"), strings.HasPrefix(n, "runsc."):
		return true
	case strings.HasPrefix(n, "gvisor-"), strings.HasPrefix(n, "gvisor."):
		return true
	case strings.Contains(n, ".runsc."), strings.Contains(n, ".gvisor."):
		return true
	}
	return false
}

// IsKernelIsolatedRuntime reports whether name identifies a runtime under which
// the workload's system calls are served by something other than the host
// kernel — a guest kernel inside a VM (Kata) or a userspace kernel in the
// Sentry (gVisor).
//
// This is the property a project asks for when it says "do not let my task's
// syscalls reach the host kernel directly". It is strictly weaker than
// IsVirtualizedRuntime, and that is the point: demanding a hypervisor when a
// userspace kernel would do refuses placement on executors that met the actual
// requirement, and a refusal nobody needed is still an outage.
//
// runc and crun report false. They are the case this exists to exclude: the
// container boundary is namespaces, cgroups and seccomp, and a kernel bug is a
// host bug.
func IsKernelIsolatedRuntime(name string) bool {
	return IsVirtualizedRuntime(name) || IsUserspaceKernelRuntime(name)
}
