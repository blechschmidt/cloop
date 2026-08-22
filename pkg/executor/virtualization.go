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
// boundary than runc and still reports false: it is a userspace kernel, not a
// virtual machine, and describing it as one would misstate what an escape
// reaches.
//
// The name is all we have to go on, and that is a real limit: an operator can
// register runc under the name "kata" and be believed. That is not a hole this
// function can close — the name is the only thing the OCI and RuntimeClass APIs
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
