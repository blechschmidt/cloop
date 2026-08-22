package container

// ociruntime.go covers the second runtime axis, which runtime.go does not.
//
// runtime.go picks the CLI we invoke: podman or docker. This file picks what
// that CLI hands each container to — the OCI runtime, selected with
// `--runtime`. The default is runc or crun, which start the workload as a
// process on the host kernel; the container boundary is namespaces, cgroups
// and seccomp, and a kernel bug is a host bug.
//
// Kata Containers is the reason this axis exists. It boots each container
// inside a lightweight VM with its own kernel, so the guest kernel is the
// thing an escape reaches first and the host kernel sits behind a hypervisor.
// For a hub that runs model-authored code on behalf of other people, that is
// a materially different boundary, and it is the one Capabilities must be
// able to advertise.
//
// # Why a bare name and never a path
//
// A path here would be a path to a binary that docker's daemon runs as root.
// Config that can name an arbitrary executable is config that can execute
// arbitrary code as root, which is the same reason DetectRuntime allow-lists
// the CLI. A bare name cannot do that: docker resolves it only against
// runtimes registered in /etc/docker/daemon.json, and podman only against
// containers.conf. Both are root-owned files an operator already controls, so
// the name is an indirection through a trusted table rather than a target.
//
// # Why the shape check is permissive and the VM claim is not
//
// The set of legitimate names is open — an operator may register kata under
// any name they like, and clusters do (kata, kata-qemu, kata-clh). Refusing
// names outside a fixed list would reject working configurations, so
// ValidateOCIRuntime checks only the shape that keeps the value from becoming
// a flag or a path.
//
// IsVirtualizedOCIRuntime is the opposite. It decides whether cloop tells an
// operator "this workload runs in a VM", and being wrong there is worse than
// being unhelpful: a project that requires virtualization would be placed on
// a sandbox that does not provide it. So it recognises only names that are
// unambiguously Kata, and everything else — including gVisor's runsc, which
// is a stronger boundary than runc but is a userspace kernel and not a
// virtual machine — reports false and is described honestly as a container.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// maxOCIRuntimeNameLen bounds the name. Real names are under 20 characters;
// the limit exists so a pathological config cannot produce an unreadable
// error message or a surprising argv.
const maxOCIRuntimeNameLen = 64

// KVMDevice is the host device Kata needs in order to start a VM. Its absence
// is the single most common reason a kata executor fails on a cloud host: the
// hub is itself a VM and nested virtualization is off.
const KVMDevice = "/dev/kvm"

// ValidateOCIRuntime checks that name is a plausible OCI runtime *name*.
//
// Empty is valid and means "the runtime's own default" — no --runtime flag is
// emitted at all, which is what every existing deployment gets.
func ValidateOCIRuntime(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return nil
	}
	if len(n) > maxOCIRuntimeNameLen {
		return fmt.Errorf("container: oci_runtime %q is too long (max %d characters)", n, maxOCIRuntimeNameLen)
	}
	// A leading dash would be parsed by the CLI as another flag rather than
	// as the value of --runtime.
	if strings.HasPrefix(n, "-") {
		return fmt.Errorf("container: oci_runtime %q may not start with a dash", n)
	}
	if strings.ContainsAny(n, `/\`) {
		return fmt.Errorf(
			"container: oci_runtime must be a registered runtime name, not a path (got %q) — "+
				"register the binary in /etc/docker/daemon.json (docker) or containers.conf "+
				"[engine.runtimes] (podman) and name it here", n)
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf(
				"container: oci_runtime %q contains %q — names may use letters, digits, dot, underscore and dash",
				n, string(r))
		}
	}
	return nil
}

// IsVirtualizedOCIRuntime reports whether name identifies a runtime that puts
// the workload behind a hypervisor rather than on the host kernel.
//
// It is executor.IsVirtualizedRuntime under this package's vocabulary. The
// matcher is shared with the Kubernetes driver, which asks the same question
// about a RuntimeClass name: see pkg/executor/virtualization.go for why one
// definition rather than two, and why it recognises so little.
func IsVirtualizedOCIRuntime(name string) bool {
	return executor.IsVirtualizedRuntime(name)
}

// kvmStatus is what a host can tell us about its virtualization support.
type kvmStatus struct {
	// Present reports that KVMDevice exists.
	Present bool
	// Usable reports that this process could open it read-write, which is
	// the access Kata's hypervisor needs. False with Present true means a
	// permissions problem — almost always group membership.
	Usable bool
	// Err is the reason Usable is false, for the remediation message.
	Err error
}

// checkKVM probes the host's virtualization device.
//
// Opening rather than stat-ing is deliberate: /dev/kvm exists with mode 0660
// root:kvm on most distributions, so a stat succeeds for a user who cannot
// use it. The failure that matters — a rootless podman user who is not in the
// kvm group — is invisible to a stat and immediate on an open.
func checkKVM() kvmStatus {
	if _, err := os.Stat(KVMDevice); err != nil {
		return kvmStatus{Err: err}
	}
	f, err := os.OpenFile(KVMDevice, os.O_RDWR, 0)
	if err != nil {
		return kvmStatus{Present: true, Err: err}
	}
	_ = f.Close()
	return kvmStatus{Present: true, Usable: true}
}

// kvmFix is the remediation for an unusable /dev/kvm.
func kvmFix(st kvmStatus) string {
	if !st.Present {
		return "this host has no " + KVMDevice + " — enable nested virtualization on the " +
			"hypervisor (GCP: --enable-nested-virtualization; AWS: a metal instance type), " +
			"load the kvm_intel/kvm_amd module, or run kata on a remote executor instead"
	}
	return "add the user running cloop to the 'kvm' group (usermod -aG kvm <user>) and " +
		"restart the service, or grant access to " + KVMDevice + " another way"
}

// registeredOCIRuntimes lists the OCI runtimes the CLI will accept, or
// reports ok=false when this CLI cannot be asked.
//
// Only docker can answer: `docker info` carries the daemon's Runtimes table,
// which is exactly the set --runtime resolves against. Podman resolves
// against containers.conf and exposes only the *active* runtime in `podman
// info`, with no way to enumerate the rest — so rather than guess, we say we
// do not know and let the caller downgrade the finding to a warning. A probe
// that cannot distinguish "absent" from "unenumerable" must not report
// "absent", because that turns a working kata deployment into a startup
// failure.
func registeredOCIRuntimes(ctx context.Context, rt Runtime) (map[string]bool, bool) {
	if rt.Name != RuntimeDocker {
		return nil, false
	}
	res, err := runCLITimeout(ctx, rt, preflightCmdTimeout, "info", "--format", "{{json .Runtimes}}")
	if err != nil || res.ExitCode != 0 {
		return nil, false
	}
	// The value is a map of name -> {path, runtimeArgs}; only the keys matter.
	var runtimes map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &runtimes); err != nil {
		return nil, false
	}
	if len(runtimes) == 0 {
		return nil, false
	}
	out := make(map[string]bool, len(runtimes))
	for name := range runtimes {
		out[name] = true
	}
	return out, true
}

// ociRuntimeFix is the remediation shown when a configured runtime is not
// registered with the CLI that has to resolve it.
func ociRuntimeFix(rt Runtime, name string) string {
	if rt.Name == RuntimeDocker {
		return fmt.Sprintf(
			"register %q in /etc/docker/daemon.json under \"runtimes\" and restart dockerd "+
				"(the kata package usually installs this), or unset executors.container.oci_runtime", name)
	}
	return fmt.Sprintf(
		"add %q to [engine.runtimes] in containers.conf pointing at the kata binary, "+
			"or unset executors.container.oci_runtime", name)
}
