package executor

// device.go carries host hardware into a sandbox.
//
// # Why this is a grant and not a sandbox-spec field
//
// Every other knob a project has over its environment lives in
// .cloop/sandbox.yaml, and this one deliberately does not. A device node is an
// authority over the machine: /dev/ttyUSB0 is a serial line into whatever is
// plugged in, /dev/nvidia0 is a compute unit with its own memory and its own
// history of escapes, /dev/net/tun is a network interface the sandbox can build
// its own path out of. Handing one over is the widest thing a sandbox request
// can ask for, and sandbox.yaml is repo-committed — it is whatever a pull
// request says it is.
//
// So the shape follows KindLocalRepo exactly, for the same reason it does: a
// human with secret.grant names the device, out of band, scoped to one project,
// with a TTL and an audit row. The repo may then *select* among what it was
// granted by name. It can narrow the set and it can never extend it, which is
// the invariant the whole sandbox pipeline is built on.
//
// # Why a first-class field rather than lifting the extra_args ban
//
// `--device` is on deniedExtraArgs and stays there. The denylist exists so that
// operator config cannot dismantle an isolation guarantee the driver advertises,
// and a device passed as a raw runtime flag does exactly that invisibly: it is
// not attributed to a lease, so revocation cannot find it; it is not in the
// Spec, so the audit trail does not record what the sandbox could reach; and it
// applies to every workload on the executor rather than to the project that was
// granted it. A typed field is what makes the same capability revocable,
// recorded and scoped.

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// MaxDevices bounds how many device nodes one workload may be given.
//
// The limit is not about runtime cost — a runtime will happily take hundreds —
// but about what a spec that asks for this many is describing. Past a handful
// the sandbox is no longer a confined environment with a piece of hardware in
// it; and every entry is another cgroup rule whose failure has to be diagnosed.
const MaxDevices = 16

// maxDevicePathLen bounds a device path. Real ones are under 40 characters.
const maxDevicePathLen = 256

// DevicePermissions is the access a workload gets to a device node, in the
// runtime's own rwm vocabulary.
//
// It is a string rather than a set of bools because that is the form both
// container runtimes and the Linux device cgroup take, and because the mistake
// worth preventing — silently widening "r" to "rwm" — is easier to see in a
// value that round-trips unchanged.
//
// # What this does and does not guarantee
//
// The value becomes the third field of the runtime's `--device src:dst:perms`,
// which programs the container's *device cgroup*. On cgroup v1 that is the
// devices controller; on cgroup v2 it is an eBPF program attached to the
// container's cgroup, and whether it is attached at all depends on the kernel,
// the runtime build and the cgroup delegation — none of which cloop can
// interrogate. On a host where it is not attached, a device granted "r" is
// readable *and* writable, because the node inside the sandbox carries the host
// node's file mode and /dev/zero is 0666 nearly everywhere.
//
// So this field is defence in depth and not a boundary cloop can promise. The
// control that does hold on every host is the node's own ownership and mode: a
// device at crw-rw---- root:dialout is unopenable by a sandbox whose UID is not
// in that group, regardless of cgroups. An operator who needs read-only access
// to be enforced sets it there. Preflight says so rather than leaving the
// stronger reading of this field to be assumed; see preflightDeviceMode.
//
// It is still emitted, and still defaults to rw rather than the runtime's rwm,
// because on the hosts where the cgroup rule *is* enforced it is enforced
// exactly, and withholding mknod by default costs nothing.
type DevicePermissions string

const (
	// DeviceRead allows read only. Correct for a sensor or a capture device.
	DeviceRead DevicePermissions = "r"
	// DeviceReadWrite allows read and write. The common case: a serial line,
	// a GPU, a TPM.
	DeviceReadWrite DevicePermissions = "rw"
	// DeviceReadWriteMknod additionally allows mknod on the device's
	// major:minor. Needed by workloads that create their own nodes, and
	// worth naming separately because it is the one that lets a sandbox
	// fabricate a second reference to the same hardware.
	DeviceReadWriteMknod DevicePermissions = "rwm"
)

// validDevicePermissions is the closed set. An arbitrary rwm permutation is
// rejected rather than normalised: "mr" is almost certainly a typo for "rw",
// and guessing which of the two an operator meant is not this layer's call.
var validDevicePermissions = map[DevicePermissions]bool{
	DeviceRead:           true,
	DeviceReadWrite:      true,
	DeviceReadWriteMknod: true,
}

// Valid reports whether p is one of the three permitted access strings.
func (p DevicePermissions) Valid() bool { return validDevicePermissions[p] }

// HostDevice is one device node exposed from the executor's host into the
// sandbox.
//
// Source and Target are separate because the sandbox-visible name is part of
// what makes a grant portable. A project told to open /dev/accel0 should not
// have to know that on this particular host the hardware happens to be
// /dev/nvidia3; the operator maps it, and the project's code does not change
// when it moves to a node that enumerates its hardware differently.
type HostDevice struct {
	// Name identifies the device within its grant, for diagnostics and for
	// the `devices:` selector in a sandbox spec.
	Name string `json:"name"`
	// Source is the absolute path of the device node on the executor's host.
	Source string `json:"source"`
	// Target is the absolute path it appears at inside the sandbox. Empty
	// means the same path as Source, which is what a workload looking for
	// well-known hardware expects.
	Target string `json:"target,omitempty"`
	// Permissions is the access granted. Empty means DeviceReadWrite, which
	// is what a device is useful with and is still short of mknod.
	Permissions DevicePermissions `json:"permissions,omitempty"`
	// LeaseID is the secret lease that authorised this device, so revocation
	// can find it and the audit trail can say who opened it. Empty is
	// permitted only for a device the operator configured directly on the
	// executor, which is not a path any project-scoped grant takes.
	LeaseID string `json:"lease_id,omitempty"`
	// KubernetesResource optionally names the extended resource a Kubernetes
	// node advertises for this hardware ("nvidia.com/gpu", "squat.ai/fuse").
	//
	// It exists because Kubernetes does not take device paths. A device
	// plugin owns the node and hands the container the right one in response
	// to a resource request, so on that driver the path is not the thing
	// asked for — the resource name is. A grant that omits it is honestly
	// undeliverable on Kubernetes rather than silently ignored there; see
	// Capabilities.SupportsDevices.
	KubernetesResource string `json:"kubernetes_resource,omitempty"`
}

// EffectiveTarget is where the device appears inside the sandbox.
func (d HostDevice) EffectiveTarget() string {
	if t := strings.TrimSpace(d.Target); t != "" {
		return t
	}
	return d.Source
}

// EffectivePermissions is the access to apply, resolving the empty default.
func (d HostDevice) EffectivePermissions() DevicePermissions {
	if d.Permissions == "" {
		return DeviceReadWrite
	}
	return d.Permissions
}

// deviceNamePattern bounds the selector name. It lands in labels, audit rows
// and a YAML list, so it is kept to the same shape as a grant name.
var deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// forbiddenDeviceSources are host paths that are never a legitimate grant,
// because exposing them is equivalent to giving up the host.
//
// This is a denylist on top of an allowlist, which is normally a smell. It is
// here because the allowlist above it is "an absolute path under /dev that an
// operator typed", and an operator typing /dev/mem has made a mistake no
// downstream layer can catch: the sandbox would be able to read and write all
// of physical memory, including the kernel, and every confinement cloop
// advertises would be decoration. Each entry is a device whose whole purpose is
// unmediated access to the machine.
var forbiddenDeviceSources = map[string]string{
	"/dev/mem":     "maps all of physical memory, including kernel text",
	"/dev/kmem":    "maps kernel virtual memory",
	"/dev/port":    "gives raw I/O port access",
	"/dev/kcore":   "exposes kernel memory as a core image",
	"/dev/msr":     "reads and writes model-specific CPU registers",
	"/dev/cpu":     "exposes per-CPU MSR and cpuid interfaces",
	"/dev/sda":     "is a whole host disk; grant a partition or a bind mount instead",
	"/dev/nvme0n1": "is a whole host disk; grant a partition or a bind mount instead",
	"/dev/vda":     "is a whole host disk; grant a partition or a bind mount instead",
}

// ValidateHostDevice checks one device grant.
//
// It is exported because three layers need the same answer: the broker when an
// operator creates a grant (so the mistake is caught at grant time, by the
// person who can fix it), the drivers before they render a runtime flag, and
// Spec.Validate on the dispatch path. One definition means a device that passes
// at grant time cannot be refused two layers down.
func ValidateHostDevice(d HostDevice) error {
	name := strings.TrimSpace(d.Name)
	if name == "" {
		return fmt.Errorf("%w: device name is empty", ErrInvalidSpec)
	}
	if !deviceNamePattern.MatchString(name) {
		return fmt.Errorf("%w: device name %q must be 1-64 characters of [A-Za-z0-9._-] "+
			"starting with a letter or digit", ErrInvalidSpec, name)
	}
	if err := validateDevicePath(name, "source", d.Source); err != nil {
		return err
	}
	// A source outside /dev is refused. The field's contract is a device node,
	// and a regular file arriving here would be a host bind mount wearing a
	// device's name — bypassing HostMount's own validation and its attribution
	// to a local_repo grant. Files have a field already; this one is for
	// hardware.
	if !isDevPath(d.Source) {
		return fmt.Errorf("%w: device %q source %q is not under /dev; a device grant "+
			"exposes a device node, and a host *file* or directory is a local_repo "+
			"grant (delivered as Spec.HostMounts)", ErrInvalidSpec, name, d.Source)
	}
	if reason := forbiddenDeviceSources[path.Clean(d.Source)]; reason != "" {
		return fmt.Errorf("%w: device %q source %q %s, so exposing it would waive every "+
			"isolation guarantee the sandbox advertises", ErrInvalidSpec, name, d.Source, reason)
	}
	if t := strings.TrimSpace(d.Target); t != "" {
		if err := validateDevicePath(name, "target", t); err != nil {
			return err
		}
		if !isDevPath(t) {
			return fmt.Errorf("%w: device %q target %q is not under /dev; a device node "+
				"mounted elsewhere is invisible to every library that looks for it",
				ErrInvalidSpec, name, t)
		}
	}
	if p := d.EffectivePermissions(); !p.Valid() {
		return fmt.Errorf("%w: device %q permissions %q must be one of %q, %q or %q",
			ErrInvalidSpec, name, d.Permissions, DeviceRead, DeviceReadWrite, DeviceReadWriteMknod)
	}
	if res := strings.TrimSpace(d.KubernetesResource); res != "" {
		if err := validateResourceName(res); err != nil {
			return fmt.Errorf("%w: device %q kubernetes_resource: %v", ErrInvalidSpec, name, err)
		}
	}
	return nil
}

// validateDevicePath enforces the shape that keeps a path from becoming a flag,
// a traversal or a shell surprise in the argv it is rendered into.
func validateDevicePath(name, field, p string) error {
	switch {
	case strings.TrimSpace(p) == "":
		return fmt.Errorf("%w: device %q has an empty %s path", ErrInvalidSpec, name, field)
	case len(p) > maxDevicePathLen:
		return fmt.Errorf("%w: device %q %s path is %d bytes, at most %d are allowed",
			ErrInvalidSpec, name, field, len(p), maxDevicePathLen)
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%w: device %q %s path %q is not absolute",
			ErrInvalidSpec, name, field, p)
	case p != path.Clean(p):
		// An uncleaned path is refused rather than cleaned, because the two
		// differ exactly when someone wrote something they did not mean: the
		// grant an operator reviews must be the string the runtime receives.
		return fmt.Errorf("%w: device %q %s path %q is not in canonical form (want %q)",
			ErrInvalidSpec, name, field, p, path.Clean(p))
	case strings.ContainsAny(p, "\n\r\x00"):
		return fmt.Errorf("%w: device %q %s path contains a control character",
			ErrInvalidSpec, name, field)
	case strings.Contains(p, ":"):
		// The runtimes' --device syntax is src:dst:perms, so a colon inside a
		// path would silently reinterpret which device is being asked for and
		// with what access.
		return fmt.Errorf("%w: device %q %s path %q contains ':', which the runtime "+
			"would parse as a field separator", ErrInvalidSpec, name, field, p)
	}
	return nil
}

// isDevPath reports whether p is /dev itself or below it.
//
// The check is on the cleaned path so that /dev/../etc/shadow — which is
// already refused as non-canonical — could not reach it by another route.
func isDevPath(p string) bool {
	c := path.Clean(p)
	return c == "/dev" || strings.HasPrefix(c, "/dev/")
}

// validateResourceName bounds a Kubernetes extended-resource name. The real
// grammar is a qualified name; this checks the part of it that matters for
// getting a legible error instead of a rejected Pod.
func validateResourceName(res string) error {
	if len(res) > 253 {
		return fmt.Errorf("resource name is %d bytes, at most 253 are allowed", len(res))
	}
	for _, r := range res {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '/':
		default:
			return fmt.Errorf("resource name %q contains %q; use letters, digits, '.', '-', '_' and '/'",
				res, string(r))
		}
	}
	return nil
}

// ValidateDevices checks a whole device list: each entry, the count, and the
// two collision classes that would otherwise be resolved by argv order.
func ValidateDevices(devices []HostDevice) error {
	if len(devices) > MaxDevices {
		return fmt.Errorf("%w: %d devices requested, at most %d are allowed",
			ErrInvalidSpec, len(devices), MaxDevices)
	}
	seenName := make(map[string]struct{}, len(devices))
	seenTarget := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		if err := ValidateHostDevice(d); err != nil {
			return err
		}
		name := strings.TrimSpace(d.Name)
		if _, dup := seenName[name]; dup {
			return fmt.Errorf("%w: device %q is listed twice", ErrInvalidSpec, name)
		}
		seenName[name] = struct{}{}

		target := path.Clean(d.EffectiveTarget())
		if _, dup := seenTarget[target]; dup {
			// Two devices at one path is not a preference the runtime resolves
			// sensibly — one wins by argv order — and the workload cannot tell
			// which piece of hardware it is talking to.
			return fmt.Errorf("%w: two devices both appear at %q inside the sandbox",
				ErrInvalidSpec, target)
		}
		seenTarget[target] = struct{}{}
	}
	return nil
}

// DeviceNames returns the grant-facing names of a device list, in order, for
// log lines and audit records.
func DeviceNames(devices []HostDevice) []string {
	if len(devices) == 0 {
		return nil
	}
	out := make([]string, 0, len(devices))
	for _, d := range devices {
		out = append(out, strings.TrimSpace(d.Name))
	}
	return out
}
