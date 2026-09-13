package secretbroker

// hostdevice.go delivers KindHostDevice: device nodes on the executor's host,
// opened to one project.
//
// # Why this is a grant
//
// It is the same argument KindLocalRepo makes, one notch sharper. A device node
// is an authority over the machine — a serial line to whatever is plugged in, a
// GPU with its own memory and its own history of escapes, a TUN device the
// sandbox can build its own path out of — and the file that would otherwise
// carry it, .cloop/sandbox.yaml, is repo-committed. A `devices:` key there that
// could name /dev/anything would turn "merge this pull request" into "hand the
// hardware to whatever the branch says".
//
// So the operator owns the inventory and the project owns the selection. A human
// with secret.grant names the devices, out of band, scoped to one project, with a
// TTL and an audit row. A sandbox spec may then *pick* from what the project
// holds, and picking fewer is the only freedom it has.
//
// # The shape
//
// The payload is the host's device inventory, stored once. One `name=path` per
// line, with an optional access mode:
//
//	secret:  lab-hardware  ->  serial0=/dev/ttyUSB0
//	                           serial1=/dev/ttyUSB1
//	                           gpu0=/dev/nvidia0:rw
//	                           gpuctl=/dev/nvidiactl:rw
//	                           tun=/dev/net/tun:rw
//
//	grant:   subject project:/srv/projects/firmware
//	         devices serial0, gpuctl
//
// One secret per host's hardware, many grants, each opening a different slice to
// a different project. The name is what the grant and the sandbox spec refer to,
// which is what makes a grant portable: a project told it has "serial0" does not
// have to know that this node enumerates the adapter as ttyUSB3.
//
// # What this cannot do
//
// It cannot make a device appear. The grant is permission to reach hardware the
// executor's host already has, and an executor that is not on that host is
// refused at placement rather than handed a path that means something else there
// — see executor.Requirements.RequireDevices.
//
// It also cannot be taken back mid-run. A device already in a sandbox's cgroup
// and mount namespace is not reachable from outside it, exactly as a bind mount
// is not; a revoked device grant lapses when the workload exits. That is a real
// limitation and it is recorded on LeaseBinding.Devices rather than papered over:
// narrowing the window means stopping the workload.

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// MaxHostDevices bounds how many devices one grant may open.
//
// It matches executor.MaxDevices because they bound the same list at two ends of
// the same pipe, and a grant that could mint more than a Spec can carry would
// fail at dispatch with an error about the Spec rather than about the grant.
const MaxHostDevices = 16

// maxDeviceInventoryLines bounds the stored payload. A host's grantable hardware
// is a short list; a payload approaching this is not an inventory, and parsing an
// unbounded one is a memory-exhaustion primitive on a path an operator's browser
// can reach.
const maxDeviceInventoryLines = 256

// GrantedDevice is one device node a grant opens to a workload.
//
// It mirrors executor.HostDevice and is deliberately a separate type, for the
// reason RepoMount is: this package does not import pkg/executor, so that the
// broker stays a statement about authority and the executor package stays a
// statement about execution. The caller that holds both — pkg/ui — converts.
type GrantedDevice struct {
	// Name is the handle from the inventory, and what a grant's allowlist and
	// a sandbox spec's `devices:` list match against.
	Name string `json:"name"`
	// Source is the absolute device path on the executor's host.
	Source string `json:"source"`
	// Target is where it appears inside the sandbox. Equal to Source unless
	// the inventory remapped it.
	Target string `json:"target"`
	// Permissions is the rwm access string ("r", "rw", "rwm").
	Permissions string `json:"permissions"`
}

// devicePermRead and friends are the three access strings. They duplicate
// executor.DevicePermissions' values rather than importing them, for the reason
// GrantedDevice duplicates HostDevice; the round trip through pkg/ui is covered
// by a test that fails if the two sets ever diverge.
const (
	devicePermRead      = "r"
	devicePermReadWrite = "rw"
	devicePermMknod     = "rwm"
)

// hostDeviceMaterial resolves a granted inventory to the devices a project may
// reach.
func (b *Broker) hostDeviceMaterial(mat Material, plaintext []byte) (Material, error) {
	inventory, err := ParseDeviceInventory(plaintext)
	if err != nil {
		return Material{}, err
	}

	selected := make([]GrantedDevice, 0, len(inventory))
	for _, d := range inventory {
		if !matchesAny(mat.Constraints.Devices, d.Name) {
			continue
		}
		// A grant that is not writable narrows every device it opens to read.
		// The direction is the invariant: a constraint may take access away and
		// never add it, so an inventory entry recorded as "r" stays "r" even
		// under a writable grant.
		if !mat.Constraints.Writable && d.Permissions != devicePermRead {
			d.Permissions = devicePermRead
		}
		selected = append(selected, d)
		if len(selected) > MaxHostDevices {
			return Material{}, wrapf(ErrInvalidConstraint,
				"host_device grant matches more than %d devices; narrow the allowlist",
				MaxHostDevices)
		}
	}
	if len(selected) == 0 {
		// Empty is an error rather than an empty device list, for the reason the
		// local_repo path gives: the grant asserts this hardware is reachable,
		// and delivering nothing would start a harness that discovers the
		// problem as an ENOENT on a path it was told to expect.
		return Material{}, wrapf(ErrInvalidConstraint,
			"host_device grant on %s matched no device in the inventory (allowlist: %s)",
			mat.SecretName, strings.Join(mat.Constraints.Devices, ", "))
	}

	// Deterministic order: this list reaches an audit row and a Spec that
	// executorstore persists, and neither should vary between identical runs.
	sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })

	names := make([]string, 0, len(selected))
	for _, d := range selected {
		names = append(names, d.Name)
	}
	mat.Devices = selected

	// Names only, and never paths. The path is a fact about one host; the name
	// is what the project was granted and what its code refers to. A workload
	// that needs the path reads the device it was given.
	mat.Env["CLOOP_HOST_DEVICES"] = strings.Join(names, ",")
	mat.Summary = fmt.Sprintf("host devices: %s", strings.Join(names, ","))
	return mat, nil
}

// ParseDeviceInventory validates a host_device payload.
//
// Exported so that storing one of these fails in front of the person who typed
// it, with a message they can act on. It is called by `cloop secret mint` and by
// the dashboard's mint route before either stores anything.
//
// Validating early matters because the late failure is *quiet*. Broker.LeaseFor
// emits a deny row for a grant whose material will not build and continues with
// the rest (see broker.go), so a malformed inventory yields a lease that is
// simply missing its devices — and a sandbox that starts, runs, and reports on
// hardware it never had. The audit row is there for anyone who goes looking; the
// run does not fail, and nobody is looking.
func ParseDeviceInventory(payload []byte) ([]GrantedDevice, error) {
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return nil, wrapf(ErrMalformedPayload,
			"host_device payload is empty; it must be one name=/dev/path per line")
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxDeviceInventoryLines {
		return nil, wrapf(ErrMalformedPayload,
			"host_device payload has %d lines, at most %d are read", len(lines), maxDeviceInventoryLines)
	}

	out := make([]GrantedDevice, 0, len(lines))
	seenName := make(map[string]struct{}, len(lines))
	seenTarget := make(map[string]struct{}, len(lines))
	for i, raw := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d, err := parseDeviceLine(line)
		if err != nil {
			return nil, wrapf(ErrMalformedPayload, "host_device line %d: %v", i+1, err)
		}
		if _, dup := seenName[d.Name]; dup {
			return nil, wrapf(ErrMalformedPayload,
				"host_device line %d: device %q is already defined", i+1, d.Name)
		}
		seenName[d.Name] = struct{}{}
		if _, dup := seenTarget[d.Target]; dup {
			// Two entries at one sandbox path cannot both be delivered, and
			// which one wins would be decided by argv order.
			return nil, wrapf(ErrMalformedPayload,
				"host_device line %d: another device already appears at %q inside the sandbox",
				i+1, d.Target)
		}
		seenTarget[d.Target] = struct{}{}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, wrapf(ErrMalformedPayload,
			"host_device payload defines no devices; it must be one name=/dev/path per line")
	}
	return out, nil
}

// parseDeviceLine parses one "name=/dev/path[:target][:perms]" entry.
func parseDeviceLine(line string) (GrantedDevice, error) {
	name, rest, ok := strings.Cut(line, "=")
	if !ok {
		return GrantedDevice{}, fmt.Errorf("%q is not in name=/dev/path form", line)
	}
	name = strings.TrimSpace(name)
	if err := validDeviceName(name); err != nil {
		return GrantedDevice{}, err
	}

	// The remainder is source[:target][:perms]. Splitting on colon rather than
	// parsing positionally keeps the two optional fields unambiguous: a mode is
	// one of three known words, so anything else in the second slot is a path.
	fields := strings.Split(strings.TrimSpace(rest), ":")
	source := strings.TrimSpace(fields[0])
	target, perms := "", devicePermReadWrite
	switch len(fields) {
	case 1:
	case 2:
		if p, isMode := deviceMode(fields[1]); isMode {
			perms = p
		} else {
			target = strings.TrimSpace(fields[1])
		}
	case 3:
		target = strings.TrimSpace(fields[1])
		p, isMode := deviceMode(fields[2])
		if !isMode {
			return GrantedDevice{}, fmt.Errorf("device %q access mode %q is not one of %s, %s or %s",
				name, fields[2], devicePermRead, devicePermReadWrite, devicePermMknod)
		}
		perms = p
	default:
		return GrantedDevice{}, fmt.Errorf("device %q has too many colon-separated fields; "+
			"want name=/dev/source[:/dev/target][:mode]", name)
	}
	if target == "" {
		target = source
	}
	for _, f := range []struct{ field, val string }{{"source", source}, {"target", target}} {
		if err := validDevicePath(name, f.field, f.val); err != nil {
			return GrantedDevice{}, err
		}
	}
	return GrantedDevice{Name: name, Source: source, Target: target, Permissions: perms}, nil
}

// deviceMode recognises an access-mode field.
func deviceMode(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case devicePermRead:
		return devicePermRead, true
	case devicePermReadWrite:
		return devicePermReadWrite, true
	case devicePermMknod:
		return devicePermMknod, true
	}
	return "", false
}

// validDeviceName bounds the inventory handle. It is matched by a glob from a
// grant and named by a repo-committed list, so it is held to the same shape as a
// repository name — with the colon refused for the same reason.
func validDeviceName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("device name is empty")
	case len(name) > 64:
		return fmt.Errorf("device name %q exceeds 64 characters", name)
	case strings.ContainsAny(name, ":\x00\n\r/\\= "):
		return fmt.Errorf("device name %q contains a colon, slash, backslash, equals sign, "+
			"space, NUL or newline", name)
	}
	return nil
}

// validDevicePath enforces what the broker can decide about a device path
// without knowing which host will honour it.
//
// Existence is deliberately *not* checked here. A grant is minted on the hub and
// may be honoured by a container executor on another machine, so "this path
// exists" is not a question the broker can answer — the executor's Preflight
// answers it, where the answer is true or false about the right host. What is
// checked is the shape, which is host-independent and is what keeps a path from
// becoming a second flag in the runtime's argv.
func validDevicePath(name, field, p string) error {
	switch {
	case p == "":
		return fmt.Errorf("device %q has an empty %s path", name, field)
	case len(p) > 256:
		return fmt.Errorf("device %q %s path exceeds 256 characters", name, field)
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("device %q %s path %q is not absolute", name, field, p)
	case p != path.Clean(p):
		return fmt.Errorf("device %q %s path %q is not in canonical form (want %q)",
			name, field, p, path.Clean(p))
	case strings.ContainsAny(p, "\x00\n\r\\"):
		return fmt.Errorf("device %q %s path contains a backslash, NUL or newline", name, field)
	}
	// Restricted to /dev because the field's contract is a device node. A
	// regular file here would be a host bind mount wearing a device's name,
	// bypassing the local_repo grant that exists for exactly that and the
	// containment check that comes with it.
	if c := path.Clean(p); c != "/dev" && !strings.HasPrefix(c, "/dev/") {
		return fmt.Errorf("device %q %s path %q is not under /dev; grant a host file or "+
			"directory as a local_repo instead", name, field, p)
	}
	if reason := forbiddenHostDevices[path.Clean(p)]; reason != "" {
		return fmt.Errorf("device %q %s path %q %s, so granting it would waive every "+
			"isolation guarantee the sandbox provides", name, field, p, reason)
	}
	return nil
}

// forbiddenHostDevices are paths that are never a legitimate grant.
//
// It duplicates executor.forbiddenDeviceSources on purpose, at the other end of
// the pipe. Catching these at grant time puts the error in front of the person
// who typed the path, in a dialog, rather than at dispatch time in front of a
// developer who cannot fix it. The executor's copy is the one that has to hold
// against a tampered Spec; this one is the one that has to be helpful.
var forbiddenHostDevices = map[string]string{
	"/dev/mem":     "maps all of physical memory, including kernel text",
	"/dev/kmem":    "maps kernel virtual memory",
	"/dev/port":    "gives raw I/O port access",
	"/dev/kcore":   "exposes kernel memory as a core image",
	"/dev/msr":     "reads and writes model-specific CPU registers",
	"/dev/cpu":     "exposes per-CPU MSR and cpuid interfaces",
	"/dev/sda":     "is a whole host disk; grant a partition or a local_repo instead",
	"/dev/nvme0n1": "is a whole host disk; grant a partition or a local_repo instead",
	"/dev/vda":     "is a whole host disk; grant a partition or a local_repo instead",
}

// validate re-checks a device immediately before a driver receives it.
//
// Materialize calls this rather than trusting the Material it was handed, for
// the reason RepoMount.validate exists: the two can be separated by a store round
// trip, and this is a material that hands a host path verbatim to a
// root-privileged runtime CLI.
func (d GrantedDevice) validate() error {
	if err := validDeviceName(d.Name); err != nil {
		return wrapf(ErrInvalidConstraint, "%v", err)
	}
	for _, f := range []struct{ field, val string }{{"source", d.Source}, {"target", d.Target}} {
		if err := validDevicePath(d.Name, f.field, f.val); err != nil {
			return wrapf(ErrInvalidConstraint, "%v", err)
		}
	}
	if _, ok := deviceMode(d.Permissions); !ok {
		return wrapf(ErrInvalidConstraint,
			"device %q has access mode %q, want one of %s, %s or %s",
			d.Name, d.Permissions, devicePermRead, devicePermReadWrite, devicePermMknod)
	}
	return nil
}
