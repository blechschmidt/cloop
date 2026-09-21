package secretbroker

// hostinterface.go delivers KindHostInterface: network interfaces on the
// executor's host, moved into one project's sandbox.
//
// # Why this is a grant
//
// It is KindHostDevice's argument with the stakes raised. A device node hands
// over a piece of hardware; an interface hands over a seat on a network
// segment, and whoever holds it can speak arbitrary Ethernet there, answer ARP
// for addresses that are not theirs, and see every frame the segment carries.
// On a lab VLAN wired to a board under test that is precisely the point. On the
// host's uplink it is the machine.
//
// And the file that would otherwise carry it, .cloop/sandbox.yaml, is
// repo-committed. An `interfaces:` key there that could name any netdev would
// turn "merge this pull request" into "hand over the network" — with the extra
// property, which no other grant has, that the host *loses* the interface for
// the duration. So the operator owns the inventory and the project owns the
// selection.
//
// # The shape
//
// The payload is the host's interface inventory, stored once. One entry per
// line, `name=ifname` with optional comma-separated attributes:
//
//	secret:  bench-net  ->  dut=cloop-lab0,target=eth1,address=172.31.99.200/24
//	                        can0=enp3s0,target=eth1
//	                        capture=enp4s0f1
//
//	grant:   subject project:/srv/projects/firmware
//	         interfaces dut
//
// Comma-separated key=value rather than the colon-delimited form
// ParseDeviceInventory uses, because an address is a field here and a v6
// address is full of colons. The two formats differ for a reason that shows up
// the first time someone writes fd00::10/64.
//
// # What this cannot do
//
// It cannot make an interface appear, and it cannot be honoured by an executor
// that is not on the machine the interface is attached to — that is a placement
// refusal (executor.Requirements.RequireInterfaces), not a runtime surprise.
//
// It also cannot be taken back mid-run: an interface inside a running sandbox's
// network namespace is not reachable from outside it, so a revoked grant lapses
// when the workload exits. Recorded on LeaseBinding.Interfaces rather than
// papered over, exactly as the device path records the same limitation.

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxHostInterfaces bounds how many interfaces one grant may open.
//
// It matches executor.MaxInterfaces because they bound the same list at two
// ends of the same pipe, and a grant that could mint more than a Spec can carry
// would fail at dispatch with an error about the Spec rather than the grant.
const MaxHostInterfaces = 8

// maxInterfaceInventoryLines bounds the stored payload, for the reason
// maxDeviceInventoryLines does: a host's grantable interfaces are a short list,
// and parsing an unbounded one is a memory-exhaustion primitive on a path an
// operator's browser can reach.
const maxInterfaceInventoryLines = 256

// GrantedInterface is one network interface a grant moves into a sandbox.
//
// It mirrors executor.HostInterface and is deliberately a separate type, for
// the reason GrantedDevice mirrors HostDevice: this package does not import
// pkg/executor, so the broker stays a statement about authority and the
// executor package stays a statement about execution. The caller that holds
// both — pkg/ui — converts.
type GrantedInterface struct {
	// Name is the handle from the inventory, and what a grant's allowlist and
	// a sandbox spec's `interfaces:` list match against.
	Name string `json:"name"`
	// Source is the interface's name on the executor's host.
	Source string `json:"source"`
	// Target is the name it takes inside the sandbox. Equal to Source unless
	// the inventory renamed it.
	Target string `json:"target"`
	// Address is the optional CIDR to configure inside the sandbox.
	Address string `json:"address,omitempty"`
	// Gateway is the optional default route to install through it.
	Gateway string `json:"gateway,omitempty"`
	// MTU optionally overrides the interface's MTU. Zero means leave it.
	MTU int `json:"mtu,omitempty"`
}

// hostInterfaceMaterial resolves a granted inventory to the interfaces a
// project may claim.
func (b *Broker) hostInterfaceMaterial(mat Material, plaintext []byte) (Material, error) {
	inventory, err := ParseInterfaceInventory(plaintext)
	if err != nil {
		return Material{}, err
	}

	selected := make([]GrantedInterface, 0, len(inventory))
	for _, n := range inventory {
		if !matchesAny(mat.Constraints.Interfaces, n.Name) {
			continue
		}
		selected = append(selected, n)
		if len(selected) > MaxHostInterfaces {
			return Material{}, wrapf(ErrInvalidConstraint,
				"host_interface grant matches more than %d interfaces; narrow the allowlist",
				MaxHostInterfaces)
		}
	}
	if len(selected) == 0 {
		// Empty is an error rather than an empty list, for the reason the
		// device path gives: the grant asserts this segment is reachable, and
		// delivering nothing would start a harness that discovers the problem
		// as a missing link on an interface it was told to bind.
		return Material{}, wrapf(ErrInvalidConstraint,
			"host_interface grant on %s matched no interface in the inventory (allowlist: %s)",
			mat.SecretName, strings.Join(mat.Constraints.Interfaces, ", "))
	}

	// Deterministic order: this list reaches an audit row and a Spec that
	// executorstore persists, and neither should vary between identical runs.
	sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })

	names := make([]string, 0, len(selected))
	for _, n := range selected {
		names = append(names, n.Name)
	}
	mat.Interfaces = selected

	// Grant handles, never host interface names. The host's name for a netdev
	// is a fact about one bench; the handle is what the project was granted.
	// A workload that needs the sandbox-side name has it: the interface is in
	// its own namespace under the target name, which it can enumerate.
	mat.Env["CLOOP_HOST_INTERFACES"] = strings.Join(names, ",")
	mat.Summary = fmt.Sprintf("host interfaces: %s", strings.Join(names, ","))
	return mat, nil
}

// ParseInterfaceInventory validates a host_interface payload.
//
// Exported so that storing one fails in front of the person who typed it, with
// a message they can act on — `cloop secret mint` and the dashboard's mint
// route both call it before anything is stored.
//
// Validating early matters more here than anywhere else, because the late
// failure is both quiet and destructive. Broker.LeaseFor emits a deny row for a
// grant whose material will not build and continues with the rest, so a
// malformed inventory yields a sandbox that starts with no wire in it; and an
// inventory naming the *wrong* interface is not caught by any amount of
// retrying, because by then the host has already handed it over.
func ParseInterfaceInventory(payload []byte) ([]GrantedInterface, error) {
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return nil, wrapf(ErrMalformedPayload,
			"host_interface payload is empty; it must be one name=ifname per line")
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxInterfaceInventoryLines {
		return nil, wrapf(ErrMalformedPayload,
			"host_interface payload has %d lines, at most %d are read",
			len(lines), maxInterfaceInventoryLines)
	}

	out := make([]GrantedInterface, 0, len(lines))
	seenName := make(map[string]struct{}, len(lines))
	seenSource := make(map[string]struct{}, len(lines))
	seenTarget := make(map[string]struct{}, len(lines))
	for i, raw := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := parseInterfaceLine(line)
		if err != nil {
			return nil, wrapf(ErrMalformedPayload, "host_interface line %d: %v", i+1, err)
		}
		if _, dup := seenName[n.Name]; dup {
			return nil, wrapf(ErrMalformedPayload,
				"host_interface line %d: interface %q is already defined", i+1, n.Name)
		}
		seenName[n.Name] = struct{}{}
		if _, dup := seenSource[n.Source]; dup {
			// A netdev lives in exactly one namespace, so two handles for one
			// host interface are not two seats: the second move would fail and
			// which handle won would be decided by ordering.
			return nil, wrapf(ErrMalformedPayload,
				"host_interface line %d: host interface %q is already claimed by another "+
					"entry; an interface can only be moved into one sandbox", i+1, n.Source)
		}
		seenSource[n.Source] = struct{}{}
		if _, dup := seenTarget[n.Target]; dup {
			return nil, wrapf(ErrMalformedPayload,
				"host_interface line %d: another interface already appears as %q inside the "+
					"sandbox", i+1, n.Target)
		}
		seenTarget[n.Target] = struct{}{}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, wrapf(ErrMalformedPayload,
			"host_interface payload defines no interfaces; it must be one name=ifname per line")
	}
	return out, nil
}

// parseInterfaceLine parses one "name=ifname[,key=value...]" entry.
func parseInterfaceLine(line string) (GrantedInterface, error) {
	fields := strings.Split(line, ",")
	head := strings.TrimSpace(fields[0])
	name, source, ok := strings.Cut(head, "=")
	if !ok {
		return GrantedInterface{}, fmt.Errorf("%q is not in name=ifname form", line)
	}
	n := GrantedInterface{
		Name:   strings.TrimSpace(name),
		Source: strings.TrimSpace(source),
	}
	if err := validInterfaceHandle(n.Name); err != nil {
		return GrantedInterface{}, err
	}

	for _, f := range fields[1:] {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		key, val, hasVal := strings.Cut(f, "=")
		if !hasVal {
			return GrantedInterface{}, fmt.Errorf(
				"interface %q attribute %q is not in key=value form (want target=, address=, "+
					"gateway= or mtu=)", n.Name, f)
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		switch key {
		case "target":
			n.Target = val
		case "address", "addr":
			n.Address = val
		case "gateway", "gw":
			n.Gateway = val
		case "mtu":
			mtu, err := strconv.Atoi(val)
			if err != nil {
				return GrantedInterface{}, fmt.Errorf("interface %q mtu %q is not a number",
					n.Name, val)
			}
			n.MTU = mtu
		default:
			// Unknown keys are refused rather than ignored: a typo'd
			// "addres=" that is silently dropped produces a sandbox whose
			// interface is up and unaddressed, which looks like a cabling
			// fault rather than a typo.
			return GrantedInterface{}, fmt.Errorf(
				"interface %q has unknown attribute %q (want target, address, gateway or mtu)",
				n.Name, key)
		}
	}
	if n.Target == "" {
		n.Target = n.Source
	}
	if err := n.validate(); err != nil {
		return GrantedInterface{}, err
	}
	return n, nil
}

// validInterfaceHandle bounds the inventory handle. Matched by a glob from a
// grant and named by a repo-committed list, so it is held to the same shape as
// a device handle, with '=' and ',' refused because the inventory format reads
// them as separators.
func validInterfaceHandle(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("interface name is empty")
	case len(name) > 64:
		return fmt.Errorf("interface name %q exceeds 64 characters", name)
	case strings.ContainsAny(name, ":\x00\n\r/\\= ,"):
		return fmt.Errorf("interface name %q contains a colon, comma, slash, backslash, "+
			"equals sign, space, NUL or newline", name)
	}
	return nil
}

// forbiddenHostInterfaces are interfaces that are never a legitimate grant.
//
// It duplicates executor.forbiddenInterfaceSources on purpose, at the other end
// of the pipe, for the reason forbiddenHostDevices does: catching these at
// grant time puts the error in front of the person who typed the name, in a
// dialog, rather than at dispatch time in front of a developer who cannot fix
// it — and in this case before a host has handed away the interface it is
// reachable on. The executor's copy is the one that has to hold against a
// tampered Spec; this one is the one that has to be helpful.
var forbiddenHostInterfaces = map[string]string{
	"lo":          "is the loopback device; the host and every container on it would lose 127.0.0.1",
	"docker0":     "is Docker's own bridge; moving it would disconnect every container on this host",
	"podman0":     "is Podman's own bridge; moving it would disconnect every container on this host",
	"cni-podman0": "is Podman's CNI bridge; moving it would disconnect every container on this host",
	"virbr0":      "is libvirt's bridge; moving it would disconnect every VM on this host",
}

// validate re-checks an interface immediately before a driver receives it, and
// at parse time.
//
// Materialize calls this rather than trusting the Material it was handed, for
// the reason GrantedDevice.validate exists: the two can be separated by a store
// round trip, and this is material that names a netdev a root-privileged
// process is about to move out of the host's namespace.
//
// Existence is deliberately not checked, here or at parse time. The interface
// may belong to a container executor on another host, so "does this exist" is a
// question about the wrong machine; the driver's attach path asks it on the
// right one, where it can also ask the question that actually protects the host
// — whether this is the interface the default route goes out of.
func (n GrantedInterface) validate() error {
	if err := validInterfaceHandle(n.Name); err != nil {
		return wrapf(ErrInvalidConstraint, "%v", err)
	}
	for _, f := range []struct{ field, val string }{{"source", n.Source}, {"target", n.Target}} {
		if err := validIfaceDeviceName(n.Name, f.field, f.val); err != nil {
			return wrapf(ErrInvalidConstraint, "%v", err)
		}
	}
	if reason := forbiddenHostInterfaces[n.Source]; reason != "" {
		return wrapf(ErrInvalidConstraint,
			"interface %q source %q %s", n.Name, n.Source, reason)
	}
	if strings.HasPrefix(n.Source, "br-") {
		return wrapf(ErrInvalidConstraint,
			"interface %q source %q is a Docker per-network bridge; grant a veth end attached "+
				"to it instead of the bridge itself", n.Name, n.Source)
	}
	if n.Address != "" {
		if err := validCIDR(n.Name, n.Address); err != nil {
			return wrapf(ErrInvalidConstraint, "%v", err)
		}
	}
	if n.Gateway != "" {
		if n.Address == "" {
			return wrapf(ErrInvalidConstraint,
				"interface %q has a gateway but no address; a default route through it is "+
					"unreachable until the interface is addressed", n.Name)
		}
		if err := validIP(n.Name, n.Gateway); err != nil {
			return wrapf(ErrInvalidConstraint, "%v", err)
		}
	}
	if n.MTU != 0 && (n.MTU < 68 || n.MTU > 65536) {
		return wrapf(ErrInvalidConstraint,
			"interface %q mtu %d is outside 68-65536", n.Name, n.MTU)
	}
	return nil
}

// validCIDR checks an address-with-prefix-length, which is what an interface
// takes — as opposed to a bare address, which is what a gateway takes.
func validCIDR(grant, s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("interface %q address %q is not an address with a prefix length "+
			"(want 172.31.99.200/24 or fd00::10/64)", grant, s)
	}
	if !p.Addr().IsValid() || p.Addr().IsUnspecified() {
		return fmt.Errorf("interface %q address %q has no host part", grant, s)
	}
	return nil
}

// validIP checks a bare address for the gateway field.
func validIP(grant, s string) error {
	if _, err := netip.ParseAddr(s); err != nil {
		return fmt.Errorf("interface %q gateway %q is not an IP address", grant, s)
	}
	return nil
}

// validIfaceDeviceName enforces what the kernel requires of a netdev name and
// what the argv requires of a token.
//
// It duplicates executor.validateIfaceName at the other end of the pipe, for
// the reason validDevicePath duplicates its executor-side twin.
func validIfaceDeviceName(grant, field, raw string) error {
	n := strings.TrimSpace(raw)
	switch {
	case n == "":
		return fmt.Errorf("interface %q has an empty %s name", grant, field)
	case len(n) > 15:
		return fmt.Errorf("interface %q %s name %q is %d characters; the kernel allows at "+
			"most 15", grant, field, n, len(n))
	case n == "." || n == "..":
		return fmt.Errorf("interface %q %s name %q is not a usable device name", grant, field, n)
	case strings.ContainsAny(n, "/ \t\n\r\x00"):
		return fmt.Errorf("interface %q %s name %q contains a slash, whitespace or NUL",
			grant, field, n)
	case strings.Contains(n, ":"):
		return fmt.Errorf("interface %q %s name %q contains ':', which ip(8) reads as an "+
			"alias separator", grant, field, n)
	case strings.ContainsAny(n, "=,"):
		return fmt.Errorf("interface %q %s name %q contains '=' or ',', which the interface "+
			"inventory reads as field separators", grant, field, n)
	case strings.HasPrefix(n, "-"):
		return fmt.Errorf("interface %q %s name %q starts with '-', which would be read as a "+
			"command-line flag", grant, field, n)
	}
	return nil
}
