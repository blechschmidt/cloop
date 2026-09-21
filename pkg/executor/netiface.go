package executor

// netiface.go carries a host network interface into a sandbox.
//
// # What this is for
//
// A device.go grant opens a character device — a serial line, a GPU, a TPM.
// This one opens something the `--device` flag cannot express at all: a network
// interface. A netdev is not a node under /dev, so there is no path to bind and
// no cgroup rule to write. It is an object owned by a network namespace, and
// the only way to put one inside a sandbox is to move it there.
//
// The case that motivates it is hardware debugging. A machine wired to a device
// under test — a board on a lab VLAN, an ECU on an automotive bus, a radio on
// its own segment — is useful as a remote executor exactly to the extent that
// the sandbox can reach what the machine is plugged into. Reaching it at L3
// through the host's routing table is not the same thing: ARP, DHCP, PTP, raw
// Ethernet and every link-layer protocol a bring-up engineer needs live below
// the layer a route can carry. Handing the interface itself over is what makes
// those work, and it is why this is L2 passthrough rather than another egress
// rule.
//
// # Why this is a grant, and shaped exactly like device.go
//
// Because it is the same authority argument, and if anything a sharper one. An
// interface is a seat on a network segment: whoever holds it can speak
// arbitrary Ethernet on it, answer ARP for addresses that are not theirs, and
// see every frame the segment delivers. On a lab VLAN that is the point; on the
// host's uplink it is the whole machine.
//
// So the shape follows KindHostDevice, which follows KindLocalRepo: an operator
// names the interfaces out of band, scoped to one project, with a TTL and an
// audit row, and the repo-committed .cloop/sandbox.yaml may only *select* from
// what the project was already granted. Nothing that parses a file from a pull
// request can widen the set.
//
// # The two ways this differs from a device, which the whole design turns on
//
// First: moving a netdev is destructive to the host while the sandbox holds it.
// A device node stays where it is and the sandbox gets a second reference; an
// interface *leaves* the host's namespace and the host can no longer use it.
// Granting the wrong one does not leak access, it severs the machine — which is
// why forbiddenInterfaceSources exists and why the driver additionally refuses
// the interface carrying the host's default route at attach time, where the
// routing table can actually be read (see Capabilities.SupportsInterfaces).
//
// Second: the kernel decides what happens on teardown, not cloop. When a
// network namespace is destroyed the kernel returns *physical* devices to the
// initial namespace and *deletes* virtual ones — veth, macvlan, vlan. So a
// passed-through NIC comes home by itself, and a passed-through veth end does
// not: it is destroyed, taking its peer with it. Drivers restore what they can
// on a graceful stop; the rest is a kernel property that is documented rather
// than papered over.

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxInterfaces bounds how many interfaces one workload may be given.
//
// Lower than MaxDevices because the resource is scarcer and the blast radius
// larger: each entry is a segment the host gives up for the life of the run,
// and a spec asking for more than a handful is describing a router rather than
// a sandbox with a wire in it.
const MaxInterfaces = 8

// maxIfaceNameLen is IFNAMSIZ-1. The kernel will not accept a longer name, and
// finding that out from `ip link` is a worse error than finding it out here.
const maxIfaceNameLen = 15

// HostInterface is one network interface moved from the executor's host into
// the sandbox's network namespace.
//
// Source and Target are separate for the reason HostDevice's are: the
// sandbox-visible name is part of what makes a grant portable. A project told
// to bind "eth1" should not have to know that this particular bench enumerates
// the adapter as enp0s31f6, and its code should not change when it moves to a
// bench that enumerates it differently.
type HostInterface struct {
	// Name identifies the interface within its grant, for diagnostics and for
	// the `interfaces:` selector in a sandbox spec. It is not an interface
	// name: it is a handle, and may be longer and more descriptive than the
	// kernel would allow a netdev to be.
	Name string `json:"name"`
	// Source is the interface's name on the executor's host.
	Source string `json:"source"`
	// Target is the name it takes inside the sandbox. Empty means keep
	// Source's name.
	//
	// Renaming is worth supporting because the host's name is frequently
	// unusable as a contract: a veth end is named for the pair that created
	// it, and a predictable-network-name NIC is named for its PCI path.
	Target string `json:"target,omitempty"`
	// Address is an optional CIDR to configure on the interface inside the
	// sandbox ("172.31.99.200/24", "fd00::10/64").
	//
	// Optional because the two sensible regimes are both real: a bench with a
	// DHCP server on it wants the sandbox to ask, and a bench without one
	// wants the operator to have decided. Empty means the interface arrives
	// up and unaddressed, which is also what a workload doing raw L2 wants.
	Address string `json:"address,omitempty"`
	// Gateway is an optional default route to install inside the sandbox via
	// this interface. Meaningless without Address and refused without it.
	//
	// Note what this does: it makes the sandbox's default route point at the
	// bench rather than at the runtime's own network. That is usually the
	// intent for an isolated segment and never the intent for a workload that
	// also needs the Internet, so it is opt-in per interface.
	Gateway string `json:"gateway,omitempty"`
	// MTU optionally overrides the interface's MTU inside the sandbox. Zero
	// means leave the kernel's value alone. Jumbo frames on a capture segment
	// are the common reason to set it.
	MTU int `json:"mtu,omitempty"`
	// LeaseID is the secret lease that authorised this interface, so
	// revocation can find it and the audit trail can say who opened it. Empty
	// is permitted only for an interface an operator configured directly on
	// the executor, which is not a path any project-scoped grant takes.
	LeaseID string `json:"lease_id,omitempty"`
}

// EffectiveTarget is the interface's name inside the sandbox.
func (i HostInterface) EffectiveTarget() string {
	if t := strings.TrimSpace(i.Target); t != "" {
		return t
	}
	return strings.TrimSpace(i.Source)
}

// ifaceHandlePattern bounds the grant handle. Same shape as a device name: it
// lands in labels, audit rows and a YAML list.
var ifaceHandlePattern = deviceNamePattern

// forbiddenInterfaceSources are interfaces that are never a legitimate grant,
// because moving one does not expose a segment — it dismantles the host.
//
// This is the netdev counterpart of forbiddenDeviceSources and it is here for a
// sharper reason. A device grant that names the wrong node gives a sandbox
// access it should not have; an interface grant that names the wrong netdev
// *takes the interface away from the host*, because a netdev lives in exactly
// one namespace at a time. Getting it wrong does not widen a boundary, it
// severs the machine — and on a remote executor that means losing the machine.
//
// Each entry is an interface whose removal breaks the host or the container
// runtime itself rather than exposing anything.
var forbiddenInterfaceSources = map[string]string{
	"lo":          "is the loopback device; the host and every container on it would lose 127.0.0.1",
	"docker0":     "is Docker's own bridge; moving it would disconnect every container on this host",
	"podman0":     "is Podman's own bridge; moving it would disconnect every container on this host",
	"cni-podman0": "is Podman's CNI bridge; moving it would disconnect every container on this host",
	"virbr0":      "is libvirt's bridge; moving it would disconnect every VM on this host",
}

// forbiddenInterfacePrefixes catch the generated names in the same families.
//
// "br-" is Docker's per-network bridge. An operator reaching for one has
// usually confused the two halves of the recipe: the bridge is what the
// sandbox's peer should be *attached to*, and the thing that gets moved is a
// veth end plugged into it. The error says so, because the difference between
// the two is the difference between a working bench and a host that has just
// dropped every container's network.
var forbiddenInterfacePrefixes = map[string]string{
	"br-": "is a Docker per-network bridge; move a veth end attached to it instead of the bridge itself",
}

// ValidateHostInterface checks one interface grant.
//
// Exported for the reason ValidateHostDevice is: the broker needs the same
// answer at grant time (so the mistake reaches the person who can fix it), the
// drivers need it before they touch a netlink socket, and Spec.Validate needs
// it on the dispatch path. One definition means an interface that passes at
// grant time cannot be refused two layers down.
//
// What it deliberately does not check is whether the interface exists, or what
// it is attached to. Both are facts about one host, and a grant minted on the
// hub may be honoured by an executor on another machine — so they belong to
// Preflight and to the driver's attach path, which run on the right one.
func ValidateHostInterface(i HostInterface) error {
	name := strings.TrimSpace(i.Name)
	if name == "" {
		return fmt.Errorf("%w: interface name is empty", ErrInvalidSpec)
	}
	if !ifaceHandlePattern.MatchString(name) {
		return fmt.Errorf("%w: interface name %q must be 1-64 characters of [A-Za-z0-9._-] "+
			"starting with a letter or digit", ErrInvalidSpec, name)
	}
	if err := validateIfaceName(name, "source", i.Source); err != nil {
		return err
	}
	src := strings.TrimSpace(i.Source)
	if reason := forbiddenInterfaceSources[src]; reason != "" {
		return fmt.Errorf("%w: interface %q source %q %s", ErrInvalidSpec, name, src, reason)
	}
	for prefix, reason := range forbiddenInterfacePrefixes {
		if strings.HasPrefix(src, prefix) {
			return fmt.Errorf("%w: interface %q source %q %s", ErrInvalidSpec, name, src, reason)
		}
	}
	if t := strings.TrimSpace(i.Target); t != "" {
		if err := validateIfaceName(name, "target", t); err != nil {
			return err
		}
		// The target is a name inside the sandbox, so the host's bridges are
		// not at stake — but "lo" is, in every namespace. Renaming an
		// interface onto the loopback's name is refused by the kernel anyway;
		// saying so here produces an error that names the grant.
		if t == "lo" {
			return fmt.Errorf("%w: interface %q target %q would collide with the sandbox's "+
				"own loopback device", ErrInvalidSpec, name, t)
		}
	}
	if a := strings.TrimSpace(i.Address); a != "" {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("%w: interface %q address %q is not an address with a prefix "+
				"length (want 172.31.99.200/24 or fd00::10/64)", ErrInvalidSpec, name, a)
		}
		if !p.Addr().IsValid() || p.Addr().IsUnspecified() {
			return fmt.Errorf("%w: interface %q address %q has no host part",
				ErrInvalidSpec, name, a)
		}
	}
	if g := strings.TrimSpace(i.Gateway); g != "" {
		if strings.TrimSpace(i.Address) == "" {
			// A route needs a source address to be reachable from, and the
			// kernel's error for this ("Nexthop has invalid gateway") names
			// neither the interface nor the grant.
			return fmt.Errorf("%w: interface %q has a gateway but no address; a default route "+
				"through it is unreachable until the interface is addressed",
				ErrInvalidSpec, name)
		}
		gw, err := netip.ParseAddr(g)
		if err != nil {
			return fmt.Errorf("%w: interface %q gateway %q is not an IP address",
				ErrInvalidSpec, name, g)
		}
		p, perr := netip.ParsePrefix(strings.TrimSpace(i.Address))
		if perr == nil && gw.Is4() != p.Addr().Is4() {
			return fmt.Errorf("%w: interface %q gateway %q and address %q are different "+
				"address families", ErrInvalidSpec, name, g, i.Address)
		}
	}
	if i.MTU != 0 && (i.MTU < 68 || i.MTU > 65536) {
		// 68 is the IPv4 minimum an interface must carry; 65536 is the
		// kernel's ceiling. Outside that range `ip link set mtu` fails with an
		// errno and no mention of which grant asked for it.
		return fmt.Errorf("%w: interface %q mtu %d is outside 68-65536",
			ErrInvalidSpec, name, i.MTU)
	}
	return nil
}

// validateIfaceName enforces what the kernel and the argv both require of a
// netdev name.
func validateIfaceName(grant, field, raw string) error {
	n := strings.TrimSpace(raw)
	switch {
	case n == "":
		return fmt.Errorf("%w: interface %q has an empty %s name", ErrInvalidSpec, grant, field)
	case len(n) > maxIfaceNameLen:
		// IFNAMSIZ is 16 including the terminator, so this is the kernel's own
		// limit rather than a policy of ours.
		return fmt.Errorf("%w: interface %q %s name %q is %d characters; the kernel allows "+
			"at most %d", ErrInvalidSpec, grant, field, n, len(n), maxIfaceNameLen)
	case n == "." || n == "..":
		// The kernel refuses these because netdev names become entries under
		// /sys/class/net.
		return fmt.Errorf("%w: interface %q %s name %q is not a usable device name",
			ErrInvalidSpec, grant, field, n)
	case strings.ContainsAny(n, "/ \t\n\r\x00"):
		return fmt.Errorf("%w: interface %q %s name %q contains a slash, whitespace or NUL",
			ErrInvalidSpec, grant, field, n)
	case strings.Contains(n, ":"):
		// `ip` reads name:label as an alias, so a colon would silently address
		// a different object than the grant names.
		return fmt.Errorf("%w: interface %q %s name %q contains ':', which ip(8) reads as an "+
			"alias separator", ErrInvalidSpec, grant, field, n)
	case strings.ContainsAny(n, "=,"):
		// Both are field separators in the inventory format this round-trips
		// through, so a name containing one could not be written down.
		return fmt.Errorf("%w: interface %q %s name %q contains '=' or ',', which the "+
			"interface inventory reads as field separators", ErrInvalidSpec, grant, field, n)
	case strings.HasPrefix(n, "-"):
		// A leading dash makes the name indistinguishable from a flag in the
		// argv it is rendered into.
		return fmt.Errorf("%w: interface %q %s name %q starts with '-', which would be read "+
			"as a command-line flag", ErrInvalidSpec, grant, field, n)
	}
	return nil
}

// ValidateInterfaces checks a whole interface list: each entry, the count, and
// the two collision classes that would otherwise be resolved by ordering.
func ValidateInterfaces(ifaces []HostInterface) error {
	if len(ifaces) > MaxInterfaces {
		return fmt.Errorf("%w: %d interfaces requested, at most %d are allowed",
			ErrInvalidSpec, len(ifaces), MaxInterfaces)
	}
	seenName := make(map[string]struct{}, len(ifaces))
	seenSource := make(map[string]struct{}, len(ifaces))
	seenTarget := make(map[string]struct{}, len(ifaces))
	for _, i := range ifaces {
		if err := ValidateHostInterface(i); err != nil {
			return err
		}
		name := strings.TrimSpace(i.Name)
		if _, dup := seenName[name]; dup {
			return fmt.Errorf("%w: interface %q is listed twice", ErrInvalidSpec, name)
		}
		seenName[name] = struct{}{}

		// Two grants naming one host interface is not two seats on a segment:
		// a netdev lives in one namespace, so the second move would fail and
		// which grant got it would be decided by ordering. Devices do not have
		// this class of collision at all, which is why ValidateDevices does
		// not check the source side.
		src := strings.TrimSpace(i.Source)
		if _, dup := seenSource[src]; dup {
			return fmt.Errorf("%w: host interface %q is claimed by two grants; an interface "+
				"can only be moved into one namespace", ErrInvalidSpec, src)
		}
		seenSource[src] = struct{}{}

		target := i.EffectiveTarget()
		if _, dup := seenTarget[target]; dup {
			return fmt.Errorf("%w: two interfaces both appear as %q inside the sandbox",
				ErrInvalidSpec, target)
		}
		seenTarget[target] = struct{}{}
	}
	return nil
}

// InterfaceNames returns the grant-facing names of an interface list, in order,
// for log lines and audit records.
func InterfaceNames(ifaces []HostInterface) []string {
	if len(ifaces) == 0 {
		return nil
	}
	out := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, strings.TrimSpace(i.Name))
	}
	return out
}
