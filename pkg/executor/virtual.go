package executor

// virtual.go defines a virtual executor: a named sub-executor of a physical
// one, with a sandbox configuration of its own (Task 20345).
//
// # What problem this solves
//
// Before this, containment was a property of a *machine*. An enrolled device
// had one sandbox mode, one engine, one runtime, one network — so a bench host
// with a hardware security module attached could either expose that module to
// every project that ran on it, or to none. The same was true of egress: a
// device whose sandboxes could reach the lab network could not also offer a
// sandbox that could not.
//
// A virtual executor is the missing unit. It shares its parent's transport —
// the same enrolled agent, the same connection, the same fleet health — and
// carries its own answer to every containment question: engine and runtime,
// image, an IP firewall with an allowlist and a denylist, and the host devices
// its sandboxes are given. Projects bind to it like to any executor, and the
// per-executor controls that already existed — resource ceilings, the access
// list — apply to it under its own ID. So one machine can offer a locked-down
// sandbox with no network to everyone, and a hardware sandbox with the HSM in
// it to the three people allowed near the HSM.
//
// # Why a virtual executor always contains
//
// Mode is required to be container. A virtual executor that ran payloads on
// its parent's host could neither enforce its firewall — there is no
// per-workload network namespace to filter — nor withhold a device, since the
// host already has them all. It would be a second name for the parent with a
// configuration that meant nothing, and a reader of that configuration would
// believe in boundaries that were not there.

import (
	"fmt"
	"regexp"
	"strings"
)

// KindVirtual is the kind of a virtual executor.
//
// Its own kind rather than its parent's, because the actions an admin can take
// differ: a virtual executor has no binary to upgrade, no credential to revoke
// and no sandbox mode separate from its definition, and a panel that offered
// those because the kind said "remote" would offer actions that do nothing.
const KindVirtual = "virtual"

// VirtualSpec is the configuration of one virtual executor.
type VirtualSpec struct {
	// Sandbox is where and how payloads run. Mode must be container.
	Sandbox SandboxSettings `json:"sandbox"`
	// Firewall is the IP-layer egress policy for every sandbox this executor
	// starts. Nil means no firewall: the sandbox gets Sandbox.Network as-is —
	// "none" by default, which is no network at all.
	//
	// Non-nil puts each sandbox on a bridge of this executor's own, filtered
	// on the host side before any sandbox can join it; see
	// container.EgressFilter. The host needs nft(8) and the agent
	// CAP_NET_ADMIN for that, and a device that cannot filter refuses the
	// work rather than running it unfiltered.
	Firewall *FirewallRules `json:"firewall,omitempty"`
	// Devices are the host devices every sandbox of this executor is given.
	Devices []DeviceSelector `json:"devices,omitempty"`
}

// DeviceSelector names one host device a virtual executor passes through.
//
// Exactly one of USB and Path is set. USB selects by identity and is resolved
// on the device at dispatch (see usb.go for why); Path names a fixed node for
// hardware that is not USB — an on-board serial port, a GPIO chip.
type DeviceSelector struct {
	// Name identifies the device in labels, audit rows and error messages.
	Name string `json:"name"`
	// USB selects a USB device by vendor, product and optionally serial or
	// port.
	USB *USBMatch `json:"usb,omitempty"`
	// Path is a device node on the executor's host.
	Path string `json:"path,omitempty"`
	// Permissions is the access granted; empty means read-write. See
	// DevicePermissions for what the container runtime can and cannot enforce.
	Permissions DevicePermissions `json:"permissions,omitempty"`
	// Group is a supplementary group the sandbox user is given so the node's
	// own permissions let it open the device — the group a udev rule assigns
	// to it, by name or number. Empty lets the device infer it from the node
	// when it can see it. Never root's.
	Group string `json:"group,omitempty"`
	// SkipInterfaceNodes passes a USB device's usbfs node alone, without the
	// tty or hidraw nodes its interfaces created. The default passes both,
	// because which of them a tool opens is the tool's business.
	SkipInterfaceNodes bool `json:"skip_interface_nodes,omitempty"`
}

// groupNamePattern is a POSIX portable user/group name, the only shape that
// can reach a --group-add flag without being a number.
var groupNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Normalize canonicalises and validates one selector.
func (d DeviceSelector) Normalize() (DeviceSelector, error) {
	out := d
	out.Name = strings.TrimSpace(d.Name)
	out.Path = strings.TrimSpace(d.Path)
	out.Group = strings.TrimSpace(d.Group)
	if !deviceNamePattern.MatchString(out.Name) {
		return DeviceSelector{}, fmt.Errorf("%w: device name %q must be 1-64 characters of "+
			"[A-Za-z0-9._-] starting with a letter or digit", ErrInvalidSpec, d.Name)
	}
	switch {
	case d.USB != nil && out.Path != "":
		return DeviceSelector{}, fmt.Errorf("%w: device %q names both a USB device and a path; "+
			"choose one", ErrInvalidSpec, out.Name)
	case d.USB != nil:
		m, err := d.USB.Normalize()
		if err != nil {
			return DeviceSelector{}, fmt.Errorf("%w: device %q: %v", ErrInvalidSpec, out.Name, err)
		}
		out.USB = &m
	case out.Path != "":
		// The same checks a device grant gets, so a node that could never be
		// granted to a project cannot be configured onto an executor either.
		if err := ValidateHostDevice(HostDevice{Name: out.Name, Source: out.Path}); err != nil {
			return DeviceSelector{}, err
		}
		out.SkipInterfaceNodes = false
	default:
		return DeviceSelector{}, fmt.Errorf("%w: device %q names neither a USB device nor a path",
			ErrInvalidSpec, out.Name)
	}
	if p := out.Permissions; p != "" && !p.Valid() {
		return DeviceSelector{}, fmt.Errorf("%w: device %q permissions %q must be one of %q, %q or %q",
			ErrInvalidSpec, out.Name, p, DeviceRead, DeviceReadWrite, DeviceReadWriteMknod)
	}
	if out.Group != "" {
		if _, numeric, err := ParseGroupID(out.Group); numeric {
			if err != nil {
				return DeviceSelector{}, fmt.Errorf("%w: device %q: %v", ErrInvalidSpec, out.Name, err)
			}
		} else if out.Group == "root" || !groupNamePattern.MatchString(out.Group) {
			return DeviceSelector{}, fmt.Errorf("%w: device %q group %q must be a group name or number "+
				"other than root's", ErrInvalidSpec, out.Name, out.Group)
		}
	}
	return out, nil
}

// Describe renders a selector for a card or an audit row.
func (d DeviceSelector) Describe() string {
	what := d.Path
	if d.USB != nil {
		what = "usb " + d.USB.String()
	}
	s := d.Name + "=" + what
	if d.Permissions != "" && d.Permissions != DeviceReadWrite {
		s += " (" + string(d.Permissions) + ")"
	}
	return s
}

// Normalize canonicalises and validates the whole configuration.
func (v VirtualSpec) Normalize() (VirtualSpec, error) {
	if err := v.Sandbox.Validate(); err != nil {
		return VirtualSpec{}, err
	}
	out := VirtualSpec{Sandbox: v.Sandbox.Normalize()}
	if out.Sandbox.Mode != SandboxModeContainer {
		return VirtualSpec{}, fmt.Errorf("%w: a virtual executor runs its payloads in a container "+
			"(mode %q); host mode could enforce neither its firewall nor its device list",
			ErrInvalidSpec, SandboxModeContainer)
	}

	if v.Firewall != nil {
		fw, err := v.Firewall.Normalize()
		if err != nil {
			return VirtualSpec{}, err
		}
		out.Firewall = &fw
		// The firewall owns the network: every sandbox of this executor joins
		// a bridge of its own, and that bridge is what the rules are
		// installed on. A named network is somebody else's and cannot be
		// filtered without filtering them too; "none" contradicts having a
		// firewall at all.
		switch out.Sandbox.Network {
		case "", SandboxNetworkBridge:
			out.Sandbox.Network = ""
		default:
			return VirtualSpec{}, fmt.Errorf("%w: a virtual executor with a firewall runs its sandboxes "+
				"on a filtered bridge of its own, so its network must be left unset (got %q); remove "+
				"the firewall to use %q", ErrInvalidSpec, out.Sandbox.Network, out.Sandbox.Network)
		}
	}

	if len(v.Devices) > MaxDevices {
		return VirtualSpec{}, fmt.Errorf("%w: %d devices, at most %d are allowed",
			ErrInvalidSpec, len(v.Devices), MaxDevices)
	}
	seen := map[string]bool{}
	for _, d := range v.Devices {
		nd, err := d.Normalize()
		if err != nil {
			return VirtualSpec{}, err
		}
		if seen[nd.Name] {
			return VirtualSpec{}, fmt.Errorf("%w: device %q is listed twice", ErrInvalidSpec, nd.Name)
		}
		seen[nd.Name] = true
		out.Devices = append(out.Devices, nd)
	}
	if len(out.Devices) > 0 && IsKernelIsolatedRuntime(out.Sandbox.Runtime) {
		// Measured, not assumed (sgx, 2026-09-27): under runsc the node is
		// created in the sandbox and every open of it fails with ENXIO, and
		// /sys/bus/usb does not exist for libusb to enumerate. Kata can only
		// hand a guest devices through VFIO. Either way the sandbox would start,
		// look configured, and be unable to touch the hardware it was for.
		return VirtualSpec{}, fmt.Errorf("%w: the %q runtime serves device files from its own kernel, "+
			"so a host device passed to it cannot be opened; use the engine's default runtime (runc "+
			"or crun) for a virtual executor with devices, and put untrusted work on another one",
			ErrInvalidSpec, out.Sandbox.Runtime)
	}
	return out, nil
}

// Validate reports whether the configuration is admissible.
func (v VirtualSpec) Validate() error {
	_, err := v.Normalize()
	return err
}

// Describe renders the configuration for an audit row or a log line.
func (v VirtualSpec) Describe() string {
	parts := []string{v.Sandbox.Describe()}
	if v.Firewall != nil {
		parts = append(parts, "firewall: "+v.Firewall.Describe())
	}
	if len(v.Devices) > 0 {
		ds := make([]string, len(v.Devices))
		for i, d := range v.Devices {
			ds[i] = d.Describe()
		}
		parts = append(parts, "devices: "+strings.Join(ds, ", "))
	}
	return strings.Join(parts, "; ")
}

// FilteredEgress reports whether this configuration bounds egress at the IP
// layer.
func (v VirtualSpec) FilteredEgress() bool { return v.Firewall != nil }

// NetworkEgress reports whether sandboxes under this configuration have a
// network to reach anything through.
func (v VirtualSpec) NetworkEgress() bool {
	if v.Firewall != nil {
		return v.Firewall.HasDestination()
	}
	n := strings.TrimSpace(v.Sandbox.Network)
	return n != "" && n != SandboxNetworkNone
}
