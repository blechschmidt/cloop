package executor

// forwarded.go carries the devices a device forwarder brings in from an
// on-prem machine to the run whose project they are bound to (Task 20430).
//
// A forwarder (pkg/deviceforward) holds one USB device or one network
// interface on a machine the cloud cannot reach, and dials the hub. A binding
// — an operator's decision, with a TTL and an audit row — makes it available to
// one project's runs. At dispatch the hub puts one ForwardedDevice per bound
// forwarder on the Spec, and the driver that starts the sandbox attaches it on
// the machine the sandbox runs on: an executor agent over its own tunnel, the
// hub for a container on its own host. Nothing listens anywhere on either.
//
// Unlike Devices and Interfaces this field names no host path or host
// interface: the device does not exist on the executor until the driver
// attaches it, and what it attaches as (a vhci-attached USB device, a TAP) is
// the driver's to decide and to give the sandbox. What the Spec carries is the
// way to reach it — Open — and the sandbox-side shape the binding chose.
//
// Open is json:"-" like SecretFiles and ProjectSeed, and for the strongest of
// their reasons: it is a live stream to hardware, which no handle store, audit
// row or reconcile pass may persist or replay.

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Kinds of forwarded device, matching the forwarder's own.
const (
	ForwardedUSB = "usb"
	ForwardedL2  = "l2"
)

// MaxForwardedDevices bounds how many forwarded devices one run may be given.
// Each is a live relay held open for the life of the run; a project asking for
// more than this is describing a lab, not a sandbox with hardware in it.
const MaxForwardedDevices = 8

// ForwardedStream is an open stream to a forwarder's device.
type ForwardedStream struct {
	io.ReadWriteCloser
	// BusID is, for a USB device, the bus id the forwarder exports it as —
	// what the consumer's USB/IP import must name.
	BusID string
}

// ForwardedDevice is one forwarded device bound to a run's project.
type ForwardedDevice struct {
	// BindingID is the binding that authorised it, for the audit trail and so
	// a revocation can find the run holding it.
	BindingID string `json:"binding_id"`
	// ForwarderID identifies the forwarder carrying it.
	ForwarderID string `json:"forwarder_id"`
	// Name is the sandbox-facing handle, the HostDevice or HostInterface name
	// the device is given under.
	Name string `json:"name"`
	// Kind is ForwardedUSB or ForwardedL2.
	Kind string `json:"kind"`
	// Label is the forwarder's operator-facing description, for logs and
	// refusals.
	Label string `json:"label,omitempty"`
	// Interface, for an L2 device, is how the sandbox sees the segment: its
	// Target name, an Address, a Gateway and an MTU. Source is left empty —
	// the consumer fills it with the TAP it creates.
	Interface HostInterface `json:"interface,omitempty"`
	// Open opens a fresh stream to the device. Never serialised.
	Open func(ctx context.Context) (ForwardedStream, error) `json:"-"`
}

// Describe renders the device for a message.
func (d ForwardedDevice) Describe() string {
	label := strings.TrimSpace(d.Label)
	if label == "" {
		label = d.ForwarderID
	}
	return fmt.Sprintf("%s device %s (forwarder %s)", d.Kind, label, d.ForwarderID)
}

// ForwardedKinds lists the distinct kinds among devs, sorted usb before l2.
func ForwardedKinds(devs []ForwardedDevice) []string {
	var usb, l2 bool
	for _, d := range devs {
		switch d.Kind {
		case ForwardedUSB:
			usb = true
		case ForwardedL2:
			l2 = true
		}
	}
	var out []string
	if usb {
		out = append(out, ForwardedUSB)
	}
	if l2 {
		out = append(out, ForwardedL2)
	}
	return out
}

// ValidateForwardedDevices checks a run's forwarded devices.
func ValidateForwardedDevices(devs []ForwardedDevice, disableNetwork bool) error {
	if len(devs) > MaxForwardedDevices {
		return fmt.Errorf("%w: %d forwarded devices exceed the limit of %d", ErrInvalidSpec, len(devs), MaxForwardedDevices)
	}
	seen := map[string]bool{}
	for _, d := range devs {
		if d.Kind != ForwardedUSB && d.Kind != ForwardedL2 {
			return fmt.Errorf("%w: forwarded device %q has kind %q, not %q or %q",
				ErrInvalidSpec, d.Name, d.Kind, ForwardedUSB, ForwardedL2)
		}
		if !deviceNamePattern.MatchString(d.Name) {
			return fmt.Errorf("%w: forwarded device name %q is not a valid handle", ErrInvalidSpec, d.Name)
		}
		if seen[d.Name] {
			return fmt.Errorf("%w: forwarded device %q is named twice", ErrInvalidSpec, d.Name)
		}
		seen[d.Name] = true
		if d.Open == nil {
			return fmt.Errorf("%w: forwarded device %q has no way to reach its forwarder", ErrInvalidSpec, d.Name)
		}
		if d.Kind == ForwardedL2 {
			if disableNetwork {
				return fmt.Errorf("%w: forwarded network segment %q cannot be given to a workload whose "+
					"network is disabled", ErrInvalidSpec, d.Name)
			}
			probe := d.Interface
			probe.Name = d.Name
			probe.Source = "fwdprobe0"
			if err := ValidateHostInterface(probe); err != nil {
				return fmt.Errorf("%w: forwarded network segment %q: %v", ErrInvalidSpec, d.Name, err)
			}
		}
	}
	return nil
}

// ForwardedDeviceTaker is a driver that attaches forwarded devices itself, on
// the machine its sandboxes run on, from Spec.ForwardedDevices. Today that is
// the remote agent driver: the agent attaches each device on its own host and
// gives it to the sandbox.
type ForwardedDeviceTaker interface {
	// CanTakeForwardedDevices reports nil when a dispatch carrying forwarded
	// devices of these kinds can be placed here, and otherwise the refusal —
	// an agent too old for the channel, a device that cannot attach, an
	// executor that runs payloads with no sandbox to give them to.
	CanTakeForwardedDevices(kinds []string) error
}

// AsForwardedDeviceTaker returns ex's ForwardedDeviceTaker, if it is one.
func AsForwardedDeviceTaker(ex Executor) (ForwardedDeviceTaker, bool) {
	t, ok := ex.(ForwardedDeviceTaker)
	return t, ok
}

// ForwardedDevicesEnv is the variable a workload reads to find its forwarded
// devices: comma-separated name=kind:where entries, where is the usbfs node a
// USB device has in the sandbox or the interface name a segment has there
// ("fwd-bench=usb:/dev/bus/usb/003/014,fwd-lab=l2:fwd0"). A segment's
// interface is moved in a moment after the sandbox starts, so a workload that
// needs it waits for the name it reads here.
const ForwardedDevicesEnv = "CLOOP_FORWARDED_DEVICES"

// ForwardedEnvEntry renders one entry of ForwardedDevicesEnv.
func ForwardedEnvEntry(name, kind, where string) string {
	return name + "=" + kind + ":" + where
}

// WithForwardedEnv appends ForwardedDevicesEnv to env when entries is not
// empty. A nil env stays otherwise empty — never seeded from the caller's own
// environment: forwarded devices go only to container sandboxes, whose driver
// forwards every name the Spec's environment carries, so inheriting here would
// hand the sandbox the hub's or the agent's environment.
func WithForwardedEnv(env []string, entries []string) []string {
	if len(entries) == 0 {
		return env
	}
	return append(append(make([]string, 0, len(env)+1), env...), ForwardedDevicesEnv+"="+strings.Join(entries, ","))
}
