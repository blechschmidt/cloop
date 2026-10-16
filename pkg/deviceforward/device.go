package deviceforward

// device.go describes the one piece of hardware a forwarder carries.
//
// # What a forwarder is, and why its device model is this small
//
// A forwarder is a minimal binary on an on-prem machine that does nothing but
// bridge one configured device — a USB device, or a layer-2 network interface
// — to a cloud control plane over an authenticated, outbound-dialled tunnel.
// It runs no harness, executes no task, and reads no project. That is the
// whole point: the trust model is "the agent runs in an isolated environment
// in the cloud with limited access to on-prem hardware", and the forwarder is
// the narrow aperture through which that limited access is granted.
//
// So the device model carries exactly what identifies the one device and
// nothing an attacker who compromised the forwarder could widen into more
// reach. A USB device is named by vendor/product/serial — the identity that
// survives re-enumeration (see pkg/executor/usb.go for why a path would not).
// An interface is named by its kernel name on the on-prem host. Neither names
// a second device, and the forwarder refuses to open anything but the one it
// was configured for.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// DeviceKind is what sort of device a forwarder carries.
type DeviceKind string

const (
	// KindUSB forwards a USB device over USB/IP: the forwarder exposes the
	// on-prem kernel's usbip server for the one device, and the consumer
	// attaches it with vhci as if it were plugged in locally.
	KindUSB DeviceKind = "usb"
	// KindL2 forwards a layer-2 network interface: the forwarder streams the
	// interface's Ethernet frames, and the consumer replays them onto a TAP,
	// so a sandbox in the cloud shares the on-prem segment at the link layer.
	KindL2 DeviceKind = "l2"
)

// Valid reports whether k is a known kind.
func (k DeviceKind) Valid() bool { return k == KindUSB || k == KindL2 }

// maxLabelLen bounds the human label. It travels to a database, an audit row
// and a dashboard, so it is bounded and sanitised like every other
// device-reported string.
const maxLabelLen = 128

// ForwardedDevice is the one device a forwarder is configured to carry.
//
// Exactly one of USB and Interface is set, selected by Kind.
type ForwardedDevice struct {
	// Kind selects which of the fields below is meaningful.
	Kind DeviceKind `json:"kind"`
	// USB identifies the forwarded USB device by vendor, product and
	// optionally serial — the identity that survives re-enumeration. Set when
	// Kind is KindUSB.
	USB *executor.USBMatch `json:"usb,omitempty"`
	// Interface is the kernel name of the forwarded network interface on the
	// on-prem host ("eth1", "can0"). Set when Kind is KindL2.
	Interface string `json:"interface,omitempty"`
	// Label is an operator-facing description shown in the dashboard and in
	// audit rows. Optional; a default is derived from the identity when empty.
	Label string `json:"label,omitempty"`
}

// Normalize canonicalises and validates the descriptor.
func (d ForwardedDevice) Normalize() (ForwardedDevice, error) {
	out := ForwardedDevice{Kind: DeviceKind(strings.ToLower(strings.TrimSpace(string(d.Kind))))}
	if !out.Kind.Valid() {
		return ForwardedDevice{}, fmt.Errorf("%w: device kind %q must be %q or %q",
			ErrInvalidSpec, d.Kind, KindUSB, KindL2)
	}
	out.Label = executor.SanitizeUSBString(strings.TrimSpace(d.Label))
	if len(out.Label) > maxLabelLen {
		out.Label = out.Label[:maxLabelLen]
	}
	switch out.Kind {
	case KindUSB:
		if d.USB == nil {
			return ForwardedDevice{}, fmt.Errorf("%w: a usb forwarder must name a USB device", ErrInvalidSpec)
		}
		if d.Interface != "" {
			return ForwardedDevice{}, fmt.Errorf("%w: a usb forwarder must not also name an interface", ErrInvalidSpec)
		}
		m, err := d.USB.Normalize()
		if err != nil {
			return ForwardedDevice{}, fmt.Errorf("%w: %v", ErrInvalidSpec, err)
		}
		out.USB = &m
	case KindL2:
		if strings.TrimSpace(d.Interface) == "" {
			return ForwardedDevice{}, fmt.Errorf("%w: an l2 forwarder must name an interface", ErrInvalidSpec)
		}
		if d.USB != nil {
			return ForwardedDevice{}, fmt.Errorf("%w: an l2 forwarder must not also name a USB device", ErrInvalidSpec)
		}
		if err := executor.ValidateHostInterface(executor.HostInterface{
			Name:   "forward",
			Source: strings.TrimSpace(d.Interface),
		}); err != nil {
			return ForwardedDevice{}, fmt.Errorf("%w: %v", ErrInvalidSpec, err)
		}
		out.Interface = strings.TrimSpace(d.Interface)
	}
	return out, nil
}

// Validate reports whether the descriptor is admissible.
func (d ForwardedDevice) Validate() error {
	_, err := d.Normalize()
	return err
}

// Describe renders the device for a card, a log line or an audit row.
func (d ForwardedDevice) Describe() string {
	var what string
	switch d.Kind {
	case KindUSB:
		if d.USB != nil {
			what = "usb " + d.USB.String()
		} else {
			what = "usb (unspecified)"
		}
	case KindL2:
		what = "interface " + d.Interface
	default:
		what = string(d.Kind)
	}
	if l := strings.TrimSpace(d.Label); l != "" {
		return l + " (" + what + ")"
	}
	return what
}

// DefaultLabel returns Label, or a label derived from the identity when none
// was set, so a forwarder always has something an operator recognises.
func (d ForwardedDevice) DefaultLabel() string {
	if l := strings.TrimSpace(d.Label); l != "" {
		return l
	}
	switch d.Kind {
	case KindUSB:
		if d.USB != nil {
			return "USB " + d.USB.String()
		}
		return "USB device"
	case KindL2:
		return "interface " + d.Interface
	}
	return "device"
}
