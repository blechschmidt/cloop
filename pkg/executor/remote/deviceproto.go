package remote

// deviceproto.go is the wire half of forwarded devices on an executor agent
// (Task 20430, protocol v22): the frames that carry a device forwarder's
// stream from the hub to the agent that attaches the device for a sandbox.
//
// # Why a channel on the agent's tunnel
//
// A device forwarder dials the hub, and so does the agent; neither can reach
// the other, and neither should. The hub already holds both connections, so it
// splices them: it opens a stream on the forwarder's tunnel, opens a device
// channel on the agent's, and copies bytes between the two. The agent attaches
// the device on its own host — a USB device through vhci_hcd with a
// socketpair, an L2 segment through a TAP — with no listener, and gives it to
// the sandbox the run starts in. The forwarder's protocol inside the channel
// (USB/IP, framed Ethernet) passes through the hub untouched.
//
// # The order, which is load-bearing
//
// The hub sends device_open for a handle *before* the start frame naming that
// handle, and waits for device_opened: a USB device must have enumerated on
// the agent's host before the container that is given its node is created.
// The start frame then lists the channels its sandbox gets in
// StartPayload.ForwardedDevices, and the agent refuses a start naming a
// channel it does not hold for that handle.
//
// # Lifetime
//
// A channel ends — and the agent detaches the device — when the run ends, when
// either side closes it (a binding or forwarder revoked, the forwarder gone),
// or when the agent's connection drops. It is never resumed: a reconnecting
// agent's sandbox simply loses the device, which is the safe direction.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Device frame types.
const (
	// TypeDeviceOpen (hub → agent) opens a device channel for a handle about
	// to start. Correlated by Frame.ID; Frame.Handle names the workload.
	TypeDeviceOpen FrameType = "device_open"
	// TypeDeviceOpened (agent → hub) answers it once the device is attached
	// on the agent's host, or the agent answers TypeError.
	TypeDeviceOpened FrameType = "device_opened"
	// TypeDeviceData carries the forwarded device's bytes in both directions.
	TypeDeviceData FrameType = "device_data"
	// TypeDeviceClose ends a channel from either end.
	TypeDeviceClose FrameType = "device_close"
)

// MinForwardedDeviceVersion is the first protocol version whose agents
// understand the device frames. A placement rule: a dispatch whose project
// holds a forwarder binding is refused on an older agent, naming the upgrade,
// because an older agent would ignore StartPayload.ForwardedDevices and start
// the sandbox without the hardware the run was promised.
const MinForwardedDeviceVersion = 22

// SupportsForwardedDevices reports whether an agent at this negotiated version
// can attach a forwarded device.
func SupportsForwardedDevices(version int) bool { return version >= MinForwardedDeviceVersion }

// MaxDeviceChunk bounds one device_data payload. A []byte travels base64 in
// JSON, so this is ~43 KiB on the wire, comfortably under MaxFrameBytes, and a
// USB/IP bulk URB or a jumbo Ethernet frame spans at most a few chunks.
const MaxDeviceChunk = 32 << 10

// maxDeviceChannelsPerConnection bounds how many device channels one agent
// connection carries — the structural backstop under the hub's own
// per-run limit (executor.MaxForwardedDevices).
const maxDeviceChannelsPerConnection = 32

// DeviceOpenPayload opens a device channel.
type DeviceOpenPayload struct {
	// ChannelID is minted by the hub and scopes every later frame.
	ChannelID string `json:"channel_id"`
	// Kind is executor.ForwardedUSB or executor.ForwardedL2.
	Kind string `json:"kind"`
	// Name is the sandbox-facing handle the device is given under.
	Name string `json:"name"`
	// Label describes the device, for the device's own log.
	Label string `json:"label,omitempty"`
	// ForwarderID and BindingID identify the forwarder and the binding that
	// authorised the device, for the device's log.
	ForwarderID string `json:"forwarder_id,omitempty"`
	BindingID   string `json:"binding_id,omitempty"`
	// BusID, for USB, is the bus id the forwarder exports: what the agent's
	// OP_REQ_IMPORT names.
	BusID string `json:"bus_id,omitempty"`
	// Interface, for L2, is the sandbox-side shape of the segment; the agent
	// fills Source with the TAP it creates.
	Interface *executor.HostInterface `json:"interface,omitempty"`
}

// DeviceOpenedPayload reports what the agent attached.
type DeviceOpenedPayload struct {
	ChannelID string `json:"channel_id"`
	// For USB: the vhci port, and the bus id and node the device enumerated
	// as on the agent's host.
	VHCIPort   int    `json:"vhci_port,omitempty"`
	LocalBusID string `json:"local_bus_id,omitempty"`
	Node       string `json:"node,omitempty"`
	// For L2: the TAP the agent created.
	TAP string `json:"tap,omitempty"`
}

// DeviceDataPayload carries one chunk in either direction.
type DeviceDataPayload struct {
	ChannelID string `json:"channel_id"`
	Data      []byte `json:"data"`
}

// DeviceClosePayload ends a channel.
type DeviceClosePayload struct {
	ChannelID string `json:"channel_id"`
	Reason    string `json:"reason,omitempty"`
}

// Validate checks an open request as the agent receives it.
func (p DeviceOpenPayload) Validate() error {
	if strings.TrimSpace(p.ChannelID) == "" {
		return fmt.Errorf("%w: device_open has no channel id", ErrProtocol)
	}
	switch p.Kind {
	case executor.ForwardedUSB:
		if strings.TrimSpace(p.BusID) == "" || len(p.BusID) > 31 {
			return fmt.Errorf("%w: device_open for a USB device has no usable bus id", ErrProtocol)
		}
	case executor.ForwardedL2:
		if p.Interface == nil {
			return fmt.Errorf("%w: device_open for a network segment has no interface", ErrProtocol)
		}
		probe := *p.Interface
		probe.Name = p.Name
		probe.Source = "fwdprobe0"
		if err := executor.ValidateHostInterface(probe); err != nil {
			return fmt.Errorf("%w: device_open: %v", ErrProtocol, err)
		}
	default:
		return fmt.Errorf("%w: device_open names kind %q", ErrProtocol, p.Kind)
	}
	return nil
}

// DecodeDeviceOpen decodes and validates an open request.
func DecodeDeviceOpen(f Frame) (DeviceOpenPayload, error) {
	var p DeviceOpenPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(f.Handle) == "" {
		return p, fmt.Errorf("%w: device_open has no handle", ErrProtocol)
	}
	return p, p.Validate()
}

// DecodeDeviceOpened decodes an open acknowledgement.
func DecodeDeviceOpened(f Frame) (DeviceOpenedPayload, error) {
	var p DeviceOpenedPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.ChannelID) == "" {
		return p, fmt.Errorf("%w: device_opened has no channel id", ErrProtocol)
	}
	return p, nil
}

// DecodeDeviceData decodes one chunk, refusing an oversized one — checked on
// receipt because the sender is the party that might be hostile.
func DecodeDeviceData(f Frame) (DeviceDataPayload, error) {
	var p DeviceDataPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.ChannelID) == "" {
		return p, fmt.Errorf("%w: device_data has no channel id", ErrProtocol)
	}
	if len(p.Data) > MaxDeviceChunk {
		return p, fmt.Errorf("%w: device_data chunk %d bytes exceeds %d", ErrProtocol, len(p.Data), MaxDeviceChunk)
	}
	return p, nil
}

// DecodeDeviceClose decodes a close notice.
func DecodeDeviceClose(f Frame) (DeviceClosePayload, error) {
	var p DeviceClosePayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.ChannelID) == "" {
		return p, fmt.Errorf("%w: device_close has no channel id", ErrProtocol)
	}
	return p, nil
}
