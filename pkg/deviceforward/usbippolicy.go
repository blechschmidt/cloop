package deviceforward

// usbippolicy.go is the forwarder's one piece of protocol awareness: it reads
// the opening request of a USB/IP connection and refuses to carry an import of
// any device but the one the forwarder was configured for.
//
// # Why this exists on top of binding one device
//
// The forwarder's USB source binds exactly the configured device to the
// kernel's usbip-host driver and exports it through a loopback usbip daemon.
// That alone would be nearly enough — a daemon only serves bound devices. But
// "bound devices" is host-global state: a device another tool bound to
// usbip-host, before or during the forwarder's life, would be served by the
// same daemon. The trust model says the cloud reaches exactly one device, so
// the forwarder enforces that on the wire too, independent of what else the
// host has bound. A compromised control plane that asked to import a second
// device gets its connection dropped, not the device.
//
// # The protocol, only as far as the first request
//
// USB/IP opens with a fixed op_common header — version (0x0111), a 16-bit code,
// a 32-bit status — all big-endian. The client's first request is one of two
// codes: a device list (OP_REQ_DEVLIST) or an import (OP_REQ_IMPORT), and an
// import carries a 32-byte NUL-padded busid. After the import is accepted the
// stream switches to opaque URB traffic, which this never looks at. So the
// filter reads one header, and for an import one busid, then becomes a pass
// through. It never parses a URB.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// USB/IP opcodes and sizes, from the kernel's usbip protocol.
const (
	usbipVersion    = 0x0111
	opReqDevlist    = 0x8005
	opReqImport     = 0x8003
	sysfsBusIDSize  = 32
	opCommonSize    = 8 // version(2) + code(2) + status(4)
	opReqImportSize = opCommonSize + sysfsBusIDSize
)

// usbipOpRequest is a parsed opening request.
type usbipOpRequest struct {
	Code  uint16
	BusID string // set only for an import
}

// parseUSBIPRequest classifies the first request in b. It returns the request,
// the number of bytes it consumed, and whether enough bytes were present. A
// false ok with a nil error means "read more and call again"; a non-nil error
// is a protocol violation that must drop the connection.
func parseUSBIPRequest(b []byte) (req usbipOpRequest, consumed int, ok bool, err error) {
	if len(b) < opCommonSize {
		return usbipOpRequest{}, 0, false, nil
	}
	version := binary.BigEndian.Uint16(b[0:2])
	code := binary.BigEndian.Uint16(b[2:4])
	if version != usbipVersion {
		return usbipOpRequest{}, 0, false, fmt.Errorf(
			"%w: USB/IP request declares version %#06x, not the expected %#06x",
			ErrProtocol, version, usbipVersion)
	}
	switch code {
	case opReqDevlist:
		return usbipOpRequest{Code: code}, opCommonSize, true, nil
	case opReqImport:
		if len(b) < opReqImportSize {
			return usbipOpRequest{}, 0, false, nil
		}
		busid := trimBusID(b[opCommonSize:opReqImportSize])
		return usbipOpRequest{Code: code, BusID: busid}, opReqImportSize, true, nil
	default:
		return usbipOpRequest{}, 0, false, fmt.Errorf(
			"%w: USB/IP request has unexpected code %#06x", ErrProtocol, code)
	}
}

// trimBusID reads a NUL-padded busid field.
func trimBusID(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// checkImport reports whether a request may be carried for a forwarder whose
// one exported device is allowedBusID. A device list is always allowed; an
// import is allowed only for the configured busid.
func checkImport(req usbipOpRequest, allowedBusID string) error {
	switch req.Code {
	case opReqDevlist:
		return nil
	case opReqImport:
		if strings.TrimSpace(req.BusID) != strings.TrimSpace(allowedBusID) {
			return fmt.Errorf(
				"%w: import of USB device %q refused; this forwarder carries only %q",
				ErrChannelRefused, req.BusID, allowedBusID)
		}
		return nil
	default:
		return fmt.Errorf("%w: refusing USB/IP request code %#06x", ErrChannelRefused, req.Code)
	}
}
