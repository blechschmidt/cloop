package deviceforward

// usbipserver.go builds the USB/IP server's side of the opening handshake:
// the OP_REP_IMPORT reply that tells a client (a vhci attach on the consumer)
// the device's bus, speed and descriptors before the kernel takes over the URB
// stream. It is kept separate from the kernel-bound source so the wire format
// can be unit-tested on any platform with no hardware.
//
// The forwarder is the USB/IP *server*, which is why it builds this reply. It
// does not marshal a single URB, though: after it sends OP_REP_IMPORT it hands
// the connection to the kernel's usbip-host driver (see usbsource_linux.go),
// and the kernel does every URB. So this file ends where the opaque phase
// begins.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// USB/IP reply opcodes and struct sizes.
const (
	opRepImport = 0x0003
	// usbipDeviceSize is sizeof(struct usbip_usb_device): path[256] + busid[32]
	// + 3×u32 + 3×u16 + 6×u8.
	usbipDeviceSize = 256 + 32 + 4 + 4 + 4 + 2 + 2 + 2 + 6
)

// usbipDevice is the kernel's struct usbip_usb_device, filled from sysfs.
type usbipDevice struct {
	Path                string
	BusID               string
	BusNum              uint32
	DevNum              uint32
	Speed               uint32
	IDVendor            uint16
	IDProduct           uint16
	BcdDevice           uint16
	BDeviceClass        uint8
	BDeviceSubClass     uint8
	BDeviceProtocol     uint8
	BConfigurationValue uint8
	BNumConfigurations  uint8
	BNumInterfaces      uint8
}

// marshal renders the struct in the wire layout: fixed-size NUL-padded strings
// and big-endian integers.
func (d usbipDevice) marshal() []byte {
	b := make([]byte, usbipDeviceSize)
	copy(b[0:256], truncField(d.Path, 256))
	copy(b[256:288], truncField(d.BusID, 32))
	o := 288
	binary.BigEndian.PutUint32(b[o:], d.BusNum)
	binary.BigEndian.PutUint32(b[o+4:], d.DevNum)
	binary.BigEndian.PutUint32(b[o+8:], d.Speed)
	binary.BigEndian.PutUint16(b[o+12:], d.IDVendor)
	binary.BigEndian.PutUint16(b[o+14:], d.IDProduct)
	binary.BigEndian.PutUint16(b[o+16:], d.BcdDevice)
	b[o+18] = d.BDeviceClass
	b[o+19] = d.BDeviceSubClass
	b[o+20] = d.BDeviceProtocol
	b[o+21] = d.BConfigurationValue
	b[o+22] = d.BNumConfigurations
	b[o+23] = d.BNumInterfaces
	return b
}

// truncField returns s as exactly n bytes, truncated or NUL-padded.
func truncField(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

// buildOpRepImport renders OP_REP_IMPORT. status 0 carries the device; a
// non-zero status is an error reply with no device body, which is how a
// refused import is reported to the client.
func buildOpRepImport(d usbipDevice, status uint32) []byte {
	head := make([]byte, opCommonSize)
	binary.BigEndian.PutUint16(head[0:2], usbipVersion)
	binary.BigEndian.PutUint16(head[2:4], opRepImport)
	binary.BigEndian.PutUint32(head[4:8], status)
	if status != 0 {
		return head
	}
	return append(head, d.marshal()...)
}

// usbSpeedCode maps the sysfs `speed` string (Mbit/s) to the kernel's
// usb_device_speed enum, which is what the client's vhci expects.
func usbSpeedCode(mbps string) uint32 {
	switch strings.TrimSpace(mbps) {
	case "1.5":
		return 1 // USB_SPEED_LOW
	case "12":
		return 2 // USB_SPEED_FULL
	case "480":
		return 3 // USB_SPEED_HIGH
	case "5000":
		return 5 // USB_SPEED_SUPER
	case "10000", "20000":
		return 6 // USB_SPEED_SUPER_PLUS
	default:
		return 0 // USB_SPEED_UNKNOWN
	}
}

// String renders the device for a log line.
func (d usbipDevice) String() string {
	return fmt.Sprintf("%s (%04x:%04x) busnum %d devnum %d", d.BusID, d.IDVendor, d.IDProduct, d.BusNum, d.DevNum)
}
