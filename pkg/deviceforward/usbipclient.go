package deviceforward

// usbipclient.go is the client half of the USB/IP opening handshake (Task
// 20430): what a consumer — an executor agent, or the hub for a sandbox on its
// own host — says to a forwarder before the kernel takes the connection over.
//
// A consumer never runs `usbip attach` and never opens a TCP port. It writes
// OP_REQ_IMPORT for the one bus id the forwarder exports onto the stream it was
// handed, reads OP_REP_IMPORT back, and gives vhci_hcd one end of an anonymous
// socketpair whose other end it relays to that stream — the mirror image of
// what the forwarder does with usbip_sockfd. These codecs are kept free of the
// kernel so they can be unit-tested anywhere; the attach itself is in
// importusb_linux.go.
//
// The device list (OP_REQ_DEVLIST / OP_REP_DEVLIST) is here too, for one
// reason: it is how the hub proves a forwarder can open its device right now
// without handing the device to anything — the probe behind the dashboard's
// Test button. A forwarder answers it with the one device it carries.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// USB/IP reply opcode for the device list, and the per-interface record size.
const (
	opRepDevlist       = 0x0005
	usbipInterfaceSize = 4 // class, subclass, protocol, padding
	// maxDevlistDevices bounds a device list read from the wire. A forwarder
	// exports exactly one device; anything claiming hundreds is not a
	// forwarder and is refused rather than allocated.
	maxDevlistDevices = 16
)

// usbipInterface is one interface record of OP_REP_DEVLIST.
type usbipInterface struct {
	Class    uint8
	SubClass uint8
	Protocol uint8
}

// exportedUSB is one device in a device list: its descriptor and interfaces.
type exportedUSB struct {
	Device     usbipDevice
	Interfaces []usbipInterface
}

// buildOpReqImport renders OP_REQ_IMPORT for busid.
func buildOpReqImport(busid string) []byte {
	b := make([]byte, opReqImportSize)
	binary.BigEndian.PutUint16(b[0:2], usbipVersion)
	binary.BigEndian.PutUint16(b[2:4], opReqImport)
	copy(b[opCommonSize:], truncField(busid, sysfsBusIDSize-1))
	return b
}

// buildOpReqDevlist renders OP_REQ_DEVLIST.
func buildOpReqDevlist() []byte {
	b := make([]byte, opCommonSize)
	binary.BigEndian.PutUint16(b[0:2], usbipVersion)
	binary.BigEndian.PutUint16(b[2:4], opReqDevlist)
	return b
}

// readOpCommon reads a reply's op_common header and checks it is the reply
// the caller expects.
func readOpCommon(r io.Reader, wantCode uint16) (status uint32, err error) {
	hdr := make([]byte, opCommonSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, fmt.Errorf("deviceforward: read USB/IP reply header: %w", err)
	}
	if v := binary.BigEndian.Uint16(hdr[0:2]); v != usbipVersion {
		return 0, fmt.Errorf("%w: USB/IP reply declares version %#06x, not %#06x", ErrProtocol, v, usbipVersion)
	}
	if c := binary.BigEndian.Uint16(hdr[2:4]); c != wantCode {
		return 0, fmt.Errorf("%w: USB/IP reply code %#06x, expected %#06x", ErrProtocol, c, wantCode)
	}
	return binary.BigEndian.Uint32(hdr[4:8]), nil
}

// readOpRepImport reads OP_REP_IMPORT and returns the device the server
// exported. A non-zero status is the server refusing the import — for a
// forwarder, a bus id other than the one it carries, or a device it could not
// bind — and is returned as ErrChannelRefused.
func readOpRepImport(r io.Reader) (usbipDevice, error) {
	status, err := readOpCommon(r, opRepImport)
	if err != nil {
		return usbipDevice{}, err
	}
	if status != 0 {
		return usbipDevice{}, fmt.Errorf("%w: the forwarder refused the USB/IP import (status %d)", ErrChannelRefused, status)
	}
	body := make([]byte, usbipDeviceSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return usbipDevice{}, fmt.Errorf("deviceforward: read USB/IP import reply: %w", err)
	}
	return parseUSBIPDevice(body), nil
}

// parseUSBIPDevice decodes struct usbip_usb_device.
func parseUSBIPDevice(b []byte) usbipDevice {
	o := 288
	return usbipDevice{
		Path:                trimBusID(b[0:256]),
		BusID:               trimBusID(b[256:288]),
		BusNum:              binary.BigEndian.Uint32(b[o:]),
		DevNum:              binary.BigEndian.Uint32(b[o+4:]),
		Speed:               binary.BigEndian.Uint32(b[o+8:]),
		IDVendor:            binary.BigEndian.Uint16(b[o+12:]),
		IDProduct:           binary.BigEndian.Uint16(b[o+14:]),
		BcdDevice:           binary.BigEndian.Uint16(b[o+16:]),
		BDeviceClass:        b[o+18],
		BDeviceSubClass:     b[o+19],
		BDeviceProtocol:     b[o+20],
		BConfigurationValue: b[o+21],
		BNumConfigurations:  b[o+22],
		BNumInterfaces:      b[o+23],
	}
}

// buildOpRepDevlist renders OP_REP_DEVLIST for the devices given.
func buildOpRepDevlist(devs []exportedUSB) []byte {
	out := make([]byte, opCommonSize+4)
	binary.BigEndian.PutUint16(out[0:2], usbipVersion)
	binary.BigEndian.PutUint16(out[2:4], opRepDevlist)
	binary.BigEndian.PutUint32(out[opCommonSize:], uint32(len(devs)))
	for _, d := range devs {
		dev := d.Device
		dev.BNumInterfaces = uint8(len(d.Interfaces))
		out = append(out, dev.marshal()...)
		for _, i := range d.Interfaces {
			out = append(out, i.Class, i.SubClass, i.Protocol, 0)
		}
	}
	return out
}

// readOpRepDevlist reads OP_REP_DEVLIST.
func readOpRepDevlist(r io.Reader) ([]exportedUSB, error) {
	status, err := readOpCommon(r, opRepDevlist)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("%w: the forwarder refused the USB/IP device list (status %d)", ErrChannelRefused, status)
	}
	nb := make([]byte, 4)
	if _, err := io.ReadFull(r, nb); err != nil {
		return nil, fmt.Errorf("deviceforward: read USB/IP device count: %w", err)
	}
	n := binary.BigEndian.Uint32(nb)
	if n > maxDevlistDevices {
		return nil, fmt.Errorf("%w: device list claims %d devices; a forwarder exports one", ErrProtocol, n)
	}
	out := make([]exportedUSB, 0, n)
	for i := uint32(0); i < n; i++ {
		body := make([]byte, usbipDeviceSize)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("deviceforward: read USB/IP device record: %w", err)
		}
		d := exportedUSB{Device: parseUSBIPDevice(body)}
		for j := 0; j < int(d.Device.BNumInterfaces); j++ {
			ib := make([]byte, usbipInterfaceSize)
			if _, err := io.ReadFull(r, ib); err != nil {
				return nil, fmt.Errorf("deviceforward: read USB/IP interface record: %w", err)
			}
			d.Interfaces = append(d.Interfaces, usbipInterface{Class: ib[0], SubClass: ib[1], Protocol: ib[2]})
		}
		out = append(out, d)
	}
	return out, nil
}

// ExportedDevice is what a forwarder reports, in its open acknowledgement,
// about the device it just opened — the facts a consumer needs to import it.
// For USB, BusID is the on-prem kernel's bus id, which OP_REQ_IMPORT must
// name; the IDs are informational.
type ExportedDevice struct {
	Kind      DeviceKind `json:"kind"`
	BusID     string     `json:"bus_id,omitempty"`
	VendorID  string     `json:"vendor_id,omitempty"`
	ProductID string     `json:"product_id,omitempty"`
	// Speed is the kernel's usb_device_speed enum value.
	Speed     uint32 `json:"speed,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// ProbeResult is what a USB probe read through a forwarder's stream.
type ProbeResult struct {
	BusID      string `json:"bus_id"`
	VendorID   string `json:"vendor_id"`
	ProductID  string `json:"product_id"`
	Speed      uint32 `json:"speed"`
	Interfaces int    `json:"interfaces"`
}

// ProbeUSB asks the forwarder behind stream for its device list and closes the
// stream (Task 20430). It proves the whole path — hub, tunnel, forwarder,
// device — answers, without binding the device or handing it to any kernel.
func ProbeUSB(ctx context.Context, stream io.ReadWriteCloser) (ProbeResult, error) {
	defer stream.Close()
	stop := closeOnDone(ctx, stream)
	defer stop()
	if _, err := stream.Write(buildOpReqDevlist()); err != nil {
		return ProbeResult{}, fmt.Errorf("deviceforward: send the USB/IP device-list request: %w", err)
	}
	devs, err := readOpRepDevlist(stream)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, fmt.Errorf("deviceforward: USB/IP device list: %w", ctx.Err())
		}
		return ProbeResult{}, err
	}
	if len(devs) != 1 {
		return ProbeResult{}, fmt.Errorf("%w: the forwarder listed %d devices, not the one it carries", ErrProtocol, len(devs))
	}
	d := devs[0]
	return ProbeResult{
		BusID:      d.Device.BusID,
		VendorID:   fmt.Sprintf("%04x", d.Device.IDVendor),
		ProductID:  fmt.Sprintf("%04x", d.Device.IDProduct),
		Speed:      d.Device.Speed,
		Interfaces: len(d.Interfaces),
	}, nil
}

// closeOnDone closes c if ctx ends before stop is called, so a blocking read
// on a stream with no deadline respects a context.
func closeOnDone(ctx context.Context, c io.Closer) (stop func()) {
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-finished:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(finished) }) }
}
