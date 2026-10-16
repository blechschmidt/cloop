package deviceforward

// source.go is the seam between the forwarder's transport — which is the same
// for every device — and the kernel-specific business of actually reaching one
// piece of hardware, which is not.
//
// A LocalSource is the on-prem endpoint of the one device a forwarder carries.
// The forwarder knows nothing about USB/IP or AF_PACKET; it asks the source
// whether the device is reachable (for the hello), and opens a fresh stream to
// it whenever the hub asks for one. Keeping this an interface is what lets the
// protocol, the mux and the relay be tested with an in-memory source on a
// machine with no hardware, while the real USB and L2 sources live behind
// build tags and run only where a kernel can honour them.

import (
	"context"
	"io"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// LocalSource is the on-prem endpoint of a forwarded device.
type LocalSource interface {
	// Device is the descriptor this source serves, for the hello.
	Device() ForwardedDevice
	// Probe reports whether the device is reachable right now. resolved, for a
	// USB source, is the concrete device the configured identity matched, so
	// the dashboard can show the real hardware. A false ok is advisory: the
	// forwarder still connects so the operator can see it, and refuses Opens
	// until the device is present.
	Probe(ctx context.Context) (ok bool, detail string, resolved *executor.USBDevice)
	// Open opens a fresh byte stream to the device — a connection to the local
	// usbip server for a USB device, a raw interface handle for L2. The caller
	// closes it when the stream ends.
	Open(ctx context.Context) (io.ReadWriteCloser, error)
	// Close releases anything held across the forwarder's whole life, such as
	// a spawned usbip daemon. Called once at shutdown.
	Close() error
}
