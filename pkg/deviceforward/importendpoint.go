package deviceforward

// importendpoint.go is the consumer side of a USB forward: a loopback TCP
// listener that speaks the USB/IP server protocol by relaying to a connected
// forwarder.
//
// It is what makes a forwarded device usable with no new client: the standard
// `usbip attach -r 127.0.0.1 -p <port> -b <busid>` connects here, and every
// byte is relayed over the tunnel to the forwarder, which answers the import
// and hands its on-prem device to this host's kernel. So the on-prem device
// appears in `usbip port` exactly as a locally-attached one, and from there the
// existing passthrough (pkg/executor) carries it into a sandbox.
//
// It binds loopback only, for the same reason the forwarder runs no public
// usbipd: the device must be reachable by this host's own vhci attach and by
// nothing on the network. A consumer on another machine reaches it through the
// hub, not through this port.

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// ImportEndpoint is a loopback listener relaying to one forwarder's device.
type ImportEndpoint struct {
	hub   *Hub
	fwdID string
	ln    net.Listener

	mu     sync.Mutex
	closed bool
}

// ListenUSB opens a loopback endpoint for a connected USB forwarder. The
// caller closes it when the device is no longer needed.
func (h *Hub) ListenUSB(forwarderID string) (*ImportEndpoint, error) {
	if _, ok := h.Session(forwarderID); !ok {
		return nil, ErrForwarderOffline
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("deviceforward: open import endpoint: %w", err)
	}
	e := &ImportEndpoint{hub: h, fwdID: forwarderID, ln: ln}
	go e.serve()
	return e, nil
}

// Addr is the loopback address a usbip client attaches to.
func (e *ImportEndpoint) Addr() *net.TCPAddr { return e.ln.Addr().(*net.TCPAddr) }

// Port is the TCP port, for the attach command shown to an operator.
func (e *ImportEndpoint) Port() int { return e.Addr().Port }

func (e *ImportEndpoint) serve() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go e.handle(c)
	}
}

func (e *ImportEndpoint) handle(c net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	stream, err := e.hub.OpenStream(ctx, e.fwdID, "usbip-attach")
	cancel()
	if err != nil {
		_ = c.Close()
		return
	}
	// stream is the hub↔forwarder channel; c is the local usbip client. Relay
	// both ways; the device's protocol passes through untouched.
	splice(stream, c)
}

// Close stops accepting and frees the listener.
func (e *ImportEndpoint) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return e.ln.Close()
}
