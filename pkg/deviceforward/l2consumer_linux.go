//go:build linux

package deviceforward

// l2consumer_linux.go is the consumer side of a layer-2 forward: a TAP
// interface on this host, fed by a connected forwarder.
//
// A USB forward is consumed by the kernel's vhci through a loopback usbip
// attach; an L2 forward is consumed by a TAP, because that is the object a
// sandbox can be given. The hub creates the TAP, opens a stream to the
// forwarder, and pumps frames between the two: a frame the on-prem interface
// receives comes down the tunnel and is written to the TAP; a frame the TAP
// emits goes up the tunnel and is injected on-prem. The TAP then appears in
// this host's interface inventory, and the existing interface passthrough
// (pkg/executor) carries it into a sandbox.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// TAPBridge is a running L2 bridge: a TAP interface fed by a forwarder.
type TAPBridge struct {
	name   string
	tap    *os.File
	stream *muxChannel

	closeOnce sync.Once
}

// Name is the TAP interface name on this host.
func (b *TAPBridge) Name() string { return b.name }

// AttachL2 creates a TAP interface and bridges it to a connected L2 forwarder.
// The TAP is created down and unaddressed; the caller brings it up and hands it
// to a sandbox. The caller closes the bridge when the interface is no longer
// needed, which removes the TAP.
func (h *Hub) AttachL2(ctx context.Context, forwarderID, tapName string) (*TAPBridge, error) {
	if _, ok := h.Session(forwarderID); !ok {
		return nil, ErrForwarderOffline
	}
	tap, name, err := openTAP(tapName)
	if err != nil {
		return nil, err
	}
	stream, err := h.OpenStream(ctx, forwarderID, "l2-bridge")
	if err != nil {
		_ = tap.Close()
		return nil, err
	}
	b := &TAPBridge{name: name, tap: tap, stream: stream}
	go func() {
		splice(stream, newPktStream(&tapPacketConn{f: tap}))
		_ = b.Close()
	}()
	return b, nil
}

// Close tears down the bridge and removes the TAP.
func (b *TAPBridge) Close() error {
	b.closeOnce.Do(func() {
		if b.stream != nil {
			_ = b.stream.Close()
		}
		if b.tap != nil {
			_ = b.tap.Close()
		}
	})
	return nil
}

// tapPacketConn is a packetIO over a TAP file.
type tapPacketConn struct{ f *os.File }

func (c *tapPacketConn) ReadPacket(p []byte) (int, error) { return c.f.Read(p) }
func (c *tapPacketConn) WritePacket(p []byte) error {
	_, err := c.f.Write(p)
	return err
}
func (c *tapPacketConn) Close() error { return c.f.Close() }

// openTAP opens /dev/net/tun and creates a TAP interface. An empty name lets
// the kernel choose one.
func openTAP(name string) (*os.File, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("deviceforward: open /dev/net/tun (needs CAP_NET_ADMIN): %w", err)
	}
	const (
		tunsetiff = 0x400454ca
		iffTap    = 0x0002
		iffNoPI   = 0x1000
	)
	var req struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	copy(req.name[:15], name)
	req.flags = iffTap | iffNoPI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunsetiff, uintptr(unsafe.Pointer(&req))); errno != 0 {
		_ = f.Close()
		return nil, "", fmt.Errorf("deviceforward: create TAP: %w", errno)
	}
	created := string(req.name[:])
	if i := indexByte([]byte(created), 0); i >= 0 {
		created = created[:i]
	}
	return f, created, nil
}
