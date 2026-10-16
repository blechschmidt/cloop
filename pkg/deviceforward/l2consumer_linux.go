//go:build linux

package deviceforward

// l2consumer_linux.go is the consumer side of a layer-2 forward: a TAP
// interface on this host, fed by a stream to a forwarder.
//
// A USB forward is consumed by the kernel's vhci (importusb_linux.go); an L2
// forward is consumed by a TAP, because that is the object a sandbox can be
// given. The consumer — an executor agent for a sandbox on its host, or the
// hub for a sandbox on its own (Task 20430) — creates the TAP and pumps frames
// between it and the stream: a frame the on-prem interface receives comes down
// the stream and is written to the TAP; a frame the TAP emits goes up the
// stream and is injected on-prem. The interface passthrough (pkg/executor)
// then moves the TAP into the sandbox's network namespace.
//
// The TAP is not persistent: it exists exactly as long as the descriptor this
// process holds, wherever its namespace ends up. So when the bridge ends — the
// stream closed by a revocation, the forwarder gone, the run over — closing the
// descriptor removes the interface from the sandbox with it, and a consumer
// that dies takes its TAPs with it.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// TAPBridge is a running L2 bridge: a TAP interface fed by a forwarder stream.
type TAPBridge struct {
	name   string
	tap    *os.File
	stream io.ReadWriteCloser

	done      chan struct{}
	closeOnce sync.Once
}

// Name is the TAP interface name on this host.
func (b *TAPBridge) Name() string { return b.name }

// Done is closed once the bridge has ended, for any reason.
func (b *TAPBridge) Done() <-chan struct{} { return b.done }

// BridgeTAP creates a TAP interface and bridges it to an open stream to an L2
// forwarder's device. The TAP is created down and unaddressed; the caller
// brings it up — or hands it to a sandbox, whose passthrough does. The bridge
// ends when the stream does, or when the caller closes it, which removes the
// TAP.
func BridgeTAP(stream io.ReadWriteCloser, tapName string) (*TAPBridge, error) {
	if stream == nil {
		return nil, fmt.Errorf("deviceforward: bridge a TAP: no stream")
	}
	tap, name, err := openTAP(tapName)
	if err != nil {
		return nil, err
	}
	b := &TAPBridge{name: name, tap: tap, stream: stream, done: make(chan struct{})}
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
		close(b.done)
	})
	return nil
}

// tapPacketConn is a packetIO over a TAP file.
type tapPacketConn struct{ f *os.File }

func (c *tapPacketConn) ReadPacket(p []byte) (int, error) { return c.f.Read(p) }

// WritePacket hands one frame to the TAP. A TAP whose interface is down —
// between its creation and the sandbox bringing it up, or while the sandbox
// has it down — refuses frames with EIO; that is the interface dropping them,
// as a down NIC would, not the bridge failing, so the frame is dropped and the
// bridge goes on. A TAP that is gone fails reads too, which ends the bridge.
func (c *tapPacketConn) WritePacket(p []byte) error {
	_, err := c.f.Write(p)
	if errors.Is(err, syscall.EIO) {
		return nil
	}
	return err
}
func (c *tapPacketConn) Close() error { return c.f.Close() }

// openTAP opens /dev/net/tun and creates a TAP interface. An empty name lets
// the kernel choose one.
//
// The descriptor is attached to the TAP before Go's runtime poller sees it.
// An os.File opened on /dev/net/tun is registered with epoll at once, and a
// tun descriptor not yet attached to an interface polls as an error: if the
// poller saw that before TUNSETIFF ran, every later read failed "not
// pollable" and the bridge ended the moment it started (Task 20430). So the
// ioctl runs on the raw, non-blocking descriptor, and only then is it wrapped.
func openTAP(name string) (*os.File, string, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
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
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunsetiff, uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, "", fmt.Errorf("deviceforward: create TAP %q: %w", name, errno)
	}
	created := string(req.name[:])
	if i := indexByte([]byte(created), 0); i >= 0 {
		created = created[:i]
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), created, nil
}
