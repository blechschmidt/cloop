//go:build linux

package deviceforward

// l2source_linux.go is the on-prem endpoint of a layer-2 forwarder: a raw
// socket on the configured interface. Every frame the interface receives is
// read and sent up the tunnel; every frame that arrives from the tunnel is
// injected back onto the wire. That is what puts a cloud sandbox on the on-prem
// segment at the link layer — ARP, DHCP, raw Ethernet and the rest — rather
// than at a layer a route could carry.
//
// It opens AF_PACKET/SOCK_RAW in promiscuous mode so the forward sees frames
// addressed to the device under test, not only to the host. That is a wide
// capability, which is exactly why it is a configured, enrolled grant and not
// something a sandbox spec can ask for.

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// L2SourceOptions configures an L2 source.
type L2SourceOptions struct {
	Logf func(string, ...any)
}

// L2Source forwards one network interface's frames.
type L2Source struct {
	iface string
	opts  L2SourceOptions

	mu     sync.Mutex
	active bool
}

// NewL2Source builds an L2 source for an interface name.
func NewL2Source(iface string, opts L2SourceOptions) (*L2Source, error) {
	if err := executor.ValidateHostInterface(executor.HostInterface{Name: "forward", Source: iface}); err != nil {
		return nil, err
	}
	return &L2Source{iface: iface, opts: opts}, nil
}

// Device reports the descriptor this source serves.
func (s *L2Source) Device() ForwardedDevice {
	return ForwardedDevice{Kind: KindL2, Interface: s.iface}
}

// Probe reports whether the interface exists and is up.
func (s *L2Source) Probe(ctx context.Context) (bool, string, *executor.USBDevice) {
	ifi, err := net.InterfaceByName(s.iface)
	if err != nil {
		return false, fmt.Sprintf("interface %q is not present on this host", s.iface), nil
	}
	if ifi.Flags&net.FlagUp == 0 {
		return false, fmt.Sprintf("interface %q is down", s.iface), nil
	}
	return true, "", nil
}

// Open opens a promiscuous raw socket on the interface, framed for the tunnel.
func (s *L2Source) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return nil, fmt.Errorf("%w: this interface is already bridged to a consumer", ErrChannelRefused)
	}
	ifi, err := net.InterfaceByName(s.iface)
	if err != nil {
		return nil, fmt.Errorf("%w: interface %q: %v", ErrChannelRefused, s.iface, err)
	}
	raw, err := openRawSocket(ifi.Index)
	if err != nil {
		return nil, err
	}
	s.active = true
	return newPktStream(&rawPacketConn{fd: raw, ifindex: ifi.Index, onClose: s.streamClosed}), nil
}

func (s *L2Source) streamClosed() {
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
}

// Close is a no-op; a raw socket is owned by its stream.
func (s *L2Source) Close() error { return nil }

// openRawSocket opens AF_PACKET/SOCK_RAW bound to an interface, in promiscuous
// mode, with ETH_P_ALL so every frame is captured.
func openRawSocket(ifindex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("deviceforward: open raw socket (needs CAP_NET_RAW): %w", err)
	}
	ll := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifindex}
	if err := syscall.Bind(fd, &ll); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("deviceforward: bind raw socket: %w", err)
	}
	// Promiscuous mode, so frames for the device under test are seen.
	mreq := packetMreq{ifindex: int32(ifindex), typ: packetMrPromisc}
	if err := setPacketMembership(fd, mreq); err != nil {
		// Not fatal: without promisc the forward still carries broadcast and
		// frames addressed to this host, which is enough for DHCP and ARP.
		_ = err
	}
	return fd, nil
}

// rawPacketConn is a packetIO over an AF_PACKET socket.
type rawPacketConn struct {
	fd      int
	ifindex int
	once    sync.Once
	onClose func()
}

func (c *rawPacketConn) ReadPacket(p []byte) (int, error) {
	n, _, err := syscall.Recvfrom(c.fd, p, 0)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *rawPacketConn) WritePacket(p []byte) error {
	ll := syscall.SockaddrLinklayer{Ifindex: c.ifindex, Halen: 6}
	return syscall.Sendto(c.fd, p, 0, &ll)
}

func (c *rawPacketConn) Close() error {
	c.once.Do(func() {
		syscall.Close(c.fd)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// packet mreq, mirrored here because syscall does not export the constants on
// every version.
const packetMrPromisc = 1

type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	addr    [8]byte
}

// setPacketMembership adds a membership (promiscuous mode) on an AF_PACKET
// socket.
func setPacketMembership(fd int, mreq packetMreq) error {
	const solPacket = 263   // SOL_PACKET
	const addMembership = 1 // PACKET_ADD_MEMBERSHIP
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(solPacket), uintptr(addMembership),
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
