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
	"encoding/binary"
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
	// The per-frame auxiliary data, which says what the kernel and the NIC
	// did to a frame on its way in: a checksum left to offload, a VLAN tag
	// stripped. See l2frame.go.
	if err := syscall.SetsockoptInt(fd, solPacket, packetAuxdata, 1); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("deviceforward: request frame auxiliary data: %w", err)
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
	oob := make([]byte, 64)
	for {
		// Four bytes short of the buffer, so a VLAN tag the NIC stripped can
		// be put back in place.
		if len(p) < 64 {
			return 0, fmt.Errorf("%w: frame buffer too small", ErrProtocol)
		}
		n, oobn, _, from, err := syscall.Recvmsg(c.fd, p[:len(p)-4], oob, syscall.MSG_TRUNC)
		if err != nil {
			return 0, err
		}
		// An ETH_P_ALL socket also sees every frame the interface transmits,
		// including the ones this forwarder just injected from the tunnel.
		// Carrying those back would echo each of the sandbox's own frames to
		// it (Task 20430), so only frames the segment delivered go up.
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgoing {
			continue
		}
		if n > len(p)-4 {
			// Larger than a frame: offloads merged several into one. A
			// truncated frame is not a frame; it is dropped, as a wire
			// would drop it.
			continue
		}
		status, tpid, tci, ok := auxdata(oob[:oobn])
		if ok && status&tpStatusVLANValid != 0 {
			if status&tpStatusVLANTPIDOK == 0 {
				tpid = 0x8100
			}
			n = insertVLAN(p, n, tpid, tci)
		}
		if ok && status&tpStatusCsumNotReady != 0 {
			completeL4Checksum(p[:n])
		}
		return n, nil
	}
}

// auxdata reads the struct tpacket_auxdata PACKET_AUXDATA delivered with a
// frame: its status, and the VLAN tag a NIC stripped from it.
func auxdata(oob []byte) (status uint32, tpid, tci uint16, ok bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, 0, 0, false
	}
	for _, m := range msgs {
		if m.Header.Level != solPacket || m.Header.Type != packetAuxdata || len(m.Data) < 20 {
			continue
		}
		// u32 tp_status, tp_len, tp_snaplen; u16 tp_mac, tp_net, tp_vlan_tci,
		// tp_vlan_tpid — host byte order.
		status = binary.NativeEndian.Uint32(m.Data[0:4])
		tci = binary.NativeEndian.Uint16(m.Data[16:18])
		tpid = binary.NativeEndian.Uint16(m.Data[18:20])
		return status, tpid, tci, true
	}
	return 0, 0, 0, false
}

const (
	solPacket     = 263 // SOL_PACKET
	packetAuxdata = 8   // PACKET_AUXDATA
)

// packetOutgoing is PACKET_OUTGOING, the sll_pkttype of a frame this host sent.
const packetOutgoing = 4

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
	const addMembership = 1 // PACKET_ADD_MEMBERSHIP
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(solPacket), uintptr(addMembership),
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
