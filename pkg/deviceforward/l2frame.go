package deviceforward

// l2frame.go makes a frame captured by an AF_PACKET socket into the frame that
// was on the wire (Task 20430).
//
// A raw socket does not hand userspace the frame a peer would have received.
// Two things the kernel and the NIC do on the way in are visible only in the
// socket's per-frame auxiliary data (PACKET_AUXDATA):
//
//   - Checksum offload. A frame from a peer whose transmit checksum is
//     offloaded — a veth, a virtio NIC, a bridge port — arrives with its TCP or
//     UDP checksum not yet computed (TP_STATUS_CSUMNOTREADY): the kernel would
//     never compute it, because the frame never reaches a wire. Forwarded as
//     is, the consumer's kernel drops it as corrupt. ARP has no checksum, so a
//     forward with this defect resolves addresses and then carries no TCP.
//   - VLAN acceleration. A NIC that strips 802.1Q tags in hardware delivers
//     the frame untagged and the tag beside it (TP_STATUS_VLAN_VALID); the
//     consumer must get the tagged frame the segment actually carried.
//
// Both are repaired here, on bytes, so the repair is testable without a
// kernel. A frame larger than what was read (GRO merged several, or it is
// over the frame bound) cannot be repaired and is dropped by the caller.

import "encoding/binary"

// tpacket_auxdata status bits.
const (
	tpStatusCsumNotReady = 0x08
	tpStatusVLANValid    = 0x10
	tpStatusVLANTPIDOK   = 0x40
)

// insertVLAN rewrites frame[:n] with an 802.1Q tag after its addresses,
// in place, returning the new length. buf must have room for four more bytes.
func insertVLAN(buf []byte, n int, tpid, tci uint16) int {
	if n < 12 || n+4 > len(buf) {
		return n
	}
	copy(buf[16:n+4], buf[12:n])
	binary.BigEndian.PutUint16(buf[12:14], tpid)
	binary.BigEndian.PutUint16(buf[14:16], tci)
	return n + 4
}

// completeL4Checksum computes the TCP or UDP checksum of an Ethernet frame
// carrying IPv4 or IPv6, in place. It leaves anything it does not understand —
// another protocol, an IPv4 fragment, an IPv6 extension header — as it is.
func completeL4Checksum(frame []byte) {
	off := 12
	if len(frame) < off+2 {
		return
	}
	etype := binary.BigEndian.Uint16(frame[off:])
	off += 2
	for etype == 0x8100 || etype == 0x88a8 {
		if len(frame) < off+4 {
			return
		}
		etype = binary.BigEndian.Uint16(frame[off+2:])
		off += 4
	}
	ip := frame[off:]
	var (
		proto  byte
		l4     []byte
		pseudo uint32
	)
	switch etype {
	case 0x0800:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return
		}
		ihl := int(ip[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if ihl < 20 || total < ihl || total > len(ip) {
			return
		}
		if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
			return // a fragment: its L4 header is not all here
		}
		proto = ip[9]
		l4 = ip[ihl:total]
		pseudo = sum16(ip[12:20]) + uint32(proto) + uint32(len(l4))
	case 0x86dd:
		if len(ip) < 40 || ip[0]>>4 != 6 {
			return
		}
		plen := int(binary.BigEndian.Uint16(ip[4:6]))
		if 40+plen > len(ip) {
			return
		}
		proto = ip[6]
		l4 = ip[40 : 40+plen]
		pseudo = sum16(ip[8:40]) + uint32(len(l4)) + uint32(proto)
	default:
		return
	}
	var at int
	switch proto {
	case 6:
		at = 16
	case 17:
		at = 6
	default:
		return
	}
	if len(l4) < at+2 {
		return
	}
	l4[at], l4[at+1] = 0, 0
	c := ^fold(pseudo + sum16(l4))
	if proto == 17 && c == 0 {
		c = 0xffff // a UDP checksum of zero means "none"
	}
	binary.BigEndian.PutUint16(l4[at:], c)
}

// sum16 is the 16-bit ones-complement sum of b, unfolded.
func sum16(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}
