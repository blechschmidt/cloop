package denylog

import (
	"encoding/binary"
	"net/netip"
)

// headers.go reads the addresses and ports out of a logged packet.
//
// The bytes are whatever the kernel copied — at most the log rule's snaplen —
// from a packet a sandbox sent, so every length is checked before it is used
// and nothing beyond the destination port is ever read. A header that does not
// add up yields false; a transport header the copy cut off yields the
// addresses and no port, because "203.0.113.7 was refused" is still the
// answer a developer is looking for.

// Header is what a refusal records of one packet.
type Header struct {
	Src, Dst netip.Addr
	Proto    Proto
	DstPort  uint16
}

// IPv6 extension headers that may sit between the fixed header and the
// transport, by next-header number.
const (
	ip6HopByHop    = 0
	ip6Routing     = 43
	ip6Fragment    = 44
	ip6AH          = 51
	ip6DestOptions = 60
	ip6MaxExtHdrs  = 8
)

// ParseHeader reads an IPv4 or IPv6 packet's header, and the destination port
// of a TCP, UDP, SCTP or UDP-Lite packet behind it.
func ParseHeader(b []byte) (Header, bool) {
	if len(b) < 1 {
		return Header{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	}
	return Header{}, false
}

func parseIPv4(b []byte) (Header, bool) {
	if len(b) < 20 {
		return Header{}, false
	}
	// An IHL past the copy leaves the addresses readable and the transport
	// not, which transportPort answers with no port.
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 {
		return Header{}, false
	}
	h := Header{
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
		Proto: Proto(b[9]),
	}
	// A non-first fragment carries no transport header: its first bytes are
	// the middle of somebody's payload, and reading a "port" out of them
	// would invent a destination.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return h, true
	}
	h.DstPort = transportPort(h.Proto, b, ihl)
	return h, true
}

func parseIPv6(b []byte) (Header, bool) {
	if len(b) < 40 {
		return Header{}, false
	}
	h := Header{
		Src: netip.AddrFrom16([16]byte(b[8:24])),
		Dst: netip.AddrFrom16([16]byte(b[24:40])),
	}
	next, off := b[6], 40
	for i := 0; ; i++ {
		ext := false
		switch next {
		case ip6HopByHop, ip6Routing, ip6DestOptions, ip6AH, ip6Fragment:
			ext = true
		}
		if !ext {
			break
		}
		if i >= ip6MaxExtHdrs || off+8 > len(b) {
			// Past the copy, or a chain no sender builds: the addresses are
			// known, the transport is not. Every extension header is at least
			// eight bytes, so off+8 bounds the reads below.
			h.Proto = Proto(next)
			return h, true
		}
		if next == ip6Fragment {
			nextHdr, fragOff := b[off], binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8
			next, off = nextHdr, off+8
			if fragOff != 0 {
				h.Proto = Proto(next)
				return h, true
			}
			continue
		}
		n := (int(b[off+1]) + 1) * 8
		if next == ip6AH {
			n = (int(b[off+1]) + 2) * 4
		}
		next, off = b[off], off+n
	}
	h.Proto = Proto(next)
	h.DstPort = transportPort(h.Proto, b, off)
	return h, true
}

// transportPort reads the destination port of a transport header starting at
// off, or 0 when the protocol has none or the copy ends before it.
func transportPort(p Proto, b []byte, off int) uint16 {
	if !p.HasPorts() || off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off+2 : off+4])
}
