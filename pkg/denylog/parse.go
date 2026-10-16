package denylog

import (
	"encoding/binary"
	"errors"
	"time"
)

// parse.go reads the messages nfnetlink_log sends a bound socket.
//
// One recv can carry many: the kernel batches up to the queue threshold or the
// flush timeout configured on the group (nflog_linux.go), as a run of netlink
// messages each holding one packet. The layout, from linux/netfilter/
// nfnetlink_log.h and linux/netfilter/nfnetlink.h:
//
//	struct nlmsghdr   len u32, type u16, flags u16, seq u32, pid u32
//	struct nfgenmsg   family u8, version u8, res_id be16 (the group)
//	attributes        len u16, type u16, value, padded to 4 bytes
//
// The type is NFNL_SUBSYS_ULOG<<8 | NFULNL_MSG_PACKET. Lengths come from the
// kernel and are checked anyway: a parser that trusted them would be the one
// place a malformed buffer could index out of range in a process holding
// CAP_NET_ADMIN.

// netlink and nfnetlink_log constants (linux/netlink.h, nfnetlink_log.h).
const (
	nlmsgHdrLen   = 16
	nfgenMsgLen   = 4
	nlaHdrLen     = 4
	nlmsgError    = 2
	nlmsgDone     = 3
	nlmsgOverrun  = 4
	nfnlSubsysLog = 4

	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulaPacketHdr  = 1
	nfulaTimestamp  = 3
	nfulaIfindexIn  = 4
	nfulaIfindexOut = 5
	nfulaPayload    = 9
	nfulaPrefix     = 10

	nlaTypeMask = 0x3fff // without NLA_F_NESTED and NLA_F_NET_BYTEORDER
)

// Packet is one logged packet, as the kernel reported it.
type Packet struct {
	// Group is the NFLOG group it was logged to.
	Group uint16
	// Family is the nfgenmsg family: AF_INET (2) or AF_INET6 (10).
	Family uint8
	// Hook is the netfilter hook it was logged in.
	Hook uint8
	// InDev and OutDev are interface indexes, 0 when absent.
	InDev, OutDev uint32
	// Prefix is the log statement's prefix.
	Prefix string
	// Time is the kernel's timestamp for the packet, zero when it sent none.
	Time time.Time
	// Payload is the packet from its network header, as far as the copy
	// went. It aliases the receive buffer and is valid only during the
	// callback.
	Payload []byte
}

// errTruncated reports a buffer whose lengths do not add up.
var errTruncated = errors.New("denylog: truncated netlink message")

// ParseMessages calls fn for every NFLOG packet message in buf and skips every
// other message. It stops at the first malformed one and reports it: what came
// before it was delivered, and nothing after it can be trusted to be aligned.
func ParseMessages(buf []byte, fn func(Packet)) error {
	for len(buf) >= nlmsgHdrLen {
		n := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if n < nlmsgHdrLen || n > len(buf) {
			return errTruncated
		}
		msg := buf[nlmsgHdrLen:n]
		if typ>>8 == nfnlSubsysLog && typ&0xff == nfulnlMsgPacket {
			p, err := parsePacket(msg)
			if err != nil {
				return err
			}
			fn(p)
		}
		// Every other type — an ack, NLMSG_DONE closing a batch, an overrun
		// notice — carries nothing to record.
		adv := align4(n)
		if adv > len(buf) {
			return nil
		}
		buf = buf[adv:]
	}
	return nil
}

func parsePacket(msg []byte) (Packet, error) {
	if len(msg) < nfgenMsgLen {
		return Packet{}, errTruncated
	}
	p := Packet{Family: msg[0], Group: binary.BigEndian.Uint16(msg[2:4])}
	attrs := msg[nfgenMsgLen:]
	for len(attrs) >= nlaHdrLen {
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		t := binary.NativeEndian.Uint16(attrs[2:4]) & nlaTypeMask
		if l < nlaHdrLen || l > len(attrs) {
			return Packet{}, errTruncated
		}
		v := attrs[nlaHdrLen:l]
		switch t {
		case nfulaPacketHdr:
			// struct nfulnl_msg_packet_hdr { __be16 hw_protocol; __u8 hook; __u8 _pad; }
			if len(v) >= 3 {
				p.Hook = v[2]
			}
		case nfulaTimestamp:
			// struct nfulnl_msg_packet_timestamp { __aligned_be64 sec, usec; }
			if len(v) >= 16 {
				sec, usec := binary.BigEndian.Uint64(v[0:8]), binary.BigEndian.Uint64(v[8:16])
				if sec > 0 && sec < 1<<40 && usec < 1_000_000 {
					p.Time = time.Unix(int64(sec), int64(usec)*1000)
				}
			}
		case nfulaIfindexIn:
			if len(v) >= 4 {
				p.InDev = binary.BigEndian.Uint32(v[0:4])
			}
		case nfulaIfindexOut:
			if len(v) >= 4 {
				p.OutDev = binary.BigEndian.Uint32(v[0:4])
			}
		case nfulaPrefix:
			// NUL-terminated by the kernel; stop at the first NUL so a
			// prefix can never carry one into a comparison.
			for i, c := range v {
				if c == 0 {
					v = v[:i]
					break
				}
			}
			p.Prefix = string(v)
		case nfulaPayload:
			p.Payload = v
		}
		adv := align4(l)
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	return p, nil
}

func align4(n int) int { return (n + 3) &^ 3 }
