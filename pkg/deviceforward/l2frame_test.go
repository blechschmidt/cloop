package deviceforward

import (
	"encoding/binary"
	"testing"
)

// verifyL4 reports whether a frame's TCP/UDP checksum verifies: the
// ones-complement sum over the pseudo-header and the segment is all ones.
func verifyL4(t *testing.T, frame []byte, v6 bool) bool {
	t.Helper()
	ip := frame[14:]
	var pseudo uint32
	var l4 []byte
	if v6 {
		plen := int(binary.BigEndian.Uint16(ip[4:6]))
		l4 = ip[40 : 40+plen]
		pseudo = sum16(ip[8:40]) + uint32(len(l4)) + uint32(ip[6])
	} else {
		ihl := int(ip[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		l4 = ip[ihl:total]
		pseudo = sum16(ip[12:20]) + uint32(ip[9]) + uint32(len(l4))
	}
	return fold(pseudo+sum16(l4)) == 0xffff
}

func ipv4TCPFrame() []byte {
	payload := []byte("hello from the sandbox\n")
	f := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(payload)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], []byte{10, 77, 0, 1})
	copy(ip[16:20], []byte{10, 77, 0, 2})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 7777)
	binary.BigEndian.PutUint16(tcp[2:], 40000)
	tcp[12] = 5 << 4
	tcp[13] = 0x12 // SYN-ACK
	// What an offloading peer leaves in the field: the pseudo-header sum,
	// not the checksum.
	binary.BigEndian.PutUint16(tcp[16:], 0x1234)
	copy(tcp[20:], payload)
	return f
}

func TestCompleteL4ChecksumTCPv4(t *testing.T) {
	f := ipv4TCPFrame()
	if verifyL4(t, f, false) {
		t.Fatal("the fixture's checksum verifies before completion; the test proves nothing")
	}
	completeL4Checksum(f)
	if !verifyL4(t, f, false) {
		t.Fatal("the completed TCP checksum does not verify")
	}
	// A fragment is left alone: its L4 header is not all there.
	frag := ipv4TCPFrame()
	binary.BigEndian.PutUint16(frag[14+6:], 0x2000)
	before := append([]byte(nil), frag...)
	completeL4Checksum(frag)
	if string(before) != string(frag) {
		t.Fatal("an IPv4 fragment was rewritten")
	}
}

func TestCompleteL4ChecksumUDPv6(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	f := make([]byte, 14+40+8+len(payload))
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	ip := f[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+len(payload)))
	ip[6], ip[7] = 17, 64
	ip[8], ip[23] = 0xfd, 1
	ip[24], ip[39] = 0xfd, 2
	udp := ip[40:]
	binary.BigEndian.PutUint16(udp[0:], 5353)
	binary.BigEndian.PutUint16(udp[2:], 5353)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	completeL4Checksum(f)
	if !verifyL4(t, f, true) {
		t.Fatal("the completed UDP/IPv6 checksum does not verify")
	}
}

func TestInsertVLANRestoresTheTag(t *testing.T) {
	f := ipv4TCPFrame()
	buf := make([]byte, len(f)+4)
	n := copy(buf, f)
	n = insertVLAN(buf, n, 0x8100, 42)
	if n != len(f)+4 || binary.BigEndian.Uint16(buf[12:]) != 0x8100 ||
		binary.BigEndian.Uint16(buf[14:]) != 42 || binary.BigEndian.Uint16(buf[16:]) != 0x0800 {
		t.Fatalf("tagged frame header = % x", buf[:18])
	}
	// A checksum is still completed through the tag.
	completeL4Checksum(buf[:n])
	if !verifyL4(t, append(append([]byte(nil), buf[:12]...), buf[16:n]...), false) {
		t.Fatal("a tagged frame's checksum was not completed")
	}
}
