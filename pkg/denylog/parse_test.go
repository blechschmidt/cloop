package denylog

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parse_test.go reads the kernel's own messages: testdata/nflog-*.hex are
// receive buffers captured from a real NFLOG group by the netns rig
// (netns_linux_test.go, -update), holding the five refusals it provokes.

func fixtureBuffers(t *testing.T) [][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "nflog-*.hex"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	var out [][]byte
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, b)
	}
	return out
}

func TestParseCapturedNFLOG(t *testing.T) {
	type seen struct {
		family uint8
		src    string
		dst    string
		proto  Proto
		rule   string
	}
	var got []seen
	for _, b := range fixtureBuffers(t) {
		if err := ParseMessages(b, func(p Packet) {
			if p.Group != 27437 {
				t.Errorf("group %d, want 27437", p.Group)
			}
			if p.Hook != 2 {
				t.Errorf("hook %d, want NF_INET_FORWARD (2): the rig's router logs in its forward chain", p.Hook)
			}
			if p.InDev == 0 || p.OutDev == 0 {
				t.Errorf("a forwarded packet without both interfaces: in=%d out=%d", p.InDev, p.OutDev)
			}
			if p.Time.IsZero() {
				t.Error("the kernel's timestamp was not read")
			}
			if len(p.Payload) > LogSnaplenForTest {
				t.Errorf("payload of %d bytes is past the rule's snaplen", len(p.Payload))
			}
			fp, rule, ok := ParsePrefix(p.Prefix)
			if !ok || fp != "0123456789ab" {
				t.Errorf("prefix %q does not parse", p.Prefix)
			}
			h, ok := ParseHeader(p.Payload)
			if !ok {
				t.Fatalf("unreadable header in %x", p.Payload)
			}
			got = append(got, seen{p.Family, h.Src.String(), netip.AddrPortFrom(h.Dst, h.DstPort).String(), h.Proto, rule})
		}); err != nil {
			t.Fatalf("ParseMessages: %v", err)
		}
	}
	want := []seen{
		{2, "10.99.0.2", "203.0.113.7:443", ProtoTCP, "deny:203.0.113.0/24"},
		{2, "10.99.0.2", "198.51.100.7:80", ProtoTCP, "default"},
		{2, "10.99.0.2", "203.0.113.7:53", ProtoUDP, "deny:203.0.113.0/24"},
		{10, "fd99::2", "[2001:db8::7]:443", ProtoTCP, "default"},
		{10, "fd99::2", "[2001:db8::7]:53", ProtoUDP, "default"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d packets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("packet %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// LogSnaplenForTest is the rules' snaplen, restated so the fixture check does
// not import the renderer it is meant to be independent of.
const LogSnaplenForTest = 80

// TestParseRejectsMalformedBuffers: every length in a netlink buffer is the
// sender's claim. Truncations and overlong lengths at each layer must stop the
// parse without a panic or a read past the end, and must not deliver a packet
// assembled from someone else's bytes.
func TestParseRejectsMalformedBuffers(t *testing.T) {
	good := fixtureBuffers(t)[0]
	first := int(binary.NativeEndian.Uint32(good[0:4]))
	msg := append([]byte(nil), good[:align4(first)]...)

	cases := map[string][]byte{
		"empty":            nil,
		"short header":     msg[:10],
		"length past end":  setU32(msg, 0, uint32(len(msg)+8)),
		"length too small": setU32(msg, 0, 8),
		"attr past end":    setU16(msg, nlmsgHdrLen+nfgenMsgLen, 0x7ff0),
		"attr too small":   setU16(msg, nlmsgHdrLen+nfgenMsgLen, 2),
		"no nfgenmsg":      setU32(msg[:nlmsgHdrLen+2], 0, nlmsgHdrLen+2),
	}
	for name, b := range cases {
		n := 0
		err := ParseMessages(b, func(Packet) { n++ })
		if name == "empty" {
			if err != nil || n != 0 {
				t.Errorf("%s: err=%v packets=%d", name, err, n)
			}
			continue
		}
		if n != 0 {
			t.Errorf("%s: delivered %d packets from a malformed buffer", name, n)
		}
		if err == nil && name != "short header" {
			t.Errorf("%s: no error", name)
		}
	}

	// Truncating anywhere must never panic.
	for i := 0; i <= len(good); i++ {
		_ = ParseMessages(good[:i], func(p Packet) { _, _ = ParseHeader(p.Payload) })
	}
}

func setU32(b []byte, off int, v uint32) []byte {
	c := append([]byte(nil), b...)
	binary.NativeEndian.PutUint32(c[off:off+4], v)
	return c
}

func setU16(b []byte, off int, v uint16) []byte {
	c := append([]byte(nil), b...)
	binary.NativeEndian.PutUint16(c[off:off+2], v)
	return c
}

// TestParseSkipsOtherMessages: acks, NLMSG_DONE and messages from other
// subsystems share the socket and carry nothing to record.
func TestParseSkipsOtherMessages(t *testing.T) {
	good := fixtureBuffers(t)[0]
	done := make([]byte, 20)
	binary.NativeEndian.PutUint32(done[0:4], 20)
	binary.NativeEndian.PutUint16(done[4:6], nlmsgDone)
	cfg := append([]byte(nil), done...)
	binary.NativeEndian.PutUint16(cfg[4:6], nfnlSubsysLog<<8|nfulnlMsgConfig)
	buf := append(append(append([]byte(nil), done...), cfg...), good...)
	n := 0
	if err := ParseMessages(buf, func(Packet) { n++ }); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("parsed %d packets around other messages, want 5", n)
	}
}

func FuzzParseMessages(f *testing.F) {
	for _, b := range fixtureBuffersF(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = ParseMessages(b, func(p Packet) {
			if h, ok := ParseHeader(p.Payload); ok && !h.Src.IsValid() {
				t.Fatal("a parsed header with no source")
			}
		})
	})
}

func fixtureBuffersF(f *testing.F) [][]byte {
	paths, _ := filepath.Glob(filepath.Join("testdata", "nflog-*.hex"))
	var out [][]byte
	for _, p := range paths {
		if raw, err := os.ReadFile(p); err == nil {
			if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// ─── headers ────────────────────────────────────────────────────────────────

func ipv4(proto byte, ihl int, frag uint16, transport []byte) []byte {
	h := make([]byte, ihl)
	h[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(h[6:8], frag)
	h[9] = proto
	copy(h[12:16], []byte{10, 0, 0, 2})
	copy(h[16:20], []byte{203, 0, 113, 7})
	return append(h, transport...)
}

func ports(dst uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 40000)
	binary.BigEndian.PutUint16(b[2:4], dst)
	return b
}

func ipv6(next byte, ext []byte, transport []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = next
	copy(h[8:24], netip.MustParseAddr("fd00::2").AsSlice())
	copy(h[24:40], netip.MustParseAddr("2001:db8::7").AsSlice())
	return append(append(h, ext...), transport...)
}

func extHdr(next byte, len8 int) []byte {
	b := make([]byte, (len8+1)*8)
	b[0], b[1] = next, byte(len8)
	return b
}

func TestParseHeader(t *testing.T) {
	frag := make([]byte, 8)
	frag[0] = 6 // TCP behind it
	laterFrag := append([]byte(nil), frag...)
	binary.BigEndian.PutUint16(laterFrag[2:4], 8<<3) // offset 8 units
	cases := []struct {
		name  string
		b     []byte
		ok    bool
		proto Proto
		port  uint16
	}{
		{"ipv4 tcp", ipv4(6, 20, 0, ports(443)), true, ProtoTCP, 443},
		{"ipv4 udp with options", ipv4(17, 32, 0, ports(53)), true, ProtoUDP, 53},
		{"ipv4 icmp", ipv4(1, 20, 0, []byte{8, 0, 0, 0}), true, ProtoICMP, 0},
		{"ipv4 later fragment", ipv4(6, 20, 0x0010, ports(443)), true, ProtoTCP, 0},
		{"ipv4 first fragment", ipv4(6, 20, 0x2000, ports(443)), true, ProtoTCP, 443},
		{"ipv4 options past the copy", ipv4(6, 20, 0, nil)[:20], true, ProtoTCP, 0},
		{"ipv4 transport cut off", ipv4(6, 20, 0, ports(443))[:22], true, ProtoTCP, 0},
		{"ipv4 bad ihl", func() []byte { b := ipv4(6, 20, 0, ports(1)); b[0] = 0x42; return b }(), false, 0, 0},
		{"ipv4 short", ipv4(6, 20, 0, nil)[:19], false, 0, 0},
		{"ipv6 tcp", ipv6(6, nil, ports(443)), true, ProtoTCP, 443},
		{"ipv6 hop-by-hop then udp", ipv6(0, extHdr(17, 0), ports(53)), true, ProtoUDP, 53},
		{"ipv6 two extensions", ipv6(0, append(extHdr(60, 0), extHdr(6, 1)...), ports(8443)), true, ProtoTCP, 8443},
		{"ipv6 first fragment", ipv6(44, frag, ports(443)), true, ProtoTCP, 443},
		{"ipv6 later fragment", ipv6(44, laterFrag, ports(443)), true, ProtoTCP, 0},
		{"ipv6 extension past copy", ipv6(0, nil, nil), true, Proto(0), 0},
		{"ipv6 icmpv6", ipv6(58, nil, []byte{128, 0, 0, 0}), true, ProtoICMPv6, 0},
		{"ipv6 short", ipv6(6, nil, nil)[:39], false, 0, 0},
		{"not ip", []byte{0x10, 0, 0}, false, 0, 0},
		{"empty", nil, false, 0, 0},
	}
	for _, c := range cases {
		h, ok := ParseHeader(c.b)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if h.Proto != c.proto || h.DstPort != c.port {
			t.Errorf("%s: proto %d port %d, want %d %d", c.name, h.Proto, h.DstPort, c.proto, c.port)
		}
		if !h.Src.IsValid() || !h.Dst.IsValid() {
			t.Errorf("%s: addresses not read", c.name)
		}
	}

	// A chain of extension headers longer than any sender builds stops the
	// walk rather than looping.
	var chain []byte
	for i := 0; i < 20; i++ {
		chain = append(chain, extHdr(60, 0)...)
	}
	if h, ok := ParseHeader(ipv6(60, chain, ports(1))); !ok || h.DstPort != 0 {
		t.Errorf("a 20-deep extension chain: %+v, %v", h, ok)
	}
}
