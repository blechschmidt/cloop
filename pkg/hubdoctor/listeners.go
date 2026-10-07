package hubdoctor

// listeners.go: which sockets are listening on a port, read from the kernel
// rather than predicted from a configuration (Task 20393).
//
// The exposure check needs this because the process on a hub's port is not
// necessarily one that read this configuration with this build: an older
// binary binds every interface whatever its configuration says, and a flag on
// a unit file is invisible to anything that reads config.yaml. Only the
// socket table says what is actually reachable.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// errListenersUnavailable reports a system whose socket table this package
// cannot read.
var errListenersUnavailable = errors.New("the listening sockets cannot be read on this system")

// procNetTCP are the socket tables a Linux kernel publishes for this network
// namespace, IPv4 and IPv6.
var procNetTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// procListeners returns every TCP socket in LISTEN state on port, from the
// kernel's socket tables. It sees the network namespace it runs in, which is
// the hub's own when the doctor runs beside it — and, for a container hub,
// when it runs inside the container.
func procListeners(port int) ([]netip.AddrPort, error) {
	if runtime.GOOS != "linux" {
		return nil, errListenersUnavailable
	}
	var out []netip.AddrPort
	read := false
	for _, path := range procNetTCP {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue // no IPv6 in this namespace
		}
		if err != nil {
			return nil, err
		}
		read = true
		out = append(out, parseProcNetTCP(data, port)...)
	}
	if !read {
		return nil, errListenersUnavailable
	}
	return out, nil
}

// tcpListen is the kernel's TCP_LISTEN state, as /proc/net/tcp prints it.
const tcpListen = "0A"

// parseProcNetTCP extracts the listening sockets on port from one of the
// kernel's socket tables. A line it cannot read is skipped: the table is the
// kernel's, and a format change should cost this check a socket rather than
// the doctor its run.
func parseProcNetTCP(data []byte, port int) []netip.AddrPort {
	var out []netip.AddrPort
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[min(1, len(lines)):] { // the first line is the header
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != tcpListen {
			continue
		}
		hexIP, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		ip, ok := decodeProcAddr(hexIP)
		if !ok {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(p)))
	}
	return out
}

// decodeProcAddr reads an address the way the kernel writes it: the network-
// order bytes as 32-bit words, each printed as a native-endian integer.
func decodeProcAddr(s string) (netip.Addr, bool) {
	raw, err := hex.DecodeString(s)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, false
	}
	out := make([]byte, len(raw))
	for w := 0; w < len(raw); w += 4 {
		binary.NativeEndian.PutUint32(out[w:w+4], binary.BigEndian.Uint32(raw[w:w+4]))
	}
	ip, ok := netip.AddrFromSlice(out)
	return ip.Unmap(), ok
}
