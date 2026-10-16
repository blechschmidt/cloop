//go:build linux

package denylog

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// netns_linux_test.go is the kernel's half of Task 20437, proved without a
// container engine: two network namespaces, a client and a router between it
// and the "Internet", the router filtering what the client sends with the
// ruleset pkg/netfilter renders for a sandbox's bridge. The client's connects
// must fail at once — a reset, an ICMP refusal — and the router's NFLOG group
// must carry one line per refusal, which this process reads with the reader it
// ships. The raw netlink buffers it reads are the parser's fixtures
// (testdata/nflog-*.hex), regenerated with -update.

var update = flag.Bool("update", false, "rewrite testdata/nflog-*.hex from a live capture")

// roleEnv switches the test binary into a helper run inside a namespace. The
// helper never reaches m.Run, so it cannot start helpers of its own.
const roleEnv = "CLOOP_DENYLOG_TEST_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "capture":
		os.Exit(captureRole())
	case "client":
		os.Exit(clientRole())
	}
	os.Exit(m.Run())
}

// captureRole binds a group, says which, and prints every buffer it reads as
// hex until its stdin closes.
func captureRole() int {
	src, err := openSource(baseGroup(), groupTries)
	if err != nil {
		fmt.Println("error", err)
		return 1
	}
	defer src.close()
	fmt.Println("group", src.group())
	stop := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(stop) }()
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-stop:
			// The kernel's flush timeout may still hold the last lines.
			deadline := time.Now().Add(600 * time.Millisecond)
			for time.Now().Before(deadline) {
				if n, err := src.read(buf); err == nil {
					fmt.Println("buf", hex.EncodeToString(buf[:n]))
				}
			}
			return 0
		default:
		}
		n, err := src.read(buf)
		if err == nil {
			fmt.Println("buf", hex.EncodeToString(buf[:n]))
		}
	}
}

// probe is one connection the client makes.
type probe struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Addr    string `json:"addr"`
	Err     string `json:"err"`
	Errno   int    `json:"errno"`
	Millis  int64  `json:"millis"`
}

var clientProbes = []probe{
	{Name: "deny-list tcp", Network: "tcp4", Addr: "203.0.113.7:443"},
	{Name: "default tcp", Network: "tcp4", Addr: "198.51.100.7:80"},
	{Name: "deny-list udp", Network: "udp4", Addr: "203.0.113.7:53"},
	{Name: "default tcp6", Network: "tcp6", Addr: "[2001:db8::7]:443"},
	{Name: "default udp6", Network: "udp6", Addr: "[2001:db8::7]:53"},
}

// clientRole makes each probe once, timing how long it takes to fail.
func clientRole() int {
	var out []probe
	for _, p := range clientProbes {
		start := time.Now()
		var err error
		if strings.HasPrefix(p.Network, "tcp") {
			var c net.Conn
			c, err = net.DialTimeout(p.Network, p.Addr, 5*time.Second)
			if c != nil {
				c.Close()
			}
		} else {
			var c net.Conn
			c, err = net.Dial(p.Network, p.Addr)
			if err == nil {
				_, _ = c.Write([]byte("probe"))
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err = c.Read(make([]byte, 16))
				c.Close()
			}
		}
		p.Millis = time.Since(start).Milliseconds()
		if err != nil {
			p.Err = err.Error()
			var errno syscall.Errno
			if errors.As(err, &errno) {
				p.Errno = int(errno)
			}
		}
		out = append(out, p)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}

// netnsRig is the two namespaces and the link between them.
type netnsRig struct {
	client, router string
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func newNetnsRig(t *testing.T) netnsRig {
	t.Helper()
	tag := fmt.Sprintf("%d", os.Getpid()%100000)
	r := netnsRig{client: "t20437c" + tag, router: "t20437r" + tag}
	run(t, "ip", "netns", "add", r.client)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", r.client).Run() })
	run(t, "ip", "netns", "add", r.router)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", r.router).Run() })

	in := func(ns string, args ...string) { run(t, "ip", append([]string{"netns", "exec", ns}, args...)...) }
	// No duplicate address detection: it holds a fresh link-local address
	// tentative for a second, and the first neighbour discovery with it, which
	// would time the rig's link-up rather than the filter.
	for _, ns := range []string{r.client, r.router} {
		in(ns, "sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0")
		in(ns, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0")
	}
	run(t, "ip", "link", "add", "t20437a", "netns", r.client, "type", "veth", "peer", "name", "t20437b", "netns", r.router)
	in(r.client, "ip", "link", "set", "lo", "up")
	in(r.client, "ip", "addr", "add", "10.99.0.2/24", "dev", "t20437a")
	in(r.client, "ip", "-6", "addr", "add", "fd99::2/64", "dev", "t20437a", "nodad")
	in(r.client, "ip", "link", "set", "t20437a", "up")
	in(r.client, "ip", "route", "add", "default", "via", "10.99.0.1")
	in(r.client, "ip", "-6", "route", "add", "default", "via", "fd99::1")
	in(r.router, "ip", "link", "set", "lo", "up")
	in(r.router, "ip", "addr", "add", "10.99.0.1/24", "dev", "t20437b")
	in(r.router, "ip", "-6", "addr", "add", "fd99::1/64", "dev", "t20437b", "nodad")
	in(r.router, "ip", "link", "set", "t20437b", "up")
	in(r.router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	in(r.router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
	// Somewhere for the router to forward to: the destinations exist only
	// as routes, so nothing but the filter can answer.
	in(r.router, "ip", "link", "add", "t20437d", "type", "dummy")
	in(r.router, "ip", "link", "set", "t20437d", "up")
	in(r.router, "ip", "route", "add", "203.0.113.0/24", "dev", "t20437d")
	in(r.router, "ip", "route", "add", "198.51.100.0/24", "dev", "t20437d")
	in(r.router, "ip", "-6", "route", "add", "2001:db8::/32", "dev", "t20437d")
	// Neighbours resolved before the filter goes in, so what the probes time
	// is the filter and not a first neighbour discovery.
	in(r.client, "ping", "-c1", "-W2", "10.99.0.1")
	in(r.client, "ping", "-6", "-c1", "-W2", "fd99::1")
	return r
}

func requireRig(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces and bind an NFLOG group")
	}
	for _, tool := range []string{"ip", "nft", "sysctl", "ping"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// TestRefusalsAreImmediateAndLogged runs the rig: refusals within a fraction
// of a second, and one parsed log line for each, naming the rule.
func TestRefusalsAreImmediateAndLogged(t *testing.T) {
	requireRig(t)
	rig := newNetnsRig(t)

	capture := exec.Command("ip", "netns", "exec", rig.router, os.Args[0], "-test.run=^$")
	capture.Env = append(os.Environ(), roleEnv+"=capture")
	stdin, err := capture.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := capture.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	capture.Stderr = os.Stderr
	if err := capture.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = capture.Process.Kill(); _ = capture.Wait() })
	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 1<<20), 1<<22)
	if !lines.Scan() {
		t.Fatal("the capture helper said nothing")
	}
	var group uint16
	if _, err := fmt.Sscanf(lines.Text(), "group %d", &group); err != nil {
		t.Fatalf("the capture helper could not bind a group: %s", lines.Text())
	}

	p, err := netfilter.Compile(netfilter.Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		AllowPorts: []uint16{443},
		DenyCIDRs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := netfilter.RenderNftables(p, netfilter.NftablesOptions{
		Table: "cloop_t20437", Bridge: "t20437b",
		Log: &netfilter.LogOptions{Group: group, Fingerprint: "0123456789ab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	nft := exec.Command("ip", "netns", "exec", rig.router, "nft", "-f", "-")
	nft.Stdin = strings.NewReader(script)
	if out, err := nft.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}

	client := exec.Command("ip", "netns", "exec", rig.client, os.Args[0], "-test.run=^$")
	client.Env = append(os.Environ(), roleEnv+"=client")
	out, err := client.Output()
	if err != nil {
		t.Fatalf("client: %v\n%s", err, out)
	}
	var probes []probe
	if err := json.Unmarshal(out, &probes); err != nil {
		t.Fatalf("client printed %q: %v", out, err)
	}
	for _, p := range probes {
		t.Logf("%-14s %-22s %4d ms  %s", p.Name, p.Addr, p.Millis, p.Err)
		if p.Err == "" {
			t.Errorf("%s: %s connected; the filter let it through", p.Name, p.Addr)
		}
		// A timeout is what Task 20437 removes: the refusal is a reset or an
		// ICMP error, answered by the router before anything could time out.
		if p.Millis > 1000 {
			t.Errorf("%s: %s took %d ms to fail — dropped, not refused", p.Name, p.Addr, p.Millis)
		}
		want := map[string][]syscall.Errno{
			"tcp4": {syscall.ECONNREFUSED}, "tcp6": {syscall.ECONNREFUSED},
			"udp4": {syscall.EHOSTUNREACH, syscall.ECONNREFUSED},
			"udp6": {syscall.EACCES, syscall.EHOSTUNREACH, syscall.ECONNREFUSED},
		}[p.Network]
		ok := false
		for _, w := range want {
			ok = ok || syscall.Errno(p.Errno) == w
		}
		if !ok {
			t.Errorf("%s: %s failed with %q (errno %d), want one of %v", p.Name, p.Addr, p.Err, p.Errno, want)
		}
	}

	_ = stdin.Close()
	var bufs [][]byte
	for lines.Scan() {
		if h, ok := strings.CutPrefix(lines.Text(), "buf "); ok {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			bufs = append(bufs, b)
		}
	}
	got := map[string]int{}
	for _, b := range bufs {
		if err := ParseMessages(b, func(pk Packet) {
			_, rule, ok := ParsePrefix(pk.Prefix)
			h, hok := ParseHeader(pk.Payload)
			if !ok || !hok {
				t.Errorf("unreadable logged packet: prefix %q, %d payload bytes", pk.Prefix, len(pk.Payload))
				return
			}
			if pk.InDev == 0 {
				t.Errorf("a forwarded packet logged without its input interface")
			}
			got[fmt.Sprintf("%s %s/%s %s", h.Src, netip.AddrPortFrom(h.Dst, h.DstPort), h.Proto, rule)]++
		}); err != nil {
			t.Fatalf("ParseMessages: %v", err)
		}
	}
	for _, want := range []string{
		"10.99.0.2 203.0.113.7:443/tcp deny:203.0.113.0/24",
		"10.99.0.2 198.51.100.7:80/tcp default",
		"10.99.0.2 203.0.113.7:53/udp deny:203.0.113.0/24",
		"fd99::2 [2001:db8::7]:443/tcp default",
		"fd99::2 [2001:db8::7]:53/udp default",
	} {
		// One line per connect: a refused connect is not retransmitted.
		if got[want] != 1 {
			t.Errorf("logged %d times, want once: %s (all: %v)", got[want], want, got)
		}
	}

	if *update {
		for i, b := range bufs {
			path := filepath.Join("testdata", fmt.Sprintf("nflog-%d.hex", i))
			if err := os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("wrote %d fixtures", len(bufs))
	}
}
