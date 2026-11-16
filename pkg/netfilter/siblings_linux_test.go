//go:build linux

package netfilter

// The sibling rules on a real kernel, with no container engine anywhere
// (Task 20502). A host network namespace carries two bridges named the way the
// container driver names sandbox bridges, a "sandbox" namespace on each, and
// routes between them; each bridge gets the ruleset a sandbox under a filter
// gets, with an allow list covering both subnets. Without the sibling rules
// the allow list lets one sandbox reach the other's listener; with them the
// connect is refused at once — and a second sandbox on the listener's own
// bridge still reaches it. Docker and podman add isolation rules of their own
// on the same hook, which is why the container e2e cannot tell whose rule
// refused; here only cloop's are installed.
//
// Needs root and ip(8); everything happens in namespaces this test creates,
// none of them the host's.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// siblingRoleEnv switches the test binary into a helper inside a namespace:
// "listen:<addr>" accepts connections and answers each with one line,
// "dial:<addr>" connects once and reports how.
const siblingRoleEnv = "CLOOP_NETFILTER_SIBLING_ROLE"

type dialReport struct {
	Reached bool   `json:"reached"`
	Err     string `json:"err,omitempty"`
	Errno   int    `json:"errno,omitempty"`
	Millis  int64  `json:"millis"`
}

func runSiblingRole(role string) int {
	kind, addr, _ := strings.Cut(role, ":")
	switch kind {
	case "listen":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("listening")
		for {
			c, err := ln.Accept()
			if err != nil {
				return 0
			}
			_, _ = c.Write([]byte("reached\n"))
			_ = c.Close()
		}
	case "dial":
		start := time.Now()
		var rep dialReport
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		rep.Millis = time.Since(start).Milliseconds()
		if err == nil {
			buf := make([]byte, 16)
			n, _ := c.Read(buf)
			rep.Reached = strings.HasPrefix(string(buf[:n]), "reached")
			_ = c.Close()
		} else {
			rep.Err = err.Error()
			var errno syscall.Errno
			if errors.As(err, &errno) {
				rep.Errno = int(errno)
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		return 0
	}
	return 2
}

func TestSiblingRulesKeepTwoBridgesApart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("namespaces, bridges and nft need root")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	tag := fmt.Sprintf("cl%d", os.Getpid()%100000)
	host, alpha, alpha2, bravo := tag+"-host", tag+"-alpha", tag+"-alpha2", tag+"-bravo"
	// outsider sits on a bridge no sandbox pattern matches — podman's default
	// network, say, which its isolate option does not keep apart.
	outsider := tag + "-out"
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	for _, ns := range []string{host, alpha, alpha2, bravo, outsider} {
		run("ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}
	run("ip", "netns", "exec", host, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	bridgeA, bridgeB, bridgeOut := "clsb20502aaaaaa", "clsb20502bbbbbb", "ol20502outside"
	for _, b := range []struct{ name, addr string }{{bridgeA, "10.77.1.1/24"}, {bridgeB, "10.77.2.1/24"},
		{bridgeOut, "10.77.3.1/24"}} {
		run("ip", "-n", host, "link", "add", b.name, "type", "bridge")
		run("ip", "-n", host, "addr", "add", b.addr, "dev", b.name)
		run("ip", "-n", host, "link", "set", b.name, "up")
	}
	plug := func(ns, bridge, addr, gw, peer string) {
		run("ip", "-n", host, "link", "add", peer, "type", "veth", "peer", "name", peer+"s")
		run("ip", "-n", host, "link", "set", peer, "master", bridge, "up")
		run("ip", "-n", host, "link", "set", peer+"s", "netns", ns)
		run("ip", "-n", ns, "link", "set", "lo", "up")
		run("ip", "-n", ns, "addr", "add", addr, "dev", peer+"s")
		run("ip", "-n", ns, "link", "set", peer+"s", "up")
		run("ip", "-n", ns, "route", "add", "default", "via", gw)
	}
	plug(alpha, bridgeA, "10.77.1.2/24", "10.77.1.1", tag+"va")
	plug(alpha2, bridgeA, "10.77.1.3/24", "10.77.1.1", tag+"vc")
	plug(bravo, bridgeB, "10.77.2.2/24", "10.77.2.1", tag+"vb")
	plug(outsider, bridgeOut, "10.77.3.2/24", "10.77.3.1", tag+"vo")

	listen := func(ns, addr string) {
		t.Helper()
		listener := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^$")
		listener.Env = append(os.Environ(), siblingRoleEnv+"=listen:"+addr)
		out, err := listener.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Process.Kill(); _ = listener.Wait() })
		ready := make([]byte, 16)
		if n, _ := out.Read(ready); !strings.HasPrefix(string(ready[:n]), "listening") {
			t.Fatalf("the listener in %s did not start: %q", ns, ready[:n])
		}
	}
	listen(alpha, "10.77.1.2:8080")
	// A server outside every sandbox network, which alpha's own connections
	// must keep reaching: replies come back through alpha's inbound rule.
	listen(outsider, "10.77.3.2:8080")
	dialTo := func(ns, addr string) dialReport {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), siblingRoleEnv+"=dial:"+addr)
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("dial from %s: %v", ns, err)
		}
		var rep dialReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("dial from %s printed %q: %v", ns, raw, err)
		}
		return rep
	}
	dial := func(ns string) dialReport { return dialTo(ns, "10.77.1.2:8080") }
	install := func(siblings string) {
		t.Helper()
		p := mustCompilePolicy(t, Input{
			AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			AllowPorts: []uint16{8080},
		})
		for _, b := range []string{bridgeA, bridgeB} {
			script := mustRenderNft(t, p, NftablesOptions{Table: TableName("sbx", b), Bridge: b, Siblings: siblings})
			cmd := exec.Command("ip", "netns", "exec", host, "nft", "-f", "-")
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft -f for %s: %v\n%s", b, err, out)
			}
		}
	}

	// The rig routes: with no ruleset, bravo and the outsider reach alpha.
	for _, from := range []string{bravo, outsider} {
		if rep := dial(from); !rep.Reached {
			t.Fatalf("with no ruleset %s could not reach alpha (%s), so the rig proves nothing", from, rep.Err)
		}
	}
	// An allow list covering both subnets opens alpha to bravo — the case the
	// sibling rules exist for.
	install("")
	if rep := dial(bravo); !rep.Reached {
		t.Fatalf("under a covering allow list without sibling rules bravo could not reach alpha (%s); the "+
			"next step would prove nothing", rep.Err)
	}
	// With them, bravo is refused, at once.
	install("clsb*")
	rep := dial(bravo)
	if rep.Reached {
		t.Fatal("bravo reached alpha's listener through the sibling rules")
	}
	if syscall.Errno(rep.Errno) != syscall.ECONNREFUSED || rep.Millis > 1000 {
		t.Errorf("bravo's connect failed with %q (errno %d) after %d ms; the sibling rule refuses at once",
			rep.Err, rep.Errno, rep.Millis)
	}
	// Nor does anything on a bridge the pattern does not match.
	if rep := dial(outsider); rep.Reached {
		t.Error("a host on a bridge no sandbox pattern matches reached alpha's listener through alpha's ruleset")
	}
	// While alpha's own connection out gets its answer: the inbound rule
	// refuses what others open, never replies to what alpha opened.
	if rep := dialTo(alpha, "10.77.3.2:8080"); !rep.Reached {
		t.Errorf("alpha's own connection to a server its allow list opens got no answer through its ruleset: %s", rep.Err)
	}
	// And a sandbox on alpha's own bridge still reaches it: the rules spare a
	// sandbox's own bridge.
	if rep := dial(alpha2); !rep.Reached {
		t.Errorf("a second sandbox on alpha's bridge could not reach alpha under the sibling rules: %s", rep.Err)
	}
	listing, err := exec.Command("ip", "netns", "exec", host, "nft", "list", "table", "inet", TableName("sbx", bridgeB)).CombinedOutput()
	defer func() {
		// The unfiltered case: alpha's bridge with the inbound guard alone,
		// and no ruleset anywhere else. Nobody opens a connection into it,
		// and its own project's sandbox still does.
		for _, b := range []string{bridgeA, bridgeB} {
			_ = exec.Command("ip", "netns", "exec", host, "nft", "delete", "table", "inet", TableName("sbx", b)).Run()
		}
		guard, err := RenderInboundGuard(NftablesOptions{Table: TableName("sbx", bridgeA), Bridge: bridgeA})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("ip", "netns", "exec", host, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(guard)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f for the guard: %v\n%s", err, out)
		}
		for _, from := range []string{bravo, outsider} {
			if rep := dial(from); rep.Reached {
				t.Errorf("%s reached alpha's unfiltered sandbox through its inbound guard", from)
			}
		}
		if rep := dial(alpha2); !rep.Reached {
			t.Errorf("alpha's own second sandbox could not reach it under the guard alone: %s", rep.Err)
		}
		if rep := dialTo(alpha, "10.77.3.2:8080"); !rep.Reached {
			t.Errorf("alpha's own connection out got no answer through the guard alone: %s", rep.Err)
		}
	}()
	if err != nil {
		t.Fatalf("nft list: %v\n%s", err, listing)
	}
	for _, l := range strings.Split(string(listing), "\n") {
		if strings.Contains(l, `comment "another sandbox's network"`) {
			if strings.Contains(l, "packets 0 ") {
				t.Errorf("bravo's outbound sibling rule counted nothing:\n%s", listing)
			}
			t.Logf("bravo's ruleset: %s", strings.TrimSpace(l))
		}
	}
}
