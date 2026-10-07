package exposure

import (
	"net"
	"net/netip"
	"testing"
)

// FuzzDecideNeverOpensAnOpenHub holds the guarantee against any listen string
// an operator could write: a hub without sign-in and without the
// acknowledgement either binds a loopback address — an IP literal, never a
// name a resolver could turn into something else — or is refused. And
// whatever Decide accepts, net.Listen is handed a well-formed host:port.
func FuzzDecideNeverOpensAnOpenHub(f *testing.F) {
	for _, s := range []string{
		"", "127.0.0.1", "::1", "[::1]", "localhost", "LOCALHOST.", "0.0.0.0", "::", "[::]",
		"::ffff:127.0.0.1", "::ffff:0.0.0.0", "127.255.255.254", "192.0.2.1", "fe80::1%eth0",
		"hub.internal", "hub.localhost", "0.0.0.0:8080", "[::1]:80", "http://0.0.0.0", " 127.0.0.1 ",
		"127.1", "0", "localhost:", "[localhost]", "*", "%", "a..b",
	} {
		f.Add(s, false, false, false)
	}
	f.Add("0.0.0.0", false, false, true)
	f.Add("0.0.0.0", true, false, false)
	f.Add("hub.internal", false, true, false)

	f.Fuzz(func(t *testing.T, listen string, sso, token, ack bool) {
		plan, err := Decide(Request{Listen: listen, Port: 8080, SSO: sso, StaticToken: token,
			AllowUnauthenticatedNetwork: ack})
		if err != nil {
			return
		}
		if _, port, serr := net.SplitHostPort(plan.Addr()); serr != nil || port != "8080" {
			t.Fatalf("Decide(%q) hands net.Listen %q", listen, plan.Addr())
		}
		switch plan.Scope {
		case ScopeLoopback:
			if a, perr := netip.ParseAddr(plan.Host); perr != nil || !a.IsLoopback() {
				t.Fatalf("Decide(%q) calls %q loopback", listen, plan.Host)
			}
		case ScopeEvery:
			if plan.Host != "" {
				t.Fatalf("Decide(%q): every interface as %q, want the empty host", listen, plan.Host)
			}
		}
		if !sso && !token && !ack && plan.Scope != ScopeLoopback {
			t.Fatalf("Decide(%q) lets a hub without sign-in listen on %s", listen, plan)
		}
		if plan.Acknowledged && (sso || token || plan.Scope == ScopeLoopback) {
			t.Fatalf("Decide(%q): acknowledged where nothing needed acknowledging (%s)", listen, plan)
		}
	})
}
