package exposure

import (
	"errors"
	"strings"
	"testing"
)

// auth is one of the three ways a hub can stand in front of a browser.
type auth struct {
	name        string
	sso, token  bool
	wantDefault string // the bind address when no address is named
}

var auths = []auth{
	// No credential at all: only this machine may reach it.
	{name: "open", wantDefault: "127.0.0.1:8080"},
	// Either credential keeps the pre-Task-20393 default, every interface.
	{name: "static token", token: true, wantDefault: "*:8080"},
	{name: "SSO", sso: true, wantDefault: "*:8080"},
}

// TestBindAddressForEveryAuthAndListen is the matrix the task names: the
// three authentication states against the default, an explicit loopback
// address, and an explicit address beyond loopback with and without the
// acknowledgement.
func TestBindAddressForEveryAuthAndListen(t *testing.T) {
	type listen struct {
		name   string
		listen string
		ack    bool
	}
	listens := []listen{
		{name: "default"},
		{name: "explicit loopback", listen: "127.0.0.1"},
		{name: "explicit IPv6 loopback", listen: "::1"},
		{name: "explicit localhost", listen: "localhost"},
		{name: "every interface, acknowledged", listen: "0.0.0.0", ack: true},
		{name: "every interface, unacknowledged", listen: "0.0.0.0"},
		{name: "one interface, acknowledged", listen: "192.0.2.10", ack: true},
		{name: "one interface, unacknowledged", listen: "192.0.2.10"},
		{name: "a host name, unacknowledged", listen: "hub.internal"},
	}
	for _, a := range auths {
		for _, l := range listens {
			t.Run(a.name+"/"+l.name, func(t *testing.T) {
				plan, err := Decide(Request{
					Listen: l.listen, Source: "--listen", Port: 8080,
					SSO: a.sso, StaticToken: a.token, AllowUnauthenticatedNetwork: l.ack,
				})
				beyond := l.listen == "0.0.0.0" || l.listen == "192.0.2.10" || l.listen == "hub.internal"
				open := !a.sso && !a.token

				// The one refusal: open, beyond loopback, named, unacknowledged.
				if open && beyond && !l.ack {
					if !errors.Is(err, ErrOpenToNetwork) {
						t.Fatalf("Decide = %v, %v; want a refusal wrapping ErrOpenToNetwork", plan, err)
					}
					msg := err.Error()
					for _, want := range []string{
						"refusing to listen on", "--listen", "no sign-in",
						"Remote executor agents need to reach the hub", AckKey, "127.0.0.1",
					} {
						if !strings.Contains(msg, want) {
							t.Errorf("refusal does not say %q:\n%s", want, msg)
						}
					}
					return
				}
				if err != nil {
					t.Fatalf("Decide: %v", err)
				}

				want := map[string]string{
					"":             a.wantDefault,
					"127.0.0.1":    "127.0.0.1:8080",
					"::1":          "[::1]:8080",
					"localhost":    "127.0.0.1:8080",
					"0.0.0.0":      "*:8080",
					"192.0.2.10":   "192.0.2.10:8080",
					"hub.internal": "hub.internal:8080",
				}[l.listen]
				if got := plan.String(); got != want {
					t.Errorf("binds %s, want %s", got, want)
				}
				if plan.Explicit != (l.listen != "") {
					t.Errorf("Explicit = %v for listen %q", plan.Explicit, l.listen)
				}
				if plan.Authenticated == open {
					t.Errorf("Authenticated = %v for %s", plan.Authenticated, a.name)
				}
				// Acknowledged means one thing: an open hub beyond loopback
				// because of the setting. Set anywhere else, it is noise in
				// every message that reads it.
				if wantAck := open && beyond && l.ack; plan.Acknowledged != wantAck {
					t.Errorf("Acknowledged = %v, want %v", plan.Acknowledged, wantAck)
				}
				// The default an open hub gets is loopback whatever else is set.
				if open && l.listen == "" && plan.BeyondLoopback() {
					t.Errorf("an open hub's default reaches beyond loopback: %s", plan)
				}
			})
		}
	}
}

// TestAcknowledgementNeverWidensTheDefault: the acknowledgement lets an
// address the operator named take effect. An open hub that names none still
// listens on loopback, so setting the key alone exposes nothing.
func TestAcknowledgementNeverWidensTheDefault(t *testing.T) {
	plan, err := Decide(Request{Port: 8080, AllowUnauthenticatedNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.String() != "127.0.0.1:8080" || plan.Acknowledged {
		t.Fatalf("open hub with only the acknowledgement binds %s (acknowledged=%v), want 127.0.0.1:8080",
			plan, plan.Acknowledged)
	}
}

// TestPlanAddrIsWhatNetListenTakes pins the strings handed to net.Listen: the
// empty host for every interface (one dual-stack socket), brackets for IPv6.
func TestPlanAddrIsWhatNetListenTakes(t *testing.T) {
	if plan, err := Decide(Request{Port: 8080}); err != nil || plan.Addr() != "127.0.0.1:8080" {
		t.Errorf("an open hub's default listens on %q (%v), want 127.0.0.1:8080", plan.Addr(), err)
	}
	cases := map[string]string{
		"":                 ":8080", // with a credential: every interface
		"0.0.0.0":          ":8080",
		"::":               ":8080",
		"[::]":             ":8080",
		"::1":              "[::1]:8080",
		"[::1]":            "[::1]:8080",
		"localhost":        "127.0.0.1:8080",
		"LocalHost.":       "127.0.0.1:8080",
		"127.0.0.2":        "127.0.0.2:8080",
		"::ffff:127.0.0.1": "127.0.0.1:8080",
		"192.0.2.10":       "192.0.2.10:8080",
	}
	for listen, want := range cases {
		plan, err := Decide(Request{Listen: listen, Port: 8080, StaticToken: true})
		if err != nil {
			t.Errorf("Decide(%q): %v", listen, err)
			continue
		}
		if got := plan.Addr(); got != want {
			t.Errorf("Decide(%q).Addr() = %q, want %q", listen, got, want)
		}
	}
}

// TestParseHostRefusesWhatIsNotAHost: a URL, a host:port and junk are
// refused with a reason, never guessed at.
func TestParseHostRefusesWhatIsNotAHost(t *testing.T) {
	for _, bad := range []string{
		"http://0.0.0.0", "0.0.0.0:8080", "[::1]:8080", "localhost:80", "a b",
		"hub_internal", "-hub", "hub-.example", "hub/x", strings.Repeat("a", 64) + ".example",
	} {
		_, err := Decide(Request{Listen: bad, Port: 8080, StaticToken: true})
		if !errors.Is(err, ErrInvalidListen) {
			t.Errorf("Decide(%q) = %v, want ErrInvalidListen", bad, err)
		}
	}
	if _, err := Decide(Request{Port: 70000}); err == nil {
		t.Error("port 70000 accepted")
	}
}

// TestLoopbackIsDecidedFromTheAddressNotTheResolver: only IP literals and
// "localhost" count as loopback. A name that resolves to 127.0.0.1 today —
// ip6-localhost, a *.localhost name, this machine's own hostname on Debian —
// is treated as reaching beyond it, so a resolver change cannot open a hub.
func TestLoopbackIsDecidedFromTheAddressNotTheResolver(t *testing.T) {
	for _, name := range []string{"ip6-localhost", "hub.localhost", "localhost.localdomain"} {
		_, err := Decide(Request{Listen: name, Port: 8080})
		if !errors.Is(err, ErrOpenToNetwork) {
			t.Errorf("open hub on %q: %v, want a refusal", name, err)
		}
	}
}

// TestLocalHostAndURL: where this machine reaches the listener — what the
// cluster advertise URL and the browser default to.
func TestLocalHostAndURL(t *testing.T) {
	cases := []struct {
		req       Request
		local     string
		url, disp string
	}{
		{Request{Port: 8080}, "127.0.0.1", "http://127.0.0.1:8080", "127.0.0.1:8080"},
		{Request{Port: 8080, StaticToken: true}, "127.0.0.1", "http://localhost:8080", "*:8080"},
		{Request{Port: 8443, SSO: true, TLS: true}, "127.0.0.1", "https://localhost:8443", "*:8443"},
		{Request{Port: 8080, SSO: true, Listen: "10.0.0.5"}, "10.0.0.5", "http://10.0.0.5:8080", "10.0.0.5:8080"},
		{Request{Port: 8080, Listen: "::1"}, "::1", "http://[::1]:8080", "[::1]:8080"},
		{Request{Port: 0, SSO: true}, "127.0.0.1", "http://localhost:0", "every interface"},
	}
	for _, tc := range cases {
		plan, err := Decide(tc.req)
		if err != nil {
			t.Fatalf("%+v: %v", tc.req, err)
		}
		if plan.LocalHost() != tc.local || plan.URL() != tc.url || plan.String() != tc.disp {
			t.Errorf("%+v: LocalHost=%q URL=%q String=%q; want %q %q %q", tc.req,
				plan.LocalHost(), plan.URL(), plan.String(), tc.local, tc.url, tc.disp)
		}
	}
}

// TestNotice: what a starting hub says. The acknowledged open hub warns (to
// stderr, every start); the open default tells the operator how to expose it
// safely; a plaintext listener beyond loopback behind an https external URL
// is pointed at loopback; everything else is silent.
func TestNotice(t *testing.T) {
	cases := []struct {
		name     string
		req      Request
		warning  bool
		contains []string
	}{
		{name: "open default", req: Request{Port: 8080}, contains: []string{
			"listens on 127.0.0.1:8080 only", "ui.oidc", "CLOOP_UI_TOKEN", "ssh -L 8080:127.0.0.1:8080"}},
		{name: "open, acknowledged", req: Request{Port: 8080, Listen: "0.0.0.0", AllowUnauthenticatedNetwork: true},
			warning: true, contains: []string{"WARNING", "no sign-in", "*:8080", AckKey}},
		{name: "plaintext beyond loopback behind https", req: Request{Port: 8081, SSO: true,
			ExternalURL: "https://hub.example.com:8888"}, contains: []string{"plaintext on *:8081", "ui.listen: 127.0.0.1"}},
		{name: "authenticated, no external URL", req: Request{Port: 8080, SSO: true}},
		{name: "authenticated, TLS of its own", req: Request{Port: 8443, SSO: true, TLS: true,
			ExternalURL: "https://hub.example.com"}},
		{name: "authenticated, loopback behind https", req: Request{Port: 8081, SSO: true, Listen: "127.0.0.1",
			ExternalURL: "https://hub.example.com"}},
		{name: "open, explicit loopback", req: Request{Port: 8080, Listen: "127.0.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Decide(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			text, warning := plan.Notice()
			if warning != tc.warning {
				t.Errorf("warning = %v, want %v (%q)", warning, tc.warning, text)
			}
			if len(tc.contains) == 0 && text != "" {
				t.Errorf("Notice = %q, want silence", text)
			}
			for _, want := range tc.contains {
				if !strings.Contains(text, want) {
					t.Errorf("Notice does not say %q: %q", want, text)
				}
			}
		})
	}
}

// TestRefusalNamesItsSource: the refusal names the setting to change — the
// flag or the config key — because "which file do I edit" is the first
// question it raises.
func TestRefusalNamesItsSource(t *testing.T) {
	_, err := Decide(Request{Listen: "0.0.0.0", Source: "ui.listen", Port: 9000})
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("Decide = %v, want *RefusalError", err)
	}
	if refusal.Source != "ui.listen" || !strings.Contains(err.Error(), "(ui.listen)") ||
		!strings.Contains(err.Error(), "ssh -L 9000:127.0.0.1:9000") {
		t.Errorf("refusal = %q", err)
	}
}
