package sameorigin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseOriginIsExact(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" = refused
	}{
		{"https://hub.example.com", "https://hub.example.com"},
		{"https://Hub.Example.com:443", "https://hub.example.com"},
		{"http://hub.example.com:80", "http://hub.example.com"},
		{"https://hub.example.com:8888", "https://hub.example.com:8888"},
		{"http://127.0.0.1:8081", "http://127.0.0.1:8081"},
		{"http://[::1]:8081", "http://[::1]:8081"},
		{"https://hub.example.com/", "https://hub.example.com"},
		// What a browser never writes in an Origin header is not read
		// generously.
		{"null", ""},
		{"", ""},
		{"https://hub.example.com/path", ""},
		{"https://user@hub.example.com", ""},
		{"https://hub.example.com?x=1", ""},
		{"ftp://hub.example.com", ""},
		{"hub.example.com", ""},
		{"https://", ""},
		{"https://hub.example.com:0", ""},
		{"https://hub.example.com:70000", ""},
		{"javascript:alert(1)", ""},
	} {
		o, err := Parse(tc.in)
		got := ""
		if err == nil {
			got = o.String()
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %q (err %v), want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestParseEntryReadsConfigurationForms(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://hub.example.com", "https://hub.example.com"},
		{"https://hub.example.com/auth/oidc", "https://hub.example.com"},
		// No scheme means https: plaintext has to be asked for by name.
		{"hub.example.com", "https://hub.example.com"},
		{"hub.example.com:8443", "https://hub.example.com:8443"},
		{"http://hub.lan:8081", "http://hub.lan:8081"},
		{"", ""},
		{"https://", ""},
		{"ws://hub.example.com", ""},
	} {
		o, err := ParseEntry(tc.in)
		got := ""
		if err == nil {
			got = o.String()
		}
		if got != tc.want {
			t.Errorf("ParseEntry(%q) = %q (err %v), want %q", tc.in, got, err, tc.want)
		}
	}
	origins, bad := ParseEntries([]string{"hub.example.com", " ", "ws://x", "http://a:1"})
	if len(origins) != 2 || len(bad) != 1 || bad[0] != "ws://x" {
		t.Errorf("ParseEntries = %v, bad %v", origins, bad)
	}
}

func TestOriginsDifferingInSchemeHostOrPortDiffer(t *testing.T) {
	base := mustParse(t, "https://hub.example.com:8888")
	for _, other := range []string{
		"http://hub.example.com:8888",
		"https://hub.example.com",
		"https://hub.example.com:8889",
		"https://sub.hub.example.com:8888",
		"https://hub.example.com.evil.example:8888",
	} {
		if mustParse(t, other) == base {
			t.Errorf("%s compared equal to %s", other, base)
		}
	}
	if mustParse(t, "https://HUB.example.com:8888") != base {
		t.Error("host comparison is case-sensitive")
	}
}

func mustParse(t *testing.T, s string) Origin {
	t.Helper()
	o, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return o
}

func TestProxiesTrustLoopbackAndConfiguredPrefixesOnly(t *testing.T) {
	p := MustParseProxies("10.1.0.0/16", "192.0.2.7", "2001:db8::/32")
	for _, tc := range []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:5000", true},
		{"127.8.9.1:5000", true},
		{"[::1]:5000", true},
		{"[::ffff:127.0.0.1]:5000", true},
		{"10.1.200.3:5000", true},
		{"10.2.0.1:5000", false},
		{"192.0.2.7:5000", true},
		{"192.0.2.8:5000", false},
		{"[2001:db8::5]:5000", true},
		{"203.0.113.9:5000", false},
		{"garbage", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.remote
		if got := p.TrustsPeer(r); got != tc.want {
			t.Errorf("TrustsPeer(%s) = %v, want %v", tc.remote, got, tc.want)
		}
	}
	var zero Proxies
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if zero.TrustsPeer(r) {
		t.Error("the zero Proxies trusted httptest's 192.0.2.1")
	}
	r.RemoteAddr = "127.0.0.1:1"
	if !zero.TrustsPeer(r) {
		t.Error("the zero Proxies does not trust loopback")
	}
}

func TestParseProxiesRefusesEverythingAndGarbage(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/33", "hub.example.com", "10.0.0.1/x"} {
		if _, err := ParseProxies([]string{bad}); err == nil {
			t.Errorf("ParseProxies(%q) accepted it", bad)
		}
	}
	p, err := ParseProxies([]string{"", " 10.0.0.0/8 "})
	if err != nil || len(p.Entries()) != 1 || p.Entries()[0] != "10.0.0.0/8" {
		t.Errorf("ParseProxies = %v, %v", p.Entries(), err)
	}
}

func TestClientIPWalksForwardedForFromTheRight(t *testing.T) {
	p := MustParseProxies("10.0.0.0/8")
	for _, tc := range []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"no proxy", "203.0.113.9:1", nil, "203.0.113.9"},
		{"untrusted peer's header is ignored", "203.0.113.9:1", []string{"198.51.100.1"}, "203.0.113.9"},
		{"loopback proxy", "127.0.0.1:1", []string{"198.51.100.1"}, "198.51.100.1"},
		// nginx's $proxy_add_x_forwarded_for appends: the client chose the
		// leftmost entry, the proxy wrote the rightmost.
		{"a spoofed leftmost entry is not the client", "127.0.0.1:1", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1"},
		{"a chain of trusted proxies", "127.0.0.1:1", []string{"198.51.100.1, 10.0.0.5"}, "198.51.100.1"},
		{"split across lines", "127.0.0.1:1", []string{"6.6.6.6", "198.51.100.1, 10.0.0.5"}, "198.51.100.1"},
		{"every hop trusted", "127.0.0.1:1", []string{"10.0.0.9, 10.0.0.5"}, "10.0.0.9"},
		{"garbage stops the walk", "127.0.0.1:1", []string{"198.51.100.1, unknown"}, "127.0.0.1"},
		{"ports and brackets", "127.0.0.1:1", []string{"[2001:db8::1]:4711"}, "2001:db8::1"},
		{"loopback without a header", "127.0.0.1:1", nil, "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := p.ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestViewOfIgnoresForwardedHeadersFromUntrustedPeers(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "hub.internal:8081"
	r.Header.Set("X-Forwarded-Proto", "https, http")
	r.Header.Set("X-Forwarded-Host", "hub.example.com:8888, hub.internal")

	if v := ViewOf(r, false); v.Scheme != "http" || v.Host != "hub.internal:8081" {
		t.Errorf("untrusted view = %+v, want the connection's own scheme and Host", v)
	}
	v := ViewOf(r, true)
	if v.Scheme != "https" || v.Host != "hub.example.com:8888" {
		t.Errorf("trusted view = %+v, want the first entry of each header", v)
	}
	if o, ok := v.Origin(); !ok || o.String() != "https://hub.example.com:8888" {
		t.Errorf("trusted origin = %v %v", o, ok)
	}

	// The connection's own TLS is never overridden downwards by a header it
	// did not need.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.TLS = &tls.ConnectionState{}
	if v := ViewOf(r2, false); !v.TLS() {
		t.Error("a TLS connection reported plaintext")
	}
	// A value that is not a scheme is ignored.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.Header.Set("X-Forwarded-Proto", "gopher")
	if v := ViewOf(r3, true); v.Scheme != "http" {
		t.Errorf("X-Forwarded-Proto: gopher produced scheme %q", v.Scheme)
	}
}

func TestCheckUnsafe(t *testing.T) {
	own := []Origin{mustParse(t, "https://hub.example.com:8888"), mustParse(t, "https://alias.example.com")}
	for _, tc := range []struct {
		name    string
		method  string
		header  map[string]string
		allowed bool
		reason  Reason
	}{
		{"GET is not checked", "GET", map[string]string{"Sec-Fetch-Site": "cross-site"}, true, ReasonSafeMethod},
		{"bearer", "POST", map[string]string{"Authorization": "Bearer x", "Sec-Fetch-Site": "cross-site"}, true, ReasonBearer},
		{"bearer is case-insensitive", "DELETE", map[string]string{"Authorization": "bearer x", "Origin": "https://evil.example"}, true, ReasonBearer},
		// A browser attaches these by itself, so they prove nothing.
		{"basic is ambient", "POST", map[string]string{"Authorization": "Basic eDp5", "Sec-Fetch-Site": "cross-site"}, false, ReasonCrossSite},
		{"negotiate is ambient", "POST", map[string]string{"Authorization": "Negotiate abc", "Origin": "https://evil.example"}, false, ReasonForeignOrigin},
		{"empty bearer", "POST", map[string]string{"Authorization": "Bearer ", "Sec-Fetch-Site": "cross-site"}, false, ReasonCrossSite},
		{"same-origin", "POST", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://whatever.example"}, true, ReasonSameOrigin},
		{"user-initiated", "POST", map[string]string{"Sec-Fetch-Site": "none"}, true, ReasonUserInitiated},
		{"cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, false, ReasonCrossSite},
		// The browser's word outranks an Origin that happens to be ours.
		{"same-site with our Origin", "PUT", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://hub.example.com:8888"}, false, ReasonSameSite},
		{"unknown fetch site", "PATCH", map[string]string{"Sec-Fetch-Site": "same-planet"}, false, ReasonUnknownFetchSite},
		{"no headers: not a browser", "POST", nil, true, ReasonNoOrigin},
		{"old browser, own origin", "POST", map[string]string{"Origin": "https://hub.example.com:8888"}, true, ReasonOwnOrigin},
		{"old browser, alias", "POST", map[string]string{"Origin": "https://alias.example.com:443"}, true, ReasonOwnOrigin},
		{"old browser, other port", "POST", map[string]string{"Origin": "https://hub.example.com:8889"}, false, ReasonForeignOrigin},
		{"old browser, other scheme", "POST", map[string]string{"Origin": "http://hub.example.com:8888"}, false, ReasonForeignOrigin},
		{"old browser, null", "POST", map[string]string{"Origin": "null"}, false, ReasonForeignOrigin},
		{"custom verb", "PURGE", map[string]string{"Sec-Fetch-Site": "cross-site"}, false, ReasonCrossSite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/x", nil)
			for k, v := range tc.header {
				r.Header.Set(k, v)
			}
			v := CheckUnsafe(r, own)
			if v.Allowed != tc.allowed || v.Reason != tc.reason {
				t.Errorf("CheckUnsafe = %+v, want allowed=%v reason=%s", v, tc.allowed, tc.reason)
			}
		})
	}
}

func TestCheckUpgradeIsExact(t *testing.T) {
	own := []Origin{mustParse(t, "http://127.0.0.1:8081"), mustParse(t, "https://hub.example.com")}
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{"", true},
		{"http://127.0.0.1:8081", true},
		{"https://hub.example.com", true},
		{"https://hub.example.com:443", true},
		// Loopback is not a credential.
		{"http://127.0.0.1:3000", false},
		{"http://localhost:8081", false},
		{"http://[::1]:8081", false},
		{"http://hub.example.com", false},
		{"https://hub.example.com:8443", false},
		{"https://evil.example", false},
		{"null", false},
		{"://:::", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/ws", nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if got := CheckUpgrade(r, own).Allowed; got != tc.want {
			t.Errorf("CheckUpgrade(Origin %q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	names := []string{"hub.lan", "Cloop.Example.com:8443", "bad entry/"}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"", true},
		{"127.0.0.1:8081", true},
		{"[::1]:8081", true},
		{"10.0.3.17:8080", true},
		{"localhost:8081", true},
		{"LOCALHOST", true},
		{"localhost.:8081", true},
		{"hub.localhost:8081", true},
		{"hub.lan:9999", true},
		{"HUB.LAN", true},
		{"cloop.example.com:8443", true},
		{"cloop.example.com:8444", false},
		{"cloop.example.com", false},
		// The shapes rebinding takes.
		{"attacker.example:8081", false},
		{"127.0.0.1.nip.io:8081", false},
		{"localhost.attacker.example", false},
		{"hub.lan.attacker.example", false},
		{"bad entry/", false},
		{"a/b", false},
	} {
		if got := HostAllowed(tc.host, names); got != tc.want {
			t.Errorf("HostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestMediaTypes(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json":                  true,
		"Application/JSON; charset=utf-8":   true,
		"application/json;charset=UTF-8":    true,
		"text/plain":                        false,
		"text/plain;charset=UTF-8":          false,
		"application/x-www-form-urlencoded": false,
		"multipart/form-data; boundary=x":   false,
		"application/json-seq":              false,
		"application/merge-patch+json":      false,
		"":                                  false,
		"application/json; =":               false,
	} {
		if got := IsJSON(ct); got != want {
			t.Errorf("IsJSON(%q) = %v, want %v", ct, got, want)
		}
	}
	if !IsMultipartForm("multipart/form-data; boundary=----x") || IsMultipartForm("text/plain") {
		t.Error("IsMultipartForm misread its input")
	}
}

func TestRefusalReasonsAreDistinctAndNeverAdmissions(t *testing.T) {
	seen := map[Reason]bool{}
	for _, r := range RefusalReasons() {
		if seen[r] || strings.TrimSpace(string(r)) == "" {
			t.Errorf("reason %q is duplicated or empty", r)
		}
		seen[r] = true
	}
	for _, admit := range []Reason{ReasonSafeMethod, ReasonBearer, ReasonSameOrigin, ReasonUserInitiated, ReasonNoOrigin, ReasonOwnOrigin} {
		if seen[admit] {
			t.Errorf("%q is listed as a refusal", admit)
		}
	}
}

// Whatever an attacker puts in the headers, CheckUnsafe never admits a request
// that a browser marked cross-site or same-site, and never admits an Origin
// that is not exactly one of ours unless the browser vouched for it.
func FuzzCheckUnsafe(f *testing.F) {
	f.Add("POST", "cross-site", "https://evil.example", "")
	f.Add("POST", "", "https://hub.example.com:8888", "")
	f.Add("DELETE", "", "null", "Basic x")
	f.Add("PUT", "same-site", "https://hub.example.com:8888", "Bearer")
	own := []Origin{{Scheme: "https", Host: "hub.example.com", Port: 8888}}
	f.Fuzz(func(t *testing.T, method, site, origin, auth string) {
		r, err := http.NewRequest(http.MethodPost, "http://hub.example.com/api/x", nil)
		if err != nil {
			t.Skip()
		}
		r.Method = method
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Origin", origin)
		r.Header.Set("Authorization", auth)
		v := CheckUnsafe(r, own)
		if !v.Allowed || !Unsafe(method) || HasBearer(r) {
			return
		}
		s := strings.ToLower(strings.TrimSpace(site))
		switch {
		case s == "cross-site" || s == "same-site":
			t.Fatalf("admitted Sec-Fetch-Site %q: %+v", site, v)
		case s == "" && strings.TrimSpace(origin) != "":
			o, err := Parse(origin)
			if err != nil || !Contains(own, o) {
				t.Fatalf("admitted foreign Origin %q: %+v", origin, v)
			}
		}
	})
}

// HostAllowed never admits a name that is neither localhost nor configured.
func FuzzHostAllowed(f *testing.F) {
	for _, s := range []string{"attacker.example:8081", "localhost", "127.0.0.1", "[::1]:1", "hub.lan", "x.localhost.evil"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if !HostAllowed(host, []string{"hub.lan"}) || strings.TrimSpace(host) == "" {
			return
		}
		h, _, err := SplitHostPort(host)
		if err != nil {
			t.Fatalf("admitted unparseable host %q", host)
		}
		h = strings.TrimSuffix(h, ".")
		if h == "hub.lan" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
			return
		}
		if _, perr := Parse("http://" + host); perr != nil && !strings.Contains(h, ":") {
			// Not a URL host at all; an IP literal would have parsed.
			t.Fatalf("admitted %q", host)
		}
		for _, c := range h {
			if (c < '0' || c > '9') && c != '.' && c != ':' && (c < 'a' || c > 'f') {
				t.Fatalf("admitted a name that is not an address: %q", host)
			}
		}
	})
}
