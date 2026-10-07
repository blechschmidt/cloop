// Package sameorigin decides whether a request to a cloop hub was made by one
// of the hub's own pages, and what the request says about where it came from
// (Task 20394).
//
// # Why a hub has to ask
//
// A browser attaches a site's cookies to every request it sends there,
// whichever page asked it to. SameSite narrows that to the *site* — scheme and
// registrable domain — not the origin, so another port on the hub's host, or a
// sibling subdomain of an enterprise domain, still gets the hub's session
// cookie sent. And a hub with no credential at all has nothing to withhold:
// every page the developer opens can post to it. A form with
// enctype=text/plain, or fetch in no-cors mode, sends a body without a
// preflight, so the only things standing between a page elsewhere and a
// queued agent task are the checks in this package:
//
//   - CheckUnsafe: a state-changing request must come from the hub's own
//     origin. The browser says so in Sec-Fetch-Site, which a page cannot set;
//     a browser too old to send it still sends Origin, which is compared
//     exactly.
//   - CheckUpgrade: the same question for a WebSocket handshake, which the
//     same-origin policy does not cover at all.
//   - HostAllowed: on a hub with no credential, DNS rebinding makes a page on
//     attacker.example same-origin with the hub itself — the browser's own
//     judgement then says "same-origin", truthfully — so the hub has to refuse
//     host names it does not answer to.
//   - IsJSON: a cross-origin page can send a body only as form data or
//     text/plain without a preflight, so a JSON API that accepts nothing else
//     cannot be reached by one.
//
// And because every one of these turns on what the request says about its
// scheme and host, Proxies decides whose X-Forwarded-* headers are believed.
//
// The package is stdlib-only on purpose: the executor agent's WebSocket
// endpoint (pkg/executor/remote) answers the same question, and the hub and
// the dashboard must not be able to give two answers to it.
package sameorigin

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Origin is a web origin as RFC 6454 defines it: a scheme, a host and a port.
// Two origins are the same exactly when all three are equal, which is what ==
// on this struct compares: Host is lower-case and Port is always explicit, so
// "https://Hub.example.com" and "https://hub.example.com:443" are one value.
type Origin struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is the lower-cased host name or IP address, an IPv6 address
	// without its brackets.
	Host string
	// Port is the TCP port, filled in from the scheme when the source left
	// it out.
	Port int
}

// ErrNotAnOrigin is wrapped by every parse failure.
var ErrNotAnOrigin = errors.New("not an http(s) origin")

// IsZero reports the zero Origin, which matches nothing.
func (o Origin) IsZero() bool { return o == Origin{} }

// String renders the origin the way a browser writes it in an Origin header:
// the scheme's default port is left out.
func (o Origin) String() string {
	if o.IsZero() {
		return ""
	}
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.Port == defaultPort(o.Scheme) {
		return o.Scheme + "://" + host
	}
	return o.Scheme + "://" + host + ":" + strconv.Itoa(o.Port)
}

// Parse reads an Origin header value: exactly scheme://host[:port], as a
// browser sends it. Anything else — a path, a query, credentials, another
// scheme, the opaque origin "null" — is refused, so that nothing a page can put
// in the header is read more generously than a browser would write it.
func Parse(s string) (Origin, error) {
	raw := strings.TrimSpace(s)
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return Origin{}, fmt.Errorf("%q: %w", s, ErrNotAnOrigin)
	}
	return fromURL(u, s)
}

// ParseEntry reads an origin from configuration: ui.external_url,
// ui.allowed_origins and the like. More forgiving than Parse in the two ways
// operators write these: a full URL may carry a path ("https://hub.example.com/"
// or the OIDC callback URL), which is ignored; and an entry without a scheme
// ("hub.example.com", "hub.example.com:8443") means https. Plaintext has to be
// asked for by name, because an http origin is one anybody on the network path
// can serve a page from.
func ParseEntry(s string) (Origin, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Origin{}, fmt.Errorf("empty entry: %w", ErrNotAnOrigin)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return Origin{}, fmt.Errorf("%q: %w", s, ErrNotAnOrigin)
	}
	return fromURL(u, s)
}

// FromHost builds the origin a request was addressed to from its scheme and
// the host it named (a Host or X-Forwarded-Host value: host, host:port, or a
// bracketed IPv6 address with an optional port).
func FromHost(scheme, hostport string) (Origin, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "http" && scheme != "https" {
		return Origin{}, fmt.Errorf("scheme %q: %w", scheme, ErrNotAnOrigin)
	}
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return Origin{}, err
	}
	if port == 0 {
		port = defaultPort(scheme)
	}
	return Origin{Scheme: scheme, Host: host, Port: port}, nil
}

// SplitHostPort splits a Host header value into a lower-cased host and a port,
// 0 when there is none. Unlike net.SplitHostPort it accepts a value without a
// port, and it refuses a host that could not appear in a URL.
func SplitHostPort(hostport string) (host string, port int, err error) {
	v := strings.TrimSpace(hostport)
	if v == "" {
		return "", 0, fmt.Errorf("empty host: %w", ErrNotAnOrigin)
	}
	host = v
	if h, p, splitErr := net.SplitHostPort(v); splitErr == nil {
		host = h
		n, convErr := strconv.Atoi(p)
		if convErr != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("port %q: %w", p, ErrNotAnOrigin)
		}
		port = n
	} else if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		host = v[1 : len(v)-1]
	}
	host = strings.ToLower(host)
	if host == "" || strings.ContainsAny(host, "/\\@?#[] \t\r\n") {
		return "", 0, fmt.Errorf("host %q: %w", hostport, ErrNotAnOrigin)
	}
	// A colon is only legitimate inside an IPv6 address.
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("host %q: %w", hostport, ErrNotAnOrigin)
	}
	return host, port, nil
}

func fromURL(u *url.URL, original string) (Origin, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Origin{}, fmt.Errorf("%q: %w", original, ErrNotAnOrigin)
	}
	if u.Host == "" {
		return Origin{}, fmt.Errorf("%q has no host: %w", original, ErrNotAnOrigin)
	}
	return FromHost(scheme, u.Host)
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// Contains reports whether o is one of set.
func Contains(set []Origin, o Origin) bool {
	if o.IsZero() {
		return false
	}
	for _, s := range set {
		if s == o {
			return true
		}
	}
	return false
}

// ParseEntries parses each configuration entry with ParseEntry, skipping
// blanks. It returns the origins that parsed and the entries that did not, so
// a caller can name the latter rather than silently drop them.
func ParseEntries(entries []string) (origins []Origin, bad []string) {
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		o, err := ParseEntry(e)
		if err != nil {
			bad = append(bad, e)
			continue
		}
		origins = append(origins, o)
	}
	return origins, bad
}
