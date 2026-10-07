package sameorigin

// Whose X-Forwarded-* headers to believe.
//
// A hub behind a TLS-terminating proxy cannot see the browser's scheme or,
// when the proxy rewrites Host, the name the browser used: the proxy says so in
// X-Forwarded-Proto and X-Forwarded-Host, and the client address in
// X-Forwarded-For. Any client can send those headers too. So they are read only
// from a peer the operator has said is a proxy — loopback, which is a proxy on
// this machine, or an address in ui.trusted_proxies — and ignored from every
// other one.
//
// Ignoring them is not cosmetic. The scheme and host decide the origin a
// request is judged against, so believing a header from anyone would let a
// client choose the origin it is compared with; the client address keys the
// rate limiter and the sign-in lockout, so believing the leftmost
// X-Forwarded-For entry — which a proxy that appends passes through from the
// client — would let anyone reset their lockout by sending a new one.

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Proxies is the set of peers whose X-Forwarded-* headers are believed.
// Loopback is always in it: a proxy on the hub's own machine is the default
// deployment, and anything that can connect from loopback can already reach
// the hub's plaintext port directly. The zero value is loopback only.
type Proxies struct {
	prefixes []netip.Prefix
}

// ParseProxies reads ui.trusted_proxies: CIDR prefixes or single addresses. A
// prefix that covers every address (0.0.0.0/0, ::/0) is refused: it would let
// any client choose the scheme, host and address the hub believes, which is
// the behaviour this setting exists to replace.
func ParseProxies(entries []string) (Proxies, error) {
	var p Proxies
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(e, "/") {
			pr, err := netip.ParsePrefix(e)
			if err != nil {
				return Proxies{}, fmt.Errorf("ui.trusted_proxies: %q is not an address or CIDR prefix", raw)
			}
			prefix = pr.Masked()
		} else {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return Proxies{}, fmt.Errorf("ui.trusted_proxies: %q is not an address or CIDR prefix", raw)
			}
			a = a.Unmap()
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		if prefix.Bits() == 0 {
			return Proxies{}, fmt.Errorf("ui.trusted_proxies: %q trusts every address, so any client could "+
				"choose the scheme, host and address the hub believes; list the proxies' own addresses", raw)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		p.prefixes = append(p.prefixes, prefix)
	}
	return p, nil
}

// MustParseProxies is ParseProxies for literals in tests and defaults.
func MustParseProxies(entries ...string) Proxies {
	p, err := ParseProxies(entries)
	if err != nil {
		panic(err)
	}
	return p
}

// Entries renders the configured prefixes, loopback not included.
func (p Proxies) Entries() []string {
	out := make([]string, 0, len(p.prefixes))
	for _, pr := range p.prefixes {
		out = append(out, pr.String())
	}
	return out
}

// Trusts reports whether a is loopback or inside a configured prefix.
func (p Proxies) Trusts(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, pr := range p.prefixes {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// TrustsPeer reports whether r's direct TCP peer is a trusted proxy.
func (p Proxies) TrustsPeer(r *http.Request) bool {
	a, ok := PeerAddr(r)
	return ok && p.Trusts(a)
}

// PeerAddr is the address of r's direct TCP peer.
func PeerAddr(r *http.Request) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ClientIP is the address of the client that made r: its direct peer, unless
// that is a trusted proxy, in which case X-Forwarded-For is walked from the
// right — each proxy appends the peer it saw — past every trusted proxy, and
// the first address that is not one is the client. Entries to the left of it
// were written by the client and are not consulted.
func (p Proxies) ClientIP(r *http.Request) string {
	peer, ok := PeerAddr(r)
	if !ok {
		if r == nil {
			return ""
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}
	client := peer
	if !p.Trusts(client) {
		return client.String()
	}
	hops := forwardedFor(r.Header)
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			// An entry the proxies would not have written: stop at the
			// last address a trusted hop vouched for.
			break
		}
		client = a.Unmap()
		if !p.Trusts(client) {
			break
		}
	}
	return client.String()
}

// forwardedFor splits every X-Forwarded-For line into its entries, in order.
// Ports and brackets, which some proxies write, are removed.
func forwardedFor(h http.Header) []string {
	var out []string
	for _, line := range h.Values("X-Forwarded-For") {
		for _, e := range strings.Split(line, ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if host, _, err := net.SplitHostPort(e); err == nil {
				e = host
			} else if strings.HasPrefix(e, "[") && strings.HasSuffix(e, "]") {
				e = e[1 : len(e)-1]
			}
			out = append(out, e)
		}
	}
	return out
}

// View is what a request says about the hop between the browser and whatever
// it connected to: the scheme it used and the host it addressed.
type View struct {
	// Scheme is "https" or "http".
	Scheme string
	// Host is the host[:port] the browser addressed, as sent.
	Host string
}

// ViewOf resolves r's client-facing scheme and host. trusted says whether r
// came from a proxy whose X-Forwarded-Proto and X-Forwarded-Host are believed;
// when it did not, they are ignored and the connection's own TLS state and
// Host header decide.
//
// Only the first entry of each header is read: a chain of proxies appends, and
// the first is the hop the browser made.
func ViewOf(r *http.Request, trusted bool) View {
	v := View{Scheme: "http", Host: r.Host}
	if r.TLS != nil {
		v.Scheme = "https"
	}
	if !trusted {
		return v
	}
	if proto := strings.ToLower(firstEntry(r.Header.Get("X-Forwarded-Proto"))); proto == "https" || proto == "http" {
		v.Scheme = proto
	}
	if host := firstEntry(r.Header.Get("X-Forwarded-Host")); host != "" {
		v.Host = host
	}
	return v
}

// Origin is the origin the browser addressed, if the view names one.
func (v View) Origin() (Origin, bool) {
	o, err := FromHost(v.Scheme, v.Host)
	return o, err == nil
}

// TLS reports that the browser's hop was encrypted.
func (v View) TLS() bool { return v.Scheme == "https" }

func firstEntry(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
