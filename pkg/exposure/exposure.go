// Package exposure decides which address `cloop ui` listens on, and refuses
// the one combination that turns a hub into an open door: no sign-in, and a
// listener the network can reach (Task 20393).
//
// # Why the bind address is a security decision here
//
// A hub with no browser credential — no OIDC single sign-on and no static
// token — answers every request from anyone who can reach it: it lists the
// projects, queues tasks and starts agent runs on its host. Whether that is
// acceptable depends entirely on who can reach it, and the hub decides that
// with one value: the address it binds. Until this package, `cloop ui` bound
// every interface whatever its authentication, so an open hub on a machine
// with a public address was an open hub on the Internet.
//
// # The rule
//
//   - A hub with a browser credential binds every interface by default, as it
//     always has: the credential is what protects it.
//   - A hub without one binds 127.0.0.1 by default, so only this machine
//     reaches it.
//   - An address the operator names (--listen, ui.listen) is honoured as
//     given — except that an open hub refuses to start on one beyond loopback
//     unless ui.allow_unauthenticated_network acknowledges it, and then warns
//     at every start. The acknowledgement never widens the default: it lets an
//     address an operator named take effect, and nothing else.
//
// # How "loopback" is decided
//
// From the address as written, never by resolving it. An IP literal is
// loopback by its value; "localhost" is loopback by RFC 6761 and is bound as
// 127.0.0.1, so no resolver configuration can turn it into anything else; and
// every other hostname counts as reaching beyond loopback, whatever it
// resolves to today. A refusal that costs an operator typing 127.0.0.1 is the
// cheap side of that trade.
package exposure

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Scope is how far a bind address reaches.
type Scope int

const (
	// ScopeLoopback reaches this machine only: 127.0.0.0/8, ::1, localhost.
	ScopeLoopback Scope = iota
	// ScopeEvery is every interface: 0.0.0.0, ::, or no host at all. Go binds
	// one dual-stack socket for each of them, so all three reach IPv4 and
	// IPv6 alike.
	ScopeEvery
	// ScopeAddress is one address beyond loopback: an interface's IP, or a
	// hostname.
	ScopeAddress
)

// String names the scope for messages.
func (s Scope) String() string {
	switch s {
	case ScopeLoopback:
		return "loopback"
	case ScopeEvery:
		return "every interface"
	default:
		return "a network address"
	}
}

// LoopbackHost is what a hub without sign-in binds when no address is named.
const LoopbackHost = "127.0.0.1"

// AckKey is the configuration key that lets a hub without sign-in listen
// beyond loopback.
const AckKey = "ui.allow_unauthenticated_network"

// ErrOpenToNetwork is wrapped by Decide's refusal, so a caller can tell it
// from a malformed address.
var ErrOpenToNetwork = errors.New("a hub without sign-in may not listen beyond loopback")

// ErrInvalidListen is wrapped by Decide when the address does not parse.
var ErrInvalidListen = errors.New("not a listen address")

// Request is what Decide needs to know about one hub.
type Request struct {
	// Listen is the bind host as the operator gave it: --listen, else
	// ui.listen. Empty asks for the default. It carries no port.
	Listen string
	// Source names where Listen came from ("--listen", "ui.listen"), for
	// messages. Empty reads as "--listen / ui.listen".
	Source string
	// Port is the TCP port (--port). Zero is allowed: it is how a caller
	// asks about a configuration without a port in mind.
	Port int

	// SSO reports ui.oidc.enabled.
	SSO bool
	// StaticToken reports a --token or CLOOP_UI_TOKEN.
	StaticToken bool
	// AllowUnauthenticatedNetwork is ui.allow_unauthenticated_network.
	AllowUnauthenticatedNetwork bool

	// TLS reports that the listener itself serves HTTPS (ui.tls, --tls-cert).
	TLS bool
	// ExternalURL is the URL browsers reach the hub at — ui.external_url, or
	// the SSO callback when only that names it (config.UIConfig.PublicURL).
	ExternalURL string
	// ExternalURLKey names the setting ExternalURL came from, for messages.
	// Empty reads as "ui.external_url".
	ExternalURLKey string
}

// Plan is where a hub listens, and the facts the decision was made on.
type Plan struct {
	// Host is what net.Listen is given: "" for every interface, otherwise an
	// address or hostname. Never "localhost", which is bound as 127.0.0.1.
	Host string
	// Port is the TCP port.
	Port int
	// Scope is how far Host reaches.
	Scope Scope
	// Explicit reports that an operator named the address; false means it is
	// the default for this hub's authentication.
	Explicit bool
	// Authenticated reports a browser credential: SSO or a static token.
	Authenticated bool
	// Acknowledged reports a hub without sign-in that listens beyond loopback
	// because ui.allow_unauthenticated_network says it may.
	Acknowledged bool
	// TLS reports that the listener serves HTTPS itself.
	TLS bool
	// ExternalHTTPS reports that the URL browsers reach the hub at is https.
	ExternalHTTPS bool
	// ExternalURL is that URL, and ExternalURLKey the setting it came from.
	ExternalURL    string
	ExternalURLKey string
}

// Addr is the host:port to listen on: ":8080" for every interface.
func (p Plan) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// String renders the bind address for a person: "127.0.0.1:8080",
// "*:8080" for every interface, "[::1]:8080". Without a port it is the host
// alone.
func (p Plan) String() string {
	host := p.Host
	if p.Scope == ScopeEvery {
		host = "*"
	}
	if p.Port <= 0 {
		if host == "*" {
			return "every interface"
		}
		return host
	}
	if host == "*" {
		return "*:" + strconv.Itoa(p.Port)
	}
	return net.JoinHostPort(host, strconv.Itoa(p.Port))
}

// Open reports a hub with no browser credential.
func (p Plan) Open() bool { return !p.Authenticated }

// HasSignIn is the one definition of "this hub can tell people apart": SSO or
// a static token. API tokens do not count — a hub whose only credentials are
// API tokens serves every caller that presents none. Decide asks it about a
// configuration, and a running hub asks it about itself before it guards a
// request against DNS rebinding (Task 20394), so the bind address and the Host
// check cannot disagree about which hubs are open.
func HasSignIn(sso, staticToken bool) bool { return sso || staticToken }

// BeyondLoopback reports a listener another machine may reach.
func (p Plan) BeyondLoopback() bool { return p.Scope != ScopeLoopback }

// LocalHost is the host this machine reaches the listener at: the bound
// address itself, or 127.0.0.1 for every interface (a dual-stack wildcard
// accepts IPv4 loopback). It is what the hub-cluster advertise URL defaults
// to, so members on one machine keep reaching each other whatever the bind.
func (p Plan) LocalHost() string {
	if p.Scope == ScopeEvery || p.Host == "" {
		return LoopbackHost
	}
	return p.Host
}

// URL is how a browser on this machine reaches the dashboard: localhost for
// every interface, the bound address otherwise.
func (p Plan) URL() string {
	scheme := "http"
	if p.TLS {
		scheme = "https"
	}
	host := p.LocalHost()
	if p.Scope == ScopeEvery {
		host = "localhost"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(p.Port))
}

// PlaintextBehindHTTPS reports a hub that serves plaintext beyond loopback
// while its external URL is https: TLS is terminated in front of it, and
// anything that reaches the port directly skips the terminator — a sign-in, a
// session cookie or an API token sent there crosses the network in the clear.
func (p Plan) PlaintextBehindHTTPS() bool {
	return p.BeyondLoopback() && !p.TLS && p.ExternalHTTPS
}

// Decide works out where a hub listens, or refuses.
//
// The only refusal for a well-formed address is ErrOpenToNetwork: a hub
// without sign-in, an address beyond loopback the operator named, and no
// acknowledgement. Every other combination is a Plan, and the caller prints
// Notice for it.
func Decide(r Request) (Plan, error) {
	if r.Port < 0 || r.Port > 65535 {
		return Plan{}, fmt.Errorf("port %d is not a TCP port", r.Port)
	}
	p := Plan{
		Port:           r.Port,
		Authenticated:  HasSignIn(r.SSO, r.StaticToken),
		TLS:            r.TLS,
		ExternalHTTPS:  isHTTPS(r.ExternalURL),
		ExternalURL:    strings.TrimSpace(r.ExternalURL),
		ExternalURLKey: strings.TrimSpace(r.ExternalURLKey),
	}
	if p.ExternalURLKey == "" {
		p.ExternalURLKey = "ui.external_url"
	}
	listen := strings.TrimSpace(r.Listen)
	if listen == "" {
		if p.Authenticated {
			p.Host, p.Scope = "", ScopeEvery
		} else {
			p.Host, p.Scope = LoopbackHost, ScopeLoopback
		}
		return p, nil
	}
	host, scope, err := ParseHost(listen)
	if err != nil {
		return Plan{}, fmt.Errorf("%s %q: %w", r.source(), listen, err)
	}
	p.Host, p.Scope, p.Explicit = host, scope, true
	if p.Authenticated || scope == ScopeLoopback {
		return p, nil
	}
	if r.AllowUnauthenticatedNetwork {
		p.Acknowledged = true
		return p, nil
	}
	return Plan{}, &RefusalError{Plan: p, Source: r.source()}
}

func (r Request) source() string {
	if s := strings.TrimSpace(r.Source); s != "" {
		return s
	}
	return "--listen / ui.listen"
}

// RefusalError is Decide's refusal: an open hub asked to listen beyond
// loopback. It wraps ErrOpenToNetwork.
type RefusalError struct {
	// Plan is what would have been bound.
	Plan Plan
	// Source names the setting that asked for it.
	Source string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("refusing to listen on %s (%s): this hub has no sign-in — ui.oidc is off and no "+
		"--token or CLOOP_UI_TOKEN is set — so anyone who can reach that address could list its projects, "+
		"queue tasks and start agent runs on this host.\n"+
		"  Remote executor agents need to reach the hub, and a hub that serves them over the network needs "+
		"SSO (ui.oidc) or a token (CLOOP_UI_TOKEN).\n"+
		"  To keep it on this machine, drop %s: a hub without sign-in listens on %s, which an SSH tunnel "+
		"(ssh -L %d:%s:%d <this-host>) or an authenticating reverse proxy can reach.\n"+
		"  To serve it without sign-in anyway, set %s: true in .cloop/config.yaml.",
		e.Plan.String(), e.Source, e.Source, LoopbackHost, portOr(e.Plan.Port), LoopbackHost,
		portOr(e.Plan.Port), AckKey)
}

func (e *RefusalError) Unwrap() error { return ErrOpenToNetwork }

func portOr(p int) int {
	if p > 0 {
		return p
	}
	return 8080
}

// Notice is what a starting hub prints about its exposure, or "" when there
// is nothing worth saying. Warning reports that it must go to stderr, every
// start: an open hub serving the network by acknowledgement.
func (p Plan) Notice() (text string, warning bool) {
	switch {
	case p.Open() && p.BeyondLoopback():
		return fmt.Sprintf("WARNING: this hub has no sign-in and listens on %s because %s is set: anyone "+
			"who can reach that address can list its projects, queue tasks and start agent runs on this host. "+
			"Enable SSO (ui.oidc) or a token (CLOOP_UI_TOKEN), or listen on %s.",
			p.String(), AckKey, LoopbackHost), true
	case p.Open() && !p.Explicit:
		return fmt.Sprintf("No sign-in is configured, so the dashboard listens on %s only. To reach it "+
			"from another machine, configure SSO (ui.oidc) or a token (CLOOP_UI_TOKEN) — the hub then "+
			"listens on every interface — or tunnel: ssh -L %d:%s:%d <this-host>.",
			p.String(), portOr(p.Port), LoopbackHost, portOr(p.Port)), false
	case p.PlaintextBehindHTTPS():
		return fmt.Sprintf("Note: serving plaintext on %s while %s is %s: a client that reaches this port "+
			"directly skips the TLS terminator in front of it. If that proxy runs on this host, set ui.listen: "+
			"%s (or --listen %s).", p.String(), p.ExternalURLKey, p.ExternalURL, LoopbackHost, LoopbackHost), false
	}
	return "", false
}

// ParseHost validates a listen host and classifies it. It returns the host to
// give net.Listen — "localhost" becomes 127.0.0.1, an IPv4-mapped address
// its IPv4 form, an unspecified address "" — and its scope.
//
// A port is refused rather than split off: the port is --port, and a second
// place to set it is a second answer to "which port is this hub on".
func ParseHost(s string) (host string, scope Scope, err error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return "", 0, fmt.Errorf("%w: empty", ErrInvalidListen)
	}
	if strings.Contains(raw, "://") {
		return "", 0, fmt.Errorf("%w: it is a URL; give the host alone, e.g. 127.0.0.1 or 0.0.0.0", ErrInvalidListen)
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return "", 0, fmt.Errorf("%w: give the host alone, without a :port — the port is --port", ErrInvalidListen)
	}
	h := raw
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if addr, perr := netip.ParseAddr(h); perr == nil {
		addr = addr.Unmap()
		// netip takes any text after a % as an IPv6 zone. A zone is an
		// interface name; one holding a bracket or a colon makes a host:port
		// net.Listen cannot split back apart.
		if !validZone(addr.Zone()) {
			return "", 0, fmt.Errorf("%w: %q is not an interface name", ErrInvalidListen, addr.Zone())
		}
		switch {
		case addr.IsUnspecified():
			return "", ScopeEvery, nil
		case addr.IsLoopback():
			return addr.String(), ScopeLoopback, nil
		default:
			return addr.String(), ScopeAddress, nil
		}
	}
	name := strings.TrimSuffix(strings.ToLower(h), ".")
	if name == "localhost" {
		return LoopbackHost, ScopeLoopback, nil
	}
	if !validHostname(name) {
		return "", 0, fmt.Errorf("%w: neither an IP address nor a host name", ErrInvalidListen)
	}
	return name, ScopeAddress, nil
}

// validZone reports an IPv6 zone a listener can be given: empty, or an
// interface name — letters, digits, '.', '_' and '-'.
func validZone(z string) bool {
	if len(z) > 64 {
		return false
	}
	for _, c := range z {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validHostname reports an RFC 1123 host name: dot-separated labels of
// letters, digits and inner hyphens, each at most 63 characters, at most 253
// in all.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func isHTTPS(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != ""
}
