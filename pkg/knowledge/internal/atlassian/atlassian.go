// Package atlassian is what cloop's knowledge connectors for Atlassian's
// products — Confluence (pkg/knowledge/confluence) and Jira
// (pkg/knowledge/jira) — share: which addresses a source may connect to, how
// a configuration's address, account and query are checked, how a request is
// made and retried, and how an error loses the credential before it leaves a
// connector.
//
// One copy, so that the rules a review checked for one connector are the
// rules each of them applies:
//
//	Policy        which addresses a source may connect to — checked where a
//	              configuration names a host, and again at every connection,
//	              after DNS
//	Client        one call's requests to one site: the credential sent as a
//	              header and nowhere else, no proxy from the environment, no
//	              redirect followed, each request bounded in time and its
//	              answer in size, 429 and 503 retried after the site's
//	              Retry-After or a bounded, jittered backoff, and every error
//	              scrubbed of the credential in each form it is sent in
//	ParseBaseURL  a configuration's address: https, a host, nothing else
//	CheckEmail    a basic-auth account's shape
//	CheckQuery    a CQL or JQL query, as far as it can be checked without the
//	              site: text, bounded, its quotes and parentheses closed, no
//	              ORDER BY
package atlassian

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
)

// Ways a source signs in.
const (
	// AuthBasic is a Cloud site's email and API token. The email is the
	// configuration's; the token is the source's secret.
	AuthBasic = "basic"
	// AuthBearer presents the secret as a bearer token: a Cloud OAuth 2.0
	// access token, or a Data Center personal access token.
	AuthBearer = "bearer"
)

// Bounds on what a configuration names.
const (
	// MaxEmailBytes bounds an email address.
	MaxEmailBytes = 254
	// MaxURLBytes bounds a base URL.
	MaxURLBytes = 2048
)

// Policy is which addresses a source may connect to.
//
// Never a cloud metadata service, the machine itself (loopback), or the local
// link — for any source: none of them is where an Atlassian site lives, and
// each is where the hub's network keeps something a request from inside it
// should not reach. A private address (RFC 1918, ULA, carrier-grade NAT) only
// when AllowPrivate is set, which a connector does for an organisation's Data
// Center source alone. The rule is applied twice: to the host as written,
// when a configuration is checked (CheckHost), and to the address every
// connection is about to be made to, after the name was resolved
// (CheckDialAddress) — so a name that resolves somewhere it should not, now
// or after a rebinding, is refused all the same.
type Policy struct {
	// AllowPrivate admits private addresses: an organisation's Data Center
	// install on its own network.
	AllowPrivate bool
	// Insecure turns the policy off, and lets a client follow http links: a
	// connector's AllowInsecure option, for tests against an httptest server.
	Insecure bool
}

// ErrBlockedAddress is the refusal to connect to an address the policy
// forbids.
var ErrBlockedAddress = errors.New("knowledge: refusing to connect")

// cgnat is RFC 6598 carrier-grade NAT space, which net/netip does not call
// private, but which is not the public Internet either.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// CheckHost applies the policy to a host as written in a configuration: an
// address literal, or a name that is this machine by definition.
func (p Policy) CheckHost(host string) error {
	if p.Insecure {
		return nil
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: %s is this machine", ErrBlockedAddress, host)
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return p.CheckAddr(ip)
	}
	return nil
}

// CheckAddr applies the policy to an address.
func (p Policy) CheckAddr(ip netip.Addr) error {
	if p.Insecure {
		return nil
	}
	if svc, ok := cloudmeta.LookupDialed(ip); ok {
		return fmt.Errorf("%w: %s is %s", ErrBlockedAddress, ip, svc.Reason())
	}
	a := cloudmeta.Unwrap(ip)
	switch {
	case !a.IsValid():
		return fmt.Errorf("%w: %q is not an address", ErrBlockedAddress, ip)
	case a.IsUnspecified():
		return fmt.Errorf("%w: %s is the unspecified address", ErrBlockedAddress, ip)
	case a.IsLoopback():
		return fmt.Errorf("%w: %s is this machine (loopback)", ErrBlockedAddress, ip)
	case a.IsMulticast() || a.IsInterfaceLocalMulticast() || a.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address", ErrBlockedAddress, ip)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("%w: %s is link-local", ErrBlockedAddress, ip)
	case a.IsPrivate() || (a.Is4() && cgnat.Contains(a)):
		if p.AllowPrivate {
			return nil
		}
		return fmt.Errorf("%w: %s is a private address, which only an organisation's Data Center source may reach — "+
			"a personal source, or a Cloud one, reaches public addresses only", ErrBlockedAddress, ip)
	}
	return nil
}

// CheckDialAddress applies p to the "ip:port" a socket is about to connect
// to.
func CheckDialAddress(address string, p Policy) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: dial address %q: %v", ErrBlockedAddress, address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// The dialer resolves before it connects; anything else is a dial
		// this package did not expect, and is refused rather than trusted.
		return fmt.Errorf("%w: dial address %q is not an IP address", ErrBlockedAddress, address)
	}
	return p.CheckAddr(ip)
}

// ParseBaseURL checks a base URL's shape — https (or http, when insecure), a
// host, no credentials, query or fragment, and a path without "." or ".."
// segments — and returns it with its scheme and host in lower case and
// without a trailing slash. example is a base URL of the product, for the
// refusals.
func ParseBaseURL(raw string, insecure bool, example string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("base_url is required: the site's address, such as %s", example)
	}
	if len(raw) > MaxURLBytes || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, errors.New("base_url is not a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, fmt.Errorf("base_url is not an absolute URL, such as %s", example)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && insecure:
	default:
		return nil, fmt.Errorf("base_url must be https, not %s: the connector sends the source's credential with every request", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("base_url may not hold a user name or password: the credential is the source's secret")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("base_url may not have a query or a fragment")
	}
	path := strings.TrimRight(u.Path, "/")
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return nil, errors.New("base_url's path may not hold . or .. segments")
		}
	}
	return &url.URL{Scheme: scheme, Host: strings.ToLower(u.Host), Path: path}, nil
}

// CheckEmail checks an email's shape: one @, something on each side, no
// spaces.
func CheckEmail(email string) error {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(email) > MaxEmailBytes ||
		strings.IndexFunc(email, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("email %q is not an email address", email)
	}
	return nil
}

// orderByPattern finds an ORDER BY, which a connector adds itself.
var orderByPattern = regexp.MustCompile(`(?i)\border\s+by\b`)

// CheckQuery checks what can be checked of a CQL or JQL query without the
// site: its size (at most maxBytes), that it is text, that its quotes and
// parentheses close — a connector wraps it in parentheses of its own, and an
// unbalanced one would change what the rest of the query means — and that it
// has no ORDER BY, since a connector orders its listing itself. The site
// parses the rest, and a sync reports what it refuses.
func CheckQuery(q string, maxBytes int) error {
	switch {
	case len(q) > maxBytes:
		return fmt.Errorf("a query is at most %d bytes", maxBytes)
	case !utf8.ValidString(q):
		return errors.New("a query is UTF-8 text")
	case strings.IndexFunc(q, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' }) >= 0:
		return errors.New("a query may not hold control characters")
	case orderByPattern.MatchString(q):
		return errors.New("leave out ORDER BY: the connector orders the listing itself")
	}
	depth := 0
	var quote rune
	escaped := false
	for _, r := range q {
		switch {
		case escaped:
			escaped = false
		case quote != 0 && r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			depth--
			if depth < 0 {
				return errors.New("a ')' closes nothing")
			}
		}
	}
	switch {
	case quote != 0:
		return fmt.Errorf("a %c is never closed", quote)
	case depth != 0:
		return errors.New("a '(' is never closed")
	}
	return nil
}

// OneLineQuery is a checked query with its line breaks and tabs as spaces, for
// a URL or a request body.
func OneLineQuery(q string) string {
	return strings.Join(strings.FieldsFunc(q, func(r rune) bool { return r == '\n' || r == '\r' || r == '\t' }), " ")
}
