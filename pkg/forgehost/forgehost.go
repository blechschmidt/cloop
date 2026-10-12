// Package forgehost decides which forge host a repository reference names, and
// whether two references name the same one (Task 20423).
//
// # Why one helper
//
// A brokered GitHub credential is good against exactly one forge: github.com
// for a personal access token, unless the secret recorded a GitHub Enterprise
// Server host, and the web host of its base_url for a GitHub App. Every place
// that chooses or binds such a credential — the hub's grant picker, workspace
// provisioning, the git proxy's sessions, a feature's push and pull request —
// has to compare the host a project's origin names against that one. They used
// to compare nothing at all: a repository was "owner/name", the host was thrown
// away, and a project whose origin named https://attacker.example/acme/tool
// matched a grant for acme/* and had the token sent there.
//
// The comparison is easy to get subtly wrong in ways that matter in only one
// direction. Folding too little refuses a working configuration
// (GitHub.com vs github.com); folding too much — matching suffixes, ignoring a
// non-default port, comparing Unicode by eye — hands the credential to a host
// nobody granted. So there is one definition, here, and every caller uses it.
//
// # What is folded, and what is not
//
// Folded, because both spellings reach the same server: letter case, a
// trailing dot, userinfo, the scheme's default port (443 for https), and an
// internationalised name's Unicode spelling (compared in its IDNA ASCII form,
// so a full-width "ｇｉｔｈｕｂ.com" is github.com).
//
// Not folded, because the two spellings reach different servers: any other
// port, any other label, and a Unicode look-alike — "gіthub.com" with a
// Cyrillic "і" is xn--gthub-n2e.com, which is somebody else's domain. There is
// no suffix or wildcard matching of any kind: github.com.attacker.example and
// attacker-github.com are simply other hosts.
package forgehost

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// GitHub is the public GitHub's web host: where a github_pat with no recorded
// host, and an App on the public API, may be presented.
const GitHub = "github.com"

// GitHubAPI is the public GitHub's REST API base.
const GitHubAPI = "https://api.github.com"

// ErrInvalid reports a reference that names no usable forge host. A caller
// treats it as a host that matches nothing: a credential is never presented to
// something this package could not identify.
var ErrInvalid = errors.New("forgehost: not a usable forge host")

// maxHostLen bounds a host. DNS caps a name at 253 octets; the port and the
// brackets of an IPv6 literal fit comfortably in the remainder.
const maxHostLen = 300

// defaultPorts is each scheme's default port, which a reference may spell out
// or leave off and still reach the same server.
var defaultPorts = map[string]int{
	"https":   443,
	"http":    80,
	"ssh":     22,
	"git+ssh": 22,
	"ssh+git": 22,
	"git":     9418,
}

// Canonical returns the host raw names in the form two references to one forge
// host compare equal in: lower case, IDNA ASCII, no trailing dot, no userinfo,
// and a port only when it is not the scheme's default.
//
// raw may be a bare host ("GitHub.com."), a host and port ("ghes:8443"), an
// authority with userinfo ("git@github.com"), or a URL whose host is wanted
// ("https://user@GitHub.com:443/acme/tool"). A bare host or authority is read
// as https. An scp-like remote ("git@github.com:acme/tool") is not a host: its
// caller splits the host off first.
func Canonical(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalid)
	}
	if len(s) > 4*maxHostLen {
		return "", fmt.Errorf("%w: %d bytes is too long for a host", ErrInvalid, len(s))
	}
	scheme := "https"
	var authority string
	if i := strings.Index(s, "://"); i >= 0 {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("%w: %q is not a URL: %v", ErrInvalid, raw, err)
		}
		scheme = strings.ToLower(u.Scheme)
		if u.Opaque != "" {
			return "", fmt.Errorf("%w: %q has no authority", ErrInvalid, raw)
		}
		authority = u.Host
	} else {
		authority = s
		if i := strings.IndexAny(authority, "/?#"); i >= 0 {
			authority = authority[:i]
		}
		// Userinfo ends at the last '@', which is where url.Parse ends it too:
		// the host is what follows it, whatever the userinfo looks like.
		if i := strings.LastIndex(authority, "@"); i >= 0 {
			authority = authority[i+1:]
		}
	}
	def, ok := defaultPorts[scheme]
	if !ok {
		return "", fmt.Errorf("%w: %q uses scheme %q, which no forge credential is presented over",
			ErrInvalid, raw, scheme)
	}
	return canonicalAuthority(authority, def)
}

// canonicalAuthority canonicalises host[:port], dropping the port when it is
// def.
func canonicalAuthority(authority string, def int) (string, error) {
	if authority == "" {
		return "", fmt.Errorf("%w: no host", ErrInvalid)
	}
	host, port := authority, ""
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end < 0 {
			return "", fmt.Errorf("%w: %q has an unterminated IPv6 literal", ErrInvalid, authority)
		}
		rest := host[end+1:]
		host = host[:end+1]
		switch {
		case rest == "":
		case strings.HasPrefix(rest, ":"):
			port = rest[1:]
		default:
			return "", fmt.Errorf("%w: %q has text after its IPv6 literal", ErrInvalid, authority)
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host, port = host[:i], host[i+1:]
		if strings.Contains(host, ":") {
			return "", fmt.Errorf("%w: %q is an IPv6 literal without brackets", ErrInvalid, authority)
		}
	}

	name, err := canonicalName(host)
	if err != nil {
		return "", fmt.Errorf("%w (in %q)", err, authority)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 || strings.TrimLeft(port, "0123456789") != "" {
			return "", fmt.Errorf("%w: %q has an unusable port", ErrInvalid, authority)
		}
		if n != def {
			name += ":" + strconv.Itoa(n)
		}
	}
	if len(name) > maxHostLen {
		return "", fmt.Errorf("%w: %q is too long", ErrInvalid, authority)
	}
	return name, nil
}

// canonicalName canonicalises a host with no port: an IPv6 literal in
// brackets, an IPv4 address, or a DNS name.
func canonicalName(host string) (string, error) {
	if strings.HasPrefix(host, "[") {
		ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("%w: %q is not an IPv6 literal", ErrInvalid, host)
		}
		return "[" + ip.String() + "]", nil
	}
	// One trailing dot is the DNS root, and names the same host. More than one
	// is an empty label, which the check below refuses.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalid)
	}
	ascii := true
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if !ascii {
		// The lookup profile is what a resolver applies: full-width and
		// ideographic forms map to their ASCII equivalents, and anything else
		// becomes its own punycode label — a different host.
		a, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("%w: %q is not a valid internationalised host name: %v", ErrInvalid, host, err)
		}
		host = strings.TrimSuffix(a, ".")
	}
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("%w: IPv6 literal %q must be bracketed", ErrInvalid, host)
		}
		return ip.String(), nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("%w: %q has an empty or overlong label", ErrInvalid, host)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return "", fmt.Errorf("%w: %q contains %q", ErrInvalid, host, r)
			}
		}
	}
	return host, nil
}

// Equal reports whether a and b name the same forge host. A reference either
// side cannot canonicalise names no host, so it is equal to nothing — not even
// to itself.
func Equal(a, b string) bool {
	ca, err := Canonical(a)
	if err != nil {
		return false
	}
	cb, err := Canonical(b)
	if err != nil {
		return false
	}
	return ca == cb
}

// IsGitHub reports whether host is the public github.com.
func IsGitHub(host string) bool { return Equal(host, GitHub) }

// WebHostForAPI returns the web host a GitHub App's API base serves: the host a
// token minted through it is good against.
//
//	https://api.github.com              → github.com
//	https://ghes.example.com/api/v3     → ghes.example.com   (GitHub Enterprise Server)
//	https://api.acme.ghe.com            → acme.ghe.com       (GitHub Enterprise Cloud with data residency)
//
// Any other base — one that names neither an /api/v3 path nor an api. host —
// is not where GitHub Enterprise Server serves its API, so it is read as
// standing in for the public API: a corporate proxy in front of
// api.github.com, or a test's fake. Its tokens are github.com tokens, and are
// bound there.
func WebHostForAPI(base string) (string, error) {
	s := strings.TrimSpace(base)
	if s == "" {
		return GitHub, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%w: API base %q is not a URL: %v", ErrInvalid, base, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%w: API base %q is not an https URL without credentials", ErrInvalid, base)
	}
	host, err := Canonical(s)
	if err != nil {
		return "", err
	}
	switch path := strings.Trim(u.Path, "/"); {
	case strings.EqualFold(path, "api/v3"):
		return host, nil
	case path == "" && strings.HasPrefix(host, "api.") && len(host) > len("api."):
		return strings.TrimPrefix(host, "api."), nil
	}
	return GitHub, nil
}

// APIBase returns the REST API base for a GitHub web host: the public API for
// github.com, and GitHub Enterprise Server's /api/v3 otherwise.
func APIBase(host string) string {
	c, err := Canonical(host)
	if err != nil || c == GitHub {
		return GitHubAPI
	}
	return "https://" + c + "/api/v3"
}

// Mismatch describes a credential refused because the host a reference names
// is not the one its grant is good against. Both are in canonical form.
type Mismatch struct {
	// Origin is the host the repository reference names.
	Origin string
	// Grant is the host the credential is good against.
	Grant string
}

// Error implements error.
func (m *Mismatch) Error() string {
	return fmt.Sprintf("the repository is on %s and the credential is good against %s only; "+
		"a brokered credential is never presented to a host other than its grant's", m.Origin, m.Grant)
}

// Check reports a *Mismatch when origin and grant name different hosts, and
// nil when they name the same one. An origin that names no usable host is a
// mismatch too, with the raw text in Origin.
func Check(origin, grant string) error {
	g, err := Canonical(grant)
	if err != nil {
		return fmt.Errorf("the credential names no usable host: %w", err)
	}
	o, err := Canonical(origin)
	if err != nil {
		return &Mismatch{Origin: strings.TrimSpace(origin), Grant: g}
	}
	if o != g {
		return &Mismatch{Origin: o, Grant: g}
	}
	return nil
}
