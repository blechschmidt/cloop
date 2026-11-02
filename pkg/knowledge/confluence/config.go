package confluence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// Deployments a source can name.
const (
	// DeploymentCloud is Confluence Cloud: an Atlassian site, read through
	// REST API v2 and, for CQL, v1 search.
	DeploymentCloud = "cloud"
	// DeploymentDataCenter is Confluence Data Center or Server, read through
	// /rest/api/content/search.
	DeploymentDataCenter = "datacenter"
)

// Ways a source signs in.
const (
	// AuthBasic is Confluence Cloud's email and API token. The email is the
	// configuration's; the token is the source's secret.
	AuthBasic = "basic"
	// AuthBearer presents the secret as a bearer token: a Cloud OAuth 2.0
	// access token, or a Data Center personal access token.
	AuthBearer = "bearer"
)

// Bounds on a configuration.
const (
	maxSpaces     = 100
	maxSpaceKey   = 255
	maxCQLBytes   = 2048
	maxEmailBytes = 254
	maxURLBytes   = 2048
)

// config is a source's configuration as stored: a JSON object. Unknown keys
// are refused, so a misspelt "space" is an error rather than a source that
// lists everything.
type config struct {
	// Deployment is "cloud" or "datacenter" ("server" reads as datacenter).
	// It may be left out for a site at *.atlassian.net or api.atlassian.com.
	Deployment string `json:"deployment,omitempty"`
	// BaseURL is the site: https://corp.atlassian.net/wiki (its /wiki is
	// added when left out), https://api.atlassian.com/ex/confluence/<cloud
	// id>/wiki for an OAuth app, or a Data Center install with its context
	// path, https://wiki.corp.example/confluence.
	BaseURL string `json:"base_url"`
	// Auth is "basic" or "bearer"; left out, it is basic when Email is set
	// and bearer otherwise.
	Auth string `json:"auth,omitempty"`
	// Email is the Atlassian account a Cloud API token belongs to.
	Email string `json:"email,omitempty"`
	// Spaces scopes the source to these space keys; CQL to what a query
	// matches. Exactly one is set.
	Spaces []string `json:"spaces,omitempty"`
	CQL    string   `json:"cql,omitempty"`
	// IncludeRestricted indexes pages that carry view restrictions, on the
	// page or a page above it. Off by default: what the hub's account may
	// read, a restricted page's own readers chose not to show everyone, and
	// every member of a project the source is bound to could search it.
	IncludeRestricted bool `json:"include_restricted,omitempty"`
}

// settings is a configuration checked and made ready to use.
type settings struct {
	deployment string
	// base is the API root, without a trailing slash: the site's /wiki on
	// Cloud, its context path on Data Center.
	base              *url.URL
	auth              string
	email             string
	spaces            []string
	cql               string
	includeRestricted bool
	// policy is which addresses the source may connect to.
	policy addressPolicy
}

// cloud reports a Cloud site.
func (s settings) cloud() bool { return s.deployment == DeploymentCloud }

// v2 reports a source listed through REST API v2: a Cloud site scoped by
// spaces. A CQL scope is a query only search answers.
func (s settings) v2() bool { return s.cloud() && len(s.spaces) > 0 }

var (
	// spaceKeyPattern is a space key: a global space's letters and digits,
	// or a personal space's "~" and its owner's name or account id. Nothing
	// in it can end a quoted CQL string.
	spaceKeyPattern = regexp.MustCompile(`^~?[A-Za-z0-9][A-Za-z0-9_.:@\-]*$`)
	// orderByPattern finds an ORDER BY, which the connector adds itself.
	orderByPattern = regexp.MustCompile(`(?i)\border\s+by\b`)
)

// parseConfig checks raw for a source of scope and returns its settings.
func (c *Connector) parseConfig(raw json.RawMessage, scope string) (settings, error) {
	var cfg config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return settings{}, fmt.Errorf("the configuration is not a confluence one: %v", err)
	}
	if dec.More() {
		return settings{}, errors.New("the configuration is one JSON object")
	}
	base, err := c.parseBaseURL(cfg.BaseURL)
	if err != nil {
		return settings{}, err
	}
	s := settings{base: base, includeRestricted: cfg.IncludeRestricted}

	switch d := strings.ToLower(strings.TrimSpace(cfg.Deployment)); d {
	case DeploymentCloud:
		s.deployment = DeploymentCloud
	case DeploymentDataCenter, "server", "data-center", "data_center":
		s.deployment = DeploymentDataCenter
	case "":
		host := strings.ToLower(base.Hostname())
		if !strings.HasSuffix(host, ".atlassian.net") && host != "api.atlassian.com" {
			return settings{}, fmt.Errorf("deployment is %q or %q: %s is not an Atlassian Cloud address, so say which it is",
				DeploymentCloud, DeploymentDataCenter, host)
		}
		s.deployment = DeploymentCloud
	default:
		return settings{}, fmt.Errorf("deployment is %q or %q, not %q", DeploymentCloud, DeploymentDataCenter, cfg.Deployment)
	}
	if s.cloud() {
		path := base.Path
		if path == "" {
			path = "/wiki"
		}
		if !strings.HasSuffix(path, "/wiki") {
			return settings{}, fmt.Errorf("a Cloud base_url is the site's /wiki — https://corp.atlassian.net/wiki, or "+
				"https://api.atlassian.com/ex/confluence/<cloud id>/wiki for an OAuth app — not %s", base.Redacted())
		}
		base.Path = path
	}

	s.email = strings.TrimSpace(cfg.Email)
	if s.email != "" {
		if err := checkEmail(s.email); err != nil {
			return settings{}, err
		}
	}
	switch a := strings.ToLower(strings.TrimSpace(cfg.Auth)); a {
	case "":
		s.auth = AuthBearer
		if s.email != "" {
			s.auth = AuthBasic
		}
	case AuthBasic, AuthBearer:
		s.auth = a
	default:
		return settings{}, fmt.Errorf("auth is %q (Cloud: email and API token) or %q (an OAuth access token, "+
			"or a Data Center personal access token), not %q", AuthBasic, AuthBearer, cfg.Auth)
	}
	switch {
	case s.auth == AuthBasic && s.email == "":
		return settings{}, errors.New("basic auth signs in with an email and an API token: set email")
	case s.auth == AuthBasic && !s.cloud():
		return settings{}, errors.New("Data Center signs in with a personal access token: use auth \"bearer\"")
	case s.auth == AuthBearer && s.email != "":
		return settings{}, errors.New("email is only for basic auth, with a Cloud API token")
	}

	spaces, err := cleanSpaces(cfg.Spaces)
	if err != nil {
		return settings{}, err
	}
	s.spaces = spaces
	s.cql = strings.TrimSpace(cfg.CQL)
	switch {
	case len(s.spaces) == 0 && s.cql == "":
		return settings{}, errors.New("scope the source: name its spaces (\"spaces\": [\"ENG\"]) or a CQL query (\"cql\")")
	case len(s.spaces) > 0 && s.cql != "":
		return settings{}, errors.New("scope the source by spaces or by a CQL query, not both")
	case s.cql != "":
		if err := checkCQL(s.cql); err != nil {
			return settings{}, fmt.Errorf("cql: %w", err)
		}
	}

	s.policy = addressPolicy{
		// A private address is a Data Center install on the organisation's
		// own network — reachable for an organisation's source only. A
		// personal source is anyone's, and a Cloud site is on the Internet.
		allowPrivate: scope == knowledge.ScopeOrg && s.deployment == DeploymentDataCenter,
		insecure:     c.opts.AllowInsecure,
	}
	if err := s.policy.checkHost(base.Hostname()); err != nil {
		return settings{}, err
	}
	return s, nil
}

// parseBaseURL checks a base URL's shape: https (or http, under
// Options.AllowInsecure), a host, no credentials, query or fragment, and a
// path without "..", returned without its trailing slash.
func (c *Connector) parseBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("base_url is required: the site's address, such as https://corp.atlassian.net/wiki")
	}
	if len(raw) > maxURLBytes || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, errors.New("base_url is not a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, errors.New("base_url is not an absolute URL, such as https://corp.atlassian.net/wiki")
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && c.opts.AllowInsecure:
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

// checkEmail checks an email's shape: one @, something on each side, no
// spaces.
func checkEmail(email string) error {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(email) > maxEmailBytes ||
		strings.IndexFunc(email, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("email %q is not an email address", email)
	}
	return nil
}

// cleanSpaces checks space keys, dropping duplicates.
func cleanSpaces(keys []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		if len(k) > maxSpaceKey || !spaceKeyPattern.MatchString(k) {
			return nil, fmt.Errorf("%q is not a space key", k)
		}
		seen[k] = true
		out = append(out, k)
	}
	if len(out) > maxSpaces {
		return nil, fmt.Errorf("a source names at most %d spaces; scope a larger one with a CQL query", maxSpaces)
	}
	return out, nil
}

// checkCQL checks what can be checked of a CQL query without the site: its
// size, that it is text, that its quotes and parentheses close — the
// connector wraps it in parentheses of its own, and an unbalanced one would
// change what the rest of the query means — and that it has no ORDER BY,
// since the connector orders the listing itself. The site parses the rest,
// and a sync reports what it refuses.
func checkCQL(q string) error {
	switch {
	case len(q) > maxCQLBytes:
		return fmt.Errorf("a query is at most %d bytes", maxCQLBytes)
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

// oneLineCQL is a checked query with its line breaks as spaces, for a URL.
func oneLineCQL(q string) string {
	return strings.Join(strings.FieldsFunc(q, func(r rune) bool { return r == '\n' || r == '\r' || r == '\t' }), " ")
}

// addressPolicy is which addresses a source may connect to.
//
// Never a cloud metadata service, the machine itself (loopback), or the local
// link — for any source: none of them is where a Confluence site lives, and
// each is where the hub's network keeps something a request from inside it
// should not reach. A private address (RFC 1918, ULA, carrier-grade NAT) only
// for an organisation's Data Center source. The rule is applied twice: to the
// host as written, when the configuration is checked, and to the address every
// connection is about to be made to, after the name was resolved — so a name
// that resolves somewhere it should not, now or after a rebinding, is refused
// all the same.
type addressPolicy struct {
	allowPrivate bool
	// insecure turns the policy off: Options.AllowInsecure, for tests.
	insecure bool
}

// ErrBlockedAddress is the refusal to connect to an address the policy
// forbids.
var ErrBlockedAddress = errors.New("confluence: refusing to connect")

// cgnat is RFC 6598 carrier-grade NAT space, which net/netip does not call
// private, but which is not the public Internet either.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// checkHost applies the policy to a host as written in a configuration: an
// address literal, or a name that is this machine by definition.
func (p addressPolicy) checkHost(host string) error {
	if p.insecure {
		return nil
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%w: %s is this machine", ErrBlockedAddress, host)
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return p.checkAddr(ip)
	}
	return nil
}

// checkAddr applies the policy to an address.
func (p addressPolicy) checkAddr(ip netip.Addr) error {
	if p.insecure {
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
		if p.allowPrivate {
			return nil
		}
		return fmt.Errorf("%w: %s is a private address, which only an organisation's Data Center source may reach — "+
			"a personal source, or a Cloud one, reaches public addresses only", ErrBlockedAddress, ip)
	}
	return nil
}
