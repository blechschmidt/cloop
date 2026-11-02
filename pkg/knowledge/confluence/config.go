package confluence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
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
	AuthBasic = atlassian.AuthBasic
	// AuthBearer presents the secret as a bearer token: a Cloud OAuth 2.0
	// access token, or a Data Center personal access token.
	AuthBearer = atlassian.AuthBearer
)

// Bounds on a configuration.
const (
	maxSpaces   = 100
	maxSpaceKey = 255
	maxCQLBytes = 2048
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
	policy atlassian.Policy
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
		if err := atlassian.CheckEmail(s.email); err != nil {
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

	s.policy = atlassian.Policy{
		// A private address is a Data Center install on the organisation's
		// own network — reachable for an organisation's source only. A
		// personal source is anyone's, and a Cloud site is on the Internet.
		AllowPrivate: scope == knowledge.ScopeOrg && s.deployment == DeploymentDataCenter,
		Insecure:     c.opts.AllowInsecure,
	}
	if err := s.policy.CheckHost(base.Hostname()); err != nil {
		return settings{}, err
	}
	return s, nil
}

// parseBaseURL checks a base URL's shape (atlassian.ParseBaseURL): https, or
// http under Options.AllowInsecure.
func (c *Connector) parseBaseURL(raw string) (*url.URL, error) {
	return atlassian.ParseBaseURL(raw, c.opts.AllowInsecure, "https://corp.atlassian.net/wiki")
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

// checkCQL checks what can be checked of a CQL query without the site
// (atlassian.CheckQuery): its size, that it is text, that its quotes and
// parentheses close — the connector wraps it in parentheses of its own, and an
// unbalanced one would change what the rest of the query means — and that it
// has no ORDER BY, since the connector orders the listing itself. The site
// parses the rest, and a sync reports what it refuses.
func checkCQL(q string) error { return atlassian.CheckQuery(q, maxCQLBytes) }

// oneLineCQL is a checked query with its line breaks as spaces, for a URL.
func oneLineCQL(q string) string { return atlassian.OneLineQuery(q) }

// ErrBlockedAddress is the refusal to connect to an address the source's
// policy forbids (atlassian.Policy): never loopback, link-local or a cloud
// metadata service, and a private address only for an organisation's Data
// Center source.
var ErrBlockedAddress = atlassian.ErrBlockedAddress
