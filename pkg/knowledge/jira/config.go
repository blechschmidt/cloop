package jira

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
	// DeploymentCloud is Jira Cloud: an Atlassian site, read through REST
	// API v3.
	DeploymentCloud = "cloud"
	// DeploymentDataCenter is Jira Data Center or Server, read through REST
	// API v2.
	DeploymentDataCenter = "datacenter"
)

// Ways a source signs in.
const (
	// AuthBasic is Jira Cloud's email and API token. The email is the
	// configuration's; the token is the source's secret.
	AuthBasic = atlassian.AuthBasic
	// AuthBearer presents the secret as a bearer token: a Cloud OAuth 2.0
	// access token, or a Data Center personal access token.
	AuthBearer = atlassian.AuthBearer
)

// Bounds on a configuration.
const (
	maxProjects   = 100
	maxProjectKey = 255
	maxJQLBytes   = 2048
)

// gatewayHost is Atlassian's API gateway, which an OAuth 2.0 app — or a
// scoped API token — reaches a Cloud site through.
const gatewayHost = "api.atlassian.com"

// config is a source's configuration as stored: a JSON object. Unknown keys
// are refused, so a misspelt "project" is an error rather than a source that
// lists everything.
type config struct {
	// Deployment is "cloud" or "datacenter" ("server" reads as datacenter).
	// It may be left out for a site at *.atlassian.net or api.atlassian.com.
	Deployment string `json:"deployment,omitempty"`
	// BaseURL is the site: https://corp.atlassian.net, or
	// https://api.atlassian.com/ex/jira/<cloud id> through Atlassian's API
	// gateway, or a Data Center install with its context path,
	// https://jira.corp.example/jira.
	BaseURL string `json:"base_url"`
	// Auth is "basic" or "bearer"; left out, it is basic when Email is set
	// and bearer otherwise.
	Auth string `json:"auth,omitempty"`
	// Email is the Atlassian account a Cloud API token belongs to.
	Email string `json:"email,omitempty"`
	// Projects scopes the source to these project keys; JQL to what a query
	// matches. Exactly one is set.
	Projects []string `json:"projects,omitempty"`
	JQL      string   `json:"jql,omitempty"`
	// IncludeSecured indexes issues that carry a security level, and comments
	// restricted to a group or a project role. Off by default: what the
	// hub's account may read, the issue's own users chose not to show
	// everyone, and every member of a project the source is bound to could
	// search it.
	IncludeSecured bool `json:"include_secured,omitempty"`
}

// settings is a configuration checked and made ready to use.
type settings struct {
	deployment string
	// base is the API root, without a trailing slash: the site on Cloud, the
	// gateway's /ex/jira/<cloud id>, or the context path on Data Center.
	base           *url.URL
	auth           string
	email          string
	projects       []string
	jql            string
	includeSecured bool
	// policy is which addresses the source may connect to.
	policy atlassian.Policy
}

// cloud reports a Cloud site.
func (s settings) cloud() bool { return s.deployment == DeploymentCloud }

// gateway reports a Cloud site reached through Atlassian's API gateway, whose
// host is not where a person reads an issue.
func (s settings) gateway() bool { return s.cloud() && s.base.Hostname() == gatewayHost }

// api is the REST API's path below the base: v3 on Cloud, v2 on Data Center.
func (s settings) api() string {
	if s.cloud() {
		return "/rest/api/3"
	}
	return "/rest/api/2"
}

var (
	// projectKeyPattern is a project key: a letter, then letters, digits and
	// underscores — nothing that can end a quoted JQL string.
	projectKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	// gatewayPathPattern is the gateway's path to one Cloud site's Jira.
	gatewayPathPattern = regexp.MustCompile(`^/ex/jira/[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
)

// parseConfig checks raw for a source of scope and returns its settings.
func (c *Connector) parseConfig(raw json.RawMessage, scope string) (settings, error) {
	var cfg config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return settings{}, fmt.Errorf("the configuration is not a jira one: %v", err)
	}
	if dec.More() {
		return settings{}, errors.New("the configuration is one JSON object")
	}
	base, err := atlassian.ParseBaseURL(cfg.BaseURL, c.opts.AllowInsecure, "https://corp.atlassian.net")
	if err != nil {
		return settings{}, err
	}
	s := settings{base: base, includeSecured: cfg.IncludeSecured}

	host := strings.ToLower(base.Hostname())
	atlassianHost := strings.HasSuffix(host, ".atlassian.net") || host == gatewayHost
	switch d := strings.ToLower(strings.TrimSpace(cfg.Deployment)); d {
	case DeploymentCloud:
		s.deployment = DeploymentCloud
	case DeploymentDataCenter, "server", "data-center", "data_center":
		s.deployment = DeploymentDataCenter
	case "":
		if !atlassianHost {
			return settings{}, fmt.Errorf("deployment is %q or %q: %s is not an Atlassian Cloud address, so say which it is",
				DeploymentCloud, DeploymentDataCenter, host)
		}
		s.deployment = DeploymentCloud
	default:
		return settings{}, fmt.Errorf("deployment is %q or %q, not %q", DeploymentCloud, DeploymentDataCenter, cfg.Deployment)
	}
	if s.cloud() {
		switch {
		case host == gatewayHost && !gatewayPathPattern.MatchString(base.Path):
			return settings{}, fmt.Errorf("a base_url on %s is https://%s/ex/jira/<cloud id>, not %s",
				gatewayHost, gatewayHost, base.Redacted())
		case strings.HasSuffix(host, ".atlassian.net") && base.Path != "":
			return settings{}, fmt.Errorf("a Jira Cloud base_url is the site itself — https://%s — or "+
				"https://%s/ex/jira/<cloud id> through the API gateway, not %s", host, gatewayHost, base.Redacted())
		}
	} else if atlassianHost {
		return settings{}, fmt.Errorf("%s is Jira Cloud: set deployment to %q", host, DeploymentCloud)
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

	projects, err := cleanProjects(cfg.Projects)
	if err != nil {
		return settings{}, err
	}
	s.projects = projects
	s.jql = strings.TrimSpace(cfg.JQL)
	switch {
	case len(s.projects) == 0 && s.jql == "":
		return settings{}, errors.New("scope the source: name a JQL query (\"jql\") or its projects (\"projects\": [\"ENG\"])")
	case len(s.projects) > 0 && s.jql != "":
		return settings{}, errors.New("scope the source by a JQL query or by projects, not both")
	case s.jql != "":
		if err := checkJQL(s.jql); err != nil {
			return settings{}, fmt.Errorf("jql: %w", err)
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

// cleanProjects checks project keys, upper-cased and without duplicates.
func cleanProjects(keys []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		k = strings.ToUpper(strings.TrimSpace(k))
		if k == "" || seen[k] {
			continue
		}
		if len(k) > maxProjectKey || !projectKeyPattern.MatchString(k) {
			return nil, fmt.Errorf("%q is not a project key", k)
		}
		seen[k] = true
		out = append(out, k)
	}
	if len(out) > maxProjects {
		return nil, fmt.Errorf("a source names at most %d projects; scope a larger one with a JQL query", maxProjects)
	}
	return out, nil
}

// checkJQL checks what can be checked of a JQL query without the site
// (atlassian.CheckQuery): its size, that it is text, that its quotes and
// parentheses close — the connector wraps it in parentheses of its own and
// appends clauses, and an unbalanced one would change what they mean — and
// that it has no ORDER BY, since the connector orders the listing itself. The
// site parses the rest, and a sync reports what it refuses.
func checkJQL(q string) error {
	if strings.TrimSpace(q) == "" {
		return errors.New("a query is required")
	}
	return atlassian.CheckQuery(q, maxJQLBytes)
}

// scopeJQL is the JQL for what the source holds, in parentheses: its query,
// or its projects.
func (s settings) scopeJQL() string {
	if s.jql != "" {
		return "(" + atlassian.OneLineQuery(s.jql) + ")"
	}
	quoted := make([]string, 0, len(s.projects))
	for _, p := range s.projects {
		quoted = append(quoted, `"`+p+`"`)
	}
	return "(project in (" + strings.Join(quoted, ", ") + "))"
}
