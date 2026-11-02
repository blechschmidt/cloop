// Package jira is the knowledge connector for Jira (Task 20469): Jira Cloud
// and Jira Data Center or Server, registered with pkg/knowledge as kind
// "jira". Each issue — its summary, description and comments — becomes one
// searchable document.
//
// # Configuration
//
// A source's configuration names the site and what of it the source holds:
//
//	{"deployment": "cloud", "base_url": "https://corp.atlassian.net",
//	 "email": "jira-bot@corp.example", "jql": "project in (ENG, OPS) AND type != Epic"}
//
//	{"deployment": "datacenter", "base_url": "https://jira.corp.example",
//	 "projects": ["ENG"], "include_secured": false}
//
// The credential is the source's secret, never the configuration's: a Cloud
// API token (signed in with the configured email: "auth": "basic", the default
// when an email is set), a Cloud OAuth 2.0 access token, or a Data Center
// personal access token ("auth": "bearer"). A Cloud source reached through
// Atlassian's API gateway names https://api.atlassian.com/ex/jira/<cloud id>.
// A source is scoped by one JQL query, or by a list of project keys, which is
// the query "project in (...)"; a binding may narrow it further by project
// keys or by JQL of its own (Narrow).
//
// # Listing
//
// A Cloud source is searched through /rest/api/3/search/jql, a page at a time
// by its nextPageToken; a Data Center one through /rest/api/2/search by
// startAt. Both are asked as a POST, so a long query fits. A listing is
// incremental: it appends "updated >= <time>" to the source's query, the time
// in milliseconds since the epoch — which JQL reads the same in every time
// zone, where a written date is read in the signed-in account's — so a sync
// reads only what changed since the last one, newest change first, less a
// small overlap for a search index that lags (see cursor.go).
//
// Each issue becomes a document: its key and summary are the title, its
// browse URL the citation, its project key the space. Its body starts with a
// header of its status, type, priority, resolution, labels, components, fix
// versions, parent and the keys of the issues it links to, then its
// description and its comments, each under a heading of its own. Jira Cloud
// writes rich text in Atlassian Document Format, which adf.go turns into text;
// Data Center writes wiki markup, which wiki.go passes through with what would
// read as structure to the chunker made into it (headings, lists, code
// blocks, tables).
//
// What a listing cannot say — an issue deleted, moved out of the query's
// scope, or given a security level without another change — a periodic
// reconciliation does (Reconcile): it lists the id of every issue the source
// would index now, and the hub removes the ones it does not name.
//
// # Issue security
//
// An issue with a security level is one only some of the site's users may
// see. The hub's account can, and every member of a project the source is
// bound to could then search it. So an issue that carries a security level is
// not indexed unless the source sets include_secured, and an issue given one
// after it was indexed is removed: a listing reports it deleted, and
// reconciliation leaves it out. A comment restricted to a group or a project
// role is left out of its issue the same way. A linked issue, or a parent, is
// named by its key alone: its summary, which a secured issue's would be, is
// never copied into another issue's document.
//
// # Requests
//
// The connector shares pkg/knowledge/internal/atlassian with the Confluence
// connector: every connection is checked at the address it connects to, after
// DNS — never loopback, link-local or a cloud metadata service, and a private
// address only for an organisation's Data Center source; a request is bounded
// in time (Options.RequestTimeout) and its answer in size; a 429 or 503 is
// retried after the site's Retry-After, or a bounded exponential backoff with
// jitter; a redirect is not followed; and every error the connector returns
// has the credential, in every form it is sent in, removed, along with
// anything else pkg/redact recognises as a credential.
package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
)

// Kind is the connector's kind.
const Kind = "jira"

// Request bounds.
const (
	// DefaultRequestTimeout bounds one request: connecting, sending, and
	// reading the whole answer.
	DefaultRequestTimeout = atlassian.DefaultRequestTimeout
	// DefaultMaxRetries bounds the retries of one request.
	DefaultMaxRetries = atlassian.DefaultMaxRetries
)

// maxResponseBytes bounds one answer. A listing asks for few issues at once
// with their descriptions and comments, and asks for fewer when an answer is
// larger. A variable only so that a test can make an answer too large without
// sending 48 MiB.
var maxResponseBytes = atlassian.DefaultMaxResponseBytes

// ErrBlockedAddress is the refusal to connect to an address the source's
// policy forbids (atlassian.Policy).
var ErrBlockedAddress = atlassian.ErrBlockedAddress

// Options configure a Connector. The zero value is the connector a hub
// registers: nothing a source's configuration says can change one.
type Options struct {
	// AllowInsecure admits an http base URL and lets a source connect to any
	// address — loopback and private ones included — whatever its scope. It is
	// for tests against an httptest server, and never set on a hub.
	AllowInsecure bool
	// Transport replaces the connector's HTTP transport, address checks and
	// all: for a test that talks to an httptest TLS server.
	Transport http.RoundTripper
	// Sleep waits between retries; it returns early with ctx's error.
	// Defaults to a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock a Retry-After date, and a change dated in the future,
	// are read against.
	Now func() time.Time
	// RequestTimeout bounds one request; DefaultRequestTimeout by default.
	RequestTimeout time.Duration
	// MaxRetries bounds the retries of one request; DefaultMaxRetries by
	// default, and none when negative.
	MaxRetries int
}

// Connector reads Jira sites.
type Connector struct {
	opts Options
}

var (
	_ knowledge.Connector     = (*Connector)(nil)
	_ knowledge.QueryNarrower = (*Connector)(nil)
	_ knowledge.Reconciler    = (*Connector)(nil)
)

func init() { knowledge.MustRegister(New(Options{})) }

// New returns a connector with opts.
func New(opts Options) *Connector {
	if opts.Sleep == nil {
		opts.Sleep = sleep
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = DefaultRequestTimeout
	}
	switch {
	case opts.MaxRetries == 0:
		opts.MaxRetries = DefaultMaxRetries
	case opts.MaxRetries < 0:
		opts.MaxRetries = 0
	}
	return &Connector{opts: opts}
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Kind returns "jira".
func (c *Connector) Kind() string { return Kind }

// Validate checks a configuration for a source of req.Scope.
func (c *Connector) Validate(req knowledge.ValidateRequest) error {
	_, err := c.parseConfig(req.Config, req.Scope)
	return err
}

// ValidateQuery checks a binding's JQL query.
func (c *Connector) ValidateQuery(_ json.RawMessage, query string) error {
	return checkJQL(query)
}

// session is one call's settings and client.
type session struct {
	s   settings
	cl  *atlassian.Client
	now func() time.Time
}

// session opens a call's settings and client.
func (c *Connector) session(config json.RawMessage, scope string, cred knowledge.Credential) (*session, error) {
	s, err := c.parseConfig(config, scope)
	if err != nil {
		return nil, fmt.Errorf("jira configuration: %w", err)
	}
	cl, err := atlassian.NewClient(atlassian.Config{
		Product: Kind, Base: s.base, Auth: s.auth, Email: s.email, Policy: s.policy,
		Transport: c.opts.Transport, Sleep: c.opts.Sleep, Now: c.opts.Now,
		Timeout: c.opts.RequestTimeout, Retries: c.opts.MaxRetries, MaxResponseBytes: maxResponseBytes,
	}, cred)
	if err != nil {
		return nil, err
	}
	return &session{s: s, cl: cl, now: c.opts.Now}, nil
}

// List returns the issues that changed since req.Cursor, a page at a time.
func (c *Connector) List(ctx context.Context, req knowledge.ListRequest) (knowledge.Page, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return knowledge.Page{}, err
	}
	defer ss.cl.Close()
	page, err := ss.list(ctx, req.Cursor, req.PageSize)
	if err != nil {
		return knowledge.Page{}, ss.cl.Clean(err)
	}
	return page, nil
}

// Fetch returns one issue. The connector lists issues whole, so the sync asks
// for one only if another connector's listing would have; it is answered all
// the same — a deletion when the issue is gone, out of scope or secured.
func (c *Connector) Fetch(ctx context.Context, req knowledge.FetchRequest) (knowledge.Document, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return knowledge.Document{}, err
	}
	defer ss.cl.Close()
	doc, err := ss.fetch(ctx, req.ExternalID)
	if err != nil {
		return knowledge.Document{}, ss.cl.Clean(err)
	}
	return doc, nil
}

// Narrow returns the id of every issue of the source that a binding's JQL
// query matches.
func (c *Connector) Narrow(ctx context.Context, req knowledge.NarrowRequest) ([]string, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return nil, err
	}
	defer ss.cl.Close()
	ids, err := ss.narrow(ctx, req.Query)
	if err != nil {
		return nil, ss.cl.Clean(err)
	}
	return ids, nil
}

// Reconcile returns the id of every issue the source would index now.
func (c *Connector) Reconcile(ctx context.Context, req knowledge.ReconcileRequest) ([]string, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return nil, err
	}
	defer ss.cl.Close()
	ids, err := ss.reconcile(ctx)
	if err != nil {
		return nil, ss.cl.Clean(err)
	}
	return ids, nil
}
