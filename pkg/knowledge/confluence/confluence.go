// Package confluence is the knowledge connector for Confluence (Task 20468):
// Confluence Cloud and Confluence Data Center or Server, registered with
// pkg/knowledge as kind "confluence".
//
// # Configuration
//
// A source's configuration names the site and what of it the source holds:
//
//	{"deployment": "cloud", "base_url": "https://corp.atlassian.net/wiki",
//	 "email": "wiki-bot@corp.example", "spaces": ["ENG", "OPS"]}
//
//	{"deployment": "datacenter", "base_url": "https://wiki.corp.example",
//	 "cql": "label = \"runbook\"", "include_restricted": false}
//
// The credential is the source's secret, never the configuration's: a Cloud
// API token (signed in with the configured email: "auth": "basic", the default
// when an email is set), a Cloud OAuth 2.0 access token, or a Data Center
// personal access token ("auth": "bearer"). A source is scoped by a list of
// space keys or by one CQL query; a binding may narrow it further by spaces or
// by CQL of its own (Narrow).
//
// # Listing
//
// A Cloud source scoped by spaces is listed through REST API v2 — its pages,
// then its blog posts, newest change first, a cursor-linked page at a time.
// Every other source is listed through CQL search (/rest/api/content/search),
// newest change first too. Each listing is incremental: the cursor keeps, per
// stream, how far back the next pass needs to go (see cursor.go), so a sync
// reads only what changed since the last one. Every document carries its web
// URL and the titles of the pages above it, for citations.
//
// What a listing cannot say — a page deleted, moved out of scope or restricted
// without being edited — a periodic reconciliation does (Reconcile): it lists
// the id of every document the source would index now, and the hub removes the
// ones it does not name.
//
// # View restrictions
//
// A page with a view restriction — its own, or one on a page above it, which
// Confluence applies to the pages below — is one some of the site's readers
// cannot see. The hub's account can, and every member of a project the source
// is bound to could then search it. So a restricted page is not indexed unless
// the source sets include_restricted, and a page restricted after it was
// indexed is removed: a listing reports it deleted, and reconciliation leaves
// it out. A restriction the connector could not read — an answer without one,
// an ancestor the site does not return — counts as a restriction. An indexed
// page carries its restrictions in its ACL hints: "restricted", and the
// "user:" and "group:" principals they name, beside "space:<key>".
//
// # Requests
//
// Every connection is checked at the address it connects to, after DNS: never
// loopback, link-local or a cloud metadata service, and a private address only
// for an organisation's Data Center source (see addressPolicy). A request is
// bounded in time (Options.RequestTimeout) and its answer in size; a 429 or
// 503 is retried after the site's Retry-After, or a bounded exponential backoff
// with jitter; a redirect is not followed. The credential is sent as a header
// and nowhere else, and every error the connector returns has it — in every
// form it is sent in — removed, along with anything else pkg/redact recognises
// as a credential.
package confluence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// Kind is the connector's kind.
const Kind = "confluence"

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
	// Now is the clock a Retry-After date is read against.
	Now func() time.Time
	// RequestTimeout bounds one request; DefaultRequestTimeout by default.
	RequestTimeout time.Duration
	// MaxRetries bounds the retries of one request; DefaultMaxRetries by
	// default, and none when negative.
	MaxRetries int
}

// Connector reads Confluence sites.
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

// Kind returns "confluence".
func (c *Connector) Kind() string { return Kind }

// Validate checks a configuration for a source of req.Scope.
func (c *Connector) Validate(req knowledge.ValidateRequest) error {
	_, err := c.parseConfig(req.Config, req.Scope)
	return err
}

// ValidateQuery checks a binding's CQL query.
func (c *Connector) ValidateQuery(_ json.RawMessage, query string) error {
	return checkCQL(query)
}

// session opens a call's settings and client.
func (c *Connector) session(config json.RawMessage, scope string, cred knowledge.Credential) (*session, error) {
	s, err := c.parseConfig(config, scope)
	if err != nil {
		return nil, fmt.Errorf("confluence configuration: %w", err)
	}
	cl, err := c.newClient(s, cred)
	if err != nil {
		return nil, err
	}
	return &session{s: s, cl: cl}, nil
}

// List returns the documents that changed since req.Cursor, a page at a time.
func (c *Connector) List(ctx context.Context, req knowledge.ListRequest) (knowledge.Page, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return knowledge.Page{}, err
	}
	defer ss.cl.close()
	page, err := ss.list(ctx, req.Cursor, req.PageSize)
	if err != nil {
		return knowledge.Page{}, ss.cl.clean(err)
	}
	return page, nil
}

// Fetch returns one document. The connector lists documents whole, so the sync
// asks for one only if another connector's listing would have; it is answered
// all the same — a deletion when the document is gone, out of scope or
// restricted.
func (c *Connector) Fetch(ctx context.Context, req knowledge.FetchRequest) (knowledge.Document, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return knowledge.Document{}, err
	}
	defer ss.cl.close()
	doc, err := ss.fetch(ctx, req.ExternalID)
	if err != nil {
		return knowledge.Document{}, ss.cl.clean(err)
	}
	return doc, nil
}

// Narrow returns the id of every document of the source that a binding's CQL
// query matches.
func (c *Connector) Narrow(ctx context.Context, req knowledge.NarrowRequest) ([]string, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return nil, err
	}
	defer ss.cl.close()
	ids, err := ss.narrow(ctx, req.Query)
	if err != nil {
		return nil, ss.cl.clean(err)
	}
	return ids, nil
}

// Reconcile returns the id of every document the source would index now.
func (c *Connector) Reconcile(ctx context.Context, req knowledge.ReconcileRequest) ([]string, error) {
	ss, err := c.session(req.Config, req.Scope, req.Credential)
	if err != nil {
		return nil, err
	}
	defer ss.cl.close()
	ids, err := ss.reconcile(ctx)
	if err != nil {
		return nil, ss.cl.clean(err)
	}
	return ids, nil
}
