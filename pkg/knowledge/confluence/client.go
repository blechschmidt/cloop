package confluence

// client.go makes a call's client: pkg/knowledge/internal/atlassian's, the one
// every Atlassian connector shares — the address checks at every connection,
// the transport that uses no proxy and follows no redirect, the bounds on time
// and answer size, the retries, and the credential scrubbed out of every
// error (see that package).

import (
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
)

// Request bounds.
const (
	// DefaultRequestTimeout bounds one request: connecting, sending, and
	// reading the whole answer.
	DefaultRequestTimeout = atlassian.DefaultRequestTimeout
	// DefaultMaxRetries bounds the retries of one request.
	DefaultMaxRetries = atlassian.DefaultMaxRetries
)

// maxResponseBytes bounds one answer. A listing asks for few pages at once
// with their bodies, and asks for fewer when an answer is larger. A variable
// only so that a test can make an answer too large without sending 48 MiB.
var maxResponseBytes = atlassian.DefaultMaxResponseBytes

// newClient builds the client for a call with cred, which it reads but keeps
// no copy of beyond the header it sends.
func (c *Connector) newClient(s settings, cred knowledge.Credential) (*atlassian.Client, error) {
	return atlassian.NewClient(atlassian.Config{
		Product: Kind, Base: s.base, Auth: s.auth, Email: s.email, Policy: s.policy,
		Transport: c.opts.Transport, Sleep: c.opts.Sleep, Now: c.opts.Now,
		Timeout: c.opts.RequestTimeout, Retries: c.opts.MaxRetries, MaxResponseBytes: maxResponseBytes,
	}, cred)
}
