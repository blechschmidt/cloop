package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
)

// Connector reads one kind of knowledge source.
//
// A connector runs on the hub, inside the sync, with the source's credential
// in hand; it is never shipped to an executor. It should read every response
// body through ReadBody (or pkg/boundedread directly), so a misbehaving remote
// cannot make the hub buffer more than it means to — the sync bounds what it
// is handed regardless.
//
// The address a source's configuration names is the hub's to reach, from the
// hub's network: a connector must not take it on trust. A personal source can
// be connected by any operator, so a connector that dials whatever host its
// configuration says hands every operator a request from inside the hub's
// network — to its loopback, a cloud metadata service, an internal
// administration port. A connector refuses such addresses for a personal
// source, and allows a private one for an organisation source only where its
// remote really lives there (a Data Center install on the company network).
type Connector interface {
	// Kind is the connector's stable name ("confluence"), what a source's
	// kind column holds: lower case, digits, '-' and '_', at most 32 bytes.
	Kind() string

	// Validate checks a source's configuration, a JSON object, before it is
	// stored. The framework has already refused anything shaped like a
	// credential; this checks the connector's own fields.
	Validate(config json.RawMessage) error

	// List returns the documents that changed since req.Cursor — from the
	// beginning when it is empty — a page at a time. Page.Cursor resumes
	// after the page and is stored once the page is indexed, so a sync that
	// stops resumes rather than repeating; Page.More says whether another page
	// follows now. A document the source deleted comes back with Deleted set.
	List(ctx context.Context, req ListRequest) (Page, error)

	// Fetch returns one document in full, for a document List returned
	// Partial.
	Fetch(ctx context.Context, req FetchRequest) (Document, error)
}

// QueryNarrower is what a connector implements to let a binding narrow it by
// a native query — JQL for Jira, CQL for Confluence.
//
// The hub cannot evaluate such a query itself, so it asks the connector at
// each sync which of the source's documents match each binding's query, and a
// search admits only those. A binding with a query therefore serves nothing
// until the first sync after it was set — the failure that leaks nothing.
type QueryNarrower interface {
	// ValidateQuery checks a binding's query for a source with this
	// configuration, before the binding is stored.
	ValidateQuery(config json.RawMessage, query string) error

	// Narrow returns the external IDs of every document of the source that
	// matches req.Query — all of them, not a page, since what is not listed
	// is taken out of the binding.
	Narrow(ctx context.Context, req NarrowRequest) ([]string, error)
}

// ListRequest asks a connector for a page of changed documents.
type ListRequest struct {
	Config     json.RawMessage
	Credential Credential
	// Cursor is the opaque position the previous page returned; empty means
	// from the beginning.
	Cursor string
	// PageSize is how many documents the sync would like at once; a
	// connector may return fewer, and must not return more than
	// MaxPageDocuments.
	PageSize int
}

// Page is one page of a listing.
type Page struct {
	Documents []Document
	// Cursor resumes the listing after this page.
	Cursor string
	// More reports that another page follows now.
	More bool
}

// FetchRequest asks a connector for one document.
type FetchRequest struct {
	Config     json.RawMessage
	Credential Credential
	ExternalID string
}

// NarrowRequest asks a QueryNarrower which documents match a query.
type NarrowRequest struct {
	Config     json.RawMessage
	Credential Credential
	Query      string
}

// Credential is a source's secret, opened on the hub for one sync and handed
// to its connector in-process. It cannot be printed or serialized: it formats
// itself, so every fmt verb — %v, %d, %x, %#v alike — shows a placeholder; the
// bytes sit behind a pointer, so even the verbs fmt prints without asking the
// value (%p, and anything printed as a bad verb) show an address; and
// encoding it is an error. A request logged or marshalled by mistake carries
// no secret with it.
type Credential struct {
	secret *credentialBytes
}

// credentialBytes is what a Credential points to: one copy of the secret,
// shared by every copy of the Credential, so wiping it wipes it for all.
type credentialBytes struct{ b []byte }

// NewCredential wraps an opened secret. The Credential now owns b: the sync
// wipes it when the sync ends.
func NewCredential(b []byte) Credential { return Credential{secret: &credentialBytes{b: b}} }

// Value returns the secret. A connector uses it for the call it was handed it
// in and keeps no copy: once the sync ends it is zeroes.
func (c Credential) Value() []byte {
	if c.secret == nil {
		return nil
	}
	return c.secret.b
}

// IsZero reports a source with no credential.
func (c Credential) IsZero() bool { return len(c.Value()) == 0 }

// String never shows the value.
func (c Credential) String() string {
	if c.IsZero() {
		return "credential(none)"
	}
	return "credential(redacted)"
}

// GoString keeps %#v from printing the bytes.
func (c Credential) GoString() string { return c.String() }

// Format answers every fmt verb with the placeholder: without it, a verb that
// does not ask for String — %d, %o, %c — prints the struct.
func (c Credential) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// errCredentialSerialized is what encoding a Credential returns.
var errCredentialSerialized = errors.New("knowledge: a credential is never serialized")

// MarshalJSON refuses: a credential has no business in a JSON document.
func (c Credential) MarshalJSON() ([]byte, error) { return nil, errCredentialSerialized }

// MarshalText refuses, for every encoder that asks for text instead.
func (c Credential) MarshalText() ([]byte, error) { return nil, errCredentialSerialized }

// wipe zeroes the secret, for every copy of the Credential.
func (c *Credential) wipe() {
	if c.secret == nil {
		return
	}
	for i := range c.secret.b {
		c.secret.b[i] = 0
	}
	c.secret.b = nil
}

// kindPattern is what a connector's Kind must look like.
var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Registry holds the connectors a hub can sync with, by kind.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{connectors: map[string]Connector{}}
}

// Register adds c, refusing a malformed kind or one already taken.
func (r *Registry) Register(c Connector) error {
	if c == nil {
		return errors.New("knowledge: register a nil connector")
	}
	kind := c.Kind()
	if !kindPattern.MatchString(kind) {
		return fmt.Errorf("knowledge: connector kind %q is not lower-case letters, digits, '-' and '_' (at most 32)", kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.connectors[kind]; taken {
		return fmt.Errorf("knowledge: a connector of kind %q is already registered", kind)
	}
	r.connectors[kind] = c
	return nil
}

// Lookup returns the connector of kind.
func (r *Registry) Lookup(kind string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.connectors[kind]
	return c, ok
}

// Kinds lists the registered kinds, sorted.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.connectors))
	for k := range r.connectors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// defaultRegistry is where connectors register themselves.
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the registry connector packages register into, and
// the one a Service uses unless told otherwise.
func DefaultRegistry() *Registry { return defaultRegistry }

// Register adds c to the default registry.
func Register(c Connector) error { return defaultRegistry.Register(c) }

// MustRegister is Register for a connector package's init, where a clash is a
// build defect.
func MustRegister(c Connector) {
	if err := Register(c); err != nil {
		panic(err)
	}
}
