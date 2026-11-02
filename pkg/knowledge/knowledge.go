// Package knowledge connects a cloop hub to an organisation's knowledge — a
// Confluence site, a Jira project — and makes what it holds searchable from the
// projects it is meant for (Task 20467).
//
// It is the base layer the connectors build on:
//
//	Connector  reads one kind of source: validates its configuration, lists
//	           what changed since an opaque cursor, and fetches a document.
//	           Connectors register into a Registry.
//	Source     one connected instance of a connector: its configuration, a
//	           reference to the secret the hub signs in with, and where the
//	           last sync stopped. An org source belongs to the organisation and
//	           is managed by admins (knowledge.admin); a personal source belongs
//	           to the person who connected it and reads with their own secret.
//	Binding    a project that may search a source, optionally narrowed to some
//	           space keys or to a connector-native query such as JQL.
//	Chunk      a heading-and-paragraph-bounded piece of a document, indexed in
//	           SQLite's FTS5 and ranked by BM25, in the hub's own database.
//
// # What it guarantees
//
// A search reads only the sources bound to the project it is asked about,
// through each binding's narrowing (pkg/statedb's knowledgeSearchSQL holds the
// joins). Every operation is authorized through a Principal — the same
// decision the hub's route gate makes, which itself rests on authz.Enforced —
// before anything is read or written. A source's credential is stored only as
// a secret store reference; the hub opens it for one sync, hands it to the
// connector in-process, and wipes it: it is never part of a Source, a
// Document, a search result or anything an executor receives. Every document
// body is bounded by size through pkg/boundedread, and scrubbed of anything
// shaped like a credential before it is indexed.
package knowledge

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// Scopes a source can have.
const (
	// ScopeOrg is the organisation's source: managed by knowledge.admin,
	// read with a shared secret.
	ScopeOrg = "org"
	// ScopePersonal is one person's source: managed by its owner, read with a
	// personal secret of theirs.
	ScopePersonal = "personal"
)

// Bounds. Each is a size a well-behaved source never approaches and a hostile
// or broken one cannot exceed.
const (
	// MaxBodyBytes bounds one document's body. A longer one is indexed up to
	// here and marked truncated.
	MaxBodyBytes = 2 << 20
	// MaxTitleBytes, MaxURLBytes, MaxExternalIDBytes and MaxSpaceKeyBytes
	// bound a document's metadata.
	MaxTitleBytes      = 512
	MaxURLBytes        = 2048
	MaxExternalIDBytes = 512
	MaxSpaceKeyBytes   = 128
	// MaxACLHints and MaxACLHintBytes bound the access hints kept per
	// document.
	MaxACLHints     = 64
	MaxACLHintBytes = 256
	// MaxAncestors bounds the ancestors kept per document: the innermost
	// ones, which place it best. Each is a title, bounded by MaxTitleBytes.
	MaxAncestors = 32
	// MaxChunksPerDocument bounds one document's chunks.
	MaxChunksPerDocument = 4096
	// MaxPageDocuments bounds what one List call may return.
	MaxPageDocuments = 1000
	// MaxConfigBytes bounds a source's configuration.
	MaxConfigBytes = 16 << 10
	// MaxNameRunes bounds a source's name.
	MaxNameRunes = 128
	// MaxSecretRefBytes bounds a secret reference.
	MaxSecretRefBytes = 256
	// MaxBindingSpaces and MaxBindingQueryBytes bound a binding's narrowing.
	MaxBindingSpaces     = 64
	MaxBindingQueryBytes = 2048
	// MaxQueryBytes and MaxQueryTerms bound a search query.
	MaxQueryBytes = 512
	MaxQueryTerms = 32
	// DefaultResults and MaxResults bound how many chunks a search returns.
	DefaultResults = 10
	MaxResults     = 50
	// MaxSyncErrorBytes bounds the error text a failed sync records.
	MaxSyncErrorBytes = 1024
)

// How often a source is synced (Task 20470). A source sets its own interval,
// in whole minutes within these bounds, or takes the default.
const (
	DefaultSyncInterval = 30 * time.Minute
	MinSyncInterval     = 5 * time.Minute
	MaxSyncInterval     = 24 * time.Hour
)

// What started a sync.
const (
	// OriginSchedule is the hub-cluster leader's scheduler.
	OriginSchedule = "schedule"
	// OriginManual is a person asking for a sync now.
	OriginManual = "manual"
)

// How a sync ended, as SyncState.Status records it.
const (
	StatusOK    = "ok"
	StatusError = "error"
	// StatusInterrupted is a sync stopped because the hub process running it
	// stopped, or stopped leading its cluster: it resumes from its cursor at
	// the next one, and is due at once.
	StatusInterrupted = "interrupted"
)

// Snippet markers: a search result's snippet surrounds each matched term with
// these, and marks text left out with SnippetEllipsis. Characters rather than
// markup, so a snippet is safe to show as text and readable to a person or a
// model as it is.
const (
	SnippetOpen     = "«"
	SnippetClose    = "»"
	SnippetEllipsis = "…"
)

var (
	// ErrNotFound reports a source, binding or project the caller cannot
	// see — including one that exists but is not theirs to see.
	ErrNotFound = errors.New("knowledge: not found")
	// ErrInvalid reports a request that is malformed or breaks a bound.
	ErrInvalid = errors.New("knowledge: invalid")
	// ErrConflict reports a name already taken.
	ErrConflict = errors.New("knowledge: conflict")
	// ErrUnavailable reports something the hub needs and does not have: the
	// secret store, or a connector for a source's kind.
	ErrUnavailable = errors.New("knowledge: unavailable")
	// ErrForbidden reports a caller who may see the thing but not do this to
	// it. The concrete error is a *ForbiddenError naming the permission.
	ErrForbidden = errors.New("knowledge: not permitted")
	// ErrDisabled reports a sync asked of a source an administrator disabled.
	ErrDisabled = errors.New("knowledge: source is disabled")
)

// ForbiddenError is a denial naming the permission that would have allowed
// it. It matches ErrForbidden.
type ForbiddenError struct {
	Permission authz.Permission
	Reason     string
}

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("knowledge: not permitted: %s (needs %s)", e.Reason, e.Permission)
}

// Is makes errors.Is(err, ErrForbidden) match.
func (e *ForbiddenError) Is(target error) bool { return target == ErrForbidden }

func forbidden(p authz.Permission, format string, args ...any) error {
	return &ForbiddenError{Permission: p, Reason: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Document is one item a connector reads from its source: a page, an issue.
type Document struct {
	// ExternalID identifies it at the source, stably across edits.
	ExternalID string
	Title      string
	// URL is where a person reads it; only http and https are kept.
	URL string
	// Space is the space or project key it belongs to ("ENG"); bindings
	// narrow by it.
	Space string
	// UpdatedAt is when the source last changed it.
	UpdatedAt time.Time
	// Body is its plain text. Markdown-style headings ("# Title", or a line
	// underlined with = or -) are what chunking splits on first.
	Body string
	// Deleted reports a document the source no longer has; the index drops
	// it. Nothing else of a deleted document is read.
	Deleted bool
	// ACL carries the source's access hints for it — "group:eng",
	// "user:alice@corp", "public" — kept with the document for consumers that
	// filter by them. A binding is what decides who may search a source; the
	// hints are recorded, not enforced, by this package.
	ACL []string
	// Ancestors are the titles of what holds it at the source, outermost
	// first — the pages above a Confluence page — so that a citation can say
	// where it sits ("Runbooks › Deploys"). Metadata, like URL and ACL:
	// changing them does not chunk the document again.
	Ancestors []string
	// Partial marks a document List returned without its body; the sync
	// fetches it before indexing.
	Partial bool
}

// Source is one connected knowledge source.
type Source struct {
	ID    int64
	Kind  string
	Name  string
	Scope string
	// Owner is a personal source's owner, in OwnerKey form; empty for an org
	// source.
	Owner string
	// Config is the connector's configuration: a JSON object, never holding a
	// credential.
	Config json.RawMessage
	// SecretRef names the secret the hub signs in with, "name" or
	// "name#KEY"; empty for a source that needs none.
	SecretRef string
	Enabled   bool
	// SyncInterval is how often the hub syncs the source, as it was set;
	// zero takes DefaultSyncInterval (see Interval).
	SyncInterval time.Duration
	Sync         SyncState
	CreatedAt    time.Time
	CreatedBy    string
	UpdatedAt    time.Time
	UpdatedBy    string
	// Counts is what the source holds. Filled where it was asked for.
	Counts Counts
}

// Interval is how often the hub syncs the source.
func (s Source) Interval() time.Duration {
	if s.SyncInterval <= 0 {
		return DefaultSyncInterval
	}
	return s.SyncInterval
}

// SyncState is how a source's last sync went.
type SyncState struct {
	// Status is "" (never synced), StatusOK, StatusError or
	// StatusInterrupted.
	Status string
	// Error is the last sync's error, scrubbed of credentials.
	Error string
	// At is when the last sync ended.
	At time.Time
	// Resumes reports whether the next sync continues from a cursor rather
	// than listing the source from the beginning.
	Resumes bool
	// ReconciledAt is when the documents were last reconciled against what
	// the source holds — by a Reconciler's answer, or a full listing's
	// sweep; zero for never.
	ReconciledAt time.Time
	// StartedAt, Duration and Origin describe the last sync: when it began,
	// how long it ran, and what started it (OriginSchedule or OriginManual).
	StartedAt time.Time
	Duration  time.Duration
	Origin    string
	// Counts is what the last sync did.
	Counts SyncCounts
	// Warning is what went wrong in the last sync without failing it: the
	// embedding endpoint was down, say. Empty for none.
	Warning string
	// More reports a last sync that stopped before its listing's end; the
	// next one is due at once.
	More bool
	// OKAt is when a sync last ended ok; zero for never.
	OKAt time.Time
	// Running is the sync in progress, if one is, and NextAt when the
	// schedule next syncs the source — zero for a disabled one. Filled where
	// a source is read through Access.
	Running *RunningSync
	NextAt  time.Time
}

// SyncCounts is what one sync did, as its source records it: never a
// document's content.
type SyncCounts struct {
	Pages     int `json:"pages"`
	Listed    int `json:"listed"`
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	// Deleted counts the documents the source reported deleted.
	Deleted  int `json:"deleted"`
	Rejected int `json:"rejected"`
	// Removed counts the documents a full listing's sweep or a
	// reconciliation found gone.
	Removed int `json:"removed"`
	// Narrowed counts the bindings whose query matches were recorded.
	Narrowed int `json:"narrowed"`
	// Complete reports that the listing reached its end.
	Complete bool `json:"complete"`
	// Full reports a sync that took part in a full listing.
	Full bool `json:"full,omitempty"`
	// Embeddings is what the sync's embedding pass did; absent when
	// semantic retrieval is off.
	Embeddings *EmbedCounts `json:"embeddings,omitempty"`
	// Warning is what went wrong without failing the sync — the embedding
	// endpoint failing, say — scrubbed of credentials.
	Warning string `json:"warning,omitempty"`
}

// RunningSync is a sync in progress, as its lease says.
type RunningSync struct {
	// Member is the hub process running it.
	Member string
	Origin string
	// Actor is who asked for a manual sync.
	Actor string
	Since time.Time
}

// Counts is how much a source holds.
type Counts struct {
	Documents int
	Chunks    int
	Bindings  int
	// Vectors counts the chunks with a vector of the hub's embedding model,
	// current or awaiting the next sync; zero while semantic retrieval is
	// off.
	Vectors int
}

// Filter narrows a binding.
type Filter struct {
	// Spaces admits only documents in these space keys; empty admits all.
	Spaces []string
	// Query admits only documents the source's connector reports as matching
	// it, at each sync: a connector-native filter such as JQL. Empty admits
	// all.
	Query string
}

// Binding makes a source searchable from one project.
type Binding struct {
	ID       int64
	SourceID int64
	// Project is the project's path.
	Project string
	Filter  Filter
	// NarrowedAt is when a sync last recorded which documents match
	// Filter.Query; zero means none has, and a binding with a query serves
	// nothing until one does.
	NarrowedAt time.Time
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// Project is a project as the hub knows it: the path a binding names, and the
// registry name an authz binding may name instead.
type Project struct {
	// Path is the project's absolute path. A feature passes its parent's.
	Path string
	Name string
}

// scope is the authz scope a request on p is decided in.
func (p Project) scope() authz.Scope {
	return authz.Scope{Project: p.Name, ProjectPath: p.Path}
}

// Hit is one chunk a search found.
type Hit struct {
	ChunkID    int64
	DocumentID int64
	Source     SourceRef
	Title      string
	URL        string
	Space      string
	ExternalID string
	// Heading is the chunk's heading path within its document.
	Heading string
	// Ancestors place the document at its source, outermost first.
	Ancestors []string
	// Snippet is the chunk's best-matching passage, terms marked with
	// SnippetOpen and SnippetClose.
	Snippet string
	// Rank is the hit's place in the results, from 1. The BM25 score it was
	// ranked by is not given out: see Access.Retrieve.
	Rank    int
	Ordinal int
	// Lexical and Semantic say what found the hit: its words — the
	// full-text index — and its meaning — its vector's nearness to the
	// query's. A search with semantic retrieval off finds by words alone.
	Lexical  bool
	Semantic bool
}

// SourceRef names a source in a search result.
type SourceRef struct {
	ID   int64
	Name string
	Kind string
}
