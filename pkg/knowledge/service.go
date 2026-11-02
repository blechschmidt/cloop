package knowledge

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Credentials is how the hub reaches a source's secret: *secretbroker.Broker
// implements it. CheckSourceCredential answers whether a reference may be
// used by a source of that owner without opening anything; SourceCredential
// opens it, for a sync.
type Credentials interface {
	CheckSourceCredential(ref, owner string) error
	SourceCredential(ref, owner string) ([]byte, error)
}

var _ Credentials = (*secretbroker.Broker)(nil)

// Service is the knowledge layer over one hub database: sources, bindings,
// indexing and search.
type Service struct {
	db          *statedb.DB
	registry    *Registry
	credentials Credentials
	chunking    ChunkOptions
	now         func() time.Time
	// fullEvery is how often a source is listed from the beginning.
	fullEvery time.Duration
	// reconcileEvery is how often a Reconciler is asked what its source
	// holds.
	reconcileEvery time.Duration
	// embeddings is semantic retrieval: off unless an Embedder is set.
	embeddings Embeddings

	// onChunk, when set, is called each time a document is chunked. Tests use
	// it to prove an unchanged document is not.
	onChunk func()
}

// Option configures a Service.
type Option func(*Service)

// WithRegistry makes the Service read sources with r's connectors instead of
// the default registry's.
func WithRegistry(r *Registry) Option { return func(s *Service) { s.registry = r } }

// WithCredentials gives the Service the secret store. Without it a source
// with a secret reference can be neither created nor synced: there is nothing
// to check the reference against.
func WithCredentials(c Credentials) Option { return func(s *Service) { s.credentials = c } }

// WithChunking sets how documents are cut.
func WithChunking(o ChunkOptions) Option { return func(s *Service) { s.chunking = o.normalized() } }

// WithClock sets the Service's clock.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New returns a Service over db, the hub's control-plane database.
func New(db *statedb.DB, opts ...Option) *Service {
	s := &Service{
		db:             db,
		registry:       defaultRegistry,
		chunking:       ChunkOptions{}.normalized(),
		now:            time.Now,
		fullEvery:      DefaultFullListingEvery,
		reconcileEvery: DefaultReconcileEvery,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Principal is who is asking, as the hub authorized them.
type Principal struct {
	// Identity is the caller's OwnerKey — a lowercased email, or
	// "sub:<subject>" — or empty where there is no signed-in person behind
	// the request: a hub without single sign-on, or its static token.
	Identity string
	// Actor names the caller in the audit trail.
	Actor string
	// Decide returns what the caller may do in a scope. The hub passes its
	// request's grant, which applies authz.Enforced like every route does;
	// PrincipalFor builds one for callers that hold a resolver instead.
	// Nil denies everything.
	Decide func(authz.Scope) authz.Decision
}

func (p Principal) allows(perm authz.Permission, scope authz.Scope) bool {
	if p.Decide == nil {
		return false
	}
	return p.Decide(scope).Allows(perm)
}

// PrincipalFor builds a principal the way the hub's gate decides a request:
// authz.Enforced says whether a role policy is in force at all — on a hub
// without single sign-on, or with no policy, every caller holds everything,
// exactly as the hub's routes treat them — and when one is, resolver decides
// per scope. A nil subject under an enforced policy is refused everything.
func PrincipalFor(sso bool, resolver *authz.Resolver, subject *authz.Subject, identity, actor string) Principal {
	enforced := authz.Enforced(sso, resolver)
	return Principal{
		Identity: secretbroker.NormalizeOwner(identity),
		Actor:    actor,
		Decide: func(scope authz.Scope) authz.Decision {
			if !enforced {
				return authz.AllowAll(authz.SourceAuthzDisabled, actor)
			}
			if subject == nil {
				return authz.Deny(authz.SourceUnauthenticated, "", scope)
			}
			return resolver.Resolve(subject, scope)
		},
	}
}

// For returns the Service acting for p. Every operation on the result is
// authorized for p before it reads or writes anything.
func (s *Service) For(p Principal) *Access {
	p.Identity = secretbroker.NormalizeOwner(p.Identity)
	return &Access{s: s, p: p}
}

// Kinds lists the connectors this Service can read with.
func (s *Service) Kinds() []string { return s.registry.Kinds() }
