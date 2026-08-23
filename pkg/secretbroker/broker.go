package secretbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultMaxLeaseTTL bounds how long any single lease is valid, regardless
// of how long its grants last.
//
// The split between grant TTL and lease TTL is the point of the design. An
// operator reasonably grants CI access to a repository for a day; it does
// not follow that a container should hold a usable token for a day. Fifteen
// minutes with renewal keeps long runs working while bounding what a
// compromised or forgotten executor still holds — and because Renew
// re-evaluates every grant, a revocation lands within one lease period
// rather than at the end of the grant.
const DefaultMaxLeaseTTL = 15 * time.Minute

// DefaultGrantTTL is used when a grant is created without an explicit TTL
// from a path that requires one.
const DefaultGrantTTL = 24 * time.Hour

// Broker issues scoped, expiring credential leases against a Store.
//
// Safe for concurrent use.
type Broker struct {
	store Store
	// seal is the key source. A *Keyring when the store can hold a KEK
	// registry (every production hub, via pkg/secretstore), a *Cipher for
	// stores that cannot — see the sealer doc comment in envelope.go.
	seal    sealer
	keyring *Keyring
	auditor Auditor

	mu     sync.Mutex
	leases map[string]*leaseState

	clock       func() time.Time
	maxLeaseTTL time.Duration
}

// leaseState remembers what a lease was issued for, so Renew can re-evaluate
// the same subject against current grants instead of trusting the old
// materials.
type leaseState struct {
	requester Requester
	actor     string
	expiresAt time.Time
}

// Option configures a Broker.
type Option func(*Broker)

// WithAuditor sets the audit sink. Without one, events are dropped — which
// is acceptable for tests and for read-only CLI paths, and never for the
// control plane.
func WithAuditor(a Auditor) Option {
	return func(b *Broker) {
		if a != nil {
			b.auditor = a
		}
	}
}

// WithClock overrides the time source. Tests use it to exercise TTL expiry
// without sleeping.
func WithClock(fn func() time.Time) Option {
	return func(b *Broker) {
		if fn != nil {
			b.clock = fn
		}
	}
}

// WithMaxLeaseTTL overrides DefaultMaxLeaseTTL. Values above the grant's own
// remaining lifetime are still clamped to it.
func WithMaxLeaseTTL(d time.Duration) Option {
	return func(b *Broker) {
		if d > 0 {
			b.maxLeaseTTL = d
		}
	}
}

// WithCipher supplies a pre-built Cipher, bypassing CLOOP_SECRET_KEY.
//
// A Cipher has no key registry, so a broker built this way seals in the
// legacy single-key shape and cannot rotate. That is right for a test double
// and wrong for a hub; prefer WithKeyring where rotation matters.
func WithCipher(c *Cipher) Option {
	return func(b *Broker) {
		if c != nil {
			b.seal = c
			b.keyring = nil
		}
	}
}

// WithKeyring supplies a pre-opened Keyring, so a caller that already built
// one (the hub, which shares it with the session store) does not pay the KDF
// cost a second time.
func WithKeyring(kr *Keyring) Option {
	return func(b *Broker) {
		if kr != nil {
			b.seal = kr
			b.keyring = kr
		}
	}
}

// New builds a Broker over store. Unless WithCipher is supplied, the payload
// key is derived from CLOOP_SECRET_KEY, and New fails if it is unset —
// a broker that cannot open payloads would otherwise fail later, at lease
// time, in the middle of somebody's run.
func New(store Store, opts ...Option) (*Broker, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidSecret)
	}
	b := &Broker{
		store:       store,
		auditor:     nopAuditor{},
		leases:      make(map[string]*leaseState),
		clock:       time.Now,
		maxLeaseTTL: DefaultMaxLeaseTTL,
	}
	for _, opt := range opts {
		opt(b)
	}
	if b.seal == nil {
		// A store that can hold a KEK registry gets envelope encryption and
		// online rotation; one that cannot keeps the single-key behaviour.
		// The distinction is made here, once, rather than by every call site
		// having to know which kind of store it handed over.
		if ks, ok := store.(KeyStore); ok {
			kr, err := OpenKeyring(ks)
			if err != nil {
				return nil, err
			}
			b.seal, b.keyring = kr, kr
		} else {
			c, err := NewCipher(store)
			if err != nil {
				return nil, err
			}
			b.seal = c
		}
	}
	return b, nil
}

// Keyring returns the broker's key registry, or nil when it was built over a
// store with no registry. Callers that rotate must handle nil rather than
// assume every broker can.
func (b *Broker) Keyring() *Keyring { return b.keyring }

func (b *Broker) now() time.Time { return b.clock().UTC() }

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// MintRequest describes a secret to store.
type MintRequest struct {
	Name     string
	Kind     Kind
	Payload  []byte
	Metadata map[string]string
	Actor    string
}

// Mint seals a payload and stores it as a new secret.
//
// The payload is zeroed in the caller's slice on return so a mint site does
// not leave plaintext in a buffer the garbage collector may not touch for a
// while. Callers that still need the bytes must pass a copy.
func (b *Broker) Mint(ctx context.Context, req MintRequest) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	ev := Event{Action: ActionMint, Actor: req.Actor, SecretName: req.Name, Kind: req.Kind}

	if err := ValidateName(req.Name); err != nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "invalid name: %v", err)
	}
	if !req.Kind.Valid() {
		return Secret{}, b.denyf(ev, ErrInvalidKind, "unknown kind %q", req.Kind)
	}
	if len(req.Payload) == 0 {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "empty payload")
	}
	if _, err := findSecretByName(b.store, req.Name); err == nil {
		return Secret{}, b.denyf(ev, ErrDuplicateName, "a secret named %q already exists", req.Name)
	}

	// The ID is minted before the payload is sealed because it *is* the
	// envelope's associated data: binding the ciphertext to the row it lives
	// in is what stops an attacker with database write access from moving a
	// secret they minted into a row that trusted grants point at.
	id, err := newID("sec")
	if err != nil {
		zero(req.Payload)
		return Secret{}, err
	}
	env, err := b.seal.SealFor(AADFor(SetSecrets, id), req.Payload)
	zero(req.Payload)
	if err != nil {
		return Secret{}, b.denyf(ev, ErrSealFailed, "seal payload: %v", err)
	}

	s := Secret{
		ID:         id,
		Kind:       req.Kind,
		Name:       req.Name,
		Sealed:     env.Ciphertext,
		KeyID:      env.KeyID,
		WrappedDEK: env.WrappedDEK,
		Metadata:   req.Metadata,
		CreatedAt:  b.now(),
		CreatedBy:  req.Actor,
	}
	if err := s.Validate(); err != nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "%v", err)
	}
	if err := b.store.PutSecret(s); err != nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "store secret: %v", err)
	}

	ev.SecretID = s.ID
	ev.Decision = DecisionAllow
	b.emit(ev)
	return s, nil
}

// DescribeSecret resolves a secret by ID or name. The payload stays sealed:
// this answers "does this reference name something, and of what kind", which is
// what a caller validating a grant before creating it needs.
//
// It exists so that path does not have to re-implement reference resolution
// against ListSecrets, where a subtly different name match would mean a grant
// validated against one secret and then created against another.
func (b *Broker) DescribeSecret(ref string) (Secret, error) {
	return resolveSecret(b.store, ref)
}

// ListSecrets returns stored secrets. Payloads stay sealed.
func (b *Broker) ListSecrets() ([]Secret, error) {
	secrets, err := b.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })
	return secrets, nil
}

// DeleteSecret removes a secret and revokes every grant that pointed at it.
// Leaving grants behind would leave rows that resolve to nothing and read,
// in a grant listing, as still-live access.
func (b *Broker) DeleteSecret(ctx context.Context, ref, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ev := Event{Action: ActionDeleteSec, Actor: actor}
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return b.denyf(ev, ErrSecretNotFound, "resolve %q: %v", SafeRef(ref), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind

	grants, err := b.store.ListGrants()
	if err != nil {
		return b.denyf(ev, ErrGrantNotFound, "list grants: %v", err)
	}
	now := b.now()
	for _, g := range grants {
		if g.SecretID == s.ID && g.RevokedAt.IsZero() {
			if rerr := b.store.RevokeGrant(g.ID, now); rerr != nil {
				return b.denyf(ev, ErrInvalidGrant, "revoke dependent grant %s: %v", g.ID, rerr)
			}
		}
	}
	if err := b.store.DeleteSecret(s.ID); err != nil {
		return b.denyf(ev, ErrSecretNotFound, "delete: %v", err)
	}

	ev.Decision = DecisionAllow
	b.emit(ev)
	return nil
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

// GrantRequest describes a grant to create.
type GrantRequest struct {
	// SecretRef is a secret ID or name.
	SecretRef   string
	Subject     Subject
	Constraints Constraints
	Scope       string
	// TTL is the grant's lifetime. Zero means DefaultGrantTTL unless
	// NoExpiry is set.
	TTL time.Duration
	// NoExpiry creates a grant that never expires. Reserved for the legacy
	// import, where imposing a TTL on secrets that previously had none
	// would break running projects at an unpredictable moment.
	NoExpiry bool
	Actor    string
}

// Grant authorises a subject to use a secret under constraints.
func (b *Broker) Grant(ctx context.Context, req GrantRequest) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	ev := Event{
		Action:      ActionGrant,
		Actor:       req.Actor,
		Subject:     req.Subject.String(),
		Constraints: req.Constraints.Summary(),
	}

	s, err := resolveSecret(b.store, req.SecretRef)
	if err != nil {
		return Grant{}, b.denyf(ev, ErrSecretNotFound, "resolve %q: %v", SafeRef(req.SecretRef), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind

	id, err := newID("grant")
	if err != nil {
		return Grant{}, err
	}
	now := b.now()
	g := Grant{
		ID:          id,
		SecretID:    s.ID,
		Scope:       strings.TrimSpace(req.Scope),
		Subject:     req.Subject,
		Constraints: req.Constraints,
		CreatedAt:   now,
		CreatedBy:   req.Actor,
	}
	if !req.NoExpiry {
		ttl := req.TTL
		if ttl <= 0 {
			ttl = DefaultGrantTTL
		}
		g.ExpiresAt = now.Add(ttl)
	}

	if err := g.Validate(s.Kind); err != nil {
		return Grant{}, b.denyErr(ev, err)
	}
	if err := b.store.PutGrant(g); err != nil {
		return Grant{}, b.denyf(ev, ErrInvalidGrant, "store grant: %v", err)
	}

	ev.GrantID = g.ID
	ev.ExpiresAt = g.ExpiresAt
	ev.Decision = DecisionAllow
	b.emit(ev)
	return g, nil
}

// GrantFilter narrows ListGrants.
type GrantFilter struct {
	// Subject, when set, keeps only grants whose subject renders to this
	// string (exact match on the "--to" syntax).
	Subject string
	// SecretRef, when set, keeps only grants for that secret.
	SecretRef string
	// ActiveOnly drops expired and revoked grants.
	ActiveOnly bool
}

// ListGrants returns grants matching the filter, newest first.
func (b *Broker) ListGrants(f GrantFilter) ([]Grant, error) {
	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, err
	}
	var secretID string
	if strings.TrimSpace(f.SecretRef) != "" {
		s, serr := resolveSecret(b.store, f.SecretRef)
		if serr != nil {
			return nil, serr
		}
		secretID = s.ID
	}

	now := b.now()
	out := grants[:0:0]
	for _, g := range grants {
		if secretID != "" && g.SecretID != secretID {
			continue
		}
		if f.Subject != "" && g.Subject.String() != f.Subject {
			continue
		}
		if f.ActiveOnly && !g.Active(now) {
			continue
		}
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

// Revoke marks a grant unusable. It takes effect on the next Lease or Renew:
// credentials already materialised into a running workload's tmpfs stay
// there until that lease expires, which is exactly the window the short
// lease TTL exists to bound.
func (b *Broker) Revoke(ctx context.Context, grantID, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ev := Event{Action: ActionRevoke, Actor: actor, GrantID: grantID}

	g, err := b.store.GetGrant(grantID)
	if err != nil {
		return b.denyf(ev, ErrGrantNotFound, "grant %q: %v", grantID, err)
	}
	ev.SecretID = g.SecretID
	ev.Subject = g.Subject.String()
	ev.Constraints = g.Constraints.Summary()
	if s, serr := b.store.GetSecret(g.SecretID); serr == nil {
		ev.SecretName, ev.Kind = s.Name, s.Kind
	}

	if !g.RevokedAt.IsZero() {
		// Idempotent: report success so a retry is not an error.
		ev.Decision = DecisionAllow
		ev.Reason = "already revoked at " + g.RevokedAt.UTC().Format(time.RFC3339)
		b.emit(ev)
		return nil
	}
	if err := b.store.RevokeGrant(grantID, b.now()); err != nil {
		return b.denyf(ev, ErrInvalidGrant, "revoke: %v", err)
	}

	ev.Decision = DecisionAllow
	b.emit(ev)
	return nil
}

// ---------------------------------------------------------------------------
// Leases
// ---------------------------------------------------------------------------

// Lease issues the credentials this executor may hold for this project.
//
// It returns only grants whose subject matches the requester and which are
// neither expired nor revoked, each minimized against its own constraints.
// An executor never sees the store, another project's grants, or any part of
// a payload that its constraints excluded.
//
// A requester with no matching grants gets an empty lease, not an error:
// "this project has no secrets" is a normal state and must not fail a run.
func (b *Broker) Lease(ctx context.Context, executorID, projectID string) (*Lease, error) {
	return b.LeaseFor(ctx, Requester{ExecutorID: executorID, ProjectID: projectID}, "")
}

// LeaseFor is Lease with executor labels (for SubjectLabel grants) and an
// explicit actor for the audit trail.
func (b *Broker) LeaseFor(ctx context.Context, r Requester, actor string) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if actor == "" {
		actor = r.ExecutorID
	}
	r.ProjectID = NormalizeProjectID(r.ProjectID)

	base := Event{
		Action:     ActionLease,
		Actor:      actor,
		ExecutorID: r.ExecutorID,
		ProjectID:  r.ProjectID,
	}

	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, b.denyf(base, ErrGrantNotFound, "list grants: %v", err)
	}
	now := b.now()

	var (
		materials []Material
		earliest  time.Time
	)
	for _, g := range grants {
		if !g.Subject.Matches(r) {
			continue
		}
		// From here on the grant was *aimed at* this requester, so every
		// outcome — including every refusal — is worth an audit row. A
		// silently skipped grant is how an operator ends up debugging "the
		// token is not arriving" with nothing to look at.
		ev := base
		ev.GrantID = g.ID
		ev.SecretID = g.SecretID
		ev.Subject = g.Subject.String()
		ev.Constraints = g.Constraints.Summary()
		ev.ExpiresAt = g.ExpiresAt

		if reason := g.DenyReason(now); reason != "" {
			sentinel := ErrGrantExpired
			if !g.RevokedAt.IsZero() {
				sentinel = ErrGrantRevoked
			}
			_ = b.denyf(ev, sentinel, "%s", reason)
			continue
		}

		s, serr := b.store.GetSecret(g.SecretID)
		if serr != nil {
			_ = b.denyf(ev, ErrSecretNotFound, "grant %s points at missing secret %s", g.ID, g.SecretID)
			continue
		}
		ev.SecretName, ev.Kind = s.Name, s.Kind

		mat, merr := b.materialFor(s, g)
		if merr != nil {
			_ = b.denyErr(ev, merr)
			continue
		}

		materials = append(materials, mat)
		ev.Decision = DecisionAllow
		ev.Reason = mat.Summary
		b.emit(ev)

		if !g.ExpiresAt.IsZero() && (earliest.IsZero() || g.ExpiresAt.Before(earliest)) {
			earliest = g.ExpiresAt
		}
	}

	id, err := newLeaseID()
	if err != nil {
		return nil, err
	}
	lease := &Lease{
		ID:         id,
		ExecutorID: r.ExecutorID,
		ProjectID:  r.ProjectID,
		IssuedAt:   now,
		ExpiresAt:  b.leaseDeadline(now, earliest),
		Materials:  materials,
	}

	b.mu.Lock()
	b.leases[lease.ID] = &leaseState{requester: r, actor: actor, expiresAt: lease.ExpiresAt}
	b.mu.Unlock()

	summary := base
	summary.LeaseID = lease.ID
	summary.Decision = DecisionAllow
	summary.ExpiresAt = lease.ExpiresAt
	summary.Reason = fmt.Sprintf("issued %d material(s): %s",
		len(materials), strings.Join(lease.SecretNames(), ","))
	b.emit(summary)

	return lease, nil
}

// leaseDeadline clamps the lease TTL to the earliest grant expiry, so a
// lease can never outlive the authority it was issued under.
func (b *Broker) leaseDeadline(now, earliestGrantExpiry time.Time) time.Time {
	deadline := now.Add(b.maxLeaseTTL)
	if !earliestGrantExpiry.IsZero() && earliestGrantExpiry.Before(deadline) {
		return earliestGrantExpiry
	}
	return deadline
}

// Renew re-issues a lease for the same requester.
//
// It deliberately re-evaluates every grant from the store rather than
// extending the existing materials. That is what makes revocation effective
// within one lease period: a grant revoked a minute ago is gone from the
// renewed lease even though the executor and project are unchanged.
func (b *Broker) Renew(ctx context.Context, leaseID string) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	b.mu.Unlock()
	if !ok {
		ev := Event{Action: ActionRenew, LeaseID: leaseID}
		return nil, b.denyf(ev, ErrLeaseNotFound, "unknown lease %q", leaseID)
	}

	renewed, err := b.LeaseFor(ctx, st.requester, st.actor)
	if err != nil {
		return nil, err
	}

	// The old lease ID is retired: a renewal issues a new one, so a stale
	// ID cannot be renewed indefinitely by something that captured it.
	b.mu.Lock()
	delete(b.leases, leaseID)
	b.mu.Unlock()

	b.emit(Event{
		Action:     ActionRenew,
		Actor:      st.actor,
		LeaseID:    renewed.ID,
		ExecutorID: renewed.ExecutorID,
		ProjectID:  renewed.ProjectID,
		Decision:   DecisionAllow,
		ExpiresAt:  renewed.ExpiresAt,
		Reason:     "renewed from " + leaseID,
	})
	return renewed, nil
}

// Release drops a lease's server-side record. Callers should Close the
// Mount as well; Release only stops the lease from being renewable.
func (b *Broker) Release(leaseID string) {
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	delete(b.leases, leaseID)
	b.mu.Unlock()
	if !ok {
		return
	}
	b.emit(Event{
		Action:     ActionRelease,
		Actor:      st.actor,
		LeaseID:    leaseID,
		ExecutorID: st.requester.ExecutorID,
		ProjectID:  st.requester.ProjectID,
		Decision:   DecisionAllow,
	})
}

// CheckRepoAccess is the in-process enforcement point for github grants: it
// reports whether this requester may act on repo, and audits the decision.
//
// cloop's own GitHub call sites (pkg/github, pkg/githubsync) route through
// here so that a repository outside the allowlist is refused before a
// request is made, rather than relying on the credential helper alone.
func (b *Broker) CheckRepoAccess(ctx context.Context, r Requester, repo, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	base := Event{
		Action:     ActionAccessCheck,
		Actor:      actor,
		ExecutorID: r.ExecutorID,
		ProjectID:  NormalizeProjectID(r.ProjectID),
	}
	grants, err := b.store.ListGrants()
	if err != nil {
		return b.denyf(base, ErrGrantNotFound, "list grants: %v", err)
	}

	now := b.now()
	var lastReason string
	for _, g := range grants {
		if !g.Subject.Matches(r) || !g.Active(now) {
			continue
		}
		s, serr := b.store.GetSecret(g.SecretID)
		if serr != nil || (s.Kind != KindGitHubPAT && s.Kind != KindGitHubApp) {
			continue
		}
		if cerr := g.Constraints.CheckRepo(repo); cerr != nil {
			lastReason = cerr.Error()
			continue
		}
		ev := base
		ev.GrantID, ev.SecretID, ev.SecretName, ev.Kind = g.ID, s.ID, s.Name, s.Kind
		ev.Constraints = g.Constraints.Summary()
		ev.Decision = DecisionAllow
		ev.Reason = "repository allowed: " + repo
		b.emit(ev)
		return nil
	}
	if lastReason == "" {
		lastReason = "no active github grant matches this subject"
	}
	return b.denyf(base, ErrRepoDenied, "%s", lastReason)
}

// zero overwrites a plaintext buffer in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// jsonUnmarshalEnv decodes an env secret's payload. Two shapes are accepted:
// a JSON object of key→value, and a bare value, which is treated as the
// single variable named after the secret (which is how every entry imported
// from the legacy flat store arrives).
func jsonUnmarshalEnv(payload []byte, secretName string) map[string]string {
	trimmed := strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]string
		if err := json.Unmarshal(payload, &m); err == nil {
			return m
		}
	}
	return map[string]string{envKeyFromName(secretName): trimmed}
}

// envKeyFromName derives an environment variable name from a secret name,
// upper-casing it and replacing separators. ValidateName has already limited
// the input charset, so the result is always a valid variable name.
func envKeyFromName(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "CLOOP_SECRET"
	}
	return out
}

// errIsDenial reports whether err is one of the denial sentinels, used to
// pick the right severity when logging a lease outcome.
func errIsDenial(err error) bool {
	return errors.Is(err, ErrRepoDenied) ||
		errors.Is(err, ErrHostDenied) ||
		errors.Is(err, ErrNamespaceDenied) ||
		errors.Is(err, ErrGrantExpired) ||
		errors.Is(err, ErrGrantRevoked) ||
		errors.Is(err, ErrMinimizedEmpty)
}
