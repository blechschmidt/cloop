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

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
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
	// appMinter turns a stored GitHub App credential into a short-lived,
	// repository-scoped installation token. See githubapp.go.
	appMinter *githubAppMinter

	// GitGuard, when set, takes custody of a GitHub PAT so the sandbox
	// receives a git-proxy session instead of the token. It turns the
	// repository allowlist from something the workload is asked to respect
	// into something it cannot exceed. See gitguard.go.
	//
	// Exported and settable after construction because the proxy it fronts is
	// started by pkg/ui alongside the hub, later than the broker and from a
	// layer this package must not import.
	GitGuard GitGuard

	// KubeGuard, when set, takes custody of a kubeconfig so the sandbox
	// receives a monitor session instead of the cluster credential. It turns
	// the namespace allowlist from a client-side default into a bound, and it
	// is the only way a kubeconfig grant's verbs mean anything at all. See
	// kubeguard.go.
	//
	// Exported and settable after construction for the same reason GitGuard
	// is: the monitor it fronts is started by pkg/ui alongside the hub, later
	// than the broker and from a layer this package must not import.
	KubeGuard KubeGuard

	mu     sync.Mutex
	leases map[string]*leaseState
	// minted holds the GitHub App installation tokens this broker is
	// responsible for destroying, keyed by lease ID: one slot per App grant
	// the lease carries, holding its current token and any it superseded
	// (apprefresh.go).
	//
	// It is the difference between revocation and forgetting. Every other
	// credential kind is minimized from something the operator already holds,
	// so withdrawing it means wiping a file; an App token is a credential this
	// hub brought into existence at GitHub, and nothing but a DELETE takes it
	// back. Losing this map would leave live tokens with no owner.
	minted map[string][]*appTokenSlot
	// slotRestoreMu serialises restoring a lease's App-token slots, so a
	// retry and the request that needs the slots cannot both add them.
	slotRestoreMu sync.Mutex
	// recordMu serialises rewrites of a held lease's grants (DropLeaseGrant),
	// each a read of the record and a conditional write of it.
	recordMu sync.Mutex

	clock       func() time.Time
	maxLeaseTTL time.Duration

	// leaseHolder, when set, is the hub process this broker issues and takes
	// over leases for, and makes every non-empty lease durable under that name
	// (leaserecord.go, Task 20382). Empty — every CLI and test broker — keeps
	// leases in memory only, as before.
	leaseHolder string
}

// appToken is one GitHub App installation token the hub minted, remembered for
// exactly as long as it takes to destroy it.
//
// The token field is a credential and is why this type is unexported with no
// accessors: it must reach the revocation call and nothing else.
type appToken struct {
	grantID    string
	secretID   string
	secretName string
	baseURL    string
	token      string
	expiresAt  time.Time
}

// leaseState remembers what a lease was issued for, so Renew can re-evaluate
// the same subject against current grants instead of trusting the old
// materials.
type leaseState struct {
	requester Requester
	actor     string
	expiresAt time.Time
	// kinds are the credential kinds this lease carried, kept so an
	// expiring lease can be counted by kind after its materials are gone.
	kinds []Kind
	// grantIDs are the grants whose material the lease carries. Extend
	// re-checks exactly these, so a lease is never kept alive by a grant it
	// does not hold, nor past one it does that was revoked.
	grantIDs []string
	// recorded reports that the lease has a durable record held by this
	// broker's leaseHolder, which Extend and Release must keep in step.
	recorded bool
	// slotsPending: Restore took the lease over but could not take over or
	// read its App-token slot records just then. They are restored before a
	// slot of the lease is next needed (appslots.go, Task 20383).
	slotsPending *pendingSlots
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

// WithoutKey builds a broker that can administer the store — list, revoke,
// delete, withdraw — and can neither seal nor open a payload (Task 20400).
//
// It exists for offboarding from a shell. Destroying a departed user's
// personal secrets needs no key: it removes rows, it never reads them. A
// broker that insisted on CLOOP_SECRET_KEY anyway would make the command fail
// in exactly the emergency it is for, on a host whose operator shell does not
// carry the hub's sealing passphrase. Every operation that would touch
// material — Mint, Lease, anything that opens a payload — fails with ErrNoKey,
// so a keyless broker cannot be mistaken for a working one.
func WithoutKey() Option {
	return func(b *Broker) { b.seal = lockedSealer{} }
}

// lockedSealer is the sealer of a WithoutKey broker.
type lockedSealer struct{}

func (lockedSealer) SealFor(string, []byte) (Envelope, error) {
	return Envelope{}, fmt.Errorf("%w: this broker administers the store and holds no key to seal with", ErrNoKey)
}

func (lockedSealer) OpenEnvelope(string, Envelope) ([]byte, error) {
	return nil, fmt.Errorf("%w: this broker administers the store and holds no key to open payloads with", ErrNoKey)
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

// WithGitHubApp supplies the GitHub API client used to mint, enumerate and
// destroy App installation tokens.
//
// Without it a broker talks to api.github.com. Tests substitute a fake so the
// suite is hermetic, and a hub with no outbound access can substitute one that
// refuses — which denies github_app grants rather than falling back to
// delivering the private key, because there is no safe fallback.
func WithGitHubApp(api GitHubAppAPI) Option {
	return func(b *Broker) {
		if api != nil {
			b.appMinter = newGitHubAppMinter(api, nil)
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
		minted:      make(map[string][]*appTokenSlot),
		clock:       time.Now,
		maxLeaseTTL: DefaultMaxLeaseTTL,
	}
	for _, opt := range opts {
		opt(b)
	}
	if b.appMinter == nil {
		b.appMinter = newGitHubAppMinter(defaultGitHubAppAPI, nil)
	}
	// The minter shares the broker's clock so a test that advances time to
	// exercise lease expiry sees the same "now" on both sides; a token whose
	// freshness was judged against the wall clock while its lease was judged
	// against a fake one is a test that proves nothing.
	b.appMinter.clock = b.clock
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
	// Owner, when set, mints a *personal* secret belonging to that identity
	// rather than a shared one belonging to the organisation (Task 20275).
	// See ownership.go for everything that changes as a result.
	Owner string
	// Personal asserts that this mint is meant to produce a personal secret.
	//
	// Redundant with a non-empty Owner in the success case, and that is the
	// point: it separates "mint this for alice@corp" from "mint this for
	// whatever identity the caller happened to resolve", so a handler whose
	// identity lookup silently returned "" produces ErrOwnerRequired instead
	// of quietly minting the user's private credential as an organisation-wide
	// one that every maintainer can then spend.
	Personal bool
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
	owner := NormalizeOwner(req.Owner)
	if req.Personal && owner == "" {
		return Secret{}, b.denyf(ev, ErrOwnerRequired,
			"a personal secret was requested but no owner identity resolved")
	}
	// The mirror image, and the one that actually bit (Task 20323). Owner and
	// Personal are documented as redundant in the success case, so a caller
	// that sets one and not the other has contradicted itself — and until this
	// check existed, Mint resolved the contradiction silently in favour of
	// Owner. A handler that passed the signed-in identity alongside a
	// shared-secret request therefore minted a *personal* secret: the hub-wide
	// GitHub App connected from the Settings dialog came out owned by whoever
	// happened to be logged in, invisible to every other maintainer.
	//
	// Refused rather than resolved in either direction. Clearing the owner
	// would widen somebody's private credential into the organisation's on the
	// strength of a flag a handler got wrong, which is the one direction that
	// cannot be undone by re-minting; keeping it is what already went wrong.
	if !req.Personal && owner != "" {
		return Secret{}, b.denyf(ev, ErrInvalidSecret,
			"a shared secret was requested but an owner (%s) was supplied; "+
				"set Personal to mint it for that identity, or omit Owner to mint it "+
				"for the organisation", owner)
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
		Owner:      owner,
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
	return b.DeleteSecretBecause(ctx, ref, actor, CauseDeleted, "")
}

// DeleteSecretBecause is DeleteSecret with a cause and a reason (Task 20400).
//
// The reason lands on the secret.delete audit row and on the tombstone; the
// cause is what a later refusal tells the project that lost the credential —
// "deleted", or "destroyed when its owner was offboarded". The store scrubs
// the sealed columns before it deletes the row (statedb.deleteBrokerSecret),
// so the material is overwritten rather than merely unlinked.
func (b *Broker) DeleteSecretBecause(ctx context.Context, ref, actor string, cause DeletionCause, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ev := Event{Action: ActionDeleteSec, Actor: actor}
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return b.denyf(ev, ErrSecretNotFound, "resolve %q: %v", SafeRef(ref), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind
	if cause == "" {
		cause = CauseDeleted
	}

	grants, err := b.store.ListGrants()
	if err != nil {
		return b.denyf(ev, ErrGrantNotFound, "list grants: %v", err)
	}
	now := b.now()
	var revoked []GrantRevocation
	revokedFor := "secret " + s.Name + " deleted"
	grantCause := RevokedSecretDeleted
	if cause == CauseOffboarded {
		revokedFor = "secret " + s.Name + " destroyed when its owner was offboarded"
		grantCause = RevokedOwnerOffboarded
	}
	for _, g := range grants {
		if g.SecretID == s.ID && g.RevokedAt.IsZero() {
			// A grant that had already lapsed lost nothing to this deletion:
			// it is stamped, so no listing reads it as live, but with no
			// cause, so no project is told it lost something it no longer had.
			cause := grantCause
			if !g.Active(now) {
				cause = ""
			}
			if rerr := b.revokeStored(g.ID, now, cause); rerr != nil {
				return b.denyf(ev, ErrInvalidGrant, "revoke dependent grant %s: %v", g.ID, rerr)
			}
			revoked = append(revoked, GrantRevocation{
				GrantID: g.ID, SecretID: s.ID, SecretName: s.Name, Kind: s.Kind, Subject: g.Subject,
				Actor: actor, Cause: cause, Reason: revokedFor, At: now, ControlPlane: b.location(),
			})
			// Deleting the App credential does not reach the tokens already
			// minted from it — those live at GitHub, not here — so they are
			// destroyed with the grants that produced them. Otherwise deleting
			// a secret would be the one withdrawal that leaves live credentials
			// behind, which is the opposite of what an operator deleting a
			// credential during an incident is asking for.
			b.destroyGrantTokens(ctx, g.ID, revokedFor)
		}
	}
	if ts, ok := b.store.(TombstoneStore); ok {
		err = ts.DeleteSecretTombstoned(s.ID, Tombstone{
			SecretID: s.ID, Name: s.Name, Kind: s.Kind, Owner: s.Owner,
			DeletedAt: now, DeletedBy: actor, Cause: cause,
			Reason: RedactString(strings.TrimSpace(reason)),
		})
	} else {
		err = b.store.DeleteSecret(s.ID)
	}
	if err != nil {
		return b.denyf(ev, ErrSecretNotFound, "delete: %v", err)
	}

	ev.Decision = DecisionAllow
	ev.Reason = deletionReason(cause, reason)
	b.emit(ev)
	// The workloads holding the grants this deletion revoked give the material
	// back now (Task 20403), as they would for a grant revoked on its own.
	b.announceRevoked(ctx, revoked...)
	return nil
}

// deletionReason is the secret.delete row's reason: empty for an ordinary
// delete that gave none, as before, and otherwise the cause and what the
// deleter wrote.
func deletionReason(cause DeletionCause, reason string) string {
	reason = strings.TrimSpace(reason)
	switch {
	case cause == CauseOffboarded && reason != "":
		return "owner offboarded: " + reason
	case cause == CauseOffboarded:
		return "owner offboarded"
	default:
		return reason
	}
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
	// Viewer is the identity the grant is created on behalf of. It gates
	// personal secrets: only their owner may hand one to an executor
	// (Task 20275). The zero value sees no personal secret at all, so a
	// caller that forgets it is refused rather than privileged.
	//
	// Shared secrets ignore it entirely, which is what keeps every existing
	// call site — the CLI, the legacy import, the approval path — correct
	// without change.
	Viewer Viewer
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

	// Ownership is checked before anything is written, and before the subject
	// is validated, so that a refusal over somebody else's credential is
	// recorded as exactly that rather than as whatever the subject happened to
	// be malformed into.
	if err := checkSpendable(s, req.Viewer); err != nil {
		return Grant{}, b.denyErr(ev, err)
	}
	// A personal credential granted to "every project" or "every executor" is
	// no longer personal: the next run by anyone redeems it. Refused rather
	// than silently narrowed, because narrowing would guess which project the
	// owner meant.
	if s.Personal() && req.Subject.Wildcard() {
		return Grant{}, b.denyf(ev, ErrPersonalWildcard,
			"%s is owned by %s and must name one project or executor, not %q",
			s.Name, s.Owner, req.Subject.String())
	}

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
		Owner:       s.Owner,
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

// Revoke marks a grant unusable: the next Lease or Renew leaves it out, and the
// subscribers this process registered with OnGrantRevoked — the hub — take its
// material back from the workloads already holding it (Task 20403). In a
// process with no subscriber, a CLI, nothing reaches those workloads from here:
// the caller announces the revocation to the running hub, and failing that the
// lease lapses within its period, as before.
func (b *Broker) Revoke(ctx context.Context, grantID, actor string) error {
	return b.RevokeBecause(ctx, grantID, actor, "")
}

// RevokeBecause is Revoke with a reason on its secret.revoke row (Task
// 20400): an offboarding revokes the grants over the departed person's
// secrets, and "revoked" alone does not say that is why.
func (b *Broker) RevokeBecause(ctx context.Context, grantID, actor, reason string) error {
	return b.RevokeWithCause(ctx, grantID, actor, "", reason)
}

// RevokeWithCause is RevokeBecause recording on the grant why it was revoked
// (Task 20400). Offboarding revokes with RevokedOwnerOffboarded, which is what
// lets the project's next lease tell it the grant went with its owner — even
// when the secret is kept under a legal hold, or destroyed days later.
func (b *Broker) RevokeWithCause(ctx context.Context, grantID, actor string, cause RevocationCause, reason string) error {
	_, _, err := b.RevokeGrant(ctx, RevokeGrantRequest{GrantID: grantID, Actor: actor, Cause: cause, Reason: reason})
	return err
}

// revokeStored stamps a grant revoked, with its cause where the store keeps
// one.
func (b *Broker) revokeStored(grantID string, at time.Time, cause RevocationCause) error {
	if cr, ok := b.store.(CausedRevoker); ok {
		return cr.RevokeGrantWithCause(grantID, at, cause)
	}
	return b.store.RevokeGrant(grantID, at)
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
		// Stamped on the base event rather than only on the success path, so a
		// *denied* lease is correlatable too. "This run asked for a credential
		// and was refused" is the more interesting of the two rows during an
		// incident, and a success-only stamp is exactly what would lose it.
		RunID: r.RunID,
	}

	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, b.denyf(base, ErrGrantNotFound, "list grants: %v", err)
	}
	now := b.now()

	// The lease's id exists before its materials do (Task 20383), so a guard
	// minting a proxy session for one of them records which lease the session
	// stands on: that is how the process taking the lease over with its run
	// finds the sessions to restore. Drawn before anything is minted, so a
	// failure here leaves no App token behind.
	id, err := newLeaseID()
	if err != nil {
		return nil, err
	}

	var (
		materials []Material
		earliest  time.Time
		rec       mints
		refused   []RefusedCredential
	)
	// refuse records a grant the project lost to something done elsewhere —
	// its secret destroyed, or its owner offboarded — on the audit row, by
	// name rather than by id, and, when tell is set, on the lease, for the
	// dispatcher to show the project (Task 20400). A shared project granted a
	// colleague's personal credential finds out this way, on its next run,
	// that the colleague was offboarded.
	refuse := func(ev Event, g Grant, sentinel error, reason, name string, kind Kind, owner string,
		deletedAt time.Time, tell bool) {
		ev.SecretName, ev.Kind = name, kind
		_ = b.denyf(ev, sentinel, "%s", reason)
		if tell {
			refused = append(refused, RefusedCredential{
				GrantID: g.ID, SecretID: g.SecretID, SecretName: name, Kind: kind,
				Owner: owner, DeletedAt: deletedAt, Reason: reason,
			})
		}
	}
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
			revoked := !g.RevokedAt.IsZero()
			if revoked {
				sentinel = ErrGrantRevoked
			}
			// Told only when the cause on the grant says the project lost it
			// to an offboarding or a deletion. One somebody revoked by hand,
			// or one that had simply expired, its owner already knows about,
			// and naming it on every run would bury the grants that matter.
			tell := revoked && g.RevokedCause.tellsTheProject()
			if t, why, gone := b.deletedSecretRefusal(g); gone {
				// Deleting a secret revokes every grant over it, so a revoked
				// grant is the usual shape a destroyed credential takes here.
				refuse(ev, g, sentinel, reason+": "+why, t.Name, t.Kind, t.Owner, t.DeletedAt, tell)
				continue
			}
			if tell && g.RevokedCause == RevokedOwnerOffboarded {
				// Its owner left and the secret was kept under a legal hold.
				if s, serr := b.store.GetSecret(g.SecretID); serr == nil {
					refuse(ev, g, sentinel, reason+": "+withdrawnDescription(s, g), s.Name, s.Kind, s.Owner,
						time.Time{}, true)
					continue
				}
			}
			_ = b.denyf(ev, sentinel, "%s", reason)
			continue
		}

		s, serr := b.store.GetSecret(g.SecretID)
		if serr != nil {
			if t, why, gone := b.deletedSecretRefusal(g); gone {
				refuse(ev, g, ErrSecretDeleted, "grant "+g.ID+" spent a secret that no longer exists: "+why,
					t.Name, t.Kind, t.Owner, t.DeletedAt, true)
				continue
			}
			reason := fmt.Sprintf("grant %s points at missing secret %s", g.ID, g.SecretID)
			refuse(ev, g, ErrSecretNotFound, reason, "", "", g.Owner, time.Time{}, true)
			continue
		}
		ev.SecretName, ev.Kind = s.Name, s.Kind

		// After the secret is resolved, so the denial row names the credential
		// the run went without, and before anything opens its payload.
		if why, ok := r.Withhold[g.ID]; ok {
			_ = b.denyf(ev, ErrGrantWithheld, "%s", why)
			continue
		}

		mat, merr := b.materialFor(ctx, s, g, r, actor, id, &rec)
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

	lease := &Lease{
		ID:         id,
		ExecutorID: r.ExecutorID,
		ProjectID:  r.ProjectID,
		RunID:      r.RunID,
		IssuedAt:   now,
		ExpiresAt:  b.leaseDeadline(now, earliest),
		Materials:  materials,
		Refused:    refused,
	}

	// Now that the lease has an ID, record which approved requests it redeemed
	// (Task 20271). After the ID is minted rather than inside the loop above,
	// because a use row keyed by a lease that failed to come into existence
	// would tell an approver their grant was exercised when it was not.
	for _, mat := range materials {
		b.recordGrantUse(mat.GrantID, id, r, now)
	}

	kinds := lease.Kinds()
	grantIDs := make([]string, 0, len(materials))
	for _, mat := range materials {
		grantIDs = append(grantIDs, mat.GrantID)
	}
	st := &leaseState{
		requester: r, actor: actor, expiresAt: lease.ExpiresAt, kinds: kinds,
		grantIDs: grantIDs,
	}
	// Durable before the lease is handed out, so a hub that dies the moment
	// it returns leaves a record its successor can take over or sweep. A lease
	// that carries nothing is released by its caller at once and has nothing
	// to outlive anyone.
	var recordErr error
	if len(materials) > 0 {
		st.recorded, recordErr = b.recordLease(LeaseRecord{
			ID: lease.ID, Requester: r, Actor: actor, IssuedAt: lease.IssuedAt,
			ExpiresAt: lease.ExpiresAt, Kinds: kinds, GrantIDs: grantIDs,
		})
	}
	b.mu.Lock()
	b.leases[lease.ID] = st
	if len(rec.slots) > 0 {
		// The lease ID exists only now, so the slots learn it here — before
		// the lease is returned, and so before anything could ask one to
		// refresh: a refresh row has to name the lease it renewed.
		for _, slot := range rec.slots {
			slot.leaseID = lease.ID
		}
		b.minted[lease.ID] = rec.slots
	}
	b.mu.Unlock()
	// The App tokens' slots are recorded with the lease (Task 20383), so the
	// process that takes it over re-mints at the same scope rather than
	// letting each token die at its hour.
	if st.recorded {
		if err := b.recordSlots(rec.slots, tokenFileNames(materials)); err != nil {
			if recordErr == nil {
				recordErr = err
			} else {
				recordErr = errors.Join(recordErr, err)
			}
		}
	}
	for _, k := range kinds {
		hubmetrics.LeaseEvents.Inc(string(k), hubmetrics.LeaseIssued)
	}

	summary := base
	summary.LeaseID = lease.ID
	summary.Decision = DecisionAllow
	summary.ExpiresAt = lease.ExpiresAt
	summary.Reason = fmt.Sprintf("issued %d material(s): %s",
		len(materials), strings.Join(lease.SecretNames(), ","))
	if recordErr != nil {
		// The lease works; what is lost is that it can outlive this process.
		// Said on the lease's own row, where an operator chasing a credential
		// nobody released after a restart will look.
		summary.Reason += "; not recorded durably, so it will not be taken over if this hub process stops: " +
			recordErr.Error()
	}
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

	// And the credentials it carried are retired with it. The renewal above
	// already minted a fresh installation token with a full hour ahead of it,
	// which is what "refresh before expiry" means here: the workload never
	// holds a token close to its expiry, because each lease period replaces it.
	// Destroying the previous one is what stops a renewed run leaving a trail
	// of live tokens behind, one per lease period.
	b.destroyLeaseTokens(ctx, leaseID, "lease renewed as "+renewed.ID)

	// Renewal is counted in addition to the issue that LeaseFor already
	// counted, not instead of it: cloop_secret_lease_events_total{event="issued"}
	// is "how many leases came into existence", which a renewal genuinely
	// does. Subtracting here would make the issued series stop matching the
	// number of distinct lease IDs the audit trail shows.
	for _, k := range renewed.Kinds() {
		hubmetrics.LeaseEvents.Inc(string(k), hubmetrics.LeaseRenewed)
	}

	b.emit(Event{
		Action:     ActionRenew,
		Actor:      st.actor,
		LeaseID:    renewed.ID,
		ExecutorID: renewed.ExecutorID,
		ProjectID:  renewed.ProjectID,
		RunID:      renewed.RunID,
		Decision:   DecisionAllow,
		ExpiresAt:  renewed.ExpiresAt,
		Reason:     "renewed from " + leaseID,
	})
	return renewed, nil
}

// Extend keeps a live lease valid for another lease period, in place: same ID,
// same materials, a later deadline.
//
// It is the renewal a dispatched workload can actually use (Task 20349).
// Renew re-issues — a new lease ID, a fresh GitHub App installation token, a
// fresh git-proxy session — and destroys the old lease's tokens, which is
// right for a caller that can hand the workload the new material and wrong for
// one that cannot: a sandbox holding a token in its environment or in a file
// the hub cannot rewrite would lose it the moment Renew returned. Nothing on
// the dispatch path could re-deliver, so nothing renewed, and every run's lease
// lapsed fifteen minutes in — its files scrubbed, its git proxy sessions
// closed, its App token destroyed at GitHub — however long the run was.
//
// What Extend keeps from Renew is the property the short TTL exists for: every
// grant the lease carries is re-read from the store and re-checked, so a grant
// revoked or expired since the lease was issued refuses the extension, the
// lease lapses on its own schedule, and the janitor takes the material back —
// a revocation still lands within one lease period. The new deadline is
// clamped to the earliest grant expiry exactly as at issue.
//
// It does not re-render anything. A secret whose value an operator re-minted
// reaches the next dispatch, not this one. An App token keeps the hour GitHub
// gave it, and is replaced before that hour runs out by a refresh at the same
// scope (apprefresh.go, Task 20375) — the one credential a lease carries that
// the hub can renew without re-issuing the lease.
func (b *Broker) Extend(ctx context.Context, leaseID string) (time.Time, error) {
	ev := Event{Action: ActionRenew, LeaseID: leaseID}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	var (
		requester Requester
		actor     string
		expiresAt time.Time
		grantIDs  []string
		recorded  bool
	)
	if ok {
		requester, actor, expiresAt = st.requester, st.actor, st.expiresAt
		grantIDs = append([]string(nil), st.grantIDs...)
		recorded = st.recorded
	}
	b.mu.Unlock()
	if !ok {
		return time.Time{}, b.denyf(ev, ErrLeaseNotFound, "unknown lease %q", leaseID)
	}
	ev.Actor = actor
	ev.ExecutorID = requester.ExecutorID
	ev.ProjectID = requester.ProjectID
	ev.RunID = requester.RunID

	now := b.now()
	if !now.Before(expiresAt) {
		// A lapsed lease stays lapsed. The janitor may already be taking its
		// material back, and extending it here would race that sweep into
		// leaving a credential with a workload the hub has written off.
		return time.Time{}, b.denyf(ev, ErrLeaseExpired,
			"lease %s lapsed at %s and cannot be extended", leaseID, expiresAt.UTC().Format(time.RFC3339))
	}

	earliest, err := b.recheckGrants(ev, leaseID, requester, grantIDs, now)
	if err != nil {
		return time.Time{}, err
	}

	deadline := b.leaseDeadline(now, earliest)
	if deadline.Before(expiresAt) {
		deadline = expiresAt
	}
	if recorded {
		// The durable record first, and only if this process still holds it:
		// a lease the process adopting its run took over (Task 20382) is that
		// process's to extend, and one this process kept extending in memory
		// would be a credential two hub processes both believe they hold.
		if moved, rerr := b.extendRecord(leaseID, deadline); moved {
			b.mu.Lock()
			delete(b.leases, leaseID)
			b.mu.Unlock()
			return time.Time{}, b.denyf(ev, ErrLeaseMoved,
				"lease %s is held by another hub process now, which keeps it alive and releases it", leaseID)
		} else if rerr != nil {
			// Extended here all the same; what is lost is that a successor
			// taking the lease over would see the earlier deadline.
			ev.Reason = "durable record not updated: " + rerr.Error()
		}
	}
	b.mu.Lock()
	st, ok = b.leases[leaseID]
	if ok && deadline.After(st.expiresAt) {
		st.expiresAt = deadline
	}
	if ok {
		deadline = st.expiresAt
	}
	b.mu.Unlock()
	if !ok {
		// Released while the grants were being read. Nothing to keep alive,
		// and recreating the record would resurrect a lease its holder gave up.
		return time.Time{}, b.denyf(ev, ErrLeaseNotFound, "lease %s was released", leaseID)
	}

	ev.Decision = DecisionAllow
	ev.ExpiresAt = deadline
	if ev.Reason != "" {
		ev.Reason = "extended in place while its run is live; " + ev.Reason
	} else {
		ev.Reason = "extended in place while its run is live"
	}
	b.emit(ev)
	return deadline, nil
}

// recheckGrants applies to every grant a live lease carries the checks its
// issue made — not revoked, not expired, still issued to this requester, its
// secret still there — and returns the earliest grant expiry, which bounds the
// lease. A superseded grant is checked, and bounded, by the successor it stands
// on (Task 20403). A failure is a denial, emitted on ev.
func (b *Broker) recheckGrants(ev Event, leaseID string, requester Requester, grantIDs []string, now time.Time) (time.Time, error) {
	var earliest time.Time
	for _, id := range grantIDs {
		authority, sentinel, why, _ := b.standing(id, requester, now)
		if sentinel != nil {
			ev.GrantID = id
			return time.Time{}, b.denyf(ev, sentinel, "lease %s holds grant %s%s", leaseID, id, why)
		}
		if !authority.ExpiresAt.IsZero() && (earliest.IsZero() || authority.ExpiresAt.Before(earliest)) {
			earliest = authority.ExpiresAt
		}
	}
	return earliest, nil
}

// Release drops a lease's server-side record and destroys any credential the
// hub minted for it. Callers should Close the Mount as well; wiping the lease
// directory is what removes the copy on disk, and this is what removes the one
// at GitHub.
//
// It takes no context because every caller is an executor cleanup path that has
// already finished its work. The revocation gets its own bounded deadline
// instead (appRevokeTimeout), so a hub cannot block on api.github.com while a
// task teardown waits behind it.
func (b *Broker) Release(leaseID string) {
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	delete(b.leases, leaseID)
	b.mu.Unlock()

	if ok && st.recorded && b.dropRecord(leaseID) {
		// Another hub process took the lease over with the run it was issued
		// for (Task 20382). The release is that process's to make, when the
		// run ends; making it here would end a credential a live run holds.
		return
	}

	// Before the early return: a lease whose state record is already gone —
	// swept, or released twice — may still have tokens to destroy, and
	// returning here would strand them.
	b.destroyLeaseTokens(context.Background(), leaseID, "lease released")

	if !ok {
		return
	}
	for _, k := range st.kinds {
		hubmetrics.LeaseEvents.Inc(string(k), hubmetrics.LeaseRevoked)
	}
	b.emit(Event{
		Action:     ActionRelease,
		Actor:      st.actor,
		LeaseID:    leaseID,
		ExecutorID: st.requester.ExecutorID,
		ProjectID:  st.requester.ProjectID,
		RunID:      st.requester.RunID,
		Decision:   DecisionAllow,
	})
}

// SweepExpired drops lease records whose TTL has passed and reports what is
// left, tallied by credential kind.
//
// It exists for two reasons that happen to have the same implementation.
//
// The metrics reason: cloop_secret_leases_live has to mean "leases that would
// be honoured right now", and the only way to know that is to apply the same
// expiry test the broker applies. Counting map entries would report leases
// that expired hours ago as live.
//
// The correctness reason: before this, a lease record was removed only by
// Renew or Release. A lease that simply expired — the ordinary end of a task
// that was killed, or an executor that went away without releasing — left its
// leaseState in the map for the lifetime of the process. On a busy hub that is
// an unbounded map keyed by lease ID, which is to say a slow leak that a
// tenant can drive. Expiry now collects them.
//
// The returned maps are (expired, live) counts by kind.
func (b *Broker) SweepExpired() (expired, live map[Kind]int) {
	expired = make(map[Kind]int)
	live = make(map[Kind]int)
	now := b.now()

	var lapsed []string
	b.mu.Lock()
	for id, st := range b.leases {
		if now.Before(st.expiresAt) {
			for _, k := range st.kinds {
				live[k]++
			}
			continue
		}
		delete(b.leases, id)
		lapsed = append(lapsed, id)
		for _, k := range st.kinds {
			expired[k]++
		}
	}
	b.mu.Unlock()

	// An expired lease is the ordinary end of a task that was killed, or of an
	// executor that went away without releasing — which is exactly the case
	// where a minted App token would otherwise survive with nothing pointing at
	// it. Destroy outside the lock: these are network calls.
	for _, id := range lapsed {
		b.destroyLeaseTokens(context.Background(), id, "lease expired")
	}

	for k, n := range expired {
		hubmetrics.LeaseEvents.Add(float64(n), string(k), hubmetrics.LeaseExpired)
	}
	return expired, live
}

// ---------------------------------------------------------------------------
// GitHub App token destruction
// ---------------------------------------------------------------------------

// destroyLeaseTokens revokes every App installation token minted for leaseID.
//
// Idempotent and cheap when there is nothing to do, which matters because
// Release is on every task-teardown path: a lease with no App material takes
// one map lookup and returns.
func (b *Broker) destroyLeaseTokens(ctx context.Context, leaseID, reason string) {
	b.mu.Lock()
	slots := b.minted[leaseID]
	delete(b.minted, leaseID)
	var tokens []appToken
	for _, slot := range slots {
		// Ended under the lock, so a refresh in flight on another goroutine
		// finds the slot ended when it comes back from GitHub and destroys
		// what it minted instead of installing it.
		tokens = append(tokens, slot.end()...)
	}
	b.mu.Unlock()
	if len(slots) > 0 {
		b.forgetSlotRecords(leaseID)
	}
	if len(tokens) == 0 {
		return
	}
	b.destroyAppTokens(ctx, tokens, reason)
}

// destroyGrantTokens revokes every App token minted under grantID, across every
// lease still holding one.
//
// This is what makes Revoke mean "the credential is dead" rather than "the next
// renewal will not include it". For every other kind the distinction is bounded
// by the lease TTL and that is the deal the short TTL buys; for an App token the
// hub is the party that created the credential, so it is the party that can end
// it now.
func (b *Broker) destroyGrantTokens(ctx context.Context, grantID, reason string) {
	if strings.TrimSpace(grantID) == "" {
		return
	}
	var (
		doomed []appToken
		leases []string
	)
	b.mu.Lock()
	for leaseID, slots := range b.minted {
		var keep []*appTokenSlot
		for _, slot := range slots {
			if slot.grantID == grantID {
				// Ended, not merely dropped: a refresh of this slot must find
				// it ended rather than renew a grant that was just withdrawn.
				doomed = append(doomed, slot.end()...)
				leases = append(leases, leaseID)
				continue
			}
			keep = append(keep, slot)
		}
		if len(keep) == 0 {
			delete(b.minted, leaseID)
		} else {
			b.minted[leaseID] = keep
		}
	}
	b.mu.Unlock()
	for _, leaseID := range leases {
		b.forgetSlotRecords(leaseID, grantID)
	}
	b.destroyAppTokens(ctx, doomed, reason)
}

// destroyAppTokens calls DELETE /installation/token for each token and audits
// the outcome.
//
// A failure is emitted as a denial rather than swallowed: the token outlives the
// lease that carried it until GitHub's own expiry, and an operator responding to
// an incident needs to know which credential is still live and for how long. The
// error is not returned because every caller is a cleanup path with nothing
// useful to do with it — the audit row is the report.
func (b *Broker) destroyAppTokens(ctx context.Context, tokens []appToken, reason string) {
	if len(tokens) == 0 || b.appMinter == nil || b.appMinter.api == nil {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appRevokeTimeout)
	defer cancel()

	for _, t := range tokens {
		ev := Event{
			Action:     ActionAppTokenDestroy,
			GrantID:    t.grantID,
			SecretID:   t.secretID,
			SecretName: t.secretName,
			Kind:       KindGitHubApp,
			ExpiresAt:  t.expiresAt,
		}
		if err := b.appMinter.api.RevokeInstallationToken(rctx, t.baseURL, t.token); err != nil {
			_ = b.denyf(ev, ErrGitHubAppRevoke,
				"%s: installation token could not be destroyed and stays live until %s: %v",
				reason, t.expiresAt.UTC().Format(time.RFC3339), err)
			continue
		}
		ev.Decision = DecisionAllow
		ev.Reason = reason + ": installation token destroyed at GitHub"
		b.emit(ev)
	}
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
		errors.Is(err, ErrGrantWithheld) ||
		errors.Is(err, ErrMinimizedEmpty)
}
