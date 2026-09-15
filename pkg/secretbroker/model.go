// Package secretbroker brokers scoped, time-limited credential grants to
// execution backends.
//
// The problem it replaces: pkg/secret is a flat key→value map with an
// all-or-nothing EnvLines(). Every workload that got any secret got all of
// them, forever, as plain environment variables. That is workable when the
// only executor is "a child process of the control plane owned by the same
// person who wrote the secrets down". It is not workable once workloads run
// in containers, on remote edge devices, and on behalf of different tenants:
// a single leaked GitHub PAT then reaches every repository the operator can
// touch, from a machine the operator does not control.
//
// The model here is three-part:
//
//	Secret   what the credential is (kind + sealed payload). Never leaves
//	         this package in plaintext except inside a Material.
//	Grant    who may use it, under what constraints, until when. Constraints
//	         are kind-specific and enforced at delivery, not documented and
//	         hoped for.
//	Lease    a short-lived, minimized materialisation of the grants that
//	         match one (executor, project) subject. Executors receive leases;
//	         they never receive the store.
//
// Enforcement, honestly scoped. Three of the constraint kinds are enforced by
// construction, because the broker rewrites the payload before it is
// delivered and a narrower payload cannot be widened by its holder:
//
//   - kubeconfig is rewritten to contain only the allowed contexts, their
//     referenced clusters/users, and an allowed namespace pinned on each;
//   - registry credentials are filtered to the allowed registries;
//   - env secrets are filtered to the allowed keys.
//
// github_pat is enforced at the point of use rather than by construction:
// GitHub has no API to narrow an already-issued PAT, so instead of exporting
// a bare GITHUB_TOKEN the broker emits a git credential helper that releases
// the token only for paths matching the allowlist (see githubpat.go). A bare
// GITHUB_TOKEN is exported only when the allowlist is explicitly "*".
//
// egress_proxy carries its allowlist to the executor, whose network policy is
// the enforcement point; in-process callers gate on Constraints.AllowsHost.
// This is the one kind whose enforcement lives outside this package, and it
// is called out here so nobody mistakes it for the kubeconfig guarantee.
//
// Fail-closed is the rule throughout: an unparseable constraint, an
// unsatisfiable one, an expired or revoked grant, or a payload that minimizes
// to nothing all produce a denial and an audit row — never a wider
// credential.
package secretbroker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Kind classifies what a secret *is*, which determines both the constraints
// that apply to it and how it is minimized and delivered.
type Kind string

const (
	// KindGitHubPAT is a GitHub personal access token. Constrained by a
	// repository allowlist and a permission set.
	KindGitHubPAT Kind = "github_pat"
	// KindGitHubApp is a GitHub App installation credential (JSON with
	// app_id/installation_id/private_key). Constrained like a PAT.
	KindGitHubApp Kind = "github_app"
	// KindKubeconfig is a kubeconfig YAML document. Constrained by allowed
	// contexts and namespaces, and rewritten to match before delivery.
	KindKubeconfig Kind = "kubeconfig"
	// KindRegistry is a container-registry credential (docker config JSON,
	// or "user:password"). Constrained by an allowed registry list.
	KindRegistry Kind = "registry"
	// KindEnv is an opaque environment variable or set of them. Constrained
	// by an allowed key list.
	KindEnv Kind = "env"
	// KindEgressProxy is an outbound proxy endpoint, possibly with embedded
	// credentials. Constrained by an allowed-host list.
	KindEgressProxy Kind = "egress_proxy"
	// KindLocalRepo is a directory on the hub host that holds git
	// repositories. Constrained by a repository allowlist, and delivered as
	// a bind mount rather than as bytes.
	//
	// It is the odd one out here and deliberately so. The payload is a path,
	// not a credential, and the thing being granted is reach into the control
	// plane's own filesystem — which is exactly why it belongs in this
	// package rather than beside SpecMount. A path that a sandbox may read is
	// an authority, and every property this broker already provides for
	// authorities is one it needs: a named subject so the grant reaches one
	// project and not the fleet, a TTL so it lapses, an audit row recording
	// who opened it, and revocation that lands within a lease period.
	//
	// The alternative — a host path in .cloop/sandbox.yaml — is the reason
	// SpecMount sources are workspace-relative: that file is repo-committed,
	// so it is whatever a pull request says it is. This kind is the same
	// capability with the trust inverted. A human with secret.grant names the
	// path, out of band, and the project receives it.
	KindLocalRepo Kind = "local_repo"
	// KindHostDevice is an inventory of device nodes on the executor's host,
	// opened to one project. Constrained by a device-name allowlist, and
	// delivered as a runtime --device rather than as bytes.
	//
	// It is the widest authority this broker issues, and it is here for the
	// reason KindLocalRepo is: the alternative is a device path in
	// .cloop/sandbox.yaml, which is whatever a pull request says it is. See
	// hostdevice.go.
	KindHostDevice Kind = "host_device"
)

// Kinds returns every valid Kind, sorted, for CLI help and validation
// messages.
func Kinds() []Kind {
	return []Kind{
		KindEgressProxy, KindEnv, KindGitHubApp,
		KindGitHubPAT, KindHostDevice, KindKubeconfig, KindLocalRepo, KindRegistry,
	}
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindGitHubPAT, KindGitHubApp, KindKubeconfig,
		KindRegistry, KindEnv, KindEgressProxy, KindLocalRepo, KindHostDevice:
		return true
	}
	return false
}

// ParseKind validates and normalises a user-supplied kind string.
func ParseKind(s string) (Kind, error) {
	k := Kind(strings.ToLower(strings.TrimSpace(s)))
	if !k.Valid() {
		names := make([]string, 0, len(Kinds()))
		for _, v := range Kinds() {
			names = append(names, string(v))
		}
		return "", fmt.Errorf("%w: unknown kind %q (want one of: %s)",
			ErrInvalidKind, s, strings.Join(names, ", "))
	}
	return k, nil
}

// Secret is a stored credential. The payload is sealed (AES-256-GCM) at all
// times outside the broker: there is deliberately no plaintext field on this
// struct, so a Secret that escapes into a log, an API response, or the
// storage layer cannot carry the credential with it.
type Secret struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Name is a human-facing unique handle ("prod-deploy-pat"). Grants are
	// created against it from the CLI.
	Name string `json:"name"`
	// Sealed is the AES-256-GCM ciphertext of the payload, encrypted under
	// this secret's own data key (see WrappedDEK). Never logged.
	Sealed []byte `json:"-"`
	// KeyID names the KEK that WrappedDEK is sealed under. LegacyKeyID means
	// the pre-envelope construction: WrappedDEK is empty and Sealed is
	// encrypted directly under the passphrase-derived key (Task 20181).
	//
	// It is exported because storage must persist it, and json:"-" because a
	// key ID in an API response tells a caller nothing they can act on while
	// telling an attacker which rows a stolen key still opens.
	KeyID string `json:"-"`
	// WrappedDEK is this secret's data key, sealed under KeyID. Rotation
	// rewrites this field and leaves Sealed untouched.
	WrappedDEK []byte `json:"-"`
	// Metadata is non-sensitive descriptive data (rotation date, ticket).
	// It is included in audit payloads, so callers must not put credential
	// material here.
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	// Owner is the identity this secret belongs to personally, in the
	// OwnerKey namespace the rest of the hub uses for people (a lowercased
	// email, or "sub:<issuer subject>"). Empty means a shared secret: the
	// organisation's credential, provisioned by a maintainer, which is what
	// every secret was before Task 20275.
	//
	// It is deliberately not a Metadata entry. Metadata is operator free text
	// that lands in audit payloads and that nothing enforces; Owner is an
	// authorisation input read by VisibleTo and by every mutation path in the
	// broker. A rule enforced against a map any caller may overwrite is not a
	// rule, and the two have opposite handling: metadata is for humans to
	// read, Owner is for this package to obey.
	Owner string `json:"owner,omitempty"`
}

// Personal reports whether the secret belongs to one person rather than to the
// organisation.
func (s Secret) Personal() bool { return strings.TrimSpace(s.Owner) != "" }

// OwnedBy reports whether identity owns this secret.
//
// Both sides go through NormalizeOwner and are then compared exactly, so that
// "is this yours" has one definition rather than two that can drift. The
// normaliser is where the asymmetry lives, and it is deliberate on both sides:
//
//	email  folded to lowercase. IdPs are inconsistent about the case they
//	       release an address in, and "Alice@corp" locked out of the secret
//	       "alice@corp" minted is a lockout, not a security win.
//	sub:   left exactly as issued. An issuer subject is an opaque identifier,
//	       case-sensitive by specification, so folding it could silently merge
//	       two distinct people into one owner.
func (s Secret) OwnedBy(identity string) bool {
	if !s.Personal() {
		return false
	}
	want := NormalizeOwner(identity)
	return want != "" && NormalizeOwner(s.Owner) == want
}

// Viewer is the identity a read or a mutation is performed on behalf of.
//
// It exists so the broker can answer "may this person see, spend or destroy
// this secret" without importing pkg/authz, which would invert the dependency:
// authz is a policy over HTTP routes and OIDC claims, and the broker must stay
// usable from the CLI and from tests with neither present.
//
// A Viewer answers one question and deliberately not two: *ownership*. Whether
// the caller holds organisation-level authority over the shared, unowned
// secrets that were the only kind before Task 20275 is not asked here — that is
// authz.PermSecretGrant and authz.PermSecretRevoke, enforced by the hub's route
// table, which already does it correctly and is already tested. Answering it
// twice, in two packages, with two notions of who counts, is how the two
// answers come to disagree.
//
// So: shared secrets pass through this type untouched, exactly as they did
// before, and every existing call site stays correct without change. What the
// zero value cannot do is see, spend or delete a *personal* secret — which is
// the whole of the new capability, and which therefore fails closed for any
// caller that forgets to say who they are.
type Viewer struct {
	// Identity is the viewer's OwnerKey, matched against Secret.Owner. It
	// authorises everything about the viewer's own personal secrets and
	// nothing about anybody else's.
	Identity string

	// Admin marks a caller entitled to administer *other people's* personal
	// secrets: to see that alice@corp keeps one here, and to destroy it when
	// she leaves.
	//
	// It confers visibility and deletion, never use. Offboarding requires both,
	// and pretending an admin cannot see the row would be theatre — the
	// material is sealed under a key the hub operator already holds. Spending
	// somebody else's credential is a different act, it is the one thing the
	// ownership model exists to prevent, and no flag here enables it.
	Admin bool
}

// PrivilegedViewer is the viewer for callers that already hold full authority
// over the secret store: the CLI running on the hub host, key rotation, and
// offboarding sweeps.
//
// Named rather than written as a literal at each site so that the places which
// deliberately see every user's secrets are greppable, and so that reviewing
// "what can see everything" is a search for one identifier.
func PrivilegedViewer(identity string) Viewer {
	return Viewer{Identity: identity, Admin: true}
}

// VisibleTo reports whether v may see that this secret exists.
func (s Secret) VisibleTo(v Viewer) bool {
	if !s.Personal() {
		return true
	}
	return v.Admin || s.OwnedBy(v.Identity)
}

// SpendableBy reports whether v may grant this secret to an executor — the act
// that puts the credential to work.
//
// Strictly narrower than VisibleTo, and the one place where Admin buys nothing.
// An admin may see a colleague's personal secret and may delete it; handing it
// to a workload is neither of those, and allowing it would make ownership
// advisory.
func (s Secret) SpendableBy(v Viewer) bool {
	if !s.Personal() {
		return true
	}
	return s.OwnedBy(v.Identity)
}

// DeletableBy reports whether v may destroy this secret.
//
// Wider than SpendableBy by exactly one case: an admin may delete a personal
// secret they do not own, because otherwise a hub could never complete an
// offboarding — an account that no longer exists cannot come back to press the
// button. The deletion is audited with the actor's name attached.
func (s Secret) DeletableBy(v Viewer) bool {
	if !s.Personal() {
		return true
	}
	return v.Admin || s.OwnedBy(v.Identity)
}

// Envelope returns the secret's sealed material in the form the keyring
// understands.
func (s Secret) Envelope() Envelope {
	return Envelope{KeyID: s.KeyID, WrappedDEK: s.WrappedDEK, Ciphertext: s.Sealed}
}

// WithEnvelope returns a copy of the secret carrying env's sealed material.
func (s Secret) WithEnvelope(env Envelope) Secret {
	s.KeyID = env.KeyID
	s.WrappedDEK = env.WrappedDEK
	s.Sealed = env.Ciphertext
	return s
}

// Validate checks a Secret's structural invariants before it is stored.
func (s Secret) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("%w: secret id is empty", ErrInvalidSecret)
	}
	if !s.Kind.Valid() {
		return fmt.Errorf("%w: secret %s has invalid kind %q", ErrInvalidKind, s.ID, s.Kind)
	}
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if len(s.Sealed) == 0 {
		return fmt.Errorf("%w: secret %s has empty payload", ErrInvalidSecret, s.ID)
	}
	return nil
}

// nameCharset restricts secret names to characters that are safe to embed in
// audit payloads, CLI output, env var derivations, and file names without
// escaping. Rejecting at the door is cheaper than escaping at every sink.
func ValidateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidSecret)
	}
	if len(name) > 128 {
		return fmt.Errorf("%w: name is longer than 128 characters", ErrInvalidSecret)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w: name %q contains %q; allowed: letters, digits, '-', '_', '.'",
				ErrInvalidSecret, name, string(r))
		}
	}
	return nil
}

// SubjectType is the dimension a Grant's subject selects on.
type SubjectType string

const (
	// SubjectProject scopes a grant to one project (or "*" for all).
	SubjectProject SubjectType = "project"
	// SubjectExecutor scopes a grant to one executor ID (or "*").
	SubjectExecutor SubjectType = "executor"
	// SubjectLabel scopes a grant to executors carrying every label in the
	// selector — the way a fleet of edge devices is addressed without
	// enumerating device IDs.
	SubjectLabel SubjectType = "label"
	// SubjectAny matches every requester. Reserved for the legacy import
	// path, where narrowing an existing flat secret store would silently
	// break running projects.
	SubjectAny SubjectType = "any"
)

// Subject is the "who" of a grant.
type Subject struct {
	Type SubjectType `json:"type"`
	// Value is the project path or executor ID for those types, "*" for a
	// wildcard within the type, and unused for label/any.
	Value string `json:"value,omitempty"`
	// Labels is the selector for SubjectLabel: every pair must be present
	// on the requester for the grant to match.
	Labels map[string]string `json:"labels,omitempty"`
}

// ParseSubject parses the CLI's "--to" syntax:
//
//	project:/srv/app     one project, by path
//	project:*            every project
//	executor:edge-01     one executor
//	label:region=eu,gpu=true   every executor carrying both labels
//	any / *              every requester (used by the legacy import)
//
// An unrecognised or empty spec is an error rather than a permissive
// default: a typo in a grant target must not silently widen it.
func ParseSubject(spec string) (Subject, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return Subject{}, fmt.Errorf("%w: subject is empty", ErrInvalidSubject)
	}
	if s == "*" || strings.EqualFold(s, "any") {
		return Subject{Type: SubjectAny}, nil
	}

	prefix, rest, found := strings.Cut(s, ":")
	if !found {
		return Subject{}, fmt.Errorf(
			"%w: %q is missing a type prefix (want project:, executor:, label:, or any)",
			ErrInvalidSubject, spec)
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	rest = strings.TrimSpace(rest)

	switch SubjectType(prefix) {
	case SubjectProject:
		if rest == "" {
			return Subject{}, fmt.Errorf("%w: project subject has no value", ErrInvalidSubject)
		}
		return Subject{Type: SubjectProject, Value: NormalizeProjectID(rest)}, nil

	case SubjectExecutor:
		if rest == "" {
			return Subject{}, fmt.Errorf("%w: executor subject has no value", ErrInvalidSubject)
		}
		return Subject{Type: SubjectExecutor, Value: rest}, nil

	case SubjectLabel:
		labels, err := parseLabelSelector(rest)
		if err != nil {
			return Subject{}, err
		}
		return Subject{Type: SubjectLabel, Labels: labels}, nil

	default:
		return Subject{}, fmt.Errorf(
			"%w: unknown subject type %q (want project, executor, label, or any)",
			ErrInvalidSubject, prefix)
	}
}

// parseLabelSelector parses "k=v,k2=v2" into a map. An empty selector is
// rejected: "label:" would otherwise match every executor, which is what
// "any" is for and should have to be spelled out.
func parseLabelSelector(s string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("%w: label selector is empty (use 'any' to match everything)", ErrInvalidSubject)
	}
	labels := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, found := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !found || k == "" {
			return nil, fmt.Errorf("%w: label %q is not in key=value form", ErrInvalidSubject, pair)
		}
		if prev, dup := labels[k]; dup && prev != v {
			return nil, fmt.Errorf("%w: label %q given twice with different values", ErrInvalidSubject, k)
		}
		labels[k] = v
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("%w: label selector is empty (use 'any' to match everything)", ErrInvalidSubject)
	}
	return labels, nil
}

// NormalizeProjectID canonicalises a project identifier so that a grant
// written as "/srv/app/" and a lease requested for "/srv/app" agree.
// Absolute paths are cleaned; anything else (an opaque project ID, or the
// "*" wildcard) is passed through trimmed. Matching is exact after this —
// no prefix or basename fuzziness, which would let /srv/app-staging pick up
// /srv/app's credentials.
func NormalizeProjectID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "*" {
		return id
	}
	if filepath.IsAbs(id) {
		return filepath.Clean(id)
	}
	return strings.TrimRight(id, "/")
}

// String renders a Subject back into the CLI's "--to" syntax.
func (s Subject) String() string {
	switch s.Type {
	case SubjectAny:
		return "any"
	case SubjectLabel:
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+s.Labels[k])
		}
		return "label:" + strings.Join(parts, ",")
	case SubjectProject, SubjectExecutor:
		return string(s.Type) + ":" + s.Value
	default:
		return string(s.Type)
	}
}

// Validate checks that a Subject is well-formed.
func (s Subject) Validate() error {
	switch s.Type {
	case SubjectAny:
		return nil
	case SubjectProject, SubjectExecutor:
		if strings.TrimSpace(s.Value) == "" {
			return fmt.Errorf("%w: %s subject has no value", ErrInvalidSubject, s.Type)
		}
		return nil
	case SubjectLabel:
		if len(s.Labels) == 0 {
			return fmt.Errorf("%w: label subject has no selector", ErrInvalidSubject)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown subject type %q", ErrInvalidSubject, s.Type)
	}
}

// Requester is the identity a lease is issued to: one executor running work
// for one project. Labels are the executor's own labels, used by
// SubjectLabel grants.
type Requester struct {
	ExecutorID string
	ProjectID  string
	Labels     map[string]string
}

// Wildcard reports whether this subject selects an open-ended set of
// requesters rather than one named project or executor.
//
// "any" and an explicit "*" both qualify. A label selector does not: it names a
// property of a machine, and an operator who labels two executors has said
// which two — whereas "*" says "and every one added later", which is a
// different promise and the one a personal credential cannot make.
func (s Subject) Wildcard() bool {
	switch s.Type {
	case SubjectAny:
		return true
	case SubjectProject, SubjectExecutor:
		return strings.TrimSpace(s.Value) == "*"
	default:
		return false
	}
}

// Matches reports whether this subject selects r.
//
// A wildcard "*" is honoured within project/executor types, but only when
// written explicitly — an empty Value never matches, so a half-constructed
// Subject fails closed instead of matching everything.
func (s Subject) Matches(r Requester) bool {
	switch s.Type {
	case SubjectAny:
		return true

	case SubjectProject:
		if s.Value == "" {
			return false
		}
		if s.Value == "*" {
			return true
		}
		return s.Value == NormalizeProjectID(r.ProjectID)

	case SubjectExecutor:
		if s.Value == "" {
			return false
		}
		if s.Value == "*" {
			return true
		}
		return s.Value == strings.TrimSpace(r.ExecutorID)

	case SubjectLabel:
		if len(s.Labels) == 0 {
			return false
		}
		for k, want := range s.Labels {
			got, ok := r.Labels[k]
			if !ok || got != want {
				return false
			}
		}
		return true

	default:
		return false
	}
}

// Grant authorises one subject to use one secret, under Constraints, until
// ExpiresAt.
type Grant struct {
	ID       string `json:"id"`
	SecretID string `json:"secret_id"`
	// Scope is a free-form operator-facing label ("ci", "deploy") used for
	// grouping and filtering. It carries no authorisation weight — that is
	// entirely Subject plus Constraints — so an operator cannot widen a
	// grant by editing it.
	Scope       string      `json:"scope,omitempty"`
	Subject     Subject     `json:"subject"`
	Constraints Constraints `json:"constraints"`
	// ExpiresAt is when the grant stops being usable. Zero means no expiry,
	// which Validate permits only because the legacy import needs it; the
	// CLI always sets a TTL.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	// Owner is copied from the secret this grant points at when that secret
	// is personal, and is empty otherwise.
	//
	// Denormalised on purpose. A grant listing is read far more often than a
	// secret is minted, and the alternative — resolving every grant's secret
	// to find out whether the row should be shown — is the N+1 read that the
	// listing handlers already go out of their way to avoid. More importantly
	// it keeps the row self-describing: when the secret is deleted, the
	// revoked grants it leaves behind still say whose credential they spent,
	// which is exactly the question an offboarding or incident review asks.
	Owner string `json:"owner,omitempty"`
}

// Personal reports whether this grant hands out a personally-owned credential.
func (g Grant) Personal() bool { return strings.TrimSpace(g.Owner) != "" }

// VisibleTo reports whether v may see this grant.
//
// A grant follows the secret it points at: over a shared secret it is
// organisation business, over a personal one it is its owner's, and the owner
// is on the row so that deciding needs no second read.
func (g Grant) VisibleTo(v Viewer) bool {
	if !g.Personal() {
		return true
	}
	if v.Admin {
		return true
	}
	// Same comparison rule as Secret.OwnedBy, reached through the same
	// normaliser rather than reimplemented — a grant that disagrees with its
	// secret about who owns it is the bug this shares code to avoid.
	want := NormalizeOwner(v.Identity)
	return want != "" && NormalizeOwner(g.Owner) == want
}

// Active reports whether the grant may be used at time now.
func (g Grant) Active(now time.Time) bool {
	return g.DenyReason(now) == ""
}

// DenyReason returns the audit-friendly reason this grant cannot be used at
// now, or "" when it is usable. Returning the reason rather than a bool is
// what lets every denial land in the audit log with a cause attached.
func (g Grant) DenyReason(now time.Time) string {
	if !g.RevokedAt.IsZero() && !now.Before(g.RevokedAt) {
		return "grant revoked at " + g.RevokedAt.UTC().Format(time.RFC3339)
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return "grant expired at " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return ""
}

// Validate checks a Grant's structural invariants, including that its
// constraints make sense for the kind of secret it points at.
func (g Grant) Validate(kind Kind) error {
	if strings.TrimSpace(g.ID) == "" {
		return fmt.Errorf("%w: grant id is empty", ErrInvalidGrant)
	}
	if strings.TrimSpace(g.SecretID) == "" {
		return fmt.Errorf("%w: grant %s has no secret id", ErrInvalidGrant, g.ID)
	}
	if err := g.Subject.Validate(); err != nil {
		return err
	}
	if !g.ExpiresAt.IsZero() && !g.CreatedAt.IsZero() && !g.ExpiresAt.After(g.CreatedAt) {
		return fmt.Errorf("%w: grant %s expires at or before its creation time", ErrInvalidGrant, g.ID)
	}
	return g.Constraints.ValidateFor(kind)
}

// newID returns a prefixed, collision-resistant identifier. 12 random bytes
// (96 bits) is far beyond what a single control plane's grant count could
// collide on, and short enough to paste into a CLI.
func newID(prefix string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secretbroker: generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}
