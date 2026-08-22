package secretbroker

import (
	"sort"
	"strings"
	"time"
)

// Store is the persistence contract the broker needs.
//
// It is an interface, and it lives here rather than in pkg/statedb, for the
// same reason pkg/executor/remote defines its own Store: the broker's policy
// logic is the part worth testing exhaustively, and it should not need a
// SQLite file to test. pkg/secretstore is the production implementation.
//
// The payload crosses this boundary sealed and only sealed. Store
// implementations therefore cannot leak plaintext credentials even if they
// log every argument they receive — which is the point, since a storage
// layer is exactly the kind of code that grows debug logging.
type Store interface {
	// PutSecret inserts or replaces a secret by ID.
	PutSecret(s Secret) error
	// GetSecret returns the secret with the given ID, or a wrapped
	// ErrSecretNotFound.
	GetSecret(id string) (Secret, error)
	// ListSecrets returns every stored secret.
	ListSecrets() ([]Secret, error)
	// DeleteSecret removes a secret. Removing a secret that does not exist
	// returns a wrapped ErrSecretNotFound.
	DeleteSecret(id string) error

	// PutGrant inserts or replaces a grant by ID.
	PutGrant(g Grant) error
	// GetGrant returns the grant with the given ID, or a wrapped
	// ErrGrantNotFound.
	GetGrant(id string) (Grant, error)
	// ListGrants returns every stored grant, including expired and revoked
	// ones — the broker filters, so that callers listing for an audit UI
	// can still see history.
	ListGrants() ([]Grant, error)
	// RevokeGrant stamps a grant revoked at the given time. Revoking an
	// already-revoked grant is a no-op, not an error: revocation is
	// idempotent by design, because a caller racing to revoke twice must
	// not be told the second attempt failed.
	RevokeGrant(id string, at time.Time) error

	// Meta reads a broker-scoped metadata value.
	Meta(key string) (value string, ok bool, err error)
	// SetMeta writes a broker-scoped metadata value.
	SetMeta(key, value string) error
}

// findSecretByName is a helper over the Store's list, used by the CLI where
// operators name secrets rather than quoting IDs. Names are unique, enforced
// at Mint time.
func findSecretByName(store Store, name string) (Secret, error) {
	secrets, err := store.ListSecrets()
	if err != nil {
		return Secret{}, err
	}
	for _, s := range secrets {
		if s.Name == name {
			return s, nil
		}
	}
	return Secret{}, wrapf(ErrSecretNotFound, "no secret named %q", SafeRef(name))
}

// safeRefKeep is how much of an unresolvable reference is echoed back. Enough
// to recognise a typo in your own secret name, too little to be a usable
// credential.
const safeRefKeep = 12

// SafeRef renders a secret reference for an error message or an audit record
// without republishing it.
//
// A "no such secret" error is one of the few places a user-supplied string is
// echoed verbatim, and the single most common way to reach it is to paste the
// credential where its *name* belongs. That mistake is silent — the operator
// sees a not-found error, retries correctly, and never learns that the first
// attempt wrote the live token into the audit log, which is then shipped
// off-box and retained for a year.
//
// Redaction alone is not enough: it recognises known token prefixes, and a
// kubeconfig token or a registry auth blob has no prefix to recognise. So the
// reference is also truncated, which is the part that generalises to
// credential shapes nobody has enumerated yet.
func SafeRef(ref string) string {
	ref = RedactString(strings.TrimSpace(ref))
	if len(ref) <= safeRefKeep {
		return ref
	}
	return ref[:safeRefKeep] + "…"
}

// resolveSecret accepts either a secret ID or a name, preferring an exact ID
// match. Operators paste both; guessing wrong would attach a grant to the
// wrong credential, so ID wins and name is the fallback.
func resolveSecret(store Store, ref string) (Secret, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Secret{}, wrapf(ErrSecretNotFound, "empty secret reference")
	}
	if s, err := store.GetSecret(ref); err == nil {
		return s, nil
	}
	return findSecretByName(store, ref)
}

// sortGrants orders grants newest-first for stable CLI and API output.
func sortGrants(grants []Grant) {
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].CreatedAt.Equal(grants[j].CreatedAt) {
			return grants[i].ID < grants[j].ID
		}
		return grants[i].CreatedAt.After(grants[j].CreatedAt)
	})
}
