package secretbroker

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Personal secrets (Task 20275).
//
// Before this, every secret in the store belonged to the organisation: a
// maintainer minted it, anybody holding secret.grant could see it, grant it and
// delete it. That is the right model for the deploy key the whole fleet shares,
// and the wrong one for the credential a single developer brings — their own
// GitHub PAT, their own kubeconfig — which on a multi-user hub they must be
// able to keep without handing a copy to every other maintainer.
//
// The rule is one sentence: a secret with an Owner is visible, grantable and
// deletable by that owner alone, and by an admin only for the things an admin
// must be able to do (see that it exists, and destroy it when its owner
// leaves). Everything below is that sentence made enforceable.
//
// It lives in the broker rather than in the HTTP handlers on purpose. A filter
// applied while rendering a response is one refactor away from being skipped,
// and the CLI would never have had it at all; a check inside Mint, Grant and
// DeleteSecret is one every caller goes through. The handlers still scope their
// reads — a response must not carry rows the viewer may not see — but they are
// narrowing a view, not holding the only copy of the rule.

// ListSecretsFor returns the secrets v may see, sorted by name.
//
// The scoped counterpart to ListSecrets, which stays unscoped because rotation,
// offboarding and the hub-host CLI all legitimately need every row. Request
// handlers must use this one; tests/security enforces that they do.
func (b *Broker) ListSecretsFor(v Viewer) ([]Secret, error) {
	secrets, err := b.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(secrets))
	for _, s := range secrets {
		if s.VisibleTo(v) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DescribeSecretFor resolves a secret by ID or name, for a viewer.
//
// A secret v may not see reports ErrSecretNotFound rather than ErrNotOwner, and
// the distinction matters: names are chosen by people and are guessable
// ("alice-github-pat"), so an error that separates "no such secret" from "not
// yours" would turn this endpoint into an oracle for who keeps what. The hub
// makes the same choice for projects a caller cannot reach, where require()
// answers 404 rather than 403.
func (b *Broker) DescribeSecretFor(ref string, v Viewer) (Secret, error) {
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return Secret{}, err
	}
	if !s.VisibleTo(v) {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretNotFound, SafeRef(ref))
	}
	return s, nil
}

// ListGrantsFor returns the grants v may see.
//
// Grants over personal secrets follow their secret: the grant row carries the
// owner precisely so this filter needs no second read.
func (b *Broker) ListGrantsFor(f GrantFilter, v Viewer) ([]Grant, error) {
	grants, err := b.ListGrants(f)
	if err != nil {
		return nil, err
	}
	out := grants[:0:0]
	for _, g := range grants {
		if g.VisibleTo(v) {
			out = append(out, g)
		}
	}
	return out, nil
}

// DeleteSecretFor removes a secret on behalf of v, revoking its grants.
//
// Deleting is the one act where an admin may reach a personal secret that is
// not theirs, because the alternative is a hub that cannot complete an
// offboarding: when someone leaves, their credentials must go with them, and an
// account that no longer exists cannot come back to press the button. The audit
// event Broker.DeleteSecret emits names the actor, so an admin doing this is
// recorded doing it.
func (b *Broker) DeleteSecretFor(ctx context.Context, ref string, v Viewer) error {
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, SafeRef(ref))
	}
	if !s.VisibleTo(v) {
		// Withheld as a non-existence for the same reason as
		// DescribeSecretFor: a delete that answers "not yours" confirms the
		// name it refused.
		return fmt.Errorf("%w: %s", ErrSecretNotFound, SafeRef(ref))
	}
	if !s.DeletableBy(v) {
		return fmt.Errorf("%w: %s belongs to %s", ErrNotOwner, s.Name, s.Owner)
	}
	return b.DeleteSecret(ctx, ref, v.Identity)
}

// checkSpendable is the gate every mutation that *spends* a secret passes
// through: granting it to an executor.
//
// A secret the viewer cannot even see is reported as absent rather than as
// forbidden, so that guessing names learns nothing; one they can see but do not
// own is refused as what it is.
func checkSpendable(s Secret, v Viewer) error {
	if s.SpendableBy(v) {
		return nil
	}
	if !s.VisibleTo(v) {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, SafeRef(s.Name))
	}
	return fmt.Errorf("%w: %s belongs to %s", ErrNotOwner, s.Name, s.Owner)
}

// NormalizeOwner trims an owner identity into the form stored on a Secret.
//
// Exported because the hub needs to compare a request's identity against a
// stored owner, and a second normaliser written at the call site is how the two
// come to disagree about whether "Alice@Corp" owns "alice@corp".
//
// Lowercased because OwnerKey already is for the email case, and storing a
// mixed-case copy would make the SQL index disagree with OwnedBy's
// case-insensitive comparison — two answers to "is this yours" is one too many.
// The "sub:" form is left alone beyond the prefix: an issuer subject is opaque
// and case-sensitive, so lowercasing it could merge two distinct people.
func NormalizeOwner(identity string) string {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return ""
	}
	if rest, ok := cutPrefixFold(identity, "sub:"); ok {
		return "sub:" + rest
	}
	return strings.ToLower(identity)
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}
