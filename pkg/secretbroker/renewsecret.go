package secretbroker

// renewsecret.go replaces a stored secret's payload in place (Task 20416).
//
// Every other change to a credential is a delete and a re-mint, which is right
// for an operator rotating a secret by hand: the grants go with the old secret
// and are made again on purpose. A credential that renews itself is different.
// A Kubernetes share's ServiceAccount token expires on the cluster's schedule,
// often within a day, and the share has to keep working through it — under the
// same secret, with the same grants, delivered to the same projects. So the
// payload is re-sealed under the secret's own id and the row replaced, and
// nothing that points at the secret notices.
//
// What renews is the caller's business — Renew computes the new payload from
// the old one — and what the broker guarantees is the rest: the plaintext is
// opened and wiped here, the new payload is sealed under the same associated
// data as the old, a renewal that raced another one is refused rather than
// silently undone, and every outcome is a secret.renew row.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrSecretChanged is a renewal that lost a race: the secret's payload changed
// between being read and being replaced, and the newer one stands.
var ErrSecretChanged = errors.New("secretbroker: the secret changed while it was being renewed")

// RenewedPayload is what a renewal produced.
type RenewedPayload struct {
	// Payload is the new plaintext. Wiped once sealed.
	Payload []byte
	// Metadata is the secret's complete new metadata; nil keeps the old.
	Metadata map[string]string
	// ExpiresAt is when the new credential stops working, for the audit row.
	ExpiresAt time.Time
	// Reason describes the renewal for the audit row. No credential.
	Reason string
}

// RenewSecretRequest asks the broker to renew one secret's payload in place.
type RenewSecretRequest struct {
	// Ref names the secret: an id or a name.
	Ref string
	// Kind, when set, is the kind the secret must be.
	Kind Kind
	// Actor is who renews: the hub, or the owner pushing a new credential.
	Actor string
	// Renew computes the new payload from the stored secret and its
	// plaintext. The plaintext is wiped when it returns, so it must not keep
	// a reference to it.
	Renew func(ctx context.Context, s Secret, plaintext []byte) (RenewedPayload, error)
	// AuditFailure decides whether a failed renewal is written to the audit
	// trail; nil writes every one. A caller retrying on a timer uses it to
	// write each distinct cause once rather than once a minute.
	AuditFailure func(error) bool
}

// RenewSecret opens a secret, has req.Renew compute its new payload, and
// stores that under the same id, grants and owner. It returns the stored
// secret.
//
// It authorises nothing: the HTTP layer decides who may renew whose secret,
// as it decides who may delete one.
func (b *Broker) RenewSecret(ctx context.Context, req RenewSecretRequest) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	ev := Event{Action: ActionRenew, Actor: req.Actor}
	if req.Renew == nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "renew %q: nothing to renew it with", SafeRef(req.Ref))
	}
	s, err := resolveSecret(b.store, req.Ref)
	if err != nil {
		return Secret{}, b.denyf(ev, ErrSecretNotFound, "resolve %q: %v", SafeRef(req.Ref), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind
	if req.Kind != "" && s.Kind != req.Kind {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "secret %s is a %s secret, not %s", s.Name, s.Kind, req.Kind)
	}

	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
	if err != nil {
		return Secret{}, b.denyf(ev, ErrSealFailed, "open payload for %s: %v", s.Name, err)
	}
	out, err := req.Renew(ctx, s, plaintext)
	zero(plaintext)
	if err != nil {
		err = fmt.Errorf("renew %s: %w", s.Name, err)
		if req.AuditFailure != nil && !req.AuditFailure(err) {
			return Secret{}, err
		}
		return Secret{}, b.denyErr(ev, err)
	}
	if len(out.Payload) == 0 {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "renew %s: the renewal produced an empty payload", s.Name)
	}
	env, err := b.seal.SealFor(AADFor(SetSecrets, s.ID), out.Payload)
	zero(out.Payload)
	if err != nil {
		return Secret{}, b.denyf(ev, ErrSealFailed, "seal the renewed payload of %s: %v", s.Name, err)
	}

	updated := s.WithEnvelope(env)
	if out.Metadata != nil {
		updated.Metadata = out.Metadata
	}
	if err := updated.Validate(); err != nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "%v", err)
	}
	// Optimistic, not locked: brokers are built per request and two hub
	// processes may renew at once. The window between this read and the write
	// is one statement; a renewal that loses it gives way to the one that won,
	// which holds a credential at least as new.
	if cur, err := b.store.GetSecret(s.ID); err != nil {
		return Secret{}, b.denyf(ev, ErrSecretNotFound, "re-read %s: %v", s.Name, err)
	} else if subtle.ConstantTimeCompare(cur.Sealed, s.Sealed) != 1 {
		return Secret{}, b.denyf(ev, ErrSecretChanged, "%s was renewed by someone else meanwhile", s.Name)
	}
	if err := b.store.PutSecret(updated); err != nil {
		return Secret{}, b.denyf(ev, ErrInvalidSecret, "store the renewed %s: %v", s.Name, err)
	}

	ev.Decision = DecisionAllow
	ev.ExpiresAt = out.ExpiresAt
	ev.Reason = strings.TrimSpace(out.Reason)
	b.emit(ev)
	return updated, nil
}

// RefuseRenewal records, as a secret.renew deny row, that a credential was
// not renewed and why — for a renewal refused before any attempt was made,
// such as a Kubernetes share whose owner the hub now denies (Task 20420).
func (b *Broker) RefuseRenewal(ref, actor, reason string) error {
	ev := Event{Action: ActionRenew, Actor: actor}
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return b.denyf(ev, ErrSecretNotFound, "resolve %q: %v", SafeRef(ref), err)
	}
	ev.SecretID, ev.SecretName, ev.Kind = s.ID, s.Name, s.Kind
	return b.denyf(ev, ErrRenewalStopped, "%s", reason)
}

// UpdateSecretMetadata rewrites a secret's metadata, leaving its payload as it
// is: bookkeeping a renewal keeps about itself, such as why the last attempt
// failed. It is not audited; what it records is.
func (b *Broker) UpdateSecretMetadata(ref string, mutate func(map[string]string)) (Secret, error) {
	s, err := resolveSecret(b.store, ref)
	if err != nil {
		return Secret{}, fmt.Errorf("%w: resolve %q: %v", ErrSecretNotFound, SafeRef(ref), err)
	}
	meta := make(map[string]string, len(s.Metadata)+2)
	for k, v := range s.Metadata {
		meta[k] = v
	}
	mutate(meta)
	cur, err := b.store.GetSecret(s.ID)
	if err != nil {
		return Secret{}, fmt.Errorf("%w: re-read %s: %v", ErrSecretNotFound, s.Name, err)
	}
	if subtle.ConstantTimeCompare(cur.Sealed, s.Sealed) != 1 {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretChanged, s.Name)
	}
	s.Metadata = meta
	if err := b.store.PutSecret(s); err != nil {
		return Secret{}, fmt.Errorf("store %s: %w", s.Name, err)
	}
	return s, nil
}
