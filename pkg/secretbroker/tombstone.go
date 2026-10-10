package secretbroker

// Tombstones: what a deleted secret was (Task 20400).
//
// Deleting a secret destroys its row — sealed payload and wrapped data key
// together — and revokes every grant over it. The grants stay, stamped, so
// "who could reach this" keeps an answer, but each then names a secret id that
// resolves to nothing. Before this file that was all a lease could say about
// one: "grant revoked at …" or "grant points at missing secret secret_…".
//
// The case that made it matter is offboarding. When somebody leaves, their
// personal secrets are destroyed — their GitHub PAT, their kubeconfig — and a
// shared project a colleague had been granted one of them finds out on its
// next run, from a refusal that named neither the credential nor the person
// it belonged to. The colleague cannot even look the grant up: a grant over a
// personal secret is visible to its owner and to admins, not to them.
//
// A tombstone is the secret's metadata, kept past its deletion: name, kind,
// owner, when, by whom, and why. Nothing sealed is kept — the point of the
// deletion is that the material is gone — and the stored reason, which an
// operator typed and which for an offboarding is often an HR matter, is held
// for the audit trail and never put into a refusal a project member reads.

import (
	"fmt"
	"strings"
	"time"
)

// DeletionCause says why a secret was destroyed, in the terms a refusal shows
// to the people who lost it.
type DeletionCause string

const (
	// CauseDeleted: somebody deleted the secret — its owner, or an operator.
	CauseDeleted DeletionCause = "deleted"
	// CauseOffboarded: the secret was personal, and was destroyed because its
	// owner was offboarded.
	CauseOffboarded DeletionCause = "offboarded"
)

// Tombstone is what is left of a deleted secret.
type Tombstone struct {
	SecretID  string        `json:"secret_id"`
	Name      string        `json:"name"`
	Kind      Kind          `json:"kind,omitempty"`
	Owner     string        `json:"owner,omitempty"`
	DeletedAt time.Time     `json:"deleted_at"`
	DeletedBy string        `json:"deleted_by,omitempty"`
	Cause     DeletionCause `json:"cause,omitempty"`
	// Reason is what the deleter wrote. It is kept for the audit trail and
	// for admins; Describe leaves it out.
	Reason string `json:"reason,omitempty"`
}

// Describe renders the tombstone for a refusal a project's members read: what
// the credential was, whose it was, and when and why it went — without the
// deleter's stated reason, which is not theirs to read.
func (t Tombstone) Describe() string {
	what := strings.TrimSpace(string(t.Kind) + " " + fmt.Sprintf("%q", t.Name))
	when := "an unrecorded date"
	if !t.DeletedAt.IsZero() {
		when = t.DeletedAt.UTC().Format("2006-01-02")
	}
	switch {
	case t.Owner != "" && t.Cause == CauseOffboarded:
		return fmt.Sprintf("%s, a personal credential of %s, was destroyed on %s when its owner was offboarded",
			what, t.Owner, when)
	case t.Owner != "":
		return fmt.Sprintf("%s, a personal credential of %s, was deleted on %s", what, t.Owner, when)
	case t.DeletedBy != "":
		return fmt.Sprintf("%s was deleted on %s by %s", what, when, t.DeletedBy)
	default:
		return fmt.Sprintf("%s was deleted on %s", what, when)
	}
}

// remedy is the sentence a refusal ends with: what the people who lost the
// credential can do about it.
func (t Tombstone) remedy() string {
	if t.Owner != "" {
		return "grant this project a credential that somebody still on this hub owns"
	}
	return "ask whoever manages shared credentials to mint a replacement and grant it"
}

// TombstoneStore is an optional Store extension that remembers what a deleted
// secret was.
//
// Optional, and detected by type assertion, for the reason RequestStore is:
// the core Store contract is implemented by test doubles and by anything
// embedding the broker, and a store without tombstones keeps working exactly
// as before — its refusals just cannot name a deleted secret.
type TombstoneStore interface {
	// DeleteSecretTombstoned removes a secret and records its tombstone in
	// one step, so nothing can observe the row gone and the tombstone absent.
	// Removing a secret that does not exist returns a wrapped
	// ErrSecretNotFound and records nothing.
	DeleteSecretTombstoned(id string, t Tombstone) error
	// GetTombstone returns the tombstone of a deleted secret, or a wrapped
	// ErrSecretNotFound when none was recorded.
	GetTombstone(secretID string) (Tombstone, error)
}

// Tombstone returns what a deleted secret was, and whether this broker's store
// remembers it.
func (b *Broker) Tombstone(secretID string) (Tombstone, bool) {
	ts, ok := b.store.(TombstoneStore)
	if !ok || strings.TrimSpace(secretID) == "" {
		return Tombstone{}, false
	}
	t, err := ts.GetTombstone(secretID)
	if err != nil {
		return Tombstone{}, false
	}
	return t, true
}

// RevocationCause says why a grant was revoked, when the revocation said
// (Task 20400). It is a fixed word rather than the revoker's text, which goes
// to the audit trail: this is what decides whether a lease that meets the
// grant hands its refusal back for the project to be told, and what it says.
type RevocationCause string

const (
	// RevokedOwnerOffboarded: the grant spent a personal secret whose owner
	// was offboarded. The secret is then destroyed, or kept under a legal
	// hold; either way the grant is gone and the project should hear why.
	RevokedOwnerOffboarded RevocationCause = "owner_offboarded"
	// RevokedSecretDeleted: the secret the grant spent was deleted.
	RevokedSecretDeleted RevocationCause = "secret_deleted"
	// RevokedSuperseded: another grant replaced this one — an edited
	// repository assignment, a credential granted again for longer (Task
	// 20403). No new lease carries it; a running lease that does keeps it,
	// standing on the successor the grant names (Grant.SupersededBy), because
	// the successor still authorises the work the run is doing.
	RevokedSuperseded RevocationCause = "superseded"
)

// tellsTheProject reports whether a grant revoked for this cause is one the
// project lost to something done elsewhere — an offboarding, a deletion — as
// opposed to a revocation somebody made of the grant itself, which its maker
// already knows about.
func (c RevocationCause) tellsTheProject() bool {
	return c == RevokedOwnerOffboarded || c == RevokedSecretDeleted
}

// CausedRevoker is an optional Store extension that records why a grant was
// revoked. A store without it revokes as before and its revocations have no
// cause, which costs only the refusal a project would otherwise be told.
type CausedRevoker interface {
	// RevokeGrantWithCause is RevokeGrant recording the cause. Revoking an
	// already-revoked grant changes neither its time nor its cause.
	RevokeGrantWithCause(id string, at time.Time, cause RevocationCause) error
}

// SupersedingRevoker is an optional Store extension that revokes a grant as
// superseded, naming its successor (Task 20403). A store without it records
// the supersession as a revocation with cause RevokedSuperseded and no
// successor, so a lease carrying the grant is withdrawn rather than kept on the
// successor's authority: less access, never more.
type SupersedingRevoker interface {
	RevokeGrantSuperseded(id string, at time.Time, successorID string) error
}

// withdrawnDescription explains a grant withdrawn from a personal secret that
// still exists — kept under a legal hold when its owner was offboarded.
func withdrawnDescription(s Secret, g Grant) string {
	return fmt.Sprintf("%s %q, a personal credential of %s, was withdrawn on %s when its owner was offboarded; "+
		"grant this project a credential that somebody still on this hub owns",
		s.Kind, s.Name, s.Owner, g.RevokedAt.UTC().Format("2006-01-02"))
}

// RefusedCredential is a grant a lease was aimed at and could not honour
// because of something done elsewhere (Task 20400): the secret behind it was
// destroyed, or the grant was withdrawn when the secret's owner was offboarded.
//
// A lease refuses grants for other reasons too — expiry, an operator's
// revocation, a withholding — and every one of those lands in the audit trail.
// This one is also handed back to the caller, because it is the refusal the
// people running the project can do nothing about from inside it and cannot
// see the cause of: often the person who owned the credential left. The
// dispatcher puts it in front of them.
//
// Metadata only, like every field on Event.
type RefusedCredential struct {
	GrantID    string    `json:"grant_id"`
	SecretID   string    `json:"secret_id"`
	SecretName string    `json:"secret_name,omitempty"`
	Kind       Kind      `json:"kind,omitempty"`
	Owner      string    `json:"owner,omitempty"`
	DeletedAt  time.Time `json:"deleted_at,omitempty"`
	// Reason is the refusal as the lease's audit row records it.
	Reason string `json:"reason"`
}

// deletedSecretRefusal explains a grant whose secret is gone, naming it when
// the store kept its tombstone. ok is false when the secret is not known to
// have been deleted — the store keeps no tombstones, or never deleted it.
func (b *Broker) deletedSecretRefusal(g Grant) (Tombstone, string, bool) {
	t, ok := b.Tombstone(g.SecretID)
	if !ok {
		return Tombstone{}, "", false
	}
	return t, fmt.Sprintf("%s; %s", t.Describe(), t.remedy()), true
}
