package secretbroker

// leaserevocation.go: a lease revocation outlives the hub process that held
// the lease (Task 20419).
//
// Revoking a lease used to be a message: every live hub process took the
// lease back from what it held, and that was all. A lease whose holder had
// died was held by nobody, so the message reached nothing — and the process
// that adopted the dead holder's run then took the lease over (Restore), which
// checks that each grant still stands and had no way to know an incident
// responder had revoked the lease itself in between. The revocation was
// silently undone, with the git proxy and Kubernetes monitor sessions the lease
// fed restored behind it.
//
// A broker over a store that implements LeaseRevocationStore now writes the
// revocation down before any holder is asked, and consults it wherever a lease
// changes hands or is kept alive:
//
//	Restore refuses a revoked lease with ErrLeaseRevoked, so the process
//	adopting the run takes the material back instead of keeping it; a
//	revocation naming one grant of the lease withdraws that grant as a revoked
//	grant is withdrawn, and the lease keeps the others.
//
//	Extend refuses a revoked lease, so a holder that never heard of the
//	revocation — a member the fan-out could not reach — stops keeping it alive,
//	and its own janitor takes it back.
//
// A revocation is pending until some process found the material taken back
// from every holder (SettleLeaseRevocation). What a pending one means is the
// caller's business; the broker only records and refuses.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// LeaseRevocation is the durable account of a lease, or one grant of it,
// revoked.
type LeaseRevocation struct {
	LeaseID string
	// GrantID narrows the revocation to one grant of the lease; "" is the
	// whole lease.
	GrantID string
	// Action is how the material is taken back, "scrub" or "kill".
	Action string
	Reason string
	Actor  string
	// ExecutorID and ProjectID name who the lease was issued to.
	ExecutorID string
	ProjectID  string
	// Holder is the hub process that held the lease when it was revoked, ""
	// when none did.
	Holder    string
	RevokedAt time.Time
	// EnforcedAt is when a process found the material taken back from every
	// holder; zero while the revocation is pending.
	EnforcedAt time.Time
	EnforcedBy string
	// Detail is the last account of why a pending revocation is pending.
	Detail string
}

// Pending reports whether the revocation is not yet enforced.
func (r LeaseRevocation) Pending() bool { return r.EnforcedAt.IsZero() }

// Whole reports whether the revocation takes the whole lease.
func (r LeaseRevocation) Whole() bool { return strings.TrimSpace(r.GrantID) == "" }

// LeaseRevocationStore persists lease revocations. Optional: a store without
// it revokes as every broker did before Task 20419, by message alone.
type LeaseRevocationStore interface {
	// PutLeaseRevocation records a revocation; recording one already there
	// re-opens it (see statedb.PutLeaseRevocation).
	PutLeaseRevocation(r LeaseRevocation) error
	// LeaseRevocations returns every revocation of one lease.
	LeaseRevocations(leaseID string) ([]LeaseRevocation, error)
	// ListLeaseRevocations returns every revocation, or only the pending.
	ListLeaseRevocations(pendingOnly bool) ([]LeaseRevocation, error)
	// SettleLeaseRevocation marks a pending revocation enforced, and reports
	// whether it was pending.
	SettleLeaseRevocation(leaseID, grantID, by, detail string, at time.Time) (bool, error)
	// NoteLeaseRevocation records why a pending revocation is still pending.
	NoteLeaseRevocation(leaseID, grantID, detail string) error
}

// revocationStore returns the store's LeaseRevocationStore, if it keeps one.
func (b *Broker) revocationStore() (LeaseRevocationStore, bool) {
	rs, ok := b.store.(LeaseRevocationStore)
	return rs, ok
}

// KeepsLeaseRevocations reports whether this broker records revocations.
func (b *Broker) KeepsLeaseRevocations() bool {
	_, ok := b.revocationStore()
	return ok
}

// RecordLeaseRevocation writes rev down, filling in who the lease was issued
// to and who holds it from the lease's record where the caller did not, and
// returns what was recorded. recorded is false with a nil error when this
// broker keeps no revocations.
//
// It records nothing about the lease's material and asks no holder anything:
// that is the caller's fan-out, which this record outlives.
func (b *Broker) RecordLeaseRevocation(rev LeaseRevocation) (LeaseRevocation, bool, error) {
	rev.LeaseID = strings.TrimSpace(rev.LeaseID)
	rev.GrantID = strings.TrimSpace(rev.GrantID)
	if rev.LeaseID == "" {
		return rev, false, errors.New("secretbroker: a revocation needs a lease id")
	}
	rs, ok := b.revocationStore()
	if !ok {
		return rev, false, nil
	}
	if rev.Action == "" {
		rev.Action = "scrub"
	}
	if rev.RevokedAt.IsZero() {
		rev.RevokedAt = b.now()
	}
	if rec, err := b.LeaseRecordFor(rev.LeaseID); err == nil {
		if rev.Holder == "" {
			rev.Holder = rec.Holder
		}
		if rev.ExecutorID == "" {
			rev.ExecutorID = rec.Requester.ExecutorID
		}
		if rev.ProjectID == "" {
			rev.ProjectID = rec.Requester.ProjectID
		}
	} else if !errors.Is(err, ErrLeaseNotFound) {
		return rev, false, fmt.Errorf("secretbroker: read lease %s before recording its revocation: %w", rev.LeaseID, err)
	}
	if err := rs.PutLeaseRevocation(rev); err != nil {
		return rev, false, fmt.Errorf("secretbroker: record revocation of lease %s: %w", rev.LeaseID, err)
	}
	return rev, true, nil
}

// LeaseRevocationsFor returns the revocations recorded for leaseID, nil when
// this broker keeps none.
func (b *Broker) LeaseRevocationsFor(leaseID string) ([]LeaseRevocation, error) {
	rs, ok := b.revocationStore()
	if !ok {
		return nil, nil
	}
	return rs.LeaseRevocations(leaseID)
}

// PendingLeaseRevocations returns every revocation not yet enforced, nil when
// this broker keeps none.
func (b *Broker) PendingLeaseRevocations() ([]LeaseRevocation, error) {
	rs, ok := b.revocationStore()
	if !ok {
		return nil, nil
	}
	return rs.ListLeaseRevocations(true)
}

// SettleLeaseRevocation records that a revocation's material was taken back
// from every holder, by the hub process by.
func (b *Broker) SettleLeaseRevocation(leaseID, grantID, by, detail string) (bool, error) {
	rs, ok := b.revocationStore()
	if !ok {
		return false, nil
	}
	return rs.SettleLeaseRevocation(leaseID, grantID, by, detail, b.now())
}

// NoteLeaseRevocation records why a revocation is still pending.
func (b *Broker) NoteLeaseRevocation(leaseID, grantID, detail string) error {
	rs, ok := b.revocationStore()
	if !ok {
		return nil
	}
	return rs.NoteLeaseRevocation(leaseID, grantID, detail)
}

// leaseRevoked returns the whole-lease revocation recorded for leaseID and the
// grants a narrower one names. err is set when the store could not be read:
// that says nothing either way, and a caller must not hand the lease on.
func (b *Broker) leaseRevoked(leaseID string) (whole *LeaseRevocation, grants map[string]LeaseRevocation, err error) {
	rs, ok := b.revocationStore()
	if !ok {
		return nil, nil, nil
	}
	revs, err := rs.LeaseRevocations(leaseID)
	if err != nil {
		return nil, nil, err
	}
	for i := range revs {
		r := revs[i]
		if r.Whole() {
			whole = &r
			continue
		}
		if grants == nil {
			grants = map[string]LeaseRevocation{}
		}
		grants[r.GrantID] = r
	}
	return whole, grants, nil
}

// describeRevocation renders a revocation for an error or an audit reason.
func describeRevocation(r LeaseRevocation) string {
	var b strings.Builder
	b.WriteString("revoked")
	if r.Actor != "" {
		b.WriteString(" by " + r.Actor)
	}
	if !r.RevokedAt.IsZero() {
		b.WriteString(" at " + r.RevokedAt.UTC().Format(time.RFC3339))
	}
	if r.Reason != "" {
		b.WriteString(" (" + r.Reason + ")")
	}
	return b.String()
}

// RevokedLeaseError is the refusal of a revoked lease, carrying the
// revocation so a caller enforcing it can act as the operator asked.
type RevokedLeaseError struct {
	Revocation LeaseRevocation
	msg        string
}

func (e *RevokedLeaseError) Error() string { return e.msg }

// Unwrap lets errors.Is(err, ErrLeaseRevoked) match.
func (e *RevokedLeaseError) Unwrap() error { return ErrLeaseRevoked }

// refuseRevoked audits and returns the refusal of a lease that was revoked.
func (b *Broker) refuseRevoked(ev Event, r LeaseRevocation, what string) error {
	msg := fmt.Sprintf("lease %s was %s and %s", r.LeaseID, describeRevocation(r), what)
	ev.Decision = DecisionDeny
	ev.Reason = msg
	b.emit(ev)
	return &RevokedLeaseError{Revocation: r, msg: "secretbroker: " + msg}
}

// RevocationOf extracts the revocation an error refusing a revoked lease
// carries.
func RevocationOf(err error) (LeaseRevocation, bool) {
	var re *RevokedLeaseError
	if errors.As(err, &re) {
		return re.Revocation, true
	}
	return LeaseRevocation{}, false
}
