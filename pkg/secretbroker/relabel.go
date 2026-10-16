package secretbroker

// relabel.go: a live lease follows its executor's labels (Task 20432).
//
// A lease is issued to a Requester, and a label grant is in it because the
// requester's labels matched. Those labels are the hub's record of the
// executor (ExecutorRecords), and the record can change while the lease is
// held: an operator edits a device's labels, or a configured executor's in the
// hub's configuration. A lease still judged by the labels it was issued under
// would keep a grant its executor no longer qualifies for until it lapsed —
// and Extend would go on renewing it, since the old labels still match.
//
// So the hub relabels the lease: from then on Extend, WithdrawnGrants, a
// renewal and a process taking the lease over all judge its grants by the new
// labels, and the grants they no longer match are taken back with Task 20403's
// semantics — WithdrawnGrants names them, and the hub withdraws each from
// every holder (pkg/ui). The record is rewritten too, so a process that adopts
// the run judges the lease as this one does.

import (
	"fmt"
	"maps"
	"strings"
)

// LeaseLabelStore is an optional LeaseStore extension that rewrites the labels
// of a held lease's requester if holder still holds it (Task 20432). A store
// without it keeps the labels a record was written with, and a process taking
// such a lease over relabels it again when it finds the record and the hub
// disagree.
type LeaseLabelStore interface {
	SetLeaseLabels(id, holder string, labels map[string]string) (bool, error)
}

// HeldRequester returns the requester the live lease leaseID is judged as, and
// whether this broker holds it.
func (b *Broker) HeldRequester(leaseID string) (r Requester, held bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.leases[leaseID]
	if !ok {
		return r, false
	}
	r = st.requester
	r.Labels = maps.Clone(r.Labels)
	return r, true
}

// RelabelLease judges the live lease leaseID as its executor carrying labels
// from now on, and reports whether that changed anything.
//
// It takes nothing back itself: the grants the new labels no longer match are
// what WithdrawnGrants reports next, for the caller to withdraw from every
// holder — the material is in workloads the broker cannot reach. The lease's
// App-token slots keep the requester they were minted for; a grant dropped
// from the lease ends its slots.
func (b *Broker) RelabelLease(leaseID string, labels map[string]string) (bool, error) {
	var next map[string]string
	if len(labels) > 0 {
		next = maps.Clone(labels)
	}
	b.recordMu.Lock()
	defer b.recordMu.Unlock()

	b.mu.Lock()
	st, ok := b.leases[leaseID]
	if !ok {
		b.mu.Unlock()
		return false, wrapf(ErrLeaseNotFound, "lease %s is not held by this broker", leaseID)
	}
	if SameLabels(st.requester.Labels, next) {
		b.mu.Unlock()
		return false, nil
	}
	// The field alone, not the struct: Release reads the requester's other
	// fields once the lease is out of the map, without the lock.
	st.requester.Labels = next
	recorded := st.recorded
	b.mu.Unlock()

	if recorded {
		if err := b.rewriteLeaseLabels(leaseID, next); err != nil {
			return true, err
		}
	}
	return true, nil
}

// rewriteLeaseLabels writes a held lease's labels into its durable record. A
// record another process holds now is that process's: ErrLeaseMoved.
func (b *Broker) rewriteLeaseLabels(leaseID string, labels map[string]string) error {
	ls, ok := b.leaseRecords()
	if !ok {
		return nil
	}
	store, ok := ls.(LeaseLabelStore)
	if !ok {
		return nil
	}
	wrote, err := store.SetLeaseLabels(leaseID, b.leaseHolder, labels)
	if err != nil {
		return fmt.Errorf("secretbroker: record the labels of lease %s: %w", leaseID, err)
	}
	if !wrote {
		return wrapf(ErrLeaseMoved, "lease %s is held by another hub process now", leaseID)
	}
	return nil
}

// LabelWithdrawal is one grant a relabeled lease no longer qualifies for.
type LabelWithdrawal struct {
	GrantID string
	// Subject is the label selector the grant — or the grant it stands on —
	// was issued to.
	Subject string
	// Reason is the sentence the holders and the audit trail are told.
	Reason string
}

// LabelWithdrawals returns the grants the live lease leaseID carries whose
// authority is a label grant that its requester's labels no longer match: the
// part of WithdrawnGrants a label change is responsible for, each with a
// reason that says so. was is what the labels were, for the sentence.
func (b *Broker) LabelWithdrawals(leaseID string, was map[string]string) []LabelWithdrawal {
	requester, ok := b.HeldRequester(leaseID)
	if !ok {
		return nil
	}
	var out []LabelWithdrawal
	for _, wg := range b.WithdrawnGrants(leaseID) {
		g, err := b.authorityFor(wg.GrantID)
		if err != nil || !g.Subject.LabelSubject() || g.Subject.Matches(requester) {
			continue
		}
		via := ""
		if g.ID != wg.GrantID {
			via = ", which grant " + wg.GrantID + " stands on,"
		}
		out = append(out, LabelWithdrawal{
			GrantID: wg.GrantID,
			Subject: g.Subject.String(),
			Reason: "grant " + g.ID + via + " is issued to " + g.Subject.String() + " and executor " +
				strings.TrimSpace(requester.ExecutorID) + " no longer carries those labels: the hub's record of " +
				"them changed from " + FormatLabels(was) + " to " + FormatLabels(requester.Labels),
		})
	}
	return out
}
