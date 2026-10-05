package secretbroker

// leaserecord.go: a lease outlives the hub process that issued it (Task 20382).
//
// A lease used to exist only in the broker that issued it — in the memory of
// one hub process. That process kept it alive while its run was live, swept it
// when it lapsed and released it when the run ended. When the process stopped
// — a deploy, a crash, the nightly restart of a hub while a device was running
// a task — the run carried on and its credentials were held by nobody: never
// extended, never swept, never released, and absent from every list an
// operator could read.
//
// A broker built WithLeaseRecords writes each lease it issues to a LeaseStore,
// naming itself the holder, and keeps the record in step: Extend moves its
// deadline, Release deletes it. Both are fenced on the holder, so a process
// that lost a lease to another — the one that adopted its run — can neither
// keep it alive nor end it.
//
// Restore is how a lease changes hands: the process adopting a run takes the
// lease over, after the same checks Extend makes, and from then on it is that
// process's to extend and release. RetireRecord ends a recorded lease that
// nobody will take over — its run ended while no hub held it, or it lapsed.
//
// What a record carries is ids and names: the requester, the actor, the kinds,
// the grants. Never material. A process that takes a lease over has the grants
// and can re-derive whatever it needs from them, so nothing that could be
// replayed is ever written down.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// LeaseRecord is the durable account of a live lease.
type LeaseRecord struct {
	ID string
	// Holder is the hub process that keeps the lease alive and owes its
	// release.
	Holder    string
	Requester Requester
	Actor     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Kinds     []Kind
	GrantIDs  []string
}

// LeaseStore persists LeaseRecords. Optional: a Store that does not implement
// it keeps leases in memory only, as every broker did before Task 20382.
//
// The conditional writes are what make a lease safe to hand over: each one
// names the holder it expects, so of two processes racing to take the same
// lease over only one succeeds, and the one that lost it cannot write over the
// winner's record.
type LeaseStore interface {
	// PutLease inserts or replaces a record.
	PutLease(r LeaseRecord) error
	// GetLease returns one record, or a wrapped ErrLeaseNotFound.
	GetLease(id string) (LeaseRecord, error)
	// ListLeases returns every record.
	ListLeases() ([]LeaseRecord, error)
	// ExtendLease moves a record's deadline if holder holds it, and reports
	// whether it did.
	ExtendLease(id, holder string, expiresAt time.Time) (bool, error)
	// TakeLease moves a record from one holder to another if from still holds
	// it, and reports whether it did.
	TakeLease(id, from, holder string) (bool, error)
	// DeleteLease removes a record if holder holds it, and reports whether it
	// did.
	DeleteLease(id, holder string) (bool, error)
}

// WithLeaseRecords makes every non-empty lease this broker issues durable,
// held by holder — the hub process's cluster member id. An empty holder
// records nothing: a lease that names no process is one nothing could take
// over from it.
func WithLeaseRecords(holder string) Option {
	return func(b *Broker) {
		b.leaseHolder = strings.TrimSpace(holder)
	}
}

// LeaseHolder returns the process this broker holds leases for, or "".
func (b *Broker) LeaseHolder() string { return b.leaseHolder }

// leaseRecords returns the store's LeaseStore when this broker keeps records.
func (b *Broker) leaseRecords() (LeaseStore, bool) {
	if b.leaseHolder == "" {
		return nil, false
	}
	ls, ok := b.store.(LeaseStore)
	return ls, ok
}

// recordLease writes rec, held by this broker. It reports whether the lease is
// now recorded; false with a nil error means this broker keeps no records.
func (b *Broker) recordLease(rec LeaseRecord) (bool, error) {
	ls, ok := b.leaseRecords()
	if !ok {
		return false, nil
	}
	rec.Holder = b.leaseHolder
	if err := ls.PutLease(rec); err != nil {
		return false, err
	}
	return true, nil
}

// extendRecord moves this broker's record of leaseID to deadline. moved
// reports that the record is not this broker's any more: another process took
// it over, or it was retired.
func (b *Broker) extendRecord(leaseID string, deadline time.Time) (moved bool, err error) {
	ls, ok := b.leaseRecords()
	if !ok {
		return false, nil
	}
	extended, err := ls.ExtendLease(leaseID, b.leaseHolder, deadline)
	if err != nil {
		return false, err
	}
	return !extended, nil
}

// dropRecord deletes this broker's record of leaseID, and reports whether
// another process holds the lease instead — in which case the release is not
// this broker's to make. A record that is simply gone, or a store that cannot
// be read, is not a handover: the release goes ahead.
func (b *Broker) dropRecord(leaseID string) (handedOver bool) {
	ls, ok := b.leaseRecords()
	if !ok {
		return false
	}
	deleted, err := ls.DeleteLease(leaseID, b.leaseHolder)
	if err != nil || deleted {
		return false
	}
	rec, err := ls.GetLease(leaseID)
	if err != nil {
		return false
	}
	return rec.Holder != b.leaseHolder
}

// LeaseRecords returns every recorded lease. Nil when this broker keeps none.
func (b *Broker) LeaseRecords() ([]LeaseRecord, error) {
	ls, ok := b.leaseRecords()
	if !ok {
		return nil, nil
	}
	return ls.ListLeases()
}

// Restore takes over a lease another hub process issued, for the run this one
// adopted: from here on this broker extends it and releases it.
//
// It refuses what Extend would refuse — a lease that lapsed while nobody held
// it, a grant revoked or expired since, a grant no longer issued to the
// requester, a secret that is gone — because taking a lease over is extending
// its life past the process that issued it, and nothing may keep a credential
// alive that its grants no longer allow. A lease another process took over
// first is refused with ErrLeaseMoved.
//
// The returned Lease names the materials the lease carries — grant, secret,
// kind, constraints — and holds none of their values: the workload already has
// them, and this process has no business re-reading them to hold a lease.
func (b *Broker) Restore(ctx context.Context, leaseID string) (*Lease, error) {
	ev := Event{Action: ActionRenew, LeaseID: leaseID}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ls, ok := b.leaseRecords()
	if !ok {
		return nil, b.denyf(ev, ErrLeaseNotFound,
			"lease %s cannot be taken over: this broker keeps no lease records", leaseID)
	}
	rec, err := ls.GetLease(leaseID)
	if err != nil {
		if errors.Is(err, ErrLeaseNotFound) {
			return nil, b.denyf(ev, ErrLeaseNotFound,
				"lease %s has no record to take over: it was released, or issued by a hub that kept none", leaseID)
		}
		return nil, fmt.Errorf("secretbroker: read lease %s: %w", leaseID, err)
	}
	ev.Actor = rec.Actor
	ev.ExecutorID = rec.Requester.ExecutorID
	ev.ProjectID = rec.Requester.ProjectID
	ev.RunID = rec.Requester.RunID

	now := b.now()
	if !now.Before(rec.ExpiresAt) {
		return nil, b.denyf(ev, ErrLeaseExpired,
			"lease %s lapsed at %s while no hub process held it, and cannot be taken over",
			leaseID, rec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if _, err := b.recheckGrants(ev, leaseID, rec.Requester, rec.GrantIDs, now); err != nil {
		return nil, err
	}
	from := rec.Holder
	if from != b.leaseHolder {
		took, err := ls.TakeLease(leaseID, from, b.leaseHolder)
		if err != nil {
			return nil, fmt.Errorf("secretbroker: take over lease %s: %w", leaseID, err)
		}
		if !took {
			return nil, b.denyf(ev, ErrLeaseMoved,
				"lease %s was taken over by another hub process first", leaseID)
		}
	}

	b.mu.Lock()
	b.leases[leaseID] = &leaseState{
		requester: rec.Requester, actor: rec.Actor, expiresAt: rec.ExpiresAt,
		kinds: append([]Kind(nil), rec.Kinds...), grantIDs: append([]string(nil), rec.GrantIDs...),
		recorded: true,
	}
	b.mu.Unlock()
	for _, k := range rec.Kinds {
		hubmetrics.LeaseEvents.Inc(string(k), hubmetrics.LeaseRenewed)
	}

	ev.Decision = DecisionAllow
	ev.ExpiresAt = rec.ExpiresAt
	ev.Reason = "taken over by the hub process that adopted its run"
	if from != "" && from != b.leaseHolder {
		ev.Reason += " (held until then by " + from + ")"
	}
	b.emit(ev)

	return &Lease{
		ID:         leaseID,
		ExecutorID: rec.Requester.ExecutorID,
		ProjectID:  rec.Requester.ProjectID,
		RunID:      rec.Requester.RunID,
		IssuedAt:   rec.IssuedAt,
		ExpiresAt:  rec.ExpiresAt,
		Materials:  b.heldMaterials(rec.GrantIDs),
	}, nil
}

// heldMaterials describes the materials a taken-over lease carries without
// opening any of them.
func (b *Broker) heldMaterials(grantIDs []string) []Material {
	var out []Material
	for _, id := range grantIDs {
		g, err := b.store.GetGrant(id)
		if err != nil {
			continue
		}
		s, err := b.store.GetSecret(g.SecretID)
		if err != nil {
			continue
		}
		out = append(out, Material{
			GrantID:     g.ID,
			SecretID:    s.ID,
			SecretName:  s.Name,
			Kind:        s.Kind,
			Constraints: g.Constraints,
			Summary:     "delivered before the hub process holding it stopped",
		})
	}
	return out
}

// RetireRecord ends a recorded lease that no hub process will take over: its
// run ended while nobody held it, or it lapsed and has been swept from the
// devices that held it. The record goes — conditionally on it still being
// held by rec.Holder, so a lease a process took over meanwhile is left alone —
// and the lease's trail gets the release row its holder never wrote. It
// reports whether the record was retired.
func (b *Broker) RetireRecord(rec LeaseRecord, reason string) (bool, error) {
	ls, ok := b.store.(LeaseStore)
	if !ok {
		return false, nil
	}
	deleted, err := ls.DeleteLease(rec.ID, rec.Holder)
	if err != nil || !deleted {
		return false, err
	}
	b.mu.Lock()
	delete(b.leases, rec.ID)
	b.mu.Unlock()
	// Any App token this broker minted for the lease goes too. A token minted
	// by the process that stopped is out of anyone's reach and lapses on
	// GitHub's own clock.
	b.destroyLeaseTokens(context.Background(), rec.ID, "lease retired: "+reason)
	for _, k := range rec.Kinds {
		hubmetrics.LeaseEvents.Inc(string(k), hubmetrics.LeaseRevoked)
	}
	b.emit(Event{
		Action:     ActionRelease,
		Actor:      rec.Actor,
		LeaseID:    rec.ID,
		ExecutorID: rec.Requester.ExecutorID,
		ProjectID:  rec.Requester.ProjectID,
		RunID:      rec.Requester.RunID,
		Decision:   DecisionAllow,
		Reason:     reason,
	})
	return true, nil
}

// LeaseRecordFor returns the record of leaseID, or a wrapped ErrLeaseNotFound.
func (b *Broker) LeaseRecordFor(leaseID string) (LeaseRecord, error) {
	ls, ok := b.store.(LeaseStore)
	if !ok {
		return LeaseRecord{}, wrapf(ErrLeaseNotFound, "lease %s: no lease records are kept here", leaseID)
	}
	return ls.GetLease(leaseID)
}

// HeldElsewhere reports whether leaseID is recorded as held by a hub process
// other than this broker's: taken over with its run. False when this broker
// keeps no records or the record cannot be read — the answer that leaves a
// lease with the process that issued it.
func (b *Broker) HeldElsewhere(leaseID string) bool {
	ls, ok := b.leaseRecords()
	if !ok {
		return false
	}
	rec, err := ls.GetLease(leaseID)
	if err != nil {
		return false
	}
	return rec.Holder != b.leaseHolder
}

// RedactionValues returns the plaintext a held lease's stored credentials
// carry — the delivered keys of its env secrets, the token of a personal
// access token — for a hub process that must scrub its workload's output
// without having issued it: the one that took the lease over with its run
// (Task 20382). The issuing process scrubbed with what it delivered; a
// rehydrated handle has nothing, because a dispatched Spec's secrets are never
// persisted.
//
// It renders nothing and mints nothing: a GitHub App token was minted for the
// lease by the process that issued it and is not in the store, and it is the
// shape the pattern-based scrubbers already recognise. Nil for a lease this
// broker does not hold.
func (b *Broker) RedactionValues(leaseID string) []string {
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	var grantIDs []string
	if ok {
		grantIDs = append(grantIDs, st.grantIDs...)
	}
	b.mu.Unlock()
	var out []string
	for _, id := range grantIDs {
		g, err := b.store.GetGrant(id)
		if err != nil {
			continue
		}
		s, err := b.store.GetSecret(g.SecretID)
		if err != nil || (s.Kind != KindEnv && s.Kind != KindGitHubPAT) {
			continue
		}
		plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
		if err != nil {
			continue
		}
		switch s.Kind {
		case KindEnv:
			for k, v := range jsonUnmarshalEnv(plaintext, s.Name) {
				if deliverableEnvKey(g.Constraints, k) && v != "" {
					out = append(out, v)
				}
			}
		case KindGitHubPAT:
			if token := strings.TrimSpace(string(plaintext)); token != "" {
				out = append(out, token)
			}
		}
		zero(plaintext)
	}
	return out
}
