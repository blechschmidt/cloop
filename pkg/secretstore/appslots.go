package secretstore

// appslots.go persists the broker's GitHub App token slots (Task 20383): the
// scope each token a lease holds was minted at, so the process that takes the
// lease over re-mints at that scope. The record type has no field a token
// could travel in; tests/security scans the table for one regardless.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Compile-time proof that the adapter keeps slot records.
var _ secretbroker.AppSlotStore = (*Store)(nil)

// PutAppSlot records a slot.
func (s *Store) PutAppSlot(r secretbroker.AppSlotRecord) error {
	scope, err := secretbroker.MarshalAppSlotScope(r)
	if err != nil {
		return fmt.Errorf("secretstore: encode app token slot %s/%s: %w", r.LeaseID, r.GrantID, err)
	}
	return s.db.PutAppTokenSlot(statedb.AppTokenSlotRow{
		LeaseID:        r.LeaseID,
		GrantID:        r.GrantID,
		Holder:         r.Holder,
		SecretID:       r.SecretID,
		SecretName:     r.SecretName,
		Scope:          scope,
		Guarded:        r.Guarded,
		SessionID:      r.SessionID,
		EnvExported:    r.EnvExported,
		FileName:       r.FileName,
		TokenExpiresAt: r.TokenExpiresAt,
		UpdatedAt:      time.Now().UTC(),
	})
}

// ListAppSlots returns the slots of leaseID. One whose scope cannot be read is
// skipped: a restore that cannot know a token's scope must not mint one.
func (s *Store) ListAppSlots(leaseID string) ([]secretbroker.AppSlotRecord, error) {
	rows, err := s.db.ListAppTokenSlots(leaseID)
	if err != nil {
		return nil, err
	}
	out := make([]secretbroker.AppSlotRecord, 0, len(rows))
	for _, row := range rows {
		rec := secretbroker.AppSlotRecord{
			LeaseID:        row.LeaseID,
			GrantID:        row.GrantID,
			Holder:         row.Holder,
			SecretID:       row.SecretID,
			SecretName:     row.SecretName,
			Guarded:        row.Guarded,
			SessionID:      row.SessionID,
			EnvExported:    row.EnvExported,
			FileName:       row.FileName,
			TokenExpiresAt: row.TokenExpiresAt,
		}
		if err := secretbroker.UnmarshalAppSlotScope(row.Scope, &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// UpdateAppSlot rewrites a slot's mutable fields if r.Holder holds it.
func (s *Store) UpdateAppSlot(r secretbroker.AppSlotRecord) (bool, error) {
	scope, err := secretbroker.MarshalAppSlotScope(r)
	if err != nil {
		return false, err
	}
	return s.db.UpdateAppTokenSlot(statedb.AppTokenSlotRow{
		LeaseID:        r.LeaseID,
		GrantID:        r.GrantID,
		Holder:         r.Holder,
		Guarded:        r.Guarded,
		SessionID:      r.SessionID,
		EnvExported:    r.EnvExported,
		TokenExpiresAt: r.TokenExpiresAt,
		Scope:          scope,
	})
}

// TakeAppSlots moves the slots of leaseID from one holder to another.
func (s *Store) TakeAppSlots(leaseID, from, holder string) (int, error) {
	return s.db.TakeAppTokenSlots(leaseID, from, holder)
}

// DeleteAppSlots forgets the slots of leaseID that holder holds.
func (s *Store) DeleteAppSlots(leaseID, holder string) (int, error) {
	return s.db.DeleteAppTokenSlots(leaseID, holder)
}

// DeleteAppSlot forgets one slot if holder holds it.
func (s *Store) DeleteAppSlot(leaseID, grantID, holder string) (bool, error) {
	return s.db.DeleteAppTokenSlot(leaseID, grantID, holder)
}
