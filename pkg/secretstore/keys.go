package secretstore

// The sealing-key registry and rotation adapter (Task 20181).
//
// Same split as the rest of this package: pkg/statedb owns the SQL,
// pkg/secretbroker owns the crypto and the rotation algorithm, and this file
// converts between them. Implementing secretbroker.KeyStore here — rather than
// folding key management into secretbroker.Store — is what lets the broker's
// in-memory test doubles stay twenty lines long while every real hub gets
// envelope encryption and online rotation for free, because pkg/secretstore is
// what a real hub hands to secretbroker.New.
//
// Nothing here decrypts. A KEK record crossing this boundary is a salt and a
// check value; a sealed row is a wrapped DEK and a ciphertext. Neither is key
// material without CLOOP_SECRET_KEY, which this package never reads.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Compile-time proof that the adapter satisfies the three contracts rotation
// needs. Without these, adding a method to one of the interfaces would fail
// somewhere far away — at the call site that passes a Store where a KeyStore
// is wanted — instead of here.
var (
	_ secretbroker.KeyStore      = (*Store)(nil)
	_ secretbroker.RotationStore = (*Store)(nil)
	_ secretbroker.SealedSet     = (*Store)(nil)
)

// ---------------------------------------------------------------------------
// KeyStore
// ---------------------------------------------------------------------------

// PutKEK persists a key-encryption key record.
func (s *Store) PutKEK(k secretbroker.KEKRecord) error {
	return translateKeyErr(s.db.PutKEK(statedb.KEKRow{
		ID:         k.ID,
		Salt:       k.Salt,
		State:      k.State,
		CheckValue: k.CheckValue,
		CreatedAt:  formatTime(k.CreatedAt),
		CreatedBy:  k.CreatedBy,
		RetiredAt:  formatTime(k.RetiredAt),
	}))
}

// ListKEKs returns every KEK, retired ones included.
func (s *Store) ListKEKs() ([]secretbroker.KEKRecord, error) {
	rows, err := s.db.ListKEKs()
	if err != nil {
		return nil, translateKeyErr(err)
	}
	out := make([]secretbroker.KEKRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, toKEK(row))
	}
	return out, nil
}

// PrimaryKEK returns the current primary, if any.
func (s *Store) PrimaryKEK() (secretbroker.KEKRecord, bool, error) {
	row, ok, err := s.db.PrimaryKEK()
	if err != nil || !ok {
		return secretbroker.KEKRecord{}, ok, translateKeyErr(err)
	}
	return toKEK(row), true, nil
}

// PromoteKEK makes a key the sole primary.
func (s *Store) PromoteKEK(id string, at time.Time) error {
	return translateKeyErr(s.db.PromoteKEK(id, at))
}

// RetireKEK destroys a key's salt, refusing while rows still reference it.
func (s *Store) RetireKEK(id string, at time.Time) error {
	return translateKeyErr(s.db.RetireKEK(id, at))
}

// ---------------------------------------------------------------------------
// RotationStore
// ---------------------------------------------------------------------------

func toKEK(row statedb.KEKRow) secretbroker.KEKRecord {
	return secretbroker.KEKRecord{
		ID:         row.ID,
		Salt:       row.Salt,
		State:      row.State,
		CheckValue: row.CheckValue,
		CreatedAt:  parseTime(row.CreatedAt),
		CreatedBy:  row.CreatedBy,
		RetiredAt:  parseTime(row.RetiredAt),
	}
}

// PutRotation records rotation progress.
func (s *Store) PutRotation(r secretbroker.RotationRecord) error {
	return translateKeyErr(s.db.PutRotation(statedb.RotationRow{
		ID:         r.ID,
		ToKeyID:    r.ToKeyID,
		State:      r.State,
		StartedAt:  formatTime(r.StartedAt),
		UpdatedAt:  formatTime(r.UpdatedAt),
		FinishedAt: formatTime(r.FinishedAt),
		StartedBy:  r.StartedBy,
		Total:      r.Total,
		Rewrapped:  r.Rewrapped,
		Skipped:    r.Skipped,
		Failed:     r.Failed,
		LastError:  r.LastError,
	}))
}

// ListRotations returns rotation history, newest first.
func (s *Store) ListRotations(limit int) ([]secretbroker.RotationRecord, error) {
	rows, err := s.db.ListRotations(limit)
	if err != nil {
		return nil, translateKeyErr(err)
	}
	out := make([]secretbroker.RotationRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, secretbroker.RotationRecord{
			ID:         row.ID,
			ToKeyID:    row.ToKeyID,
			State:      row.State,
			StartedAt:  parseTime(row.StartedAt),
			UpdatedAt:  parseTime(row.UpdatedAt),
			FinishedAt: parseTime(row.FinishedAt),
			StartedBy:  row.StartedBy,
			Total:      row.Total,
			Rewrapped:  row.Rewrapped,
			Skipped:    row.Skipped,
			Failed:     row.Failed,
			LastError:  row.LastError,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// SealedSet
// ---------------------------------------------------------------------------

// SealedSetName identifies this population in rotation reports and, more
// importantly, namespaces every envelope's associated data.
func (s *Store) SealedSetName() string { return secretbroker.SetSecrets }

// CountSealedByKey groups stored secrets by the key sealing them.
func (s *Store) CountSealedByKey() (map[string]int, error) {
	counts, err := s.db.CountBrokerSecretsByKey()
	return counts, translateKeyErr(err)
}

// ListSealedNotUnder returns secrets still sealed under some other key.
//
// A secret's associated data is its own ID, matching what Broker.Mint sealed
// it with. Getting this wrong would not silently weaken anything — the rewrap
// would fail authentication and the row would be reported as stuck — which is
// the property AAD binding is supposed to have.
func (s *Store) ListSealedNotUnder(keyID string, limit int) ([]secretbroker.SealedRow, error) {
	rows, err := s.db.ListBrokerSecretsNotUnderKey(keyID, limit)
	if err != nil {
		return nil, translateKeyErr(err)
	}
	out := make([]secretbroker.SealedRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, secretbroker.SealedRow{
			ID:  row.ID,
			AAD: secretbroker.AADFor(secretbroker.SetSecrets, row.ID),
			Env: secretbroker.Envelope{
				KeyID:      row.KeyID,
				WrappedDEK: row.WrappedDEK,
				Ciphertext: row.Ciphertext,
			},
		})
	}
	return out, nil
}

// ReplaceSealed swaps a secret's envelope under compare-and-swap.
func (s *Store) ReplaceSealed(id string, expect, next secretbroker.Envelope) (bool, error) {
	ok, err := s.db.ReplaceBrokerSecretSealed(id,
		statedb.SealedRow{KeyID: expect.KeyID, WrappedDEK: expect.WrappedDEK, Ciphertext: expect.Ciphertext},
		statedb.SealedRow{KeyID: next.KeyID, WrappedDEK: next.WrappedDEK, Ciphertext: next.Ciphertext})
	return ok, translateKeyErr(err)
}

// ---------------------------------------------------------------------------

// translateKeyErr maps storage sentinels onto broker sentinels so a caller
// matches against one set — the same reason translateErr exists for secrets
// and grants.
func translateKeyErr(err error) error {
	switch {
	case err == nil:
		return nil
	case isErr(err, statedb.ErrKEKInUse):
		return fmt.Errorf("%w: %v", secretbroker.ErrKeyInUse, err)
	case isErr(err, statedb.ErrKEKNotFound):
		return fmt.Errorf("%w: %v", secretbroker.ErrKeyUnknown, err)
	default:
		return err
	}
}
