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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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
	_ secretbroker.KeyAttributor = (*Store)(nil)
	_ secretbroker.KEKRewrapper  = (*Store)(nil)
	_ secretbroker.RotationStore = (*Store)(nil)
	_ secretbroker.SealedSet     = (*Store)(nil)
)

// ---------------------------------------------------------------------------
// KeyStore
// ---------------------------------------------------------------------------

// PutKEK persists a key-encryption key record.
func (s *Store) PutKEK(k secretbroker.KEKRecord) error {
	row, err := fromKEK(k)
	if err != nil {
		return err
	}
	return translateKeyErr(s.db.PutKEK(row))
}

// fromKEK converts a record to its row. A KMS-held key's annotations are
// stored as a JSON object of base64 values: opaque to SQL, and not secret.
func fromKEK(k secretbroker.KEKRecord) (statedb.KEKRow, error) {
	ann, err := encodeAnnotations(k.KMSAnnotations)
	if err != nil {
		return statedb.KEKRow{}, err
	}
	return statedb.KEKRow{
		ID:             k.ID,
		Salt:           k.Salt,
		State:          k.State,
		CheckValue:     k.CheckValue,
		CreatedAt:      formatTime(k.CreatedAt),
		CreatedBy:      k.CreatedBy,
		RetiredAt:      formatTime(k.RetiredAt),
		Root:           k.Root,
		Wrap:           k.Wrap,
		KMSKeyID:       k.KMSKeyID,
		KMSCiphertext:  k.KMSCiphertext,
		KMSAnnotations: ann,
	}, nil
}

// RewrapKEK replaces a KMS-held key's wrapping under compare-and-swap
// (Task 20433).
func (s *Store) RewrapKEK(id string, expect []byte, next secretbroker.KEKRecord) (bool, error) {
	row, err := fromKEK(next)
	if err != nil {
		return false, err
	}
	ok, err := s.db.RewrapKEK(id, expect, row)
	return ok, translateKeyErr(err)
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

// AttributeKEK records the root a key derives from, once (Task 20425).
func (s *Store) AttributeKEK(id, root string) (bool, error) {
	ok, err := s.db.SetKEKRoot(id, root)
	return ok, translateKeyErr(err)
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
		Root:       row.Root,
		Wrap:       row.Wrap,
		KMSKeyID:   row.KMSKeyID,
		// A column that does not decode leaves the annotations empty, and the
		// KMS then refuses to unwrap the key — naming it — rather than this
		// adapter refusing to list the registry at all.
		KMSCiphertext:  row.KMSCiphertext,
		KMSAnnotations: decodeAnnotations(row.KMSAnnotations),
	}
}

// KEKFromRow converts a registry row read without a Store — a backup's, by a
// restore's preflight or an escrow check — to the record the keyring judges.
func KEKFromRow(row statedb.KEKRow) secretbroker.KEKRecord { return toKEK(row) }

func encodeAnnotations(m map[string][]byte) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	enc := make(map[string]string, len(m))
	for k, v := range m {
		enc[k] = base64.StdEncoding.EncodeToString(v)
	}
	b, err := json.Marshal(enc)
	if err != nil {
		return "", fmt.Errorf("secretstore: encode KMS annotations: %w", err)
	}
	return string(b), nil
}

func decodeAnnotations(s string) map[string][]byte {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var enc map[string]string
	if err := json.Unmarshal([]byte(s), &enc); err != nil {
		return nil
	}
	out := make(map[string][]byte, len(enc))
	for k, v := range enc {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil
		}
		out[k] = b
	}
	return out
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
