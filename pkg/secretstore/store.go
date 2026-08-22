// Package secretstore backs the secret broker with SQLite.
//
// It is a type-converting adapter, in the same shape and for the same
// reasons as pkg/executorstore: pkg/statedb owns the rows and the SQL,
// pkg/secretbroker owns the policy and the crypto, and this package joins
// them. Keeping the broker free of a SQLite dependency is what lets its
// constraint-enforcement logic — the part worth testing exhaustively — be
// tested against an in-memory store with no database file in sight.
//
// The payload crosses this boundary sealed in both directions. Nothing here
// holds a key or decrypts anything.
package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store implements secretbroker.Store over a *statedb.DB.
type Store struct {
	db *statedb.DB
}

// New wraps a database handle.
func New(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("secretstore: nil database")
	}
	return &Store{db: db}, nil
}

// Compile-time proof that the adapter satisfies the broker's contract.
var _ secretbroker.Store = (*Store)(nil)

// PutSecret persists a sealed secret.
func (s *Store) PutSecret(sec secretbroker.Secret) error {
	meta, err := json.Marshal(sec.Metadata)
	if err != nil {
		return fmt.Errorf("secretstore: encode metadata for %s: %w", sec.ID, err)
	}
	return s.db.PutBrokerSecret(statedb.BrokerSecretRow{
		ID:           sec.ID,
		Kind:         string(sec.Kind),
		Name:         sec.Name,
		Payload:      sec.Sealed,
		KeyID:        sec.KeyID,
		WrappedDEK:   sec.WrappedDEK,
		MetadataJSON: string(meta),
		CreatedAt:    formatTime(sec.CreatedAt),
		CreatedBy:    sec.CreatedBy,
	})
}

// GetSecret returns one secret by ID, translating the storage sentinel into
// the broker's so callers can use a single errors.Is target.
func (s *Store) GetSecret(id string) (secretbroker.Secret, error) {
	row, err := s.db.GetBrokerSecret(id)
	if err != nil {
		return secretbroker.Secret{}, translateErr(err)
	}
	return toSecret(row), nil
}

// ListSecrets returns every stored secret.
func (s *Store) ListSecrets() ([]secretbroker.Secret, error) {
	rows, err := s.db.ListBrokerSecrets()
	if err != nil {
		return nil, translateErr(err)
	}
	out := make([]secretbroker.Secret, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSecret(row))
	}
	return out, nil
}

// DeleteSecret removes a secret.
func (s *Store) DeleteSecret(id string) error {
	return translateErr(s.db.DeleteBrokerSecret(id))
}

// PutGrant persists a grant.
func (s *Store) PutGrant(g secretbroker.Grant) error {
	constraints, err := json.Marshal(g.Constraints)
	if err != nil {
		return fmt.Errorf("secretstore: encode constraints for %s: %w", g.ID, err)
	}
	return s.db.PutBrokerGrant(statedb.BrokerGrantRow{
		ID:              g.ID,
		SecretID:        g.SecretID,
		Scope:           g.Scope,
		SubjectType:     string(g.Subject.Type),
		SubjectValue:    encodeSubjectValue(g.Subject),
		ConstraintsJSON: string(constraints),
		ExpiresAt:       formatTime(g.ExpiresAt),
		CreatedAt:       formatTime(g.CreatedAt),
		CreatedBy:       g.CreatedBy,
		RevokedAt:       formatTime(g.RevokedAt),
	})
}

// GetGrant returns one grant by ID.
func (s *Store) GetGrant(id string) (secretbroker.Grant, error) {
	row, err := s.db.GetBrokerGrant(id)
	if err != nil {
		return secretbroker.Grant{}, translateErr(err)
	}
	return toGrant(row)
}

// ListGrants returns every grant.
//
// A row whose constraints or subject cannot be decoded is skipped rather
// than failing the whole listing, but it is skipped in the deny direction:
// a grant the broker cannot read is a grant the broker will not honour, so a
// corrupt row silently loses access rather than silently keeping it.
func (s *Store) ListGrants() ([]secretbroker.Grant, error) {
	rows, err := s.db.ListBrokerGrants()
	if err != nil {
		return nil, translateErr(err)
	}
	out := make([]secretbroker.Grant, 0, len(rows))
	for _, row := range rows {
		g, gerr := toGrant(row)
		if gerr != nil {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

// RevokeGrant stamps a grant revoked.
func (s *Store) RevokeGrant(id string, at time.Time) error {
	return translateErr(s.db.RevokeBrokerGrant(id, at))
}

// Meta reads a broker-scoped metadata value.
func (s *Store) Meta(key string) (string, bool, error) {
	v, ok, err := s.db.BrokerMeta(key)
	return v, ok, translateErr(err)
}

// SetMeta writes a broker-scoped metadata value.
func (s *Store) SetMeta(key, value string) error {
	return translateErr(s.db.SetBrokerMeta(key, value))
}

// ---------------------------------------------------------------------------
// conversions
// ---------------------------------------------------------------------------

func toSecret(row statedb.BrokerSecretRow) secretbroker.Secret {
	var meta map[string]string
	if row.MetadataJSON != "" {
		_ = json.Unmarshal([]byte(row.MetadataJSON), &meta)
	}
	return secretbroker.Secret{
		ID:         row.ID,
		Kind:       secretbroker.Kind(row.Kind),
		Name:       row.Name,
		Sealed:     row.Payload,
		KeyID:      row.KeyID,
		WrappedDEK: row.WrappedDEK,
		Metadata:   meta,
		CreatedAt:  parseTime(row.CreatedAt),
		CreatedBy:  row.CreatedBy,
	}
}

func toGrant(row statedb.BrokerGrantRow) (secretbroker.Grant, error) {
	var c secretbroker.Constraints
	if row.ConstraintsJSON != "" {
		if err := json.Unmarshal([]byte(row.ConstraintsJSON), &c); err != nil {
			return secretbroker.Grant{}, fmt.Errorf("secretstore: decode constraints for %s: %w", row.ID, err)
		}
	}
	subject, err := decodeSubject(row.SubjectType, row.SubjectValue)
	if err != nil {
		return secretbroker.Grant{}, err
	}
	return secretbroker.Grant{
		ID:          row.ID,
		SecretID:    row.SecretID,
		Scope:       row.Scope,
		Subject:     subject,
		Constraints: c,
		ExpiresAt:   parseTime(row.ExpiresAt),
		CreatedAt:   parseTime(row.CreatedAt),
		CreatedBy:   row.CreatedBy,
		RevokedAt:   parseTime(row.RevokedAt),
	}, nil
}

// encodeSubjectValue flattens a subject's payload into the single
// subject_value column: the project path or executor ID directly, and the
// label selector in its canonical "k=v,k2=v2" form.
func encodeSubjectValue(sub secretbroker.Subject) string {
	if sub.Type == secretbroker.SubjectLabel {
		// Subject.String() renders the canonical, sorted selector; strip
		// its "label:" prefix to get the bare value.
		return strings.TrimPrefix(sub.String(), "label:")
	}
	return sub.Value
}

// decodeSubject is the inverse. It routes through the broker's own parser
// rather than reconstructing the struct field by field, so the storage layer
// cannot produce a Subject the parser would have rejected — which is how a
// malformed row would otherwise turn into an over-broad match.
func decodeSubject(subjectType, value string) (secretbroker.Subject, error) {
	st := secretbroker.SubjectType(subjectType)
	if st == secretbroker.SubjectAny {
		return secretbroker.Subject{Type: secretbroker.SubjectAny}, nil
	}
	return secretbroker.ParseSubject(subjectType + ":" + value)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// isErr is errors.Is, named locally so the key adapter reads the same way.
func isErr(err, target error) bool { return errors.Is(err, target) }

// translateErr maps storage sentinels onto broker sentinels so callers match
// against one set.
func translateErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, statedb.ErrBrokerSecretNotFound):
		return fmt.Errorf("%w: %v", secretbroker.ErrSecretNotFound, err)
	case errors.Is(err, statedb.ErrBrokerGrantNotFound):
		return fmt.Errorf("%w: %v", secretbroker.ErrGrantNotFound, err)
	default:
		return err
	}
}
