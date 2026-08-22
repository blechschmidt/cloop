package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// egress.go adapts pkg/statedb to pkg/egressbroker's Store, in the same shape
// and for the same reasons as store.go does for the credential broker: the
// rows and the SQL live in statedb, the policy lives in the broker, and this
// package is the only thing that knows both.
//
// It lives here rather than in a package of its own because the two brokers
// share a database, an audit sink, and a lifetime — `cloop egress grant`
// opens exactly the same handle `cloop secret grant` does. A second adapter
// package would have duplicated the time formatting and subject encoding
// below, and duplicated subject encoding is how two grants that look
// identical in a listing end up matching different requesters.

// EgressStore implements egressbroker.Store over a *statedb.DB.
type EgressStore struct {
	db *statedb.DB
}

// NewEgressStore wraps a database handle.
func NewEgressStore(db *statedb.DB) (*EgressStore, error) {
	if db == nil {
		return nil, fmt.Errorf("secretstore: nil database")
	}
	return &EgressStore{db: db}, nil
}

// Compile-time proof that the adapter satisfies the broker's contract.
var _ egressbroker.Store = (*EgressStore)(nil)

// egressPolicy is the JSON shape of the policy_json column.
//
// It is a separate struct from egressbroker.Grant rather than a marshal of
// the whole grant: the identity and lifecycle columns (id, subject, expiry,
// revocation) are first-class columns because they are queried and indexed,
// and duplicating them inside the blob would create two answers to "when does
// this expire" that a hand-edited row could make disagree.
type egressPolicy struct {
	Hosts        []string `json:"hosts,omitempty"`
	CIDRs        []string `json:"cidrs,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	MaxBytesUp   int64    `json:"max_bytes_up,omitempty"`
	MaxBytesDown int64    `json:"max_bytes_down,omitempty"`
	// SessionTTLSeconds is stored in seconds rather than as a
	// time.Duration's nanosecond integer, so a human reading the row can
	// tell 900 from 900000000000.
	SessionTTLSeconds int64 `json:"session_ttl_seconds,omitempty"`
}

// PutGrant persists an egress grant.
func (s *EgressStore) PutGrant(g egressbroker.Grant) error {
	policy, err := json.Marshal(egressPolicy{
		Hosts:             g.Hosts,
		CIDRs:             g.CIDRs,
		Ports:             g.Ports,
		Methods:           g.Methods,
		MaxBytesUp:        g.MaxBytesUp,
		MaxBytesDown:      g.MaxBytesDown,
		SessionTTLSeconds: int64(g.SessionTTL / time.Second),
	})
	if err != nil {
		return fmt.Errorf("secretstore: encode egress policy for %s: %w", g.ID, err)
	}
	return s.db.PutEgressGrant(statedb.EgressGrantRow{
		ID:           g.ID,
		Scope:        g.Scope,
		SubjectType:  string(g.Subject.Type),
		SubjectValue: encodeSubjectValue(g.Subject),
		PolicyJSON:   string(policy),
		ExpiresAt:    formatTime(g.ExpiresAt),
		CreatedAt:    formatTime(g.CreatedAt),
		CreatedBy:    g.CreatedBy,
		RevokedAt:    formatTime(g.RevokedAt),
	})
}

// GetGrant returns one grant by ID.
func (s *EgressStore) GetGrant(id string) (egressbroker.Grant, error) {
	row, err := s.db.GetEgressGrant(id)
	if err != nil {
		return egressbroker.Grant{}, translateEgressErr(err)
	}
	return toEgressGrant(row)
}

// ListGrants returns every grant.
//
// A row whose policy or subject cannot be decoded is skipped, and skipped in
// the deny direction: a grant the broker cannot read is a grant it will not
// honour, so a corrupt row silently loses access rather than silently keeping
// it. This mirrors Store.ListGrants exactly, and for the same reason.
func (s *EgressStore) ListGrants() ([]egressbroker.Grant, error) {
	rows, err := s.db.ListEgressGrants()
	if err != nil {
		return nil, translateEgressErr(err)
	}
	out := make([]egressbroker.Grant, 0, len(rows))
	for _, row := range rows {
		g, gerr := toEgressGrant(row)
		if gerr != nil {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

// RevokeGrant stamps a grant revoked.
func (s *EgressStore) RevokeGrant(id string, at time.Time) error {
	return translateEgressErr(s.db.RevokeEgressGrant(id, at))
}

// toEgressGrant converts a row into the broker's domain type.
//
// The result is *not* re-validated here. Validation is the broker's, and it
// mutates (Normalize fills in default ports); running it on read would let a
// stored grant silently acquire ports it was never granted, which is the one
// direction a normalisation must never move. A row that was written through
// the broker has already been normalised, and one that was not is caught by
// the fail-closed decision functions — CheckPort denies an empty list.
func toEgressGrant(row statedb.EgressGrantRow) (egressbroker.Grant, error) {
	var p egressPolicy
	if row.PolicyJSON != "" {
		if err := json.Unmarshal([]byte(row.PolicyJSON), &p); err != nil {
			return egressbroker.Grant{}, fmt.Errorf("secretstore: decode egress policy for %s: %w", row.ID, err)
		}
	}
	subject, err := decodeSubject(row.SubjectType, row.SubjectValue)
	if err != nil {
		return egressbroker.Grant{}, err
	}
	return egressbroker.Grant{
		ID:           row.ID,
		Scope:        row.Scope,
		Subject:      subject,
		Hosts:        p.Hosts,
		CIDRs:        p.CIDRs,
		Ports:        p.Ports,
		Methods:      p.Methods,
		MaxBytesUp:   p.MaxBytesUp,
		MaxBytesDown: p.MaxBytesDown,
		SessionTTL:   time.Duration(p.SessionTTLSeconds) * time.Second,
		ExpiresAt:    parseTime(row.ExpiresAt),
		CreatedAt:    parseTime(row.CreatedAt),
		CreatedBy:    row.CreatedBy,
		RevokedAt:    parseTime(row.RevokedAt),
	}, nil
}

// translateEgressErr maps the storage sentinel onto the broker's, so callers
// match against one set.
func translateEgressErr(err error) error {
	if err != nil && errors.Is(err, statedb.ErrEgressGrantNotFound) {
		return fmt.Errorf("%w: %v", egressbroker.ErrGrantNotFound, err)
	}
	return err
}
