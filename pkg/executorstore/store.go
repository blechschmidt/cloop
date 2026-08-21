// Package executorstore backs the remote-executor enrollment flow with SQLite.
//
// It is a type-converting adapter and nothing else: pkg/statedb owns the rows
// and the SQL, pkg/executor/remote owns the protocol and the crypto, and this
// package joins them. Keeping it separate keeps two dependencies apart that
// neither side wants:
//
//   - pkg/executor/remote must not depend on SQLite. The agent binary running
//     on an edge device imports it, and linking a database engine into a
//     process whose whole job is to fork workloads is dead weight on exactly
//     the hardware that can least afford it.
//   - pkg/statedb must not depend on pkg/executor/remote, which pulls in a
//     WebSocket stack a storage layer has no business knowing about.
//
// The duplication of record shapes across the boundary is the price of that
// separation, and it is a small and stable price: these structs change only
// when the enrollment schema does.
package executorstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store implements remote.Store over a *statedb.DB.
type Store struct {
	db *statedb.DB
}

// New wraps a database handle.
func New(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("executorstore: nil database")
	}
	return &Store{db: db}, nil
}

// Compile-time proof that the adapter satisfies the interface the enrollment
// flow is written against.
var _ remote.Store = (*Store)(nil)

// PutEnrollment persists a minted token record.
func (s *Store) PutEnrollment(rec remote.EnrollmentRecord) error {
	return s.db.PutEnrollmentToken(statedb.EnrollmentTokenRow{
		ID:              rec.ID,
		Name:            rec.Name,
		SecretHash:      rec.SecretHash,
		WorkDirRoot:     rec.WorkDirRoot,
		Labels:          rec.Labels,
		CreatedAt:       rec.CreatedAt,
		ExpiresAt:       rec.ExpiresAt,
		CreatedBy:       rec.CreatedBy,
		RedeemedAt:      rec.RedeemedAt,
		RedeemedAgentID: rec.RedeemedAgentID,
		RevokedAt:       rec.RevokedAt,
	})
}

// GetEnrollment loads a token by ID.
func (s *Store) GetEnrollment(id string) (remote.EnrollmentRecord, error) {
	row, err := s.db.GetEnrollmentToken(id)
	if err != nil {
		return remote.EnrollmentRecord{}, translateErr(err)
	}
	return remote.EnrollmentRecord{
		ID:              row.ID,
		Name:            row.Name,
		SecretHash:      row.SecretHash,
		WorkDirRoot:     row.WorkDirRoot,
		Labels:          row.Labels,
		CreatedAt:       row.CreatedAt,
		ExpiresAt:       row.ExpiresAt,
		CreatedBy:       row.CreatedBy,
		RedeemedAt:      row.RedeemedAt,
		RedeemedAgentID: row.RedeemedAgentID,
		RevokedAt:       row.RevokedAt,
	}, nil
}

// RedeemEnrollment atomically claims a token.
func (s *Store) RedeemEnrollment(id, agentID string, at time.Time) error {
	return translateErr(s.db.RedeemEnrollmentToken(id, agentID, at))
}

// RevokeEnrollment marks a token revoked.
func (s *Store) RevokeEnrollment(id string, at time.Time) error {
	return translateErr(s.db.RevokeEnrollmentToken(id, at))
}

// ListEnrollments returns every token, newest first.
func (s *Store) ListEnrollments() ([]remote.EnrollmentRecord, error) {
	rows, err := s.db.ListEnrollmentTokens()
	if err != nil {
		return nil, err
	}
	out := make([]remote.EnrollmentRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, remote.EnrollmentRecord{
			ID:              row.ID,
			Name:            row.Name,
			SecretHash:      row.SecretHash,
			WorkDirRoot:     row.WorkDirRoot,
			Labels:          row.Labels,
			CreatedAt:       row.CreatedAt,
			ExpiresAt:       row.ExpiresAt,
			CreatedBy:       row.CreatedBy,
			RedeemedAt:      row.RedeemedAt,
			RedeemedAgentID: row.RedeemedAgentID,
			RevokedAt:       row.RevokedAt,
		})
	}
	return out, nil
}

// PutAgent persists an agent credential record.
func (s *Store) PutAgent(rec remote.AgentRecord) error {
	return s.db.PutAgentCredential(statedb.AgentCredentialRow{
		AgentID:      rec.AgentID,
		Name:         rec.Name,
		SecretHash:   rec.SecretHash,
		WorkDirRoot:  rec.WorkDirRoot,
		Labels:       rec.Labels,
		CreatedAt:    rec.CreatedAt,
		LastSeen:     rec.LastSeen,
		RevokedAt:    rec.RevokedAt,
		EnrollmentID: rec.EnrollmentID,
	})
}

// GetAgent loads an agent by ID.
func (s *Store) GetAgent(agentID string) (remote.AgentRecord, error) {
	row, err := s.db.GetAgentCredential(agentID)
	if err != nil {
		return remote.AgentRecord{}, translateErr(err)
	}
	return toAgentRecord(row), nil
}

// RevokeAgent marks an agent's credential revoked.
func (s *Store) RevokeAgent(agentID string, at time.Time) error {
	return translateErr(s.db.RevokeAgentCredential(agentID, at))
}

// TouchAgent records a successful authentication.
func (s *Store) TouchAgent(agentID string, at time.Time) error {
	return translateErr(s.db.TouchAgentCredential(agentID, at))
}

// ListAgents returns every enrolled agent.
func (s *Store) ListAgents() ([]remote.AgentRecord, error) {
	rows, err := s.db.ListAgentCredentials()
	if err != nil {
		return nil, err
	}
	out := make([]remote.AgentRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAgentRecord(row))
	}
	return out, nil
}

func toAgentRecord(row statedb.AgentCredentialRow) remote.AgentRecord {
	return remote.AgentRecord{
		AgentID:      row.AgentID,
		Name:         row.Name,
		SecretHash:   row.SecretHash,
		WorkDirRoot:  row.WorkDirRoot,
		Labels:       row.Labels,
		CreatedAt:    row.CreatedAt,
		LastSeen:     row.LastSeen,
		RevokedAt:    row.RevokedAt,
		EnrollmentID: row.EnrollmentID,
	}
}

// translateErr maps storage sentinels onto the protocol sentinels the
// enrollment flow matches with errors.Is.
//
// Without this, Redeem's careful distinction between "unknown token", "already
// redeemed", and "revoked" would collapse into an opaque storage error at
// exactly the point where an operator investigating a leaked token most needs
// to know which one happened.
func translateErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, statedb.ErrEnrollmentNotFound):
		return fmt.Errorf("%w: %v", remote.ErrTokenInvalid, err)
	case errors.Is(err, statedb.ErrEnrollmentSpent):
		return fmt.Errorf("%w: %v", remote.ErrTokenAlreadyUsed, err)
	case errors.Is(err, statedb.ErrAgentCredentialNotFound):
		return fmt.Errorf("%w: %v", remote.ErrAgentNotFound, err)
	default:
		return err
	}
}
