// Package forwarderstore backs the device-forwarder enrollment flow with
// SQLite, the way executorstore backs the executor-agent one.
//
// It is a type-converting adapter and nothing else: pkg/statedb owns the rows,
// pkg/deviceforward owns the protocol and the crypto, and this package joins
// them. The separation keeps pkg/deviceforward free of a SQLite dependency —
// the forwarder binary on an edge device imports deviceforward, and linking a
// database engine into a process whose whole job is to copy bytes between a
// device and a socket would be dead weight on exactly the hardware that can
// least afford it.
package forwarderstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store implements deviceforward.Store over a *statedb.DB.
type Store struct {
	db *statedb.DB
}

// New wraps a database handle.
func New(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("forwarderstore: nil database")
	}
	return &Store{db: db}, nil
}

var _ deviceforward.Store = (*Store)(nil)

func marshalDevice(d deviceforward.ForwardedDevice) string {
	b, err := json.Marshal(d)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func unmarshalDevice(s string) deviceforward.ForwardedDevice {
	var d deviceforward.ForwardedDevice
	_ = json.Unmarshal([]byte(s), &d)
	return d
}

// PutEnrollment persists a minted token.
func (s *Store) PutEnrollment(rec deviceforward.EnrollmentRecord) error {
	return s.db.PutForwarderEnrollment(statedb.ForwarderEnrollmentRow{
		ID:                  rec.ID,
		Name:                rec.Name,
		SecretHash:          rec.SecretHash,
		DeviceJSON:          marshalDevice(rec.Device),
		Owner:               rec.Owner,
		CreatedAt:           rec.CreatedAt,
		ExpiresAt:           rec.ExpiresAt,
		CreatedBy:           rec.CreatedBy,
		RedeemedAt:          rec.RedeemedAt,
		RedeemedForwarderID: rec.RedeemedAgentID,
		RevokedAt:           rec.RevokedAt,
	})
}

// GetEnrollment loads a token by ID.
func (s *Store) GetEnrollment(id string) (deviceforward.EnrollmentRecord, error) {
	row, err := s.db.GetForwarderEnrollment(id)
	if err != nil {
		return deviceforward.EnrollmentRecord{}, convertErr(err)
	}
	return deviceforward.EnrollmentRecord{
		ID:              row.ID,
		Name:            row.Name,
		SecretHash:      row.SecretHash,
		Device:          unmarshalDevice(row.DeviceJSON),
		Owner:           row.Owner,
		CreatedAt:       row.CreatedAt,
		ExpiresAt:       row.ExpiresAt,
		CreatedBy:       row.CreatedBy,
		RedeemedAt:      row.RedeemedAt,
		RedeemedAgentID: row.RedeemedForwarderID,
		RevokedAt:       row.RevokedAt,
	}, nil
}

// RedeemEnrollment atomically claims a token.
func (s *Store) RedeemEnrollment(id, forwarderID string, at time.Time) error {
	return convertErr(s.db.RedeemForwarderEnrollment(id, forwarderID, at))
}

// RevokeEnrollment marks a token revoked.
func (s *Store) RevokeEnrollment(id string, at time.Time) error {
	return convertErr(s.db.RevokeForwarderEnrollment(id, at))
}

// ListEnrollments returns every token.
func (s *Store) ListEnrollments() ([]deviceforward.EnrollmentRecord, error) {
	rows, err := s.db.ListForwarderEnrollments()
	if err != nil {
		return nil, err
	}
	out := make([]deviceforward.EnrollmentRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, deviceforward.EnrollmentRecord{
			ID:              row.ID,
			Name:            row.Name,
			SecretHash:      row.SecretHash,
			Device:          unmarshalDevice(row.DeviceJSON),
			Owner:           row.Owner,
			CreatedAt:       row.CreatedAt,
			ExpiresAt:       row.ExpiresAt,
			CreatedBy:       row.CreatedBy,
			RedeemedAt:      row.RedeemedAt,
			RedeemedAgentID: row.RedeemedForwarderID,
			RevokedAt:       row.RevokedAt,
		})
	}
	return out, nil
}

// PutForwarder persists a forwarder credential.
func (s *Store) PutForwarder(rec deviceforward.ForwarderRecord) error {
	return s.db.PutForwarder(statedb.ForwarderRow{
		ForwarderID:  rec.ForwarderID,
		Name:         rec.Name,
		SecretHash:   rec.SecretHash,
		DeviceJSON:   marshalDevice(rec.Device),
		Owner:        rec.Owner,
		CreatedAt:    rec.CreatedAt,
		LastSeen:     rec.LastSeen,
		RevokedAt:    rec.RevokedAt,
		EnrollmentID: rec.EnrollmentID,
	})
}

// GetForwarder loads a forwarder by ID.
func (s *Store) GetForwarder(forwarderID string) (deviceforward.ForwarderRecord, error) {
	row, err := s.db.GetForwarder(forwarderID)
	if err != nil {
		return deviceforward.ForwarderRecord{}, convertErr(err)
	}
	return forwarderFromRow(row), nil
}

// RevokeForwarder marks a credential revoked.
func (s *Store) RevokeForwarder(forwarderID string, at time.Time) error {
	return convertErr(s.db.RevokeForwarder(forwarderID, at))
}

// TouchForwarder records that a forwarder was seen.
func (s *Store) TouchForwarder(forwarderID string, at time.Time) error {
	return s.db.TouchForwarder(forwarderID, at)
}

// ListForwarders returns every forwarder.
func (s *Store) ListForwarders() ([]deviceforward.ForwarderRecord, error) {
	rows, err := s.db.ListForwarders()
	if err != nil {
		return nil, err
	}
	out := make([]deviceforward.ForwarderRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, forwarderFromRow(row))
	}
	return out, nil
}

func forwarderFromRow(row statedb.ForwarderRow) deviceforward.ForwarderRecord {
	return deviceforward.ForwarderRecord{
		ForwarderID:  row.ForwarderID,
		Name:         row.Name,
		SecretHash:   row.SecretHash,
		Device:       unmarshalDevice(row.DeviceJSON),
		Owner:        row.Owner,
		CreatedAt:    row.CreatedAt,
		LastSeen:     row.LastSeen,
		RevokedAt:    row.RevokedAt,
		EnrollmentID: row.EnrollmentID,
	}
}

// convertErr maps storage sentinels to the deviceforward ones callers branch on.
func convertErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, statedb.ErrForwarderEnrollmentNotFound):
		return fmt.Errorf("%w: %v", deviceforward.ErrTokenInvalid, err)
	case errors.Is(err, statedb.ErrForwarderEnrollmentSpent):
		return fmt.Errorf("%w: %v", deviceforward.ErrTokenAlreadyUsed, err)
	case errors.Is(err, statedb.ErrForwarderNotFound):
		return fmt.Errorf("%w: %v", deviceforward.ErrForwarderNotFound, err)
	default:
		return err
	}
}
