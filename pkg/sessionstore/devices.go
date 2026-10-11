package sessionstore

// Device authorizations in the control-plane database (Task 20412): the
// statedb half of oidcauth.DeviceStore. Nothing here is sealed, because
// nothing here is a credential — the rows carry digests of the two codes and of
// the session credential the terminal committed to, never any of the three
// (see migrations/0066_device_login.sql). It lives beside the session store
// because it is the same database, opened once, and because a hub that keeps
// its sessions here must keep its sign-ins in flight here too: a terminal's
// poll can land on any member of a hub cluster.

import (
	"errors"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var _ oidcauth.DeviceStore = (*Store)(nil)

// PutDevice records a new authorization.
func (s *Store) PutDevice(rec oidcauth.DeviceRecord) error {
	return s.db.PutDeviceAuthorization(toDeviceRow(rec))
}

// GetDevice returns the authorization for a device code digest.
func (s *Store) GetDevice(deviceHash string) (oidcauth.DeviceRecord, error) {
	row, err := s.db.GetDeviceAuthorization(deviceHash)
	if err != nil {
		return oidcauth.DeviceRecord{}, deviceErr(err)
	}
	return fromDeviceRow(row), nil
}

// GetDeviceByUserCode returns the newest authorization for a user code digest.
func (s *Store) GetDeviceByUserCode(userCodeHash string) (oidcauth.DeviceRecord, error) {
	row, err := s.db.GetDeviceAuthorizationByUserCode(userCodeHash)
	if err != nil {
		return oidcauth.DeviceRecord{}, deviceErr(err)
	}
	return fromDeviceRow(row), nil
}

// UpdateDevice applies change under the database's write lock.
func (s *Store) UpdateDevice(deviceHash string, change func(*oidcauth.DeviceRecord) (bool, error)) (oidcauth.DeviceRecord, error) {
	row, err := s.db.UpdateDeviceAuthorization(deviceHash, func(row *statedb.DeviceAuthorizationRow) (bool, error) {
		rec := fromDeviceRow(*row)
		changed, err := change(&rec)
		if err != nil || !changed {
			return false, err
		}
		*row = toDeviceRow(rec)
		return true, nil
	})
	if err != nil {
		return oidcauth.DeviceRecord{}, deviceErr(err)
	}
	return fromDeviceRow(row), nil
}

// DeleteDevicesBefore removes the authorizations that expired at or before
// cutoff.
func (s *Store) DeleteDevicesBefore(cutoff time.Time) ([]oidcauth.DeviceRecord, error) {
	rows, err := s.db.DeleteDeviceAuthorizationsBefore(cutoff)
	if err != nil {
		return nil, err
	}
	out := make([]oidcauth.DeviceRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromDeviceRow(row))
	}
	return out, nil
}

// CountDevicesSince counts the authorizations issued after since.
func (s *Store) CountDevicesSince(since time.Time) (int, error) {
	return s.db.CountDeviceAuthorizations(since)
}

// deviceErr translates the storage sentinel into the one oidcauth answers.
func deviceErr(err error) error {
	if errors.Is(err, statedb.ErrDeviceAuthorizationNotFound) {
		return oidcauth.ErrDeviceNotFound
	}
	return err
}

func toDeviceRow(rec oidcauth.DeviceRecord) statedb.DeviceAuthorizationRow {
	return statedb.DeviceAuthorizationRow{
		DeviceHash:      rec.DeviceHash,
		UserCodeHash:    rec.UserCodeHash,
		CredentialHash:  rec.CredentialHash,
		Status:          string(rec.Status),
		ClientIP:        rec.ClientIP,
		ClientUserAgent: rec.ClientUserAgent,
		ClientHostname:  rec.ClientHostname,
		CreatedAt:       rec.CreatedAt,
		ExpiresAt:       rec.ExpiresAt,
		IntervalSeconds: int(rec.Interval / time.Second),
		LastPolledAt:    rec.LastPolledAt,
		Approver:        rec.Approver,
		ApproverSession: rec.ApproverSession,
		Subject:         rec.Subject,
		DecidedAt:       rec.DecidedAt,
		Reason:          rec.Reason,
	}
}

func fromDeviceRow(row statedb.DeviceAuthorizationRow) oidcauth.DeviceRecord {
	return oidcauth.DeviceRecord{
		DeviceHash:      row.DeviceHash,
		UserCodeHash:    row.UserCodeHash,
		CredentialHash:  row.CredentialHash,
		Status:          oidcauth.DeviceStatus(row.Status),
		ClientIP:        row.ClientIP,
		ClientUserAgent: row.ClientUserAgent,
		ClientHostname:  row.ClientHostname,
		CreatedAt:       row.CreatedAt,
		ExpiresAt:       row.ExpiresAt,
		Interval:        time.Duration(row.IntervalSeconds) * time.Second,
		LastPolledAt:    row.LastPolledAt,
		Approver:        row.Approver,
		ApproverSession: row.ApproverSession,
		Subject:         row.Subject,
		DecidedAt:       row.DecidedAt,
		Reason:          row.Reason,
	}
}
