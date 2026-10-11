package oidcauth

// Device authorization storage (Task 20412): the interface pkg/sessionstore
// implements over the control-plane database, and the process-local
// implementation a hub without one falls back to — the same split as
// SessionStore, for the same reason. This package decides what a code may do;
// a store only keeps it.

import (
	"errors"
	"sync"
	"time"
)

// ErrDeviceNotFound is what a store returns for a device code or user code it
// does not hold: mistyped, never issued, or expired and swept. All three are
// answered alike.
var ErrDeviceNotFound = errors.New("oidcauth: device authorization not found")

// DeviceStatus is where a device authorization is in its life.
type DeviceStatus string

const (
	// DeviceStatusPending: issued, and nobody has approved or denied it yet.
	DeviceStatusPending DeviceStatus = "pending"
	// DeviceStatusApproved: a signed-in browser approved it, and the session
	// it names exists; the terminal has not collected the approval yet.
	DeviceStatusApproved DeviceStatus = "approved"
	// DeviceStatusDenied: refused — by the person it was shown to, or by the
	// hub on their behalf (they were offboarded, or signed out everywhere).
	DeviceStatusDenied DeviceStatus = "denied"
	// DeviceStatusConsumed: approved and collected. A second exchange of the
	// same device code is refused: a code is single-use.
	DeviceStatusConsumed DeviceStatus = "consumed"
)

// DeviceRecord is one device authorization as stored.
//
// It holds no credential. DeviceHash and UserCodeHash are digests of the two
// codes, and CredentialHash is the digest of the session credential the
// terminal generated and kept — the approval writes the session under
// CLISessionID of it, so nothing here can be presented as one. It is cleared
// once the session is collected.
type DeviceRecord struct {
	DeviceHash     string
	UserCodeHash   string
	CredentialHash string
	Status         DeviceStatus

	// ClientIP, ClientUserAgent and ClientHostname describe who asked: the
	// first two as the hub saw the request, the last as the terminal reported
	// it. Labels for the person deciding, never inputs to the decision.
	ClientIP        string
	ClientUserAgent string
	ClientHostname  string

	CreatedAt time.Time
	ExpiresAt time.Time

	// Interval is how often the terminal may poll, and LastPolledAt when it
	// last did. Polling faster earns slow_down and a longer interval.
	Interval     time.Duration
	LastPolledAt time.Time

	// Approver is who decided (an owner key, or "hub" when the hub denied it
	// on someone's behalf), ApproverSession the hashed id of the browser
	// session that did, Subject their IdP subject, and Reason why a denial
	// happened.
	Approver        string
	ApproverSession string
	Subject         string
	DecidedAt       time.Time
	Reason          string
}

// expired reports whether the code can no longer be approved.
func (d DeviceRecord) expired(now time.Time) bool {
	return !d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt)
}

// DeviceStore persists device authorizations. Implementations must be safe for
// concurrent use, and — on a control plane several hub processes share — must
// serialise UpdateDevice across all of them: an approval racing a denial, or
// two polls racing the exchange, has to see one winner.
type DeviceStore interface {
	// PutDevice records a new authorization. It must not overwrite one.
	PutDevice(DeviceRecord) error

	// GetDevice returns the authorization for a device code digest, or an
	// error wrapping ErrDeviceNotFound.
	GetDevice(deviceHash string) (DeviceRecord, error)

	// GetDeviceByUserCode returns the newest authorization for a user code
	// digest, or an error wrapping ErrDeviceNotFound.
	GetDeviceByUserCode(userCodeHash string) (DeviceRecord, error)

	// UpdateDevice reads the authorization for deviceHash, applies change
	// to it, and writes it back if change reports a change — atomically. It
	// returns the record as stored afterwards. change must not call the
	// store.
	UpdateDevice(deviceHash string, change func(*DeviceRecord) (bool, error)) (DeviceRecord, error)

	// DeleteDevicesBefore removes the authorizations whose ExpiresAt is at or
	// before cutoff, returning them.
	DeleteDevicesBefore(cutoff time.Time) ([]DeviceRecord, error)

	// CountDevicesSince counts the authorizations issued after since: the
	// hub-wide issuing rate.
	CountDevicesSince(since time.Time) (int, error)
}

// ── in-memory store ─────────────────────────────────────────────────────────

// memDeviceStore is the DeviceStore of a hub with no control-plane database.
// Its codes die with the process, as its sessions do.
type memDeviceStore struct {
	mu   sync.Mutex
	rows map[string]DeviceRecord
}

// NewMemoryDeviceStore returns a process-local device store.
func NewMemoryDeviceStore() DeviceStore {
	return &memDeviceStore{rows: map[string]DeviceRecord{}}
}

// maxMemoryDevices bounds the process-local store, as maxSessions bounds the
// session map. Issuing is rate-limited long before this; the bound is what
// stops a limiter bug from becoming unbounded memory.
const maxMemoryDevices = 10000

func (m *memDeviceStore) PutDevice(rec DeviceRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rows[rec.DeviceHash]; exists {
		return errors.New("oidcauth: device authorization already exists")
	}
	if len(m.rows) >= maxMemoryDevices {
		return errors.New("oidcauth: too many device authorizations in flight")
	}
	m.rows[rec.DeviceHash] = rec
	return nil
}

func (m *memDeviceStore) GetDevice(deviceHash string) (DeviceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[deviceHash]
	if !ok {
		return DeviceRecord{}, ErrDeviceNotFound
	}
	return rec, nil
}

func (m *memDeviceStore) GetDeviceByUserCode(userCodeHash string) (DeviceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var (
		best  DeviceRecord
		found bool
	)
	for _, rec := range m.rows {
		if rec.UserCodeHash != userCodeHash {
			continue
		}
		if !found || rec.CreatedAt.After(best.CreatedAt) {
			best, found = rec, true
		}
	}
	if !found {
		return DeviceRecord{}, ErrDeviceNotFound
	}
	return best, nil
}

func (m *memDeviceStore) UpdateDevice(deviceHash string, change func(*DeviceRecord) (bool, error)) (DeviceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[deviceHash]
	if !ok {
		return DeviceRecord{}, ErrDeviceNotFound
	}
	changed, err := change(&rec)
	if err != nil {
		return DeviceRecord{}, err
	}
	if changed {
		rec.DeviceHash = deviceHash
		m.rows[deviceHash] = rec
	}
	return m.rows[deviceHash], nil
}

func (m *memDeviceStore) DeleteDevicesBefore(cutoff time.Time) ([]DeviceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DeviceRecord
	for id, rec := range m.rows {
		if !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(cutoff) {
			out = append(out, rec)
			delete(m.rows, id)
		}
	}
	return out, nil
}

func (m *memDeviceStore) CountDevicesSince(since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, rec := range m.rows {
		if rec.CreatedAt.After(since) {
			n++
		}
	}
	return n, nil
}
