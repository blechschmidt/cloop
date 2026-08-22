// Package quotastore persists per-identity quotas in the hub's own state
// database (Task 20182).
//
// It is the SQLite half of the split described in pkg/quota: that package
// owns the policy — precedence, admission, the atomic check-and-increment —
// and is stdlib-only, while this one owns the rows. The seam is quota.Store,
// and it is the same shape as oidcauth.SessionStore/sessionstore and
// secretbroker.Store/secretstore.
//
// Nothing here is encrypted. A quota row holds a ceiling and a count, which
// is policy and telemetry rather than credential material; the identity
// strings it is keyed by are already in plaintext in the project registry and
// the session table. Sealing them would cost the ability to read the table
// during an incident and buy nothing an attacker with database access does
// not already have.
package quotastore

import (
	"encoding/json"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Store is the statedb-backed quota.Store.
type Store struct {
	db *statedb.DB
}

// New wraps an open state database.
func New(db *statedb.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("quotastore: nil database")
	}
	return &Store{db: db}, nil
}

var _ quota.Store = (*Store)(nil)

// LoadOverrides returns every per-identity override.
//
// A row whose limits_json will not parse is skipped rather than failing the
// whole load. The alternative is a hub that refuses to start because one
// hand-edited row is malformed — and refusing to start is not the safe
// direction here: it takes down every tenant to protect one ceiling.
func (s *Store) LoadOverrides() ([]quota.Override, error) {
	rows, err := s.db.ListQuotaOverrides()
	if err != nil {
		return nil, err
	}
	out := make([]quota.Override, 0, len(rows))
	for _, r := range rows {
		var limits quota.Limits
		if r.LimitsJSON != "" {
			if err := json.Unmarshal([]byte(r.LimitsJSON), &limits); err != nil {
				continue
			}
		}
		normalized, err := limits.Normalize()
		if err != nil {
			continue
		}
		out = append(out, quota.Override{
			Identity:  r.Identity,
			Limits:    normalized,
			UpdatedAt: r.UpdatedAt,
			UpdatedBy: r.UpdatedBy,
		})
	}
	return out, nil
}

// PutOverride writes one identity's override.
func (s *Store) PutOverride(o quota.Override) error {
	limits := o.Limits
	if limits == nil {
		limits = quota.Limits{}
	}
	blob, err := json.Marshal(limits)
	if err != nil {
		return fmt.Errorf("quotastore: encode limits for %q: %w", o.Identity, err)
	}
	return s.db.PutQuotaOverride(statedb.QuotaOverrideRow{
		Identity:   o.Identity,
		LimitsJSON: string(blob),
		UpdatedAt:  o.UpdatedAt,
		UpdatedBy:  o.UpdatedBy,
	})
}

// DeleteOverride removes one identity's override.
func (s *Store) DeleteOverride(identity string) (bool, error) {
	return s.db.DeleteQuotaOverride(identity)
}

// LoadCounters returns every persisted counter, stale day buckets included.
// pkg/quota decides which are still current — the storage layer holds no
// clock, so it cannot know what "today" means to the process reading it.
func (s *Store) LoadCounters() ([]quota.CounterRow, error) {
	rows, err := s.db.ListQuotaCounters()
	if err != nil {
		return nil, err
	}
	out := make([]quota.CounterRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, quota.CounterRow{
			Identity:  r.Identity,
			Resource:  quota.Resource(r.Resource),
			Bucket:    r.Bucket,
			Value:     r.Value,
			UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

// PutCounter writes one counter's value.
func (s *Store) PutCounter(c quota.CounterRow) error {
	return s.db.PutQuotaCounter(statedb.QuotaCounterRow{
		Identity:  c.Identity,
		Resource:  string(c.Resource),
		Bucket:    c.Bucket,
		Value:     c.Value,
		UpdatedAt: c.UpdatedAt,
	})
}

// ReplaceGauges swaps the whole gauge set atomically.
func (s *Store) ReplaceGauges(rows []quota.CounterRow) error {
	out := make([]statedb.QuotaCounterRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, statedb.QuotaCounterRow{
			Identity:  r.Identity,
			Resource:  string(r.Resource),
			Bucket:    "",
			Value:     r.Value,
			UpdatedAt: r.UpdatedAt,
		})
	}
	return s.db.ReplaceQuotaGauges(out)
}

// PruneCountersBefore deletes daily counters older than bucket.
func (s *Store) PruneCountersBefore(bucket string) error {
	return s.db.PruneQuotaCounters(bucket)
}
