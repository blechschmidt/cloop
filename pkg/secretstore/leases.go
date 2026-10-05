package secretstore

// leases.go persists the broker's lease records (Task 20382): who holds each
// live lease and what it was issued under, so a lease outlives the hub process
// that issued it. Ids and names only — the type has no field a credential
// value could travel in.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Compile-time proof that the adapter keeps lease records.
var _ secretbroker.LeaseStore = (*Store)(nil)

// leaseDoc is a record's record_json: everything the row's own columns do not
// carry, under names this package owns rather than the broker's field names,
// so renaming a Go field cannot silently orphan the records already written.
type leaseDoc struct {
	ExecutorID    string            `json:"executor_id,omitempty"`
	ProjectID     string            `json:"project_id,omitempty"`
	RunID         string            `json:"run_id,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	GitHubProxied bool              `json:"github_proxied,omitempty"`
	Withhold      map[string]string `json:"withhold,omitempty"`
	Actor         string            `json:"actor,omitempty"`
	Kinds         []string          `json:"kinds,omitempty"`
	GrantIDs      []string          `json:"grant_ids,omitempty"`
}

// PutLease records a lease.
func (s *Store) PutLease(r secretbroker.LeaseRecord) error {
	kinds := make([]string, 0, len(r.Kinds))
	for _, k := range r.Kinds {
		kinds = append(kinds, string(k))
	}
	doc, err := json.Marshal(leaseDoc{
		ExecutorID:    r.Requester.ExecutorID,
		ProjectID:     r.Requester.ProjectID,
		RunID:         r.Requester.RunID,
		Labels:        r.Requester.Labels,
		GitHubProxied: r.Requester.GitHubProxied,
		Withhold:      r.Requester.Withhold,
		Actor:         r.Actor,
		Kinds:         kinds,
		GrantIDs:      r.GrantIDs,
	})
	if err != nil {
		return fmt.Errorf("secretstore: encode lease %s: %w", r.ID, err)
	}
	return s.db.PutSecretLease(statedb.SecretLeaseRow{
		LeaseID:    r.ID,
		Holder:     r.Holder,
		ExecutorID: r.Requester.ExecutorID,
		ProjectID:  r.Requester.ProjectID,
		RunID:      r.Requester.RunID,
		Record:     string(doc),
		IssuedAt:   r.IssuedAt,
		ExpiresAt:  r.ExpiresAt,
		UpdatedAt:  time.Now().UTC(),
	})
}

// GetLease returns one record, or a wrapped secretbroker.ErrLeaseNotFound.
func (s *Store) GetLease(id string) (secretbroker.LeaseRecord, error) {
	row, err := s.db.GetSecretLease(id)
	if err != nil {
		return secretbroker.LeaseRecord{}, translateErr(err)
	}
	return leaseFromRow(row)
}

// ListLeases returns every record. One that cannot be read is skipped rather
// than failing the list: the sweep that reads it must not be stopped by one
// bad row from reaching the others.
func (s *Store) ListLeases() ([]secretbroker.LeaseRecord, error) {
	rows, err := s.db.ListSecretLeases()
	if err != nil {
		return nil, err
	}
	out := make([]secretbroker.LeaseRecord, 0, len(rows))
	for _, row := range rows {
		rec, err := leaseFromRow(row)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// ExtendLease moves a record's deadline if holder holds it.
func (s *Store) ExtendLease(id, holder string, expiresAt time.Time) (bool, error) {
	return s.db.ExtendSecretLease(id, holder, expiresAt)
}

// TakeLease hands a record from one holder to another.
func (s *Store) TakeLease(id, from, holder string) (bool, error) {
	return s.db.TakeSecretLease(id, from, holder)
}

// DeleteLease removes a record if holder holds it.
func (s *Store) DeleteLease(id, holder string) (bool, error) {
	return s.db.DeleteSecretLease(id, holder)
}

func leaseFromRow(row statedb.SecretLeaseRow) (secretbroker.LeaseRecord, error) {
	var doc leaseDoc
	if err := json.Unmarshal([]byte(row.Record), &doc); err != nil {
		return secretbroker.LeaseRecord{}, fmt.Errorf("secretstore: decode lease %s: %w", row.LeaseID, err)
	}
	kinds := make([]secretbroker.Kind, 0, len(doc.Kinds))
	for _, k := range doc.Kinds {
		kinds = append(kinds, secretbroker.Kind(k))
	}
	executorID, projectID, runID := doc.ExecutorID, doc.ProjectID, doc.RunID
	if executorID == "" {
		executorID = row.ExecutorID
	}
	if projectID == "" {
		projectID = row.ProjectID
	}
	if runID == "" {
		runID = row.RunID
	}
	return secretbroker.LeaseRecord{
		ID:     row.LeaseID,
		Holder: row.Holder,
		Requester: secretbroker.Requester{
			ExecutorID:    executorID,
			ProjectID:     projectID,
			RunID:         runID,
			Labels:        doc.Labels,
			GitHubProxied: doc.GitHubProxied,
			Withhold:      doc.Withhold,
		},
		Actor:     doc.Actor,
		IssuedAt:  row.IssuedAt,
		ExpiresAt: row.ExpiresAt,
		Kinds:     kinds,
		GrantIDs:  doc.GrantIDs,
	}, nil
}
