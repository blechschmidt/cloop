package secretstore

// The SQLite side of self-service grant requests (Task 20271).
//
// Same split as the rest of this package: pkg/statedb owns the rows,
// pkg/secretbroker owns the lifecycle, and this file converts. A request names
// a secret and never carries one, so nothing here is sealed and nothing here
// needs a key — which is why the request path keeps working on a hub where
// CLOOP_SECRET_KEY is unset and the secret broker itself will not start.
//
// Well, almost: Broker.RequestAccess resolves the named secret to validate its
// kind, so in practice the request path rides on the same broker. The point
// stands for the storage layer, and it is the reason these methods are on Store
// rather than gated behind the cipher.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Compile-time proof that the adapter satisfies the broker's optional request
// contract. Without this, a method renamed on one side would degrade the broker
// to ErrRequestsUnsupported at runtime — the request panel would go quiet and
// nothing would say why.
var _ secretbroker.RequestStore = (*Store)(nil)

// PutAccessRequest persists a request.
func (s *Store) PutAccessRequest(r secretbroker.AccessRequest) error {
	constraints, err := json.Marshal(r.Constraints)
	if err != nil {
		return fmt.Errorf("secretstore: encode constraints for request %s: %w", r.ID, err)
	}
	return translateErr(s.db.PutGrantRequest(statedb.GrantRequestRow{
		ID:              r.ID,
		RequestedBy:     r.RequestedBy,
		SecretID:        r.SecretID,
		SecretName:      r.SecretName,
		Kind:            string(r.Kind),
		SubjectType:     string(r.Subject.Type),
		SubjectValue:    encodeSubjectValue(r.Subject),
		Scope:           r.Scope,
		ConstraintsJSON: string(constraints),
		TTLSeconds:      int64(r.TTL / time.Second),
		Justification:   r.Justification,
		State:           string(r.State),
		CreatedAt:       formatTime(r.CreatedAt),
		ExpiresAt:       formatTime(r.ExpiresAt),
		DecidedBy:       r.DecidedBy,
		DecidedAt:       formatTime(r.DecidedAt),
		DecisionNote:    r.DecisionNote,
		GrantID:         r.GrantID,
		GrantExpiresAt:  formatTime(r.GrantExpiresAt),
	}))
}

// GetAccessRequest returns one request by ID.
func (s *Store) GetAccessRequest(id string) (secretbroker.AccessRequest, error) {
	row, err := s.db.GetGrantRequest(id)
	if err != nil {
		return secretbroker.AccessRequest{}, translateErr(err)
	}
	return toAccessRequest(row)
}

// ListAccessRequests returns every request.
//
// A row whose subject or constraints cannot be decoded is skipped, matching
// ListGrants — and skipped in the same direction, which here means the request
// becomes invisible and therefore unapprovable. That is the safe failure: a
// corrupt row cannot be turned into a grant whose scope nobody can read.
func (s *Store) ListAccessRequests() ([]secretbroker.AccessRequest, error) {
	rows, err := s.db.ListGrantRequests()
	if err != nil {
		return nil, translateErr(err)
	}
	out := make([]secretbroker.AccessRequest, 0, len(rows))
	for _, row := range rows {
		r, rerr := toAccessRequest(row)
		if rerr != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// ExpireAccessRequests moves lapsed pending requests to expired.
//
// A row that cannot be decoded is still expired — the UPDATE ran against it —
// but is dropped from the returned slice, so it produces no audit event. That
// is the honest outcome: the broker cannot say what lapsed if it cannot read
// the request, and inventing a partial event would put a subject the store
// could not parse into the permanent trail.
func (s *Store) ExpireAccessRequests(now time.Time) ([]secretbroker.AccessRequest, error) {
	rows, err := s.db.ExpireGrantRequests(now)
	if err != nil {
		return nil, translateErr(err)
	}
	out := make([]secretbroker.AccessRequest, 0, len(rows))
	for _, row := range rows {
		r, rerr := toAccessRequest(row)
		if rerr != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// RecordRequestUse notes one lease that redeemed an approved request's grant.
func (s *Store) RecordRequestUse(u secretbroker.RequestUse) error {
	return translateErr(s.db.PutGrantRequestUse(statedb.GrantRequestUseRow{
		RequestID:   u.RequestID,
		LeaseID:     u.LeaseID,
		GrantID:     u.GrantID,
		ExecutorID:  u.ExecutorID,
		ProjectPath: u.ProjectID,
		TaskID:      u.TaskID,
		FirstSeen:   formatTime(u.FirstSeen),
		LastSeen:    formatTime(u.LastSeen),
	}))
}

// ListRequestUses returns the leases recorded against one request.
//
// It reconciles task attribution first. That write-during-a-read is deliberate
// and is explained in statedb.AttributeRequestUseTasks: a lease is issued before
// the workload that holds it is dispatched, so the task can only be learned
// afterwards, and only while the dispatched handle is still live. Doing it here
// means an approver opening the panel captures attributions that would otherwise
// be lost when the workload ends. A failure is ignored rather than surfaced —
// the uses themselves are still the answer, just with one column short.
func (s *Store) ListRequestUses(requestID string) ([]secretbroker.RequestUse, error) {
	_, _ = s.db.AttributeRequestUseTasks()

	rows, err := s.db.ListGrantRequestUses(requestID)
	if err != nil {
		return nil, translateErr(err)
	}
	out := make([]secretbroker.RequestUse, 0, len(rows))
	for _, row := range rows {
		out = append(out, secretbroker.RequestUse{
			RequestID:  row.RequestID,
			LeaseID:    row.LeaseID,
			GrantID:    row.GrantID,
			ExecutorID: row.ExecutorID,
			ProjectID:  row.ProjectPath,
			TaskID:     row.TaskID,
			FirstSeen:  parseTime(row.FirstSeen),
			LastSeen:   parseTime(row.LastSeen),
		})
	}
	return out, nil
}

// toAccessRequest converts a row, routing the subject through the broker's own
// parser for the reason decodeSubject gives: a storage layer must not be able to
// produce a Subject the parser would have rejected.
func toAccessRequest(row statedb.GrantRequestRow) (secretbroker.AccessRequest, error) {
	var c secretbroker.Constraints
	if row.ConstraintsJSON != "" {
		if err := json.Unmarshal([]byte(row.ConstraintsJSON), &c); err != nil {
			return secretbroker.AccessRequest{},
				fmt.Errorf("secretstore: decode constraints for request %s: %w", row.ID, err)
		}
	}
	subject, err := decodeSubject(row.SubjectType, row.SubjectValue)
	if err != nil {
		return secretbroker.AccessRequest{}, err
	}
	state := secretbroker.RequestState(row.State)
	if !state.Valid() {
		// An unrecognised state is not a request this binary can reason about,
		// and guessing "pending" would make it decidable. Refuse it into the
		// skip path instead.
		return secretbroker.AccessRequest{},
			fmt.Errorf("secretstore: request %s has unknown state %q", row.ID, row.State)
	}
	return secretbroker.AccessRequest{
		ID:             row.ID,
		RequestedBy:    row.RequestedBy,
		SecretID:       row.SecretID,
		SecretName:     row.SecretName,
		Kind:           secretbroker.Kind(row.Kind),
		Subject:        subject,
		Constraints:    c,
		Scope:          row.Scope,
		TTL:            time.Duration(row.TTLSeconds) * time.Second,
		Justification:  row.Justification,
		State:          state,
		CreatedAt:      parseTime(row.CreatedAt),
		ExpiresAt:      parseTime(row.ExpiresAt),
		DecidedBy:      row.DecidedBy,
		DecidedAt:      parseTime(row.DecidedAt),
		DecisionNote:   row.DecisionNote,
		GrantID:        row.GrantID,
		GrantExpiresAt: parseTime(row.GrantExpiresAt),
	}, nil
}
