package secretstore

import (
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Auditor writes broker decisions into the hash-chained audit_events table.
//
// Every mint, grant, lease, renew, revoke, and denial lands here with the
// subject, the secret ID, and the reason. Payloads never do — see the
// redaction note on Audit.
type Auditor struct {
	db *statedb.DB
}

// NewAuditor wraps a database handle as a broker audit sink. A nil db
// yields a sink that drops events, so a caller that could not open the
// database still gets a working broker rather than a nil-pointer panic on
// the first decision.
func NewAuditor(db *statedb.DB) *Auditor {
	return &Auditor{db: db}
}

var _ secretbroker.Auditor = (*Auditor)(nil)

// Audit persists one brokered-operation event.
//
// Redact is called again here even though the broker already redacts on
// emission. That is not redundancy for its own sake: this is the last
// function before a credential-shaped string would become a permanent,
// hash-chained, deliberately-immutable row. An audit log is the worst place
// in the system to discover a leak, because the tamper-evidence that makes
// it valuable is also what makes it awkward to clean up. Redacting at the
// boundary means a future caller who constructs an Event by hand, or a
// broker change that adds a new emission path, cannot write plaintext here
// by omission.
//
// Best-effort, matching pkg/statedb's other audit emitters: a full or
// read-only database must not stop a workload from getting its credentials.
// The chain verifier surfaces the resulting gap.
func (a *Auditor) Audit(ev secretbroker.Event) {
	if a == nil || a.db == nil {
		return
	}
	ev = secretbroker.Redact(ev)

	entityID := ev.SecretID
	if entityID == "" {
		entityID = ev.GrantID
	}

	actor := ev.Actor
	if actor == "" {
		actor = "secretbroker"
	}

	payload := map[string]any{
		"decision": string(ev.Decision),
	}
	put := func(k, v string) {
		if v != "" {
			payload[k] = v
		}
	}
	put("subject", ev.Subject)
	put("secret_id", ev.SecretID)
	put("secret_name", ev.SecretName)
	put("kind", string(ev.Kind))
	put("grant_id", ev.GrantID)
	put("lease_id", ev.LeaseID)
	put("executor_id", ev.ExecutorID)
	put("project_id", ev.ProjectID)
	put("constraints", ev.Constraints)
	put("reason", ev.Reason)
	if !ev.ExpiresAt.IsZero() {
		payload["expires_at"] = ev.ExpiresAt.UTC()
	}

	statedb.AuditSecretDecision(a.db, statedb.SecretAuditInput{
		Actor:     actor,
		EventType: string(ev.Action),
		EntityID:  entityID,
		Timestamp: ev.Time,
		Payload:   payload,
	})
}
