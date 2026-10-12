package provision

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// auditEvent builds one control-plane audit row. The action is given as its
// registered name and checked against the catalog, so a misspelling is an
// error here rather than an unregistered row in the trail.
func auditEvent(actor string, action auditaction.Action, entity, entityID string, payload map[string]any,
	at time.Time) (*statedb.AuditEvent, error) {
	if _, ok := auditaction.Lookup(action); !ok {
		return nil, fmt.Errorf("provision: audit action %q is not registered", action)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("provision: encode audit payload: %w", err)
	}
	if actor == "" {
		actor = "scim"
	}
	return &statedb.AuditEvent{
		Timestamp:  at.UTC(),
		Actor:      actor,
		EventType:  string(action),
		EntityType: entity,
		EntityID:   entityID,
		Payload:    string(blob),
	}, nil
}
