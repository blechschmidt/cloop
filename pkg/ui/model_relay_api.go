package ui

// model_relay_api.go: a project's own model allowlist for its relayed runs
// (Task 20435). The hub's allowlist (executors.model_relay.models) is the
// ceiling; a project's maintainers may narrow it for their project, and a
// project list naming a model the hub's leaves out admits nothing more. Kept in
// the control plane's database — never in the project's tree, which the
// sandbox the relay serves can write.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// modelRelayModelsRequest is PUT /api/projects/{idx}/model-relay's body.
type modelRelayModelsRequest struct {
	// Models narrows the hub's allowlist for the project's runs, as globs;
	// empty clears the project's list, so the hub's applies.
	Models []string `json:"models"`
}

// handleProjectModelRelay stores a project's own model allowlist and answers
// with the project's Claude credential card, relay summary included.
func (s *Server) handleProjectModelRelay(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}
	var req modelRelayModelsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	models := make([]string, 0, len(req.Models))
	for _, m := range req.Models {
		if m = strings.TrimSpace(m); m != "" {
			models = append(models, m)
		}
	}
	if len(models) > 0 {
		hub := []string{}
		if cfg, err := controlPlaneConfig(); err == nil && cfg != nil {
			hub = cfg.Executors.ModelRelay.EffectiveModels()
		}
		if len(claudeproxy.IntersectModels(models, hub)) == 0 {
			jsonErr(w, "none of "+strings.Join(models, ", ")+" is a model the hub's relay allows ("+
				strings.Join(hub, ", ")+"); a project's list narrows the hub's and cannot widen it",
				http.StatusBadRequest)
			return
		}
	}
	if err := setProjectRelayModels(entry.Path, models); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditModelRelayModels(r, entry.Path, models)
	jsonOK(w, s.harnessCredentialView(r, entry))
}

// auditModelRelayModels records a change to a project's model allowlist.
func (s *Server) auditModelRelayModels(r *http.Request, workDir string, models []string) {
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	payload, _ := json.Marshal(map[string]any{"project": policyProjectPath(workDir), "models": models})
	_ = db.AsControlPlane().AppendAuditEvent(&statedb.AuditEvent{
		Timestamp: time.Now().UTC(), Actor: s.recipientIdentity(r).OwnerKey(),
		EventType: string(auditaction.ActionModelRelayModelsSet), EntityType: "project",
		EntityID: policyProjectPath(workDir), Payload: string(payload),
	})
}
