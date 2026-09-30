package ui

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// reviewGateRoutes are the review gate's endpoints (Task 20357). The settings
// also travel on the project state as review_gate, which is what the
// dashboard renders from; these read and change them.
func (s *Server) reviewGateRoutes() []routeSpec {
	return []routeSpec{
		{Pattern: "GET /api/options/review-gate", Handler: s.handleReviewGateGet, Perm: authz.PermProjectRead, Scope: scopeProject},
		{Pattern: "POST /api/options/review-gate", Handler: s.handleReviewGateSet, Perm: authz.PermConfigWrite, Scope: scopeProject},
	}
}

// handleReviewGateGet returns the project's review gate settings; a project
// that never configured one reports a disabled gate.
//
// GET /api/options/review-gate
func (s *Server) handleReviewGateGet(w http.ResponseWriter, r *http.Request) {
	ps, err := state.LoadLite(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	g := ps.ReviewGate
	if g == nil {
		g = &pm.ReviewGate{}
	}
	jsonOK(w, map[string]any{"review_gate": g, "modes": pm.ReviewModes,
		"default_fix_rounds": pm.DefaultReviewFixRounds, "max_fix_rounds": pm.MaxReviewFixRounds})
}

// handleReviewGateSet replaces the project's review gate settings. The body is
// the whole setting — the dialog sends every field — and is refused whole if
// any field is unusable, so a typo never half-configures a gate that decides
// what gets pushed.
//
// POST /api/options/review-gate  body: {"enabled":true,"provider":"anthropic",
// "model":"claude-opus-5-5","effort":"","mode":"fix","max_fix_rounds":2,"instructions":"..."}
func (s *Server) handleReviewGateSet(w http.ResponseWriter, r *http.Request) {
	var req pm.ReviewGate
	limitJSONBody(w, r, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	req.Normalize()
	if err := req.Validate(); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	// Only the setting is written, not the whole state: a run may be saving
	// its tasks right now, and a full save from this handler's copy would
	// write stale tasks back over them. The run adopts the change at its
	// next sync.
	if err := state.SetReviewGate(workDir, &req); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if ps, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, ps)
	}
	jsonOK(w, map[string]any{"ok": true, "review_gate": req})
}
