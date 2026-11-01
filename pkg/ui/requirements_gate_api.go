package ui

// requirements_gate_api.go: the overview's requirements gate control (Task
// 20461).
//
//	POST /api/options/requirements-gate   {"mode": "off"|"linked"|"linked+must", "assess": bool}
//
// Either field may be left out to keep its value. The setting is stored on its
// own, as "done means committed" is (handleOptionsToggle): a run may be saving
// its tasks right now, and a full save from this handler's copy would write
// stale tasks back over them. A running orchestrator picks it up at its next
// sync and checks the next task its agent reports done with it.
//
// The project's config.yaml may declare the gate too (requirements.gate), and
// `cloop run` applies a declaration at every start. So when the file declares
// one, the handler rewrites the declaration as well — otherwise the next run
// would put back the setting the person just changed.

import (
	"net/http"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// handleRequirementsGateSet answers POST /api/options/requirements-gate.
func (s *Server) handleRequirementsGateSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode   *string `json:"mode"`
		Assess *bool   `json:"assess"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Mode == nil && req.Assess == nil {
		jsonErr(w, "nothing to change: give mode (off, linked or linked+must), assess, or both", http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	next := ps.RequirementsGate.Clone()
	if next == nil {
		next = &pm.RequirementsGate{Mode: pm.RequirementsGateOff}
	}
	if req.Mode != nil {
		mode, err := pm.ParseRequirementsGateMode(*req.Mode)
		if err != nil {
			jsonErr(w, "mode: "+err.Error(), http.StatusBadRequest)
			return
		}
		next.Mode = mode
	}
	if req.Assess != nil {
		next.Assess = *req.Assess
	}
	if err := state.SetRequirementsGate(workDir, next); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	declared := false
	cfg, err := config.Load(workDir)
	if err == nil && cfg.Requirements.Declares() {
		declared = true
		cfg.Requirements.Gate = next.EffectiveMode()
		if cfg.Requirements.Assess != nil || next.Assess {
			assess := next.Assess
			cfg.Requirements.Assess = &assess
		}
		err = config.Save(workDir, cfg)
	}
	if err != nil {
		// The project's own setting is stored; only the declaration lags.
		jsonOK(w, map[string]any{"ok": true, "requirements_gate": next,
			"warning": "the setting is stored, but config.yaml's requirements section could not be updated: " + err.Error() +
				" — the next run may put the declared value back"})
		return
	}
	if fresh, err := state.LoadLite(workDir); err == nil {
		s.broadcastStateDiff(workDir, fresh)
	}
	jsonOK(w, map[string]any{"ok": true, "requirements_gate": next, "declared": declared})
}
