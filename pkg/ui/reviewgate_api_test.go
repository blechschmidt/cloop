package ui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Task 20357: the review gate is configured from the project overview.
func TestReviewGateAPI(t *testing.T) {
	dir := setupProjectDir(t, "review gate", []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskInProgress}})
	ts := newTestServer(t, dir, nil)

	status, body := rawJSON(t, ts, http.MethodGet, "/api/options/review-gate", nil)
	if status != http.StatusOK {
		t.Fatalf("GET = %d %v", status, body)
	}
	if g, _ := body["review_gate"].(map[string]interface{}); g == nil || g["enabled"] != false {
		t.Fatalf("an unconfigured project should report a disabled gate: %v", body)
	}

	status, body = rawJSON(t, ts, http.MethodPost, "/api/options/review-gate", map[string]interface{}{
		"enabled": true, "provider": " Anthropic ", "model": "claude-opus-5-5", "effort": "",
		"mode": "block", "max_fix_rounds": 0, "instructions": "Reject migrations.",
	})
	if status != http.StatusOK {
		t.Fatalf("POST = %d %v", status, body)
	}
	s, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := s.ReviewGate
	if !g.Active() || g.Provider != "anthropic" || g.Model != "claude-opus-5-5" || g.Mode != pm.ReviewModeBlock || g.Instructions != "Reject migrations." {
		t.Fatalf("stored gate = %+v", g)
	}
	if s.Plan.TaskByID(1).Status != pm.TaskInProgress {
		t.Error("saving the gate rewrote a running task")
	}

	// The dashboard renders from the project state.
	status, body = rawJSON(t, ts, http.MethodGet, "/api/state", nil)
	if rg, _ := body["review_gate"].(map[string]interface{}); status != http.StatusOK || rg == nil || rg["model"] != "claude-opus-5-5" {
		t.Errorf("/api/state does not carry review_gate: %d %v", status, body["review_gate"])
	}

	for _, bad := range []map[string]interface{}{
		{"enabled": true, "provider": "mock"},
		{"enabled": true, "model": "--dangerously-skip-permissions"},
		{"enabled": true, "mode": "sometimes"},
		{"enabled": true, "max_fix_rounds": 9},
		{"enabled": true, "effort": "ultra"},
		{"enabled": true, "instructions": strings.Repeat("x", pm.MaxReviewInstructionsBytes+1)},
		{"enabled": true, "reviewer": "unknown field"},
	} {
		if status, body := rawJSON(t, ts, http.MethodPost, "/api/options/review-gate", bad); status != http.StatusBadRequest {
			t.Errorf("POST %v = %d %v, want 400", bad, status, body)
		}
	}
	// A refused request leaves the stored gate as it was.
	if s, _ := state.Load(dir); s.ReviewGate == nil || s.ReviewGate.Model != "claude-opus-5-5" {
		t.Errorf("a refused update changed the gate: %+v", s.ReviewGate)
	}
}
