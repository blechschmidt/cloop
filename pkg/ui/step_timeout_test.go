package ui

import (
	"encoding/json"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
)

// TestMarshalStateForWire_InjectsStepTimeout is a regression for Task 20147:
// the per-project step timeout (which lives in config.yaml, not ProjectState)
// must be present on every full-state WebSocket broadcast, not just the HTTP
// /api/state response. Before the fix, the first task_update after a run
// started shipped a full state without step_timeout, the frontend's
// render(data) replaced appState wholesale, and the Active Options panel
// snapped back to its placeholder — making it look like the value had been
// reset on run start.
func TestMarshalStateForWire_InjectsStepTimeout(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.StepTimeout = "15m"
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	ps := &state.ProjectState{WorkDir: dir, Goal: "test"}
	raw, err := marshalStateForWire(ps)
	if err != nil {
		t.Fatalf("marshalStateForWire: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v\npayload: %s", err, raw)
	}
	if out["step_timeout"] != "15m" {
		t.Fatalf("step_timeout = %v, want 15m\npayload: %s", out["step_timeout"], raw)
	}
}

// TestMarshalStateForWire_StepTimeoutDisabledByDefault verifies that an unset
// step timeout is normalised to "0" (disabled) on the wire so the UI reads it
// as "off" rather than implying a 10m default that is no longer applied
// (Task 20147: disabled by default).
func TestMarshalStateForWire_StepTimeoutDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	// Leave StepTimeout unset.
	if err := config.Save(dir, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	ps := &state.ProjectState{WorkDir: dir, Goal: "test"}
	raw, err := marshalStateForWire(ps)
	if err != nil {
		t.Fatalf("marshalStateForWire: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v\npayload: %s", err, raw)
	}
	if out["step_timeout"] != "0" {
		t.Fatalf("step_timeout = %v, want 0 (disabled)\npayload: %s", out["step_timeout"], raw)
	}
}
