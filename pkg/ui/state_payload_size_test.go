package ui

// Task 20125: verify that /api/state strips the multi-MiB Steps[] slice
// and surfaces a slim steps_count field instead. The browser only reads
// steps.length here; the actual rows come from /api/steps and
// /api/event-history (paginated). Without this trim the endpoint shipped
// ~2.7 MiB per request on a 5k-step project and dominated UI latency.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
)

func TestApiStateOmitsStepsArray(t *testing.T) {
	dir := setupProjectDir(t, "test goal", nil)

	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	big := make([]byte, 8*1024)
	for i := range big {
		big[i] = 'x'
	}
	for i := 0; i < 25; i++ {
		ps.Steps = append(ps.Steps, state.StepResult{
			Step:     i,
			Task:     "Task",
			Output:   string(big),
			ExitCode: 0,
			Duration: "1s",
			Time:     time.Now(),
		})
	}
	if err := ps.SaveDirect(); err != nil {
		t.Fatalf("save: %v", err)
	}

	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, ok := body["steps"]; ok && v != nil {
		if arr, isArr := v.([]interface{}); isArr && len(arr) > 0 {
			t.Errorf("expected steps[] to be omitted/empty, got %d entries", len(arr))
		}
	}

	got, ok := body["steps_count"].(float64)
	if !ok {
		t.Fatalf("expected numeric steps_count, body keys=%v", stateKeys(body))
	}
	if int(got) != 25 {
		t.Errorf("steps_count=%v, want 25", got)
	}
}

func stateKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
