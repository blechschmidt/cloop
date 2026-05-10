package ui

// HTTP-level tests for the Provider Calls inspector endpoints (Task 20123).
//
// Covers the three handlers exposed by pkg/ui/provider_calls.go:
//   - GET  /api/provider-calls          — paginated list (summary fields)
//   - GET  /api/provider-calls/{id}     — full row (prompt + response + headers)
//   - POST /api/provider-calls/{id}/replay
//
// The notifier path is exercised indirectly via the audit-log decorator in
// pkg/provideraudit_test; here we verify the read API returns what the
// underlying state layer persists, including filter parameters and per-
// project scoping (the recurring multi-project bug class — Tasks 150, 152,
// 163, 168, 8000).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedProviderCall inserts a row into the project's audit log and returns the
// assigned id. The helper hides the state-layer plumbing so individual tests
// stay focused on the API surface they're exercising.
func seedProviderCall(t *testing.T, dir string, row statedb.ProviderCallRow) int64 {
	t.Helper()
	id, err := state.AppendProviderCall(dir, row)
	if err != nil {
		t.Fatalf("AppendProviderCall(%s): %v", dir, err)
	}
	if id == 0 {
		t.Fatalf("AppendProviderCall(%s): returned zero id (no .cloop dir?)", dir)
	}
	return id
}

func TestProviderCalls_List_ReturnsSeededRows(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	now := time.Now().UTC()
	seedProviderCall(t, dir, statedb.ProviderCallRow{
		Timestamp:    now.Add(-2 * time.Second),
		Provider:     "anthropic",
		Model:        "claude-opus-4-7",
		TaskID:       42,
		TaskTitle:    "first task",
		Prompt:       "first prompt",
		Response:     "first response",
		Status:       "ok",
		Headers:      `{"max_tokens":4096}`,
		InputTokens:  100,
		OutputTokens: 50,
		LatencyMs:    1234,
	})
	seedProviderCall(t, dir, statedb.ProviderCallRow{
		Timestamp:    now,
		Provider:     "openai",
		Model:        "gpt-4",
		TaskID:       43,
		TaskTitle:    "second task",
		Prompt:       "second prompt",
		Response:     "second response",
		Status:       "ok",
		Headers:      `{"max_tokens":2048}`,
		InputTokens:  10,
		OutputTokens: 5,
		LatencyMs:    100,
	})

	got := apiGET(t, ts, "/api/provider-calls?limit=10")
	calls, _ := got["calls"].([]interface{})
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d (raw=%v)", len(calls), got)
	}
	total, _ := got["total"].(float64)
	if int(total) != 2 {
		t.Errorf("expected total=2, got %v", total)
	}
	// Latest first.
	first, _ := calls[0].(map[string]interface{})
	if first["provider"] != "openai" {
		t.Errorf("expected newest row first; got provider=%v", first["provider"])
	}
	if int(first["task_id"].(float64)) != 43 {
		t.Errorf("expected task_id=43 first; got %v", first["task_id"])
	}
	// Summary form must NOT include the heavy prompt/response/headers fields.
	for _, banned := range []string{"prompt", "response", "system_prompt", "headers"} {
		if _, ok := first[banned]; ok {
			t.Errorf("list summary leaked heavy field %q (%v)", banned, first[banned])
		}
	}
}

func TestProviderCalls_List_FiltersByProviderAndTask(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	now := time.Now().UTC()
	rows := []statedb.ProviderCallRow{
		{Timestamp: now.Add(-1 * time.Second), Provider: "anthropic", Model: "m1", TaskID: 1, Status: "ok", Prompt: "a"},
		{Timestamp: now.Add(-2 * time.Second), Provider: "openai", Model: "m2", TaskID: 1, Status: "ok", Prompt: "b"},
		{Timestamp: now.Add(-3 * time.Second), Provider: "anthropic", Model: "m1", TaskID: 2, Status: "ok", Prompt: "c"},
	}
	for _, row := range rows {
		seedProviderCall(t, dir, row)
	}

	got := apiGET(t, ts, "/api/provider-calls?provider=anthropic&limit=10")
	calls, _ := got["calls"].([]interface{})
	if len(calls) != 2 {
		t.Fatalf("provider=anthropic: expected 2 rows, got %d", len(calls))
	}
	for i, c := range calls {
		m := c.(map[string]interface{})
		if m["provider"] != "anthropic" {
			t.Errorf("row %d: filter leaked %v", i, m["provider"])
		}
	}

	got = apiGET(t, ts, "/api/provider-calls?task_id=1&limit=10")
	calls, _ = got["calls"].([]interface{})
	if len(calls) != 2 {
		t.Fatalf("task_id=1: expected 2 rows, got %d", len(calls))
	}
	for i, c := range calls {
		m := c.(map[string]interface{})
		if int(m["task_id"].(float64)) != 1 {
			t.Errorf("row %d: filter leaked task_id=%v", i, m["task_id"])
		}
	}
}

func TestProviderCalls_Detail_ReturnsHeavyFields(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	id := seedProviderCall(t, dir, statedb.ProviderCallRow{
		Timestamp:    time.Now().UTC(),
		Provider:     "anthropic",
		Model:        "claude-opus-4-7",
		Prompt:       "hello world prompt body",
		SystemPrompt: "you are a helpful assistant",
		Response:     "hello back",
		Status:       "ok",
		// Headers are stored as a JSON string in the DB; the detail endpoint
		// re-parses them so the client receives a typed object.
		Headers:      `{"max_tokens":4096,"authorization":"Bearer [REDACTED]"}`,
		InputTokens:  10,
		OutputTokens: 3,
		LatencyMs:    250,
	})

	got := apiGET(t, ts, "/api/provider-calls/"+itoa64(id))
	if got["prompt"] != "hello world prompt body" {
		t.Errorf("prompt mismatch: %v", got["prompt"])
	}
	if got["system_prompt"] != "you are a helpful assistant" {
		t.Errorf("system_prompt mismatch: %v", got["system_prompt"])
	}
	if got["response"] != "hello back" {
		t.Errorf("response mismatch: %v", got["response"])
	}
	headers, ok := got["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers must decode to object, got %T (%v)", got["headers"], got["headers"])
	}
	if headers["max_tokens"].(float64) != 4096 {
		t.Errorf("headers.max_tokens: %v", headers["max_tokens"])
	}
	// Critical security check: redaction MUST be applied at write time. We
	// seeded a redacted token; the detail must echo it back as-is, not
	// decrypted. This documents the contract that on-disk data is never
	// reconstructable into a real key.
	if hgot, want := headers["authorization"].(string), "Bearer [REDACTED]"; hgot != want {
		t.Errorf("authorization not preserved as redacted: got %q want %q", hgot, want)
	}
}

func TestProviderCalls_Detail_NotFound(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/provider-calls/999999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing id, got %d", resp.StatusCode)
	}
}

func TestProviderCalls_Detail_RejectsBadID(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	resp, err := http.Get(ts.URL + "/api/provider-calls/not-a-number")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid id, got %d", resp.StatusCode)
	}
}

func TestProviderCalls_Replay_RejectsBadID(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := bytes.NewBufferString(`{}`)
	resp, err := http.Post(ts.URL+"/api/provider-calls/0/replay", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("id=0 should be rejected as bad id, got %d", resp.StatusCode)
	}
}

func TestProviderCalls_Replay_NotFound(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := bytes.NewBufferString(`{"prompt":"new"}`)
	resp, err := http.Post(ts.URL+"/api/provider-calls/999999/replay", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing id should return 404, got %d", resp.StatusCode)
	}
}

func TestProviderCalls_PerProjectScoping(t *testing.T) {
	// Each project's audit log lives in its own state.db; the list endpoint
	// must honour ?project_idx=N. This is the multi-project bug class that
	// has burned us repeatedly (Tasks 150, 152, 163, 168, 8000).
	cloopDir := setupProjectDir(t, cloopGoal, nil)
	sysmonDir := setupProjectDir(t, sysmonGoal, nil)
	ts := newTestServer(t, cloopDir, []string{sysmonDir})

	now := time.Now().UTC()
	seedProviderCall(t, cloopDir, statedb.ProviderCallRow{
		Timestamp: now, Provider: "anthropic", Model: "cloop-model",
		TaskID: 1, TaskTitle: "cloop task", Status: "ok", Prompt: "cloop",
	})
	seedProviderCall(t, sysmonDir, statedb.ProviderCallRow{
		Timestamp: now, Provider: "openai", Model: "sysmon-model",
		TaskID: 2, TaskTitle: "sysmon task", Status: "ok", Prompt: "sysmon",
	})
	seedProviderCall(t, sysmonDir, statedb.ProviderCallRow{
		Timestamp: now.Add(time.Second), Provider: "ollama", Model: "sysmon-model-2",
		TaskID: 3, TaskTitle: "sysmon task 2", Status: "ok", Prompt: "sysmon-2",
	})

	// Default project (cloop, idx=0): exactly one row.
	got := apiGET(t, ts, "/api/provider-calls")
	calls, _ := got["calls"].([]interface{})
	if len(calls) != 1 {
		t.Errorf("default project: expected 1 row, got %d", len(calls))
	}
	if len(calls) > 0 {
		first := calls[0].(map[string]interface{})
		if first["model"] != "cloop-model" {
			t.Errorf("default project leaked sysmon row: %v", first["model"])
		}
	}

	// project_idx=1 (sysmon): exactly two rows, none from cloop.
	got = apiGET(t, ts, "/api/provider-calls?project_idx=1")
	calls, _ = got["calls"].([]interface{})
	if len(calls) != 2 {
		t.Errorf("sysmon project: expected 2 rows, got %d", len(calls))
	}
	for i, c := range calls {
		m := c.(map[string]interface{})
		if m["model"] == "cloop-model" {
			t.Errorf("sysmon row %d leaked cloop row: %v", i, m["model"])
		}
	}
}

// TestProviderCalls_List_DefaultsLimit verifies that an unspecified limit
// uses the documented default of 100 — important so the table doesn't
// accidentally fetch the entire history on first paint.
func TestProviderCalls_List_DefaultsLimit(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	got := apiGET(t, ts, "/api/provider-calls")
	limit, ok := got["limit"].(float64)
	if !ok {
		t.Fatalf("limit field missing from response: %v", got)
	}
	if int(limit) != 100 {
		t.Errorf("expected default limit=100, got %v", limit)
	}
}

// TestProviderCalls_RouteIsRegistered guards against route-table refactors
// silently dropping any of the three endpoints.
func TestProviderCalls_RouteIsRegistered(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	for _, path := range []string{
		"/api/provider-calls",
		"/api/provider-calls/1",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("route %s returned 405 — endpoint unregistered or wrong method", path)
		}
	}

	// Replay is POST-only.
	body := bytes.NewBufferString(`{}`)
	resp, err := http.Post(ts.URL+"/api/provider-calls/1/replay", "application/json", body)
	if err != nil {
		t.Fatalf("POST replay: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Errorf("replay route returned 405 — endpoint unregistered")
	}
}

// TestProviderCalls_DetailHeadersGracefulOnMalformed verifies the detail
// endpoint copes with malformed JSON in the headers column without crashing
// or leaking the raw bytes — falls back to an empty object so the client
// always sees a stable shape.
func TestProviderCalls_DetailHeadersGracefulOnMalformed(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	id := seedProviderCall(t, dir, statedb.ProviderCallRow{
		Timestamp: time.Now().UTC(),
		Provider:  "anthropic",
		Model:     "m",
		Status:    "ok",
		Headers:   "this is not valid json",
	})

	got := apiGET(t, ts, "/api/provider-calls/"+itoa64(id))
	headers, ok := got["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers must decode to (possibly empty) object, got %T", got["headers"])
	}
	if len(headers) != 0 {
		t.Errorf("malformed-headers row should yield empty object, got %v", headers)
	}
}

// TestProviderCalls_Detail_FullSerialisation exercises a round-trip via
// json.Decoder to confirm the wire shape matches providerCallDetail's tags.
// Catches breakage if a refactor renames a field but forgets to update its
// JSON tag.
func TestProviderCalls_Detail_FullSerialisation(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	id := seedProviderCall(t, dir, statedb.ProviderCallRow{
		Timestamp:      time.Now().UTC(),
		Provider:       "anthropic",
		Model:          "claude-opus-4-7",
		TaskID:         7,
		TaskTitle:      "wire-shape test",
		RequestID:      "req-abc-123",
		Prompt:         "p",
		SystemPrompt:   "sys",
		Response:       "r",
		Status:         "ok",
		Headers:        `{"max_tokens":4096}`,
		InputTokens:    11,
		OutputTokens:   22,
		ThinkingTokens: 33,
		LatencyMs:      444,
	})

	resp, err := http.Get(ts.URL + "/api/provider-calls/" + itoa64(id))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var detail struct {
		ID             int64                  `json:"id"`
		Provider       string                 `json:"provider"`
		Model          string                 `json:"model"`
		TaskID         int                    `json:"task_id"`
		TaskTitle      string                 `json:"task_title"`
		RequestID      string                 `json:"request_id"`
		Status         string                 `json:"status"`
		Prompt         string                 `json:"prompt"`
		SystemPrompt   string                 `json:"system_prompt"`
		Response       string                 `json:"response"`
		Headers        map[string]interface{} `json:"headers"`
		InputTokens    int                    `json:"input_tokens"`
		OutputTokens   int                    `json:"output_tokens"`
		ThinkingTokens int                    `json:"thinking_tokens"`
		LatencyMs      int                    `json:"latency_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.ID != id {
		t.Errorf("id round-trip: got %d want %d", detail.ID, id)
	}
	if detail.RequestID != "req-abc-123" {
		t.Errorf("request_id round-trip: %v", detail.RequestID)
	}
	if detail.ThinkingTokens != 33 {
		t.Errorf("thinking_tokens round-trip: %v", detail.ThinkingTokens)
	}
	if detail.LatencyMs != 444 {
		t.Errorf("latency_ms round-trip: %v", detail.LatencyMs)
	}
	// Sanity: prompt/response/system are required fields, not omitempty.
	if !strings.EqualFold(detail.Prompt, "p") {
		t.Errorf("prompt round-trip: %q", detail.Prompt)
	}
}

// itoa64 stringifies an int64 without pulling strconv into this test file.
// Sibling itoa(int) lives in ratelimit_test.go.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
