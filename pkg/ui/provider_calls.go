// Provider call inspector handlers (Task 20105 / Task 20123).
//
// Backs the Web UI's "Provider Calls" panel:
//
//   GET    /api/provider-calls          — paginated list (summary fields)
//   GET    /api/provider-calls/{id}     — full row (prompt + response + headers)
//   POST   /api/provider-calls/{id}/replay
//                                       — re-run the call (optionally with an
//                                         edited prompt) and return both
//                                         responses for side-by-side diffing
//
// The list is per-project (resolveWorkDir(r) honours ?project_idx). Live
// updates flow over the existing per-project WebSocket as type:"provider_call"
// envelopes — see registerProviderCallNotifier below.

package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provideraudit"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// providerCallSummary is the shape returned by GET /api/provider-calls.
// It omits the heavy prompt/response/headers fields so the list stays cheap.
type providerCallSummary struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	TaskID         int       `json:"task_id"`
	TaskTitle      string    `json:"task_title"`
	RequestID      string    `json:"request_id,omitempty"`
	Status         string    `json:"status"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	ThinkingTokens int       `json:"thinking_tokens,omitempty"`
	LatencyMs      int       `json:"latency_ms"`
}

// providerCallDetail is the shape returned by GET /api/provider-calls/{id}.
// Adds the heavy fields. Headers is parsed back from the JSON-encoded blob
// stored in the DB so the client receives a structured object, not a string.
type providerCallDetail struct {
	providerCallSummary
	Prompt       string                 `json:"prompt"`
	SystemPrompt string                 `json:"system_prompt,omitempty"`
	Response     string                 `json:"response"`
	Headers      map[string]interface{} `json:"headers"`
}

// handleProviderCallsList serves GET /api/provider-calls?offset=N&limit=M&task_id=K&provider=P
func (s *Server) handleProviderCallsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	taskID, _ := strconv.Atoi(q.Get("task_id"))
	providerFilter := q.Get("provider")
	if limit <= 0 {
		limit = 100
	}

	rows, total, err := state.ListProviderCalls(s.resolveWorkDir(r), offset, limit, taskID, providerFilter)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	out := make([]providerCallSummary, 0, len(rows))
	for _, rw := range rows {
		out = append(out, summaryFromRow(rw))
	}
	jsonOK(w, map[string]interface{}{
		"calls":  out,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

// handleProviderCallDetail serves GET /api/provider-calls/{id}.
func (s *Server) handleProviderCallDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid call id", http.StatusBadRequest)
		return
	}
	row, err := state.LoadProviderCall(s.resolveWorkDir(r), id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonOK(w, detailFromRow(*row))
}

// handleProviderCallReplay serves POST /api/provider-calls/{id}/replay.
//
// Body (all fields optional):
//
//	{
//	  "prompt":        "...",   // override prompt; defaults to the original
//	  "system_prompt": "...",   // override system prompt
//	  "model":         "...",   // override model; defaults to the original
//	}
//
// Response:
//
//	{
//	  "original": providerCallDetail,
//	  "replayed": {
//	    "id":           int64,    // id of the new audit row
//	    "prompt":       string,
//	    "response":     string,
//	    "error":        string,
//	    "latency_ms":   int,
//	    "input_tokens": int,
//	    "output_tokens": int,
//	    "model":        string,
//	  }
//	}
//
// The replay re-uses the project's current configuration to construct a
// provider, so changes the user has made since the original call (different
// API key, different base URL) are picked up. The new call is itself
// recorded into the audit log via the same auditDecorator, so the user can
// inspect/replay it again. A 30-second timeout caps wall-clock cost.
func (s *Server) handleProviderCallReplay(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid call id", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	original, err := state.LoadProviderCall(workDir, id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}

	limitJSONBody(w, r, s.effectiveMaxBodyBytes())
	var body struct {
		Prompt       *string `json:"prompt"`
		SystemPrompt *string `json:"system_prompt"`
		Model        *string `json:"model"`
	}
	// Empty body is fine — replay verbatim.
	_ = json.NewDecoder(r.Body).Decode(&body)

	replayPrompt := original.Prompt
	if body.Prompt != nil {
		replayPrompt = *body.Prompt
	}
	replaySystem := original.SystemPrompt
	if body.SystemPrompt != nil {
		replaySystem = *body.SystemPrompt
	}
	replayModel := original.Model
	if body.Model != nil && *body.Model != "" {
		replayModel = *body.Model
	}

	cfg, cfgErr := config.Load(workDir)
	if cfgErr != nil {
		jsonErr(w, "load config: "+cfgErr.Error(), http.StatusInternalServerError)
		return
	}
	prov, provErr := buildReplayProvider(cfg, original.Provider)
	if provErr != nil {
		jsonErr(w, "build provider: "+provErr.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	opts := provider.Options{
		Model:        replayModel,
		MaxTokens:    4096,
		Timeout:      30 * time.Second,
		SystemPrompt: replaySystem,
		WorkDir:      workDir,
	}
	// Tag the replay with the originating task so the new audit row is
	// correlated. Replays without a task originate from the inspector itself.
	if original.TaskID > 0 {
		ctx = provideraudit.WithTaskContext(ctx, original.TaskID, original.TaskTitle)
	}

	start := time.Now()
	res, callErr := prov.Complete(ctx, replayPrompt, opts)
	latency := time.Since(start)

	replay := map[string]interface{}{
		"prompt":        replayPrompt,
		"system_prompt": replaySystem,
		"model":         replayModel,
		"latency_ms":    int(latency / time.Millisecond),
		"provider":      original.Provider,
	}
	if callErr != nil {
		replay["error"] = callErr.Error()
		replay["status"] = "error"
	} else if res != nil {
		replay["response"] = res.Output
		replay["input_tokens"] = res.InputTokens
		replay["output_tokens"] = res.OutputTokens
		replay["thinking_tokens"] = res.ThinkingTokens
		replay["status"] = "ok"
	}

	jsonOK(w, map[string]interface{}{
		"original": detailFromRow(*original),
		"replayed": replay,
	})
}

// summaryFromRow converts a DB row into the API summary type.
func summaryFromRow(r statedb.ProviderCallRow) providerCallSummary {
	return providerCallSummary{
		ID:             r.ID,
		Timestamp:      r.Timestamp,
		Provider:       r.Provider,
		Model:          r.Model,
		TaskID:         r.TaskID,
		TaskTitle:      r.TaskTitle,
		RequestID:      r.RequestID,
		Status:         r.Status,
		ErrorMessage:   r.ErrorMessage,
		InputTokens:    r.InputTokens,
		OutputTokens:   r.OutputTokens,
		ThinkingTokens: r.ThinkingTokens,
		LatencyMs:      r.LatencyMs,
	}
}

// detailFromRow converts a DB row into the API detail type. Headers is
// re-parsed from the JSON blob; on parse failure it defaults to an empty
// map so the client never sees a partially-typed payload.
func detailFromRow(r statedb.ProviderCallRow) providerCallDetail {
	d := providerCallDetail{
		providerCallSummary: summaryFromRow(r),
		Prompt:              r.Prompt,
		SystemPrompt:        r.SystemPrompt,
		Response:            r.Response,
		Headers:             map[string]interface{}{},
	}
	if r.Headers != "" {
		_ = json.Unmarshal([]byte(r.Headers), &d.Headers)
	}
	return d
}

// providerCallNotifierRegistered guards against double-registration when a
// process spins up multiple Server instances (tests, or the dual cloop ui
// + cloop serve case). Without this guard the first server's notifier would
// be silently overwritten and live updates would stop flowing to its
// WebSocket clients.
var providerCallNotifierRegistered atomic.Bool

// registerProviderCallNotifier wires pkg/provideraudit so every newly-
// recorded call is broadcast over the project's WebSocket clients as a
// type:"provider_call" envelope.
//
// Idempotent: a second Server.Start() call on the same process is a no-op.
// The notifier is process-global because pkg/provideraudit is process-
// global; in a multi-server-per-process setup the LAST registered server
// wins for new notifications. (The realistic deployment is one server per
// process.)
func (s *Server) registerProviderCallNotifier() {
	if !providerCallNotifierRegistered.CompareAndSwap(false, true) {
		return
	}
	provideraudit.SetGlobalNotifier(func(workDir string, row statedb.ProviderCallRow) {
		summary := summaryFromRow(row)
		raw, err := json.Marshal(summary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: marshal provider_call notifier: %v\n", err)
			return
		}
		s.broadcastToProject(workDir, wsMessage{Type: "provider_call", Data: raw})
	})
}
