package ciworkflow_test

// anthropic_test.go plays api.anthropic.com for the hub's relay.
//
// It is strict where the real API is strict about the fields the relay touches
// — the credential, the version header, `model`, `max_tokens` and a thinking
// budget that has to fit under it — because those are the places a relay can
// turn a request the harness got right into one the API refuses. Everything
// else in the body is the harness's business and is only recorded.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hubAnthropicKey is the credential the hub relays with. It is written into the
// hub's config and nowhere else, so finding it anywhere a pipeline can read is
// a leak.
const hubAnthropicKey = "sk-ant-api03-ciworkflow-hub-credential-never-leaves-the-hub"

// upstreamRequest is one call the relay made.
type upstreamRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte

	Model        string
	MaxTokens    int
	Stream       bool
	InputTokens  int64 // what the reply reported, for comparing with the hub's meter
	OutputTokens int64
	Status       int
}

type fakeAnthropic struct {
	srv *httptest.Server

	// reply is the assistant text every Messages call answers with. It
	// carries a per-run nonce so output left over from another run cannot
	// satisfy an assertion about this one.
	reply string

	mu       sync.Mutex
	requests []upstreamRequest
}

func newFakeAnthropic(t *testing.T, pki *testPKI) *fakeAnthropic {
	t.Helper()
	f := &fakeAnthropic{
		reply: "cloop-relay-" + randHex(t, 6) + ": reviewed the diff, no bug found.",
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = pki.serverTLS()
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAnthropic) seen() []upstreamRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upstreamRequest(nil), f.requests...)
}

func (f *fakeAnthropic) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	rec := upstreamRequest{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
		Header: r.Header.Clone(), Body: body,
	}
	defer func() {
		f.mu.Lock()
		f.requests = append(f.requests, rec)
		f.mu.Unlock()
	}()
	fail := func(status int, kind, msg string) {
		rec.Status = status
		writeJSON(w, status, map[string]any{
			"type": "error", "error": map[string]any{"type": kind, "message": msg},
		})
	}

	if r.Header.Get("X-Api-Key") != hubAnthropicKey {
		fail(http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
		return
	}
	if r.Header.Get("Anthropic-Version") == "" {
		fail(http.StatusBadRequest, "invalid_request_error", "anthropic-version: header is required")
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		rec.Status = http.StatusOK
		writeJSON(w, http.StatusOK, map[string]any{
			"data": []any{
				map[string]any{"type": "model", "id": "claude-sonnet-5", "display_name": "Claude Sonnet 5"},
				map[string]any{"type": "model", "id": "claude-haiku-4-5-20251001", "display_name": "Claude Haiku 4.5"},
			},
			"has_more": false,
		})
		return
	case r.Method != http.MethodPost:
		fail(http.StatusNotFound, "not_found_error", "Not found")
		return
	case r.URL.Path != "/v1/messages" && r.URL.Path != "/v1/messages/count_tokens":
		fail(http.StatusNotFound, "not_found_error", "Not found")
		return
	}

	var req struct {
		Model     string `json:"model"`
		MaxTokens *int   `json:"max_tokens"`
		Stream    bool   `json:"stream"`
		Thinking  *struct {
			Type         string `json:"type"`
			BudgetTokens *int   `json:"budget_tokens"`
		} `json:"thinking"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		fail(http.StatusBadRequest, "invalid_request_error", "body is not valid JSON")
		return
	}
	rec.Model, rec.Stream = req.Model, req.Stream
	if !strings.HasPrefix(req.Model, "claude-") {
		fail(http.StatusNotFound, "not_found_error", fmt.Sprintf("model: %s", req.Model))
		return
	}
	// The same rough estimate for both endpoints, so count_tokens and the
	// usage on the matching call agree.
	input := int64(len(body)/4 + 1)

	if r.URL.Path == "/v1/messages/count_tokens" {
		rec.Status, rec.InputTokens = http.StatusOK, input
		writeJSON(w, http.StatusOK, map[string]any{"input_tokens": input})
		return
	}

	if req.MaxTokens == nil {
		fail(http.StatusBadRequest, "invalid_request_error", "max_tokens: Field required")
		return
	}
	rec.MaxTokens = *req.MaxTokens
	if rec.MaxTokens < 1 {
		fail(http.StatusBadRequest, "invalid_request_error", "max_tokens: must be at least 1")
		return
	}
	if req.Thinking != nil && req.Thinking.Type == "enabled" {
		if req.Thinking.BudgetTokens == nil || *req.Thinking.BudgetTokens < 1024 {
			fail(http.StatusBadRequest, "invalid_request_error",
				"thinking.enabled.budget_tokens: Input should be greater than or equal to 1024")
			return
		}
		if *req.Thinking.BudgetTokens >= rec.MaxTokens {
			fail(http.StatusBadRequest, "invalid_request_error",
				"`max_tokens` must be greater than `thinking.budget_tokens`")
			return
		}
	}

	const output = 9
	rec.Status, rec.InputTokens, rec.OutputTokens = http.StatusOK, input, output
	msgID := "msg_ciworkflow_" + fmt.Sprint(len(f.seen())+1)
	if !req.Stream {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": msgID, "type": "message", "role": "assistant", "model": req.Model,
			"content":     []any{map[string]any{"type": "text", "text": f.reply}},
			"stop_reason": "end_turn", "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": input, "output_tokens": output},
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	send := func(event string, data map[string]any) {
		b, _ := json.Marshal(data)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	send("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": msgID, "type": "message", "role": "assistant", "model": req.Model,
		"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": input, "output_tokens": 1},
	}})
	send("content_block_start", map[string]any{"type": "content_block_start", "index": 0,
		"content_block": map[string]any{"type": "text", "text": ""}})
	// Two deltas rather than one, so a client that kept only the last one
	// would print half the answer and fail the assertion on it.
	half := len(f.reply) / 2
	for _, part := range []string{f.reply[:half], f.reply[half:]} {
		send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "text_delta", "text": part}})
	}
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{"type": "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": output}})
	send("message_stop", map[string]any{"type": "message_stop"})
}
