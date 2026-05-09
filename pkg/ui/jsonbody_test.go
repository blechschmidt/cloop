package ui

// Regression tests for the JSON request body size cap.
//
// The UI runs as a long-lived daemon, so handlers that decode JSON without an
// upper bound let a malicious or buggy client OOM the process by streaming a
// multi-GB body. limitJSONBody wraps r.Body with http.MaxBytesReader to cap
// allocation. These tests assert that:
//
//   1. Oversized bodies are rejected before they reach handler logic, with a
//      4xx response and bounded memory usage.
//   2. Bodies just under the limit still decode successfully.
//   3. The chat handlers, which carry transcript history, accept payloads
//      between the default cap and their elevated cap.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// TestJSONBody_RejectsOversize_ConfigSet sends a 2 MiB JSON body to the
// /api/config/set handler (default 1 MiB cap) and expects a 4xx response
// rather than the daemon attempting to read the entire payload into memory.
func TestJSONBody_RejectsOversize_ConfigSet(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	// Build a JSON object with a single oversized "value" string. The leading
	// `{"key":"x","value":"` plus the trailing `"}` puts the payload above
	// the 1 MiB cap once the 2 MiB filler is included.
	const filler = 2 << 20 // 2 MiB
	var buf bytes.Buffer
	buf.WriteString(`{"key":"anthropic.api_key","value":"`)
	buf.Write(bytes.Repeat([]byte("a"), filler))
	buf.WriteString(`"}`)

	resp, err := http.Post(ts.URL+"/api/config/set", "application/json", &buf)
	if err != nil {
		// MaxBytesReader closes the connection after the limit; net/http may
		// return EOF before the response is fully read. Treat any non-nil
		// error as a successful rejection so long as it's not a panic.
		if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "connection") {
			t.Fatalf("unexpected transport error: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected 4xx for oversized body, got 200 — handler accepted unbounded JSON")
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("expected 4xx rejection, got %d", resp.StatusCode)
	}
}

// TestJSONBody_AcceptsUnderLimit confirms a normal-sized config-set request
// still works after the cap was added (no false-positive rejections).
func TestJSONBody_AcceptsUnderLimit(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	body := strings.NewReader(`{"key":"anthropic.model","value":"claude-opus-4-7"}`)
	resp, err := http.Post(ts.URL+"/api/config/set", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for normal-sized body, got %d", resp.StatusCode)
	}
}

// TestJSONBody_ChatLimitHigherThanDefault verifies the chat handler accepts
// a body larger than the default 1 MiB cap (it uses maxChatJSONBodyBytes,
// 4 MiB, because legitimate transcripts can be large).
func TestJSONBody_ChatLimitHigherThanDefault(t *testing.T) {
	if maxChatJSONBodyBytes <= maxJSONBodyBytes {
		t.Fatalf("test premise broken: maxChatJSONBodyBytes (%d) must exceed maxJSONBodyBytes (%d)",
			maxChatJSONBodyBytes, maxJSONBodyBytes)
	}

	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)

	// Build a chat body just above 1 MiB but well under 4 MiB. We expect the
	// handler to NOT reject on size grounds. Whether the chat backend then
	// succeeds is irrelevant — we only assert the response is not 413/400-
	// because-of-size. A 200 or any backend failure code is acceptable.
	const fill = (1 << 20) + (256 << 10) // 1.25 MiB filler
	var buf bytes.Buffer
	buf.WriteString(`{"message":"`)
	buf.Write(bytes.Repeat([]byte("h"), fill))
	buf.WriteString(`"}`)
	bodyLen := buf.Len()
	if int64(bodyLen) <= maxJSONBodyBytes {
		t.Fatalf("test setup error: body (%d) must exceed default cap (%d)", bodyLen, maxJSONBodyBytes)
	}
	if int64(bodyLen) >= maxChatJSONBodyBytes {
		t.Fatalf("test setup error: body (%d) must be under chat cap (%d)", bodyLen, maxChatJSONBodyBytes)
	}

	resp, err := http.Post(ts.URL+"/api/chat", "application/json", &buf)
	if err != nil {
		t.Fatalf("POST /api/chat: %v", err)
	}
	defer resp.Body.Close()

	// The server should at least have read the body successfully — it must
	// NOT report 413 (Request Entity Too Large) and must NOT close the
	// connection mid-read for size reasons. The response code itself can be
	// 200 or a backend error; we only verify size handling.
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("chat handler rejected legitimate 1.25 MiB body with 413 — chat cap not applied")
	}
}
