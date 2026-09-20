package ui

// Regression tests for Task 20325: the suggest panel reported
//
//	could not parse suggestions: invalid character 'w' looking for beginning of value
//
// The 'w' was the first letter of "warning:". The handler ran
// `cloop suggest --json` through pkg/executor, which merges the child's stdout
// and stderr into one buffer, and then json.Unmarshal'd the whole buffer — so
// any diagnostic written during startup displaced the payload. Here a stub
// binary stands in for the real command and reproduces that stream shape
// exactly.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// the real warning that broke the panel, verbatim from pkg/statedb/migrate.go.
const schemaWarning = `warning: schema version 37 was applied from "0037_project_members.sql", ` +
	`but this build embeds "0037_secret_grant_requests.sql" for that version — so ` +
	`"0037_secret_grant_requests.sql" has been SKIPPED and its effects are absent from this ` +
	`database. Two migrations were numbered the same; renumber the later one and re-apply it by hand.`

// writeSuggestStub creates an executable standing in for `cloop suggest
// --json`: it writes noise to stderr, then body to stdout. Returns its path.
func writeSuggestStub(t *testing.T, stderrNoise, stdoutBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub uses a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "cloop-suggest-stub")
	script := "#!/bin/sh\n" +
		"cat >&2 <<'CLOOP_STUB_STDERR'\n" + stderrNoise + "\nCLOOP_STUB_STDERR\n" +
		"cat <<'CLOOP_STUB_STDOUT'\n" + stdoutBody + "\nCLOOP_STUB_STDOUT\n" +
		"exit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("writing stub: %v", err)
	}
	return path
}

// runSuggest drives the real handlers: POST /api/suggest/generate, then poll
// /api/suggest/status until the job reports done. Returns the status payload.
func runSuggest(t *testing.T, dir, stub string) map[string]interface{} {
	t.Helper()

	srv := New(dir, 0, "")
	srv.SelfExe = stub
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/suggest/generate", "application/json",
		strings.NewReader(`{"count":2}`))
	if err != nil {
		t.Fatalf("POST /api/suggest/generate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/suggest/generate returned HTTP %d", resp.StatusCode)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("suggest job did not finish within 30s")
		}
		status := apiGET(t, ts, "/api/suggest/status")
		if done, _ := status["done"].(bool); done {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// framedPayload is what `cloop suggest --json` writes today.
func framedPayload(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"summary": "two ideas",
		"suggestions": []map[string]interface{}{
			{"id": 1, "title": "first idea", "category": "feature", "effort": "m"},
			{"id": 2, "title": "second idea", "category": "ux", "effort": "s"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "<<<cloop-json:begin>>>\n" + string(body) + "\n<<<cloop-json:end>>>"
}

// The bug itself: a warning ahead of the payload must not break parsing.
func TestSuggestSurvivesStderrWarning(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	stub := writeSuggestStub(t, schemaWarning, framedPayload(t))

	status := runSuggest(t, dir, stub)

	if msg, _ := status["error"].(string); msg != "" {
		t.Fatalf("suggest failed with a warning on stderr: %s", msg)
	}
	suggestions, _ := status["suggestions"].([]interface{})
	if len(suggestions) != 2 {
		t.Fatalf("want 2 suggestions, got %d (%v)", len(suggestions), status["suggestions"])
	}
	if summary, _ := status["summary"].(string); summary != "two ideas" {
		t.Fatalf("summary not recovered: %q", summary)
	}
	first, _ := suggestions[0].(map[string]interface{})
	if title, _ := first["title"].(string); title != "first idea" {
		t.Fatalf("suggestion body not recovered: %v", first)
	}
}

// Diagnostics containing JSON punctuation defeat the "first { to last }"
// heuristic that framing replaced, so pin that they are tolerated too.
func TestSuggestSurvivesStderrNoiseWithBraces(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	noise := `{"level":"warn","msg":"a structured log line"}` + "\n" +
		"warning: config max_parallel: value 99 outside [1, 64] — clamped to default"
	stub := writeSuggestStub(t, noise, framedPayload(t))

	status := runSuggest(t, dir, stub)

	if msg, _ := status["error"].(string); msg != "" {
		t.Fatalf("suggest failed with brace-bearing noise on stderr: %s", msg)
	}
	if suggestions, _ := status["suggestions"].([]interface{}); len(suggestions) != 2 {
		t.Fatalf("want 2 suggestions, got %d", len(suggestions))
	}
}

// A binary predating the frame writes a bare document; the hub must still read
// it rather than refusing outright.
func TestSuggestReadsUnframedPayloadFromOlderBinary(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	bare := `{"summary":"legacy","suggestions":[{"id":1,"title":"only idea"}]}`
	stub := writeSuggestStub(t, "", bare)

	status := runSuggest(t, dir, stub)

	if msg, _ := status["error"].(string); msg != "" {
		t.Fatalf("unframed payload rejected: %s", msg)
	}
	if suggestions, _ := status["suggestions"].([]interface{}); len(suggestions) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(suggestions))
	}
}

// When there is genuinely no payload the operator must be told what the
// command printed instead — the old message named a byte they could not see.
func TestSuggestErrorQuotesOutputWhenPayloadIsMissing(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	stub := writeSuggestStub(t, "warning: the provider is rate limited", "")

	status := runSuggest(t, dir, stub)

	msg, _ := status["error"].(string)
	if msg == "" {
		t.Fatal("want an error when no payload was produced")
	}
	if !strings.Contains(msg, "rate limited") {
		t.Fatalf("error should quote the command's output, got %q", msg)
	}
	if strings.Contains(msg, "invalid character") {
		t.Fatalf("error should not be a raw decoder complaint, got %q", msg)
	}
}
