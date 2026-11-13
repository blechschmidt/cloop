package ui

// Regression test for Task 48: the AI Chat panel could not run anything.
//
// handleChat dispatches `cloop do <message>`, which interprets the message,
// prints the command it resolved to, and then — unless --yes was given — asks
// "Execute the command above? [y/N]" on stdout and reads the answer from
// stdin. A workload dispatched through pkg/executor has no terminal on either
// end, so the read returned immediately with nothing, nothing is not "y", and
// the handler relayed "Cancelled." to the browser with ok=true. Every message
// anyone ever sent to that panel ended that way.
//
// The stub below stands in for the real sub-binary and records the argv it was
// given, which is the only place the fix is observable from the handler: the
// prompt is gone because the flag that skips it is now passed.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeArgvStub creates an executable that appends its arguments to a file,
// one per line, and prints body. Returns the stub path and the record path.
func writeArgvStub(t *testing.T, body string) (stub, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub uses a POSIX shell")
	}
	dir := t.TempDir()
	stub = filepath.Join(dir, "cloop-stub")
	record = filepath.Join(dir, "argv")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + record + "; done\n" +
		"cat <<'CLOOP_STUB_OUT'\n" + body + "\nCLOOP_STUB_OUT\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("writing stub: %v", err)
	}
	return stub, record
}

func TestChatDispatchesWithoutAConfirmationPromptItCannotAnswer(t *testing.T) {
	dir := t.TempDir()
	stub, record := writeArgvStub(t, "Running: cloop task list\n\n#1 do the thing")

	srv := New(dir, 0, "")
	srv.SelfExe = stub
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/chat", "application/json",
		strings.NewReader(`{"message":"show me the task list"}`))
	if err != nil {
		t.Fatalf("POST /api/chat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/chat returned HTTP %d", resp.StatusCode)
	}

	var got struct {
		OK       bool   `json:"ok"`
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the chat handler never ran the sub-binary: %v", err)
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	if len(argv) == 0 || argv[0] != "do" {
		t.Fatalf("argv = %q, want the `do` subcommand first", argv)
	}
	var sawYes bool
	for _, a := range argv {
		if a == "--yes" || a == "-y" {
			sawYes = true
		}
	}
	if !sawYes {
		t.Errorf("argv = %q, want --yes: without it `cloop do` asks a question down a pipe "+
			"that nothing can answer, and cancels every message the chat sends", argv)
	}
	if argv[len(argv)-1] != "show me the task list" {
		t.Errorf("argv = %q, want the user's message as the final argument", argv)
	}

	if !got.OK {
		t.Errorf("ok = false, want the dispatch to have succeeded; response = %q", got.Response)
	}
	if !strings.Contains(got.Response, "do the thing") {
		t.Errorf("response = %q, want the sub-binary's output relayed to the browser",
			got.Response)
	}
}

// TestChatPassesAMessageStartingWithADashAsText guards the "--" separator: a
// message that opens with a dash is an instruction to interpret, not an option
// to this binary, and without the separator cobra would read it as one.
func TestChatPassesAMessageStartingWithADashAsText(t *testing.T) {
	dir := t.TempDir()
	stub, record := writeArgvStub(t, "ok")

	srv := New(dir, 0, "")
	srv.SelfExe = stub
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/api/chat", "application/json",
		strings.NewReader(`{"message":"--help me start the run"}`))
	if err != nil {
		t.Fatalf("POST /api/chat: %v", err)
	}
	resp.Body.Close()

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the chat handler never ran the sub-binary: %v", err)
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	dash := -1
	for i, a := range argv {
		if a == "--" {
			dash = i
			break
		}
	}
	if dash < 0 {
		t.Fatalf("argv = %q, want a -- separator before the message", argv)
	}
	if dash != len(argv)-2 || argv[len(argv)-1] != "--help me start the run" {
		t.Errorf("argv = %q, want the message as the only argument after --", argv)
	}
}
