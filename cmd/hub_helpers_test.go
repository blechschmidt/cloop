package cmd

// The contract the hub reads the dashboard's model calls by (Task 20442): each
// helper reports its result framed (pkg/clijson) — and its failure framed too,
// so the hub can show the provider's reason rather than whatever else shared
// the stream — and `plan chat` streams chunks ahead of its answer. Run as the
// hub runs them: this test binary acting as cloop, in the project directory.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// helperProject is a project whose provider is the one named.
func helperProject(t *testing.T, providerName string) string {
	t.Helper()
	dir := t.TempDir()
	ps, err := state.Init(dir, "hub helpers", 0)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: "+providerName+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runHelper runs `cloop <args>` in dir as the hub would, returning its merged
// output and how it exited.
func runHelper(t *testing.T, exe, dir string, args ...string) ([]byte, error) {
	t.Helper()
	c := exec.Command(exe, args...)
	c.Dir = dir
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return out.Bytes(), err
}

func TestHubHelpersReportTheirFailuresFramed(t *testing.T) {
	// A `claude` that fails the way an upstream outage does — not a 401, which
	// would be retried after a credential refresh.
	bin := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\necho 'API Error: 503 {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	exe := cliSelfExe(t)
	dir := helperProject(t, "claudecode")

	for _, args := range [][]string{
		{"task", "decompose", "1", "--dry-run", "--json"},
		{"task", "revise", "1", "--instruction=and the indexes", "--description=Move every table.", "--json"},
		{"task", "ai-blocker", "1", "--json"},
		{"plan", "chat", "--message=What is next?", "--json"},
		// Not a model failure: a preview was asked for without --dry-run.
		{"task", "decompose", "1", "--json"},
		{"task", "revise", "99", "--instruction=x", "--description=y", "--json"},
	} {
		out, err := runHelper(t, exe, dir, args...)
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Errorf("cloop %s exited %v, want a failure:\n%s", strings.Join(args, " "), err, out)
			continue
		}
		var failed struct{ Error string }
		if err := clijson.Unmarshal(out, &failed); err != nil || failed.Error == "" {
			t.Errorf("cloop %s did not report its failure framed (%v):\n%s", strings.Join(args, " "), err, out)
		}
	}
}

func TestPlanChatStreamsChunksAheadOfItsAnswer(t *testing.T) {
	dir := helperProject(t, "mock")
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "mock_responses.yaml"),
		[]byte("rules:\n  - substring: \"What is next?\"\n    response: \"Task 1 comes first.\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runHelper(t, cliSelfExe(t), dir, "plan", "chat", "--message=What is next?",
		`--history=[{"role":"user","content":"hi"}]`, "--json")
	if err != nil {
		t.Fatalf("plan chat: %v\n%s", err, out)
	}
	var tokens []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		if payload, ok := clijson.ChunkPayload(line); ok {
			var c struct{ Token string }
			if err := json.Unmarshal(payload, &c); err != nil {
				t.Fatalf("chunk %q: %v", line, err)
			}
			tokens = append(tokens, c.Token)
		}
	}
	var final struct{ Answer string }
	if err := clijson.Unmarshal(out, &final); err != nil {
		t.Fatalf("no final frame: %v\n%s", err, out)
	}
	if strings.Join(tokens, "") != "Task 1 comes first." || final.Answer != "Task 1 comes first." {
		t.Fatalf("streamed %q, answered %q:\n%s", tokens, final.Answer, out)
	}
	if bytes.Index(out, []byte(clijson.ChunkMarker)) > bytes.Index(out, []byte(clijson.BeginMarker)) {
		t.Errorf("the answer was framed before its chunks:\n%s", out)
	}
}
