package e2e_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Input files end to end (Task 20511), with the real binary and a stub
// `claude` on PATH: a file attached to a task with `cloop task add
// --input-file` is in the directory the agent's prompt and $CLOOP_TASK_INPUTS
// name, the agent works from it, and what it makes from it comes back as the
// task's result — beside the input, which the run leaves where it was.

const inputsStub = `#!/bin/bash
prompt="$(cat)"
printf '%s' "$prompt" > "$STUB_DIR/prompt.txt"
printf '%s' "$CLOOP_TASK_INPUTS" > "$STUB_DIR/inbox.txt"
ls -1 "$CLOOP_TASK_INPUTS" > "$STUB_DIR/ls.txt"
if ! tr a-z A-Z < "$CLOOP_TASK_INPUTS/brief.txt" > "$CLOOP_TASK_ATTACHMENTS/BRIEF.txt"; then
  echo "TASK_FAILED: no brief"
  exit 0
fi
echo "Shouted the brief."
echo "TASK_DONE"
`

func TestE2EAnAgentWorksFromItsTasksInputFiles(t *testing.T) {
	base := newWorkDir(t)
	project, stubDir, inputs := filepath.Join(base, "project"), filepath.Join(base, "stub"), filepath.Join(base, "inputs")
	for _, d := range []string{project, stubDir, inputs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stubDir, "claude"), []byte(inputsStub), 0o755); err != nil {
		t.Fatal(err)
	}
	brief := filepath.Join(inputs, "brief.txt")
	if err := os.WriteFile(brief, []byte("make it loud\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mustRun(t, project, "init", "--provider", "claudecode", "--skip-clarify", "Shout every brief")
	out := mustRun(t, project, "task", "add", "Shout the brief", "--no-ai", "--auto", "--input-file", brief)
	if !strings.Contains(out, "Attached brief.txt to task 1 as an input file") {
		t.Fatalf("task add does not say it attached the input file:\n%s", out)
	}
	if out, err := run(t, project, "task", "add", "Refused", "--no-ai", "--auto", "--input-file", filepath.Join(inputs, "missing.txt")); err == nil ||
		!strings.Contains(out, "missing.txt") {
		t.Fatalf("a missing input file was not refused before the task was added: %v\n%s", err, out)
	}
	if s, err := state.Load(project); err != nil || len(s.Plan.Tasks) != 1 {
		t.Fatalf("the refused task was added anyway: %v", err)
	}

	// `cloop run`, with nothing of this agent's own run leaking in.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath(t), "run")
	cmd.Dir = project
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLOOP_") || strings.HasPrefix(kv, "CLOOP_HOME=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "NO_COLOR=1", "TERM=dumb", "STUB_DIR="+stubDir,
		"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	runOut, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cloop run: %v\n%s", err, runOut)
	}

	inbox := readFile(t, filepath.Join(stubDir, "inbox.txt"))
	if want := filepath.Join(project, ".cloop", "attachments", "inbox", "1"); inbox != want {
		t.Fatalf("$CLOOP_TASK_INPUTS = %q, want %q\n%s", inbox, want, runOut)
	}
	if ls := strings.TrimSpace(readFile(t, filepath.Join(stubDir, "ls.txt"))); ls != "brief.txt" {
		t.Fatalf("the inbox held %q", ls)
	}
	prompt := readFile(t, filepath.Join(stubDir, "prompt.txt"))
	for _, want := range []string{"## INPUT FILES", "- brief.txt (13 B, text/plain)", inbox} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the prompt does not say %q", want)
		}
	}
	if _, err := os.Lstat(inbox); !os.IsNotExist(err) {
		t.Errorf("the inbox outlived the run: %v", err)
	}

	s, err := state.Load(project)
	if err != nil {
		t.Fatal(err)
	}
	if task := s.Plan.TaskByID(1); task.Status != pm.TaskDone || task.AttachmentCount != 2 {
		t.Fatalf("task 1 = %s with %d attachments, want done with its input and its result\n%s", task.Status,
			task.AttachmentCount, runOut)
	}
	var rows []struct {
		Name string `json:"name"`
		Role string `json:"role"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal([]byte(mustRun(t, project, "task", "attachments", "1", "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, r := range rows {
		roles[r.Name] = r.Role
	}
	if len(rows) != 2 || roles["brief.txt"] != "input" || roles["BRIEF.txt"] != "" {
		t.Fatalf("task 1's attachments = %+v, want the input and the run's result", rows)
	}
	saved := filepath.Join(base, "result.txt")
	mustRun(t, project, "task", "attachments", "get", "1", "BRIEF.txt", "-o", saved)
	if got := readFile(t, saved); got != "MAKE IT LOUD\n" {
		t.Fatalf("the result = %q", got)
	}
	listing := mustRun(t, project, "task", "attachments", "1")
	if !strings.Contains(listing, "ROLE") || !strings.Contains(listing, "input") || !strings.Contains(listing, "result") {
		t.Fatalf("the listing does not say which is which:\n%s", listing)
	}
}
