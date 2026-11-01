package cmd

// `cloop task add/edit --requirement` (Task 20460).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/state"
)

func cliTaskLinks(t *testing.T, dir string) map[int]string {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]string{}
	if ps.Plan != nil {
		for _, task := range ps.Plan.Tasks {
			out[task.ID] = fmt.Sprint(task.Requirements)
		}
	}
	return out
}

func TestTaskCommandsLinkRequirements(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	mustRun(t, exe, dir, "requirements", "add", "Config errors exit non-zero", "--test", "true")
	mustRun(t, exe, dir, "requirements", "add", "A draft", "--status", "draft")
	mustRun(t, exe, dir, "requirements", "add", "Retired", "--status", "deprecated")

	out := mustRun(t, exe, dir, "task", "add", "make config errors exit non-zero", "--no-ai",
		"--requirement", "R-2", "--requirement", "1,R-1")
	if !strings.Contains(out, "Implements: R-1, R-2") {
		t.Errorf("task add did not say what the task implements:\n%s", out)
	}
	if got := cliTaskLinks(t, dir); got[1] != "[1 2]" {
		t.Fatalf("task 1 implements %s", got[1])
	}

	// Refused before anything is written — and, without --no-ai, before any
	// model is asked.
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"unknown":    {[]string{"task", "add", "x", "--no-ai", "--requirement", "R-9"}, "R-9 is not a requirement of this project"},
		"deprecated": {[]string{"task", "add", "x", "--no-ai", "--requirement", "3"}, "R-3 is deprecated"},
		"not an id":  {[]string{"task", "add", "x", "--no-ai", "--requirement", "REQ-1"}, "is not a requirement"},
		"before a model": {[]string{"task", "add", "x", "--auto", "--provider", "anthropic", "--requirement", "R-9"},
			"R-9 is not a requirement of this project"},
		"edit unknown": {[]string{"task", "edit", "1", "--requirement", "1,8"}, "R-8 is not a requirement of this project"},
	} {
		out, err := runHelper(t, exe, dir, c.args...)
		if err == nil || !strings.Contains(string(out), c.want) {
			t.Errorf("%s: %v\n%s\nwant a refusal saying %q", name, err, out, c.want)
		}
	}
	if got := cliTaskLinks(t, dir); len(got) != 1 || got[1] != "[1 2]" {
		t.Fatalf("a refused command changed the plan: %v", got)
	}

	if out := mustRun(t, exe, dir, "task", "edit", "1", "--requirement", "R-1"); !strings.Contains(out, "Implements: R-1") {
		t.Errorf("task edit did not say what the task implements:\n%s", out)
	}
	if got := cliTaskLinks(t, dir); got[1] != "[1]" {
		t.Errorf("after edit --requirement R-1, task 1 implements %s", got[1])
	}
	if out := mustRun(t, exe, dir, "task", "show", "1"); !strings.Contains(out, "Implements: R-1") {
		t.Errorf("task show does not name the requirement:\n%s", out)
	}
	mustRun(t, exe, dir, "task", "edit", "1", "--title", "renamed")
	if got := cliTaskLinks(t, dir); got[1] != "[1]" {
		t.Errorf("an edit without --requirement changed the links to %s", got[1])
	}
	mustRun(t, exe, dir, "task", "edit", "1", "--requirement", "none")
	if got := cliTaskLinks(t, dir); got[1] != "[]" {
		t.Errorf("after edit --requirement none, task 1 implements %s", got[1])
	}

	// Removing a requirement says which tasks it was taken out of.
	mustRun(t, exe, dir, "task", "edit", "1", "--requirement", "R-1,R-2")
	if out := mustRun(t, exe, dir, "requirements", "show", "R-2"); !strings.Contains(out, "Implemented by:") ||
		!strings.Contains(out, "#1 renamed (pending)") {
		t.Errorf("requirements show does not list the task that implements it:\n%s", out)
	}
	if out := mustRun(t, exe, dir, "requirements", "remove", "R-1"); !strings.Contains(out, "No longer implemented by task #1") {
		t.Errorf("requirements remove did not name the task it unlinked:\n%s", out)
	}
	if got := cliTaskLinks(t, dir); got[1] != "[2]" {
		t.Errorf("after removing R-1, task 1 implements %s", got[1])
	}
}
