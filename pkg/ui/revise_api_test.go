package ui

// Tests for revising a task's details from a spoken instruction (Task 20302).
//
// The prompt and the reply cleaner are pure functions in pkg/pm, tested there.
// The model call is `cloop task revise` on the project's executor since Task
// 20442, so the handler is tested against a stand-in for that subcommand
// (model_calls_test.go's modelStub), which records what it was asked and
// answers as the real one would; cmd tests the real one.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ---------------------------------------------------------------------------
// the handler
// ---------------------------------------------------------------------------

// setupReviseProject builds a project whose executor's `cloop task revise`
// answers with reply, or fails with failWith, and returns its directory and
// the stand-in.
func setupReviseProject(t *testing.T, tasks []*pm.Task, reply string, failWith string) (string, *modelStub) {
	t.Helper()
	dir := setupProjectDir(t, "revise-test", tasks)
	stub := newModelStub(t)
	if failWith != "" {
		stub.answer(t, "task-revise", framed(t, map[string]string{"error": failWith}), 1)
	} else {
		stub.answer(t, "task-revise", framed(t, map[string]string{
			"description": reply, "provider": "t20302fake", "model": "fake-1"}), 0)
	}
	return dir, stub
}

// loadTaskDescription reads a task's stored description back off disk.
func loadTaskDescription(t *testing.T, dir string, id int) string {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		t.Fatalf("task %d: %v", id, err)
	}
	return task.Description
}

func postRevise(t *testing.T, dir string, stub *modelStub, id string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := &Server{WorkDir: dir, SelfExe: stub.exe}
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+id+"/revise", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	srv.handleTaskRevise(rec, req)
	return rec
}

func reviseTasks() []*pm.Task {
	return []*pm.Task{{
		ID:          7,
		Title:       "Bound the artifact reads",
		Description: "Cap each read at 1 MiB and log the truncation.",
		Status:      pm.TaskPending,
	}}
}

// TestHandleTaskRevise_AppliesTheInstructionToTheDraft is the feature working:
// the model's answer comes back as `description`, and — the part that makes
// this endpoint different from Replace — it was asked about the text in the
// *open editor*, not the copy saved in the plan.
func TestHandleTaskRevise_AppliesTheInstructionToTheDraft(t *testing.T) {
	const revised = "Cap each read at 1 MiB, log the truncation, and cover the glasses page."
	dir, stub := setupReviseProject(t, reviseTasks(), "```\n"+revised+"\n```", "")

	// Deliberately different from the stored description: an editor who has
	// typed since the modal opened must have *their* text revised, or this
	// feature destroys the edits the whole chooser exists to protect.
	const draft = "Cap each read at 1 MiB. TODO: decide the limit."
	rec := postRevise(t, dir, stub, "7", map[string]any{
		"instruction": "also cover the glasses page",
		"description": draft,
		"title":       "Bound the artifact reads",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST revise = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Provider    string `json:"provider"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — %s", err, rec.Body.String())
	}
	// Cleaned on the hub too: the answer came from the executor's cloop.
	if !got.OK || got.Description != revised || got.Provider != "t20302fake" {
		t.Fatalf("got %+v, want the model's answer %q unwrapped", got, revised)
	}
	// Joined to their flags, so text starting with "-" is never a flag.
	want := []string{"task", "revise", "7", "--instruction=also cover the glasses page",
		"--description=" + draft, "--title=Bound the artifact reads", "--timeout", "1m30s", "--json"}
	if args := stubArgs(t, dir); strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("the executor was asked for %q, want %q — the draft in the editor, not the saved copy", args, want)
	}
}

// TestHandleTaskRevise_NeverMutatesThePlan is the safety argument for letting a
// model rewrite somebody's task at all: it proposes into a textarea, and Save
// Changes is still the only way into the plan.
func TestHandleTaskRevise_NeverMutatesThePlan(t *testing.T) {
	const stored = "Cap each read at 1 MiB and log the truncation."
	dir, stub := setupReviseProject(t, reviseTasks(), "something else entirely", "")

	if rec := postRevise(t, dir, stub, "7", map[string]any{
		"instruction": "rewrite it",
		"description": stored,
	}); rec.Code != http.StatusOK {
		t.Fatalf("POST revise = %d: %s", rec.Code, rec.Body.String())
	}

	after := loadTaskDescription(t, dir, 7)
	if after != stored {
		t.Errorf("the stored description changed to %q — revising must propose, never save", after)
	}
}

func TestHandleTaskRevise_Refusals(t *testing.T) {
	cases := []struct {
		name string
		id   string
		body map[string]any
		want int
		says string
	}{
		{"a non-numeric id", "abc",
			map[string]any{"instruction": "x", "description": "y"}, http.StatusBadRequest, "invalid task id"},
		{"a task that does not exist", "999",
			map[string]any{"instruction": "x", "description": "y"}, http.StatusNotFound, ""},
		{"nothing was said", "7",
			map[string]any{"instruction": "   ", "description": "y"}, http.StatusBadRequest, "nothing was said"},
		// The chooser only offers this option when the field has text in it, so
		// an empty draft means the client and the plan disagree. Refusing beats
		// spending a provider call to have a model invent a description from an
		// instruction that assumes one.
		{"nothing to revise", "7",
			map[string]any{"instruction": "add a test", "description": "  "}, http.StatusBadRequest, "Replace"},
	}
	dir, stub := setupReviseProject(t, reviseTasks(), "unused", "")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postRevise(t, dir, stub, c.id, c.body)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
			if c.says != "" && !strings.Contains(rec.Body.String(), c.says) {
				t.Errorf("refusal does not mention %q: %s", c.says, rec.Body.String())
			}
		})
	}
	if args := stubArgs(t, dir); args != nil {
		t.Errorf("a refused request made a model call: %q", args)
	}
}

// TestHandleTaskRevise_ProviderFailureIsABadGateway keeps the one part of this
// that can fail distinguishable from the hub failing. The dashboard leaves the
// chooser open on this status so Replace and Add to the end stay reachable; a
// 500 would read as "the hub is broken, start again".
func TestHandleTaskRevise_ProviderFailureIsABadGateway(t *testing.T) {
	dir, stub := setupReviseProject(t, reviseTasks(), "", "model is having a day")
	rec := postRevise(t, dir, stub, "7", map[string]any{
		"instruction": "add a test", "description": "some details",
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("provider failure = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "revising the details failed: model is having a day") {
		t.Errorf("the provider's own reason is not surfaced: %s", rec.Body.String())
	}
}

// TestHandleTaskRevise_EmptyAnswerIsRefused stops a model that replies with
// whitespace from blanking the editor's description — whatever the executor's
// cloop sent back.
func TestHandleTaskRevise_EmptyAnswerIsRefused(t *testing.T) {
	dir, stub := setupReviseProject(t, reviseTasks(), "   \n  ", "")
	rec := postRevise(t, dir, stub, "7", map[string]any{
		"instruction": "add a test", "description": "some details",
	})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "the model returned nothing to apply") {
		t.Fatalf("empty model answer = %d %s, want 502", rec.Code, rec.Body.String())
	}
}
