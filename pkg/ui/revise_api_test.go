package ui

// Tests for revising a task's details from a spoken instruction (Task 20302).
//
// Three layers, and the split is deliberate. The prompt and the reply cleaner
// are pure functions tested directly, because they are the whole contract with
// the model and a test that can only reach them through HTTP and a live API key
// is a test nobody runs. The handler is tested against a registered fake
// provider, which is what makes the happy path — the one where a model's answer
// actually lands in the response — reachable at all.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// ---------------------------------------------------------------------------
// the prompt
// ---------------------------------------------------------------------------

// TestReviseDescriptionPrompt_CarriesBothInputsAndTheRules pins what the model
// is actually told. Each assertion below is a way the feature silently becomes
// something else: without the current details it writes a new description from
// scratch (which is the Replace button, not this one); without the delimiters a
// description quoting an instruction is read as one; without the "reply with
// only" rule the answer arrives wrapped in "Sure! Here is the revised…" and
// that lands verbatim in somebody's plan.
func TestReviseDescriptionPrompt_CarriesBothInputsAndTheRules(t *testing.T) {
	const (
		title   = "Bound the artifact reads"
		current = "Cap each read at 1 MiB and log the truncation."
		instr   = "also make sure it works on the glasses page"
	)
	p := reviseDescriptionPrompt(title, current, instr)

	for _, want := range []string{title, current, instr} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt omits %q:\n%s", want, p)
		}
	}
	for _, tag := range []string{"<details>", "</details>", "<instruction>", "</instruction>"} {
		if !strings.Contains(p, tag) {
			t.Errorf("prompt omits the %s delimiter — free text the user dictated would "+
				"read to the model as part of this prompt:\n%s", tag, p)
		}
	}
	// The instruction has to be framed as being *about* the details, not as a
	// message to the assistant, or "ignore the above" in a description becomes
	// an instruction rather than a quotation.
	if !strings.Contains(p, "strictly as an instruction about the details above") {
		t.Errorf("prompt does not confine the instruction to the details:\n%s", p)
	}
	if !strings.Contains(p, "no code fences") {
		t.Errorf("prompt does not forbid code fences, which is the formatting the "+
			"cleaner then has to guess at:\n%s", p)
	}
	// Two things it must not do. Rewriting the title is invisible here (the
	// title field is not what this writes to) but produces details that open by
	// restating their own heading; inventing scope is how a dictated "and add a
	// test" comes back as four new requirements.
	if !strings.Contains(p, "Do not restate or rewrite the task title.") {
		t.Errorf("prompt does not exclude the title:\n%s", p)
	}
	if !strings.Contains(p, "Do not invent scope") {
		t.Errorf("prompt does not forbid inventing scope:\n%s", p)
	}
}

// ---------------------------------------------------------------------------
// the reply cleaner
// ---------------------------------------------------------------------------

func TestCleanRevisedDescription(t *testing.T) {
	long := strings.Repeat("é", maxReviseDescriptionRunes+500)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text survives untouched",
			"Cap each read at 1 MiB.", "Cap each read at 1 MiB."},
		{"surrounding whitespace goes",
			"\n\n  Cap each read.  \n", "Cap each read."},
		{"a fence wrapping the whole answer is unwrapped",
			"```\nCap each read.\n```", "Cap each read."},
		{"a language-tagged fence is unwrapped too",
			"```markdown\nCap each read.\n```", "Cap each read."},
		// The case that makes the "whole answer" qualifier load-bearing: a
		// description legitimately containing a code block must keep it, or
		// this cleaner silently eats the example somebody dictated.
		{"an inner code block is preserved",
			"Do this:\n\n```go\nx := 1\n```\n\nThen that.",
			"Do this:\n\n```go\nx := 1\n```\n\nThen that."},
		// Opens with a fence but does not close at the end — unwrapping would
		// drop the trailing prose.
		{"an unbalanced leading fence is left alone",
			"```go\nx := 1\n```\nand then some prose",
			"```go\nx := 1\n```\nand then some prose"},
		{"nothing at all stays nothing", "   \n ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cleanRevisedDescription(c.in); got != c.want {
				t.Errorf("cleanRevisedDescription(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}

	t.Run("an enormous answer is capped without splitting a rune", func(t *testing.T) {
		got := cleanRevisedDescription(long)
		if n := len([]rune(got)); n != maxReviseDescriptionRunes {
			t.Fatalf("capped to %d runes, want %d", n, maxReviseDescriptionRunes)
		}
		if strings.ContainsRune(got, '�') {
			t.Error("the cap split a multi-byte rune — counting bytes rather than runes " +
				"mangles the non-ASCII prose a dictated description is often made of")
		}
	})
}

func TestTruncateRunes_CountsRunesNotBytes(t *testing.T) {
	const s = "ünïcödé"
	if got := truncateRunes(s, 3); got != "ünï" {
		t.Errorf("truncateRunes(%q, 3) = %q, want %q", s, got, "ünï")
	}
	if got := truncateRunes(s, 100); got != s {
		t.Errorf("truncateRunes past the end changed the string: %q", got)
	}
	if got := truncateRunes(s, 0); got != "" {
		t.Errorf("truncateRunes(_, 0) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// the handler
// ---------------------------------------------------------------------------

// reviseStubProvider is registered under a name nothing else looks up, so this
// addition to the process-wide provider registry cannot change what any other
// test in this binary builds.
const reviseFakeProviderName = "t20302fake"

// reviseLastPrompt is what the stub was last asked, guarded because these tests
// may run alongside others in the same binary. Read after the request returns.
var (
	reviseLastPrompt   string
	reviseLastPromptMu sync.Mutex
)

func setReviseLastPrompt(s string) {
	reviseLastPromptMu.Lock()
	defer reviseLastPromptMu.Unlock()
	reviseLastPrompt = s
}

func lastRevisePrompt() string {
	reviseLastPromptMu.Lock()
	defer reviseLastPromptMu.Unlock()
	return reviseLastPrompt
}

type reviseStubProvider struct {
	reply string
	err   error
}

func (p *reviseStubProvider) Name() string         { return reviseFakeProviderName }
func (p *reviseStubProvider) DefaultModel() string { return "fake-1" }

func (p *reviseStubProvider) Complete(ctx context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	setReviseLastPrompt(prompt)
	if p.err != nil {
		return nil, p.err
	}
	return &provider.Result{Output: p.reply, Provider: p.Name(), Model: "fake-1"}, nil
}

// setupReviseProject builds a project whose configured provider answers with
// reply, and returns its directory.
func setupReviseProject(t *testing.T, tasks []*pm.Task, reply string, failWith error) string {
	t.Helper()
	dir := setupProjectDir(t, "revise-test", tasks)

	provider.Register(reviseFakeProviderName, func(provider.ProviderConfig) (provider.Provider, error) {
		return &reviseStubProvider{reply: reply, err: failWith}, nil
	})
	cfg := "provider: " + reviseFakeProviderName + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
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

func postRevise(t *testing.T, dir string, id string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+id+"/revise", strings.NewReader(string(raw)))
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
	dir := setupReviseProject(t, reviseTasks(), revised, nil)

	// Deliberately different from the stored description: an editor who has
	// typed since the modal opened must have *their* text revised, or this
	// feature destroys the edits the whole chooser exists to protect.
	const draft = "Cap each read at 1 MiB. TODO: decide the limit."
	rec := postRevise(t, dir, "7", map[string]any{
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
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — %s", err, rec.Body.String())
	}
	if !got.OK || got.Description != revised {
		t.Fatalf("got ok=%v description=%q, want the model's answer %q", got.OK, got.Description, revised)
	}
	prompt := lastRevisePrompt()
	if !strings.Contains(prompt, draft) {
		t.Errorf("the model was not shown the draft in the editor — it would revise the "+
			"saved copy and discard unsaved edits.\nprompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "also cover the glasses page") {
		t.Errorf("the model was not shown the instruction:\n%s", prompt)
	}
}

// TestHandleTaskRevise_NeverMutatesThePlan is the safety argument for letting a
// model rewrite somebody's task at all: it proposes into a textarea, and Save
// Changes is still the only way into the plan.
func TestHandleTaskRevise_NeverMutatesThePlan(t *testing.T) {
	const stored = "Cap each read at 1 MiB and log the truncation."
	dir := setupReviseProject(t, reviseTasks(), "something else entirely", nil)

	if rec := postRevise(t, dir, "7", map[string]any{
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
	dir := setupReviseProject(t, reviseTasks(), "unused", nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postRevise(t, dir, c.id, c.body)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
			if c.says != "" && !strings.Contains(rec.Body.String(), c.says) {
				t.Errorf("refusal does not mention %q: %s", c.says, rec.Body.String())
			}
		})
	}
}

// TestHandleTaskRevise_ProviderFailureIsABadGateway keeps the one part of this
// that can fail distinguishable from the hub failing. The dashboard leaves the
// chooser open on this status so Replace and Add to the end stay reachable; a
// 500 would read as "the hub is broken, start again".
func TestHandleTaskRevise_ProviderFailureIsABadGateway(t *testing.T) {
	dir := setupReviseProject(t, reviseTasks(), "", fmt.Errorf("model is having a day"))
	rec := postRevise(t, dir, "7", map[string]any{
		"instruction": "add a test", "description": "some details",
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("provider failure = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "model is having a day") {
		t.Errorf("the provider's own reason is not surfaced: %s", rec.Body.String())
	}
}

// TestHandleTaskRevise_EmptyAnswerIsRefused stops a model that replies with
// whitespace from blanking the editor's description.
func TestHandleTaskRevise_EmptyAnswerIsRefused(t *testing.T) {
	dir := setupReviseProject(t, reviseTasks(), "   \n  ", nil)
	rec := postRevise(t, dir, "7", map[string]any{
		"instruction": "add a test", "description": "some details",
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("empty model answer = %d, want 502: %s", rec.Code, rec.Body.String())
	}
}
