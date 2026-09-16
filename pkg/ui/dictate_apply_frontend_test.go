package ui

// What happens to a transcript dictated into the edit modal (Task 20302).
//
// The microphone beside the Add Task field appends into an empty box and is
// done. The one added to the edit modal speaks into a description somebody
// already wrote, so the interesting behaviour is entirely about *not* writing:
// ask first, and only then replace, extend, or hand the sentence to a model as
// an instruction.
//
// Driven through the real bundle against testdata/domshim.js rather than
// grepped, because every assertion here is about state after a sequence — a
// grep can confirm that a Replace button exists and cannot confirm that
// pressing Append left the original paragraph in place. The gesture that
// produces the transcript is covered in real Chromium by
// dictate_ptt_browser_test.go; this picks up where the audio stops.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type dictateApplyPost struct {
	URL  string `json:"url"`
	Body string `json:"body"`
}

type dictateApplyResult struct {
	ChooserOpen bool               `json:"chooser_open"`
	Details     string             `json:"details"`
	Heard       string             `json:"heard"`
	Typed       string             `json:"typed"`
	Posts       []dictateApplyPost `json:"posts"`
	Add         bool               `json:"add"`
	Edit        bool               `json:"edit"`
	Error       string             `json:"error"`
}

func runDictateApplyScenarios(t *testing.T) map[string]dictateApplyResult {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/dictate_apply_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]dictateApplyResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if fatal, ok := results["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", fatal.Error)
	}
	for _, name := range []string{
		"both_microphones_revealed", "asks_before_overwriting", "replace_overwrites",
		"append_keeps_existing", "revise_sends_the_draft", "empty_details_do_not_ask",
		"revise_failure_keeps_the_chooser", "cancelled_revision_is_dropped",
		"closing_the_editor_dismisses_the_chooser",
	} {
		if _, ok := results[name]; !ok {
			t.Fatalf("scenario %q did not run:\n%s", name, out)
		}
	}
	return results
}

// TestDashboard_DictatedDetailsAskBeforeOverwriting is the whole feature; the
// subtests below read one scenario each out of a single node run.
func TestDashboard_DictatedDetailsAskBeforeOverwriting(t *testing.T) {
	got := runDictateApplyScenarios(t)

	const (
		existing = "Cap each read at 1 MiB and log the truncation."
		heard    = "also cover the glasses page"
		revised  = "Cap each read at 1 MiB, log the truncation, and cover the glasses page."
	)

	t.Run("a hub that can transcribe shows both microphones", func(t *testing.T) {
		r := got["both_microphones_revealed"]
		if !r.Add {
			t.Error("the Add Task microphone is hidden on a hub with a speech backend")
		}
		if !r.Edit {
			t.Error("the edit modal's microphone never appears — it is revealed by the " +
				"same /api/dictate probe as the Add Task one, and a second copy of that " +
				"check is what would drift")
		}
	})

	t.Run("it asks before overwriting", func(t *testing.T) {
		r := got["asks_before_overwriting"]
		if !r.ChooserOpen {
			t.Error("a transcript spoken over existing details applied silently — " +
				"which of replace and extend was meant is not recoverable from the audio")
		}
		if r.Details != existing {
			t.Errorf("the details changed to %q before the user chose anything", r.Details)
		}
		if !strings.Contains(r.Heard, heard) {
			t.Errorf("the chooser shows %q, not what was heard — there is nothing else "+
				"on screen telling the user what they are deciding about", r.Heard)
		}
	})

	t.Run("replace overwrites", func(t *testing.T) {
		r := got["replace_overwrites"]
		if r.ChooserOpen {
			t.Error("the chooser is still open after a choice was made")
		}
		if r.Details != heard {
			t.Errorf("details after Replace = %q, want the transcript %q", r.Details, heard)
		}
	})

	t.Run("adding to the end keeps what was there", func(t *testing.T) {
		r := got["append_keeps_existing"]
		if r.ChooserOpen {
			t.Error("the chooser is still open after a choice was made")
		}
		want := existing + "\n\n" + heard
		if r.Details != want {
			t.Errorf("details after Add to the end =\n%q\nwant\n%q", r.Details, want)
		}
	})

	// The one that spends a provider call, and the one whose payload matters:
	// a revision computed from the *saved* description would discard whatever
	// the editor typed since the modal opened — the exact loss the chooser
	// exists to prevent.
	t.Run("editing with AI revises the open draft", func(t *testing.T) {
		r := got["revise_sends_the_draft"]
		if r.ChooserOpen {
			t.Error("the chooser is still open after a successful revision")
		}
		if r.Details != revised {
			t.Errorf("details after Edit with AI = %q, want the model's answer %q", r.Details, revised)
		}
		if len(r.Posts) != 1 {
			t.Fatalf("Edit with AI made %d requests to the revise endpoint, want exactly 1", len(r.Posts))
		}
		p := r.Posts[0]
		// pUrl is what carries ?project_idx; without it the hub revises task 7
		// of whichever project happens to be first.
		if !strings.Contains(p.URL, "project_idx=") {
			t.Errorf("revise was called as %q, without a project scope", p.URL)
		}
		var body struct {
			Instruction string `json:"instruction"`
			Description string `json:"description"`
			Title       string `json:"title"`
		}
		if err := json.Unmarshal([]byte(p.Body), &body); err != nil {
			t.Fatalf("revise body is not JSON: %v — %s", err, p.Body)
		}
		if body.Instruction != heard {
			t.Errorf("instruction sent = %q, want what was heard %q", body.Instruction, heard)
		}
		if body.Description != r.Typed {
			t.Errorf("description sent = %q, want the text in the open editor %q —\n"+
				"revising the saved copy silently discards unsaved edits", body.Description, r.Typed)
		}
	})

	t.Run("an empty description is not a question", func(t *testing.T) {
		r := got["empty_details_do_not_ask"]
		if r.ChooserOpen {
			t.Error("asked what to do with an empty field — every answer is the same one, " +
				"and a dialog like that teaches people to dismiss dialogs")
		}
		if r.Details != heard {
			t.Errorf("details = %q, want the transcript written straight in", r.Details)
		}
	})

	t.Run("a failed revision leaves the other answers reachable", func(t *testing.T) {
		r := got["revise_failure_keeps_the_chooser"]
		if !r.ChooserOpen {
			t.Error("the chooser closed when the model failed — Replace and Add to the end " +
				"still work, and reaching them again costs the user the whole sentence")
		}
		if r.Details != existing {
			t.Errorf("a failed revision changed the details to %q", r.Details)
		}
	})

	// The last way this feature could still edit a description nobody accepted:
	// the request is already in flight when the user gives up, and the answer
	// lands seconds later over whatever they wrote in the meantime.
	t.Run("a cancelled revision is dropped when it arrives", func(t *testing.T) {
		r := got["cancelled_revision_is_dropped"]
		if r.ChooserOpen {
			t.Error("the chooser reopened when the cancelled revision arrived")
		}
		want := existing + " typed after cancelling"
		if r.Details != want {
			t.Errorf("details = %q, want %q — a revision the user cancelled overwrote "+
				"what they typed after cancelling it", r.Details, want)
		}
	})

	t.Run("closing the editor dismisses the chooser", func(t *testing.T) {
		if got["closing_the_editor_dismisses_the_chooser"].ChooserOpen {
			t.Error("the chooser outlived the modal underneath it — its buttons now " +
				"write into a field that is no longer on screen")
		}
	})
}

// TestDashboard_EditModalDictationMarkup covers the parts of the feature that
// are markup rather than behaviour, and that the node run therefore cannot see:
// domshim auto-vivifies every element, so a chooser with no buttons in the HTML
// passes every scenario above.
func TestDashboard_EditModalDictationMarkup(t *testing.T) {
	src := dashboardSource

	// The microphone has to be inside the edit modal, not merely somewhere on
	// the page — the whole feature is "while editing a task".
	start := strings.Index(src, `<div id="modal-overlay"`)
	if start < 0 {
		t.Fatal("the edit modal is gone from the page")
	}
	end := strings.Index(src[start:], `<!-- Task details modal`)
	if end < 0 {
		t.Fatal("cannot find the end of the edit modal")
	}
	modal := src[start : start+end]
	for _, want := range []string{`id="dictateEditBtn"`, `onclick="toggleEditDictation()"`, `id="modalDesc"`} {
		if !strings.Contains(modal, want) {
			t.Errorf("the edit modal does not contain %s", want)
		}
	}
	// Gated like every other task mutation, so a viewer is not shown a
	// microphone that spends the project's budget.
	if !strings.Contains(modal, `id="dictateEditBtn" data-perm="task.mutate"`) {
		t.Error(`the edit modal's microphone does not declare data-perm="task.mutate"`)
	}

	// All three answers, each wired to a handler. Task 20302 asks for replace
	// versus edit; "Add to the end" is the free, non-destructive middle that
	// makes the other two safe to offer.
	for _, want := range []string{
		`onclick="dictateApplyReplace()"`,
		`onclick="dictateApplyAppend()"`,
		`onclick="dictateApplyRevise()"`,
		`id="dr-heard"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the dictated-details chooser is missing %s", want)
		}
	}
}
