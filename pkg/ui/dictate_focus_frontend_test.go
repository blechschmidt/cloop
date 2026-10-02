package ui

// Where a dictated transcript lands (Task 20309).
//
// Both microphones used to own a field outright — the Add Task one wrote into
// the title, the edit modal's into the description — so every other text box on
// those two screens was unreachable by voice and the only way to fill one was
// to dictate into the field the button did own and then retype. Now the caret
// decides, and the button's field is the fallback.
//
// Two halves, and only one of them is the new behaviour. The other is that a
// caret the *page* placed must not count: opening the edit modal focuses its
// Title, so without that distinction every transcript dictated in that dialog
// would land in the Title and the chooser protecting the description
// (Task 20302) would be unreachable. Both are asserted here.
//
// Driven through the real bundle against testdata/domshim.js rather than
// grepped: every assertion is about which field holds which string after a
// sequence, and no amount of reading the source can establish that. The gesture
// that produces the transcript — pointer capture, the synthesised click, the
// caret a real mousedown steals — is Chromium's, and dictate_ptt_browser_test.go
// drives it there.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type dictateFocusResult struct {
	Title       string `json:"title"`
	Caret       int    `json:"caret"`
	Desc        string `json:"desc"`
	Filter      string `json:"filter"`
	Priority    string `json:"priority"`
	Heard       string `json:"heard"`
	ChooserOpen bool   `json:"chooser_open"`
	Live        int    `json:"live"`
	Error       string `json:"error"`
}

const (
	dictateFocusHeard    = "also cover the glasses page"
	dictateFocusExisting = "Cap each read at 1 MiB and log the truncation."
	// What openEditModal loads into the editor, so the modal scenarios assert
	// against a field that already holds something — which is the only way to
	// tell "left alone" from "written to".
	dictateFocusTaskTitle = "Bound the artifact reads"
)

func runDictateFocusScenarios(t *testing.T) map[string]dictateFocusResult {
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
	scenarios, err := filepath.Abs("testdata/dictate_focus_scenarios.js")
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

	var results map[string]dictateFocusResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if fatal, ok := results["fatal"]; ok {
		t.Fatalf("the scenarios threw: %s", fatal.Error)
	}
	// A scenario the driver never reached leaves a zero value, and several of
	// the assertions below are satisfied by an empty string.
	for _, name := range []string{
		"no_caret_uses_the_button_field", "caret_wins", "caret_outside_the_row",
		"number_field_is_not_a_destination", "appends_with_a_space",
		"second_session_extends", "fallback_appends", "dialog_focus_does_not_retarget",
		"caret_in_the_editor_title", "press_on_the_focused_title_claims_it",
		"caret_in_the_description_still_asks",
		"destination_is_fixed_at_start", "microphone_released",
	} {
		if _, ok := results[name]; !ok {
			t.Fatalf("scenario %q did not run:\n%s", name, out)
		}
	}
	return results
}

func TestDashboard_DictationFollowsTheCaret(t *testing.T) {
	got := runDictateFocusScenarios(t)

	t.Run("with no caret the button keeps its own field", func(t *testing.T) {
		r := got["no_caret_uses_the_button_field"]
		if r.Title != dictateFocusHeard {
			t.Errorf("task title = %q, want %q — most presses follow no click into a "+
				"text box, so the fallback is the common path and not an edge case",
				r.Title, dictateFocusHeard)
		}
		if r.Desc != "" {
			t.Errorf("the description field also received %q", r.Desc)
		}
	})

	t.Run("the caret takes the transcript", func(t *testing.T) {
		r := got["caret_wins"]
		if r.Desc != dictateFocusHeard {
			t.Errorf("description = %q, want %q — this is the whole request: the "+
				"field was unreachable by voice, and the only way to fill it was to "+
				"dictate into the title and retype", r.Desc, dictateFocusHeard)
		}
		if r.Title != "" {
			t.Errorf("the title field still received %q, so the caret was ignored", r.Title)
		}
	})

	t.Run("a field outside the Add Task row still counts", func(t *testing.T) {
		r := got["caret_outside_the_row"]
		if r.Filter != dictateFocusHeard {
			t.Errorf("filter box = %q, want %q — it is the field a user is most "+
				"likely to have the caret in when they reach for the microphone, and "+
				"\"wherever the caret is\" has to mean it", r.Filter, dictateFocusHeard)
		}
		if r.Title != "" {
			t.Errorf("the title field received %q instead", r.Title)
		}
	})

	t.Run("a number field is not a destination", func(t *testing.T) {
		r := got["number_field_is_not_a_destination"]
		if r.Priority != "" {
			t.Errorf("priority = %q — speech arrives as words and a number input "+
				"discards what it cannot parse without saying so, which would lose "+
				"the sentence with nothing on screen to explain it", r.Priority)
		}
		if r.Title != dictateFocusHeard {
			t.Errorf("title = %q, want the transcript to fall back to it rather than "+
				"disappear", r.Title)
		}
	})

	t.Run("words join what is already there", func(t *testing.T) {
		want := "bound the reads " + dictateFocusHeard
		if d := got["appends_with_a_space"].Desc; d != want {
			t.Errorf("description = %q, want %q — a transcript carries no spacing of "+
				"its own, so dropped straight against existing text it runs the two "+
				"words together", d, want)
		}
	})

	t.Run("a second session extends the same field", func(t *testing.T) {
		r := got["second_session_extends"]
		want := dictateFocusHeard + " " + dictateFocusHeard
		if r.Desc != want {
			t.Errorf("description after two sessions = %q, want %q — the write leaves "+
				"the caret where it finished, which is the caret the next session reads",
				r.Desc, want)
		}
		if r.Title != "" {
			t.Errorf("the second session fell back to the title (%q) instead of "+
				"staying where the first one landed", r.Title)
		}
	})

	// Only when nothing editable has the caret does the old behaviour come back,
	// and it comes back whole: appended to the title, not dropped at a selection
	// the title remembers from when it last had focus.
	t.Run("with no caret the title gets today's append", func(t *testing.T) {
		r := got["fallback_appends"]
		want := "Fix the " + dictateFocusHeard
		if r.Title != want {
			t.Errorf("task title = %q, want %q — a selection in a field the caret "+
				"is not in is invisible, and words dropped there land mid-word", r.Title, want)
		}
		if r.Caret != len(want) {
			t.Errorf("caret at %d after the append, want the end (%d)", r.Caret, len(want))
		}
	})

	// The regression the programmatic-focus distinction exists to prevent. The
	// edit modal focuses its Title the instant it opens; if that counted as the
	// user's caret, this dialog's microphone would never again reach the
	// description it sits beside.
	t.Run("the dialog's own opening focus does not retarget it", func(t *testing.T) {
		r := got["dialog_focus_does_not_retarget"]
		if !r.ChooserOpen {
			t.Error("dictating straight into a freshly opened editor did not open the " +
				"chooser — the transcript went somewhere other than the description, " +
				"and the protection Task 20302 added is now unreachable")
		}
		if r.Title != dictateFocusTaskTitle {
			t.Errorf("the task title became %q, want it left at %q: the caret "+
				"openOverlay placed was read as the user's", r.Title, dictateFocusTaskTitle)
		}
		if r.Heard != dictateFocusHeard {
			t.Errorf("the chooser is asking about %q, want %q", r.Heard, dictateFocusHeard)
		}
	})

	t.Run("the caret in the editor's title sends the words there", func(t *testing.T) {
		r := got["caret_in_the_editor_title"]
		// Joined to the title the editor loaded, not substituted for it: the
		// caret sits at the end of an existing title, and a microphone that
		// silently discarded it would be a worse trade than the one being fixed.
		want := dictateFocusTaskTitle + " " + dictateFocusHeard
		if r.Title != want {
			t.Errorf("editor title = %q, want %q", r.Title, want)
		}
		if r.ChooserOpen {
			t.Error("the chooser opened for the title — it is a one-line field whose " +
				"whole content is visible, so there is nothing to ask about")
		}
		if r.Desc != dictateFocusExisting {
			t.Errorf("the description changed to %q", r.Desc)
		}
	})

	// The dialog's Title already has focus, so a click into it dispatches no
	// focusin; without the press counting, the user who aimed at the Title
	// would see their words go to the description instead.
	t.Run("a press on the title the dialog focused claims it", func(t *testing.T) {
		r := got["press_on_the_focused_title_claims_it"]
		if want := dictateFocusTaskTitle + " " + dictateFocusHeard; r.Title != want {
			t.Errorf("editor title = %q, want %q", r.Title, want)
		}
		if r.ChooserOpen || r.Desc != dictateFocusExisting {
			t.Errorf("the words went to the description (chooser open %v, description %q)",
				r.ChooserOpen, r.Desc)
		}
	})

	t.Run("aiming at the description still asks first", func(t *testing.T) {
		r := got["caret_in_the_description_still_asks"]
		if !r.ChooserOpen {
			t.Error("putting the caret in the description skipped the chooser — the " +
				"question it asks is about the field's contents, not about which " +
				"button was pressed")
		}
		if r.Desc != dictateFocusExisting {
			t.Errorf("the description was written to before the user answered: %q", r.Desc)
		}
	})

	t.Run("the destination is fixed when the session starts", func(t *testing.T) {
		r := got["destination_is_fixed_at_start"]
		if r.Desc != dictateFocusHeard {
			t.Errorf("description = %q, want %q — a transcription round trip is "+
				"seconds long and the page stays live throughout, so resolving late "+
				"lets a click made while waiting redirect a sentence already spoken",
				r.Desc, dictateFocusHeard)
		}
		if r.Filter != "" {
			t.Errorf("the words followed the caret to the filter box (%q) instead of "+
				"staying where they were spoken", r.Filter)
		}
	})

	t.Run("the microphone is released whichever field the words went to", func(t *testing.T) {
		if n := got["microphone_released"].Live; n != 0 {
			t.Errorf("%d microphone track(s) still live after a completed dictation — "+
				"the browser's recording indicator stays lit with nothing able to "+
				"turn it off", n)
		}
	})
}

// TestDashboard_DictationFieldsAreDictatable checks the claims the node
// scenarios have to make on their own behalf.
//
// domshim auto-vivifies elements and has no markup to derive a tag or an input
// type from, so dictate_focus_scenarios.js states them: newTaskDesc is a
// textarea (Task 20343), newTaskPriority is a number input. Those statements are what make the
// scenarios mean anything — "a number field is not a destination" proves
// nothing if the field it names is really a text box — and nothing else keeps
// them honest as the markup moves.
func TestDashboard_DictationFieldsAreDictatable(t *testing.T) {
	src := dashboardSource

	// Mirrors DICTATE_TEXT_TYPES in 15-voice.js. An input with no type attribute
	// reports "text" from the DOM, which is what most of these are.
	dictatable := map[string]bool{"": true, "text": true, "search": true, "url": true, "tel": true, "email": true}

	for _, f := range []struct {
		id   string
		want bool // may a transcript land here?
		why  string
	}{
		{"newTaskTitle", true, "the Add Task microphone's own field"},
		{"newTaskDesc", true, "the field Task 20309 exists to make reachable"},
		{"filterQ", true, "the box a user most often has the caret in"},
		{"modalTitle_", true, "the editor field the caret can now redirect to"},
		{"modalDesc", true, "the editor field the chooser protects"},
		{"newTaskPriority", false, "speech would be discarded unparsed"},
		{"modalPriority", false, "speech would be discarded unparsed"},
		{"modalMaxMinutes", false, "speech would be discarded unparsed"},
	} {
		tag, typ, ok := fieldTagAndType(src, f.id)
		if !ok {
			t.Errorf("no element with id %q in the dashboard — the dictation "+
				"scenarios name it (%s)", f.id, f.why)
			continue
		}
		got := tag == "textarea" || (tag == "input" && dictatable[typ])
		if got != f.want {
			t.Errorf("id=%q is <%s type=%q>, which dictation %s accept; want it %s (%s)",
				f.id, tag, typ,
				map[bool]string{true: "would", false: "would not"}[got],
				map[bool]string{true: "dictatable", false: "refused"}[f.want], f.why)
		}
	}
}

var fieldTagRe = regexp.MustCompile(`<(input|textarea)\b[^>]*>`)

// fieldTagAndType finds the element carrying id and reports its tag and its
// type attribute. Deliberately crude — it only has to read the handful of
// single-line form controls named above.
func fieldTagAndType(src, id string) (tag, typ string, ok bool) {
	for _, m := range fieldTagRe.FindAllString(src, -1) {
		if !strings.Contains(m, `id="`+id+`"`) {
			continue
		}
		tag = strings.ToLower(strings.TrimLeft(strings.Fields(m)[0], "<"))
		if t := regexp.MustCompile(`\btype="([^"]*)"`).FindStringSubmatch(m); t != nil {
			typ = strings.ToLower(t[1])
		}
		return tag, typ, true
	}
	return "", "", false
}
