package ui

// Browser gate for modal focus containment (Task 20288).
//
// overlay_focus_test.go checks that every dialog goes through the shared
// helper. That is a structural claim, and it is the one that has to hold on a
// runner with no browser. This file checks the claim the helper actually
// makes — that focus cannot leave an open dialog, and that it goes back where
// it came from when the dialog closes — which is not a structural property at
// all and cannot be observed without a real implementation of focus, layout,
// Tab and `inert`. testdata/domshim.js has none of those.
//
// It skips when no browser is installed, which is the normal case in CI: the
// assertions are a gate on a developer box and on any runner that has Chrome,
// never a source of red builds on one that does not. See
// testdata/overlay_browser.js, and testdata/ptt_browser.js for the same
// arrangement applied to push-to-talk.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

type overlayActive struct {
	ID       string `json:"id"`
	Tag      string `json:"tag"`
	InDialog bool   `json:"inDialog"`
	IsBody   bool   `json:"isBody"`
}

type overlayResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Preflight struct {
		InvokerID        string   `json:"invoker_id"`
		LoginOverlayOpen bool     `json:"login_overlay_open"`
		HelperPresent    bool     `json:"helper_present"`
		Focusables       []string `json:"focusables"`
	} `json:"preflight"`

	FocusStartsInside struct {
		Active     overlayActive `json:"active"`
		Focusables []string      `json:"focusables"`
		AriaModal  string        `json:"aria_modal"`
		Role       string        `json:"role"`
	} `json:"focus_starts_inside"`

	TabCyclesForward struct {
		Sequence []overlayActive `json:"sequence"`
		Count    int             `json:"count"`
	} `json:"tab_cycles_forward"`

	ShiftTabWrapsBackward struct {
		Active overlayActive `json:"active"`
	} `json:"shift_tab_wraps_backward"`

	TabNeverEscapes struct {
		Escaped *overlayActive `json:"escaped"`
		Steps   int            `json:"steps"`
	} `json:"tab_never_escapes"`

	BackgroundIsInert struct {
		Found            bool `json:"found"`
		HasInertAncestor bool `json:"has_inert_ancestor"`
		FocusTook        bool `json:"focus_took"`
		FocusUnchanged   bool `json:"focus_unchanged"`
	} `json:"background_is_inert"`

	CloseRestoresFocus struct {
		Active struct {
			ID     string `json:"id"`
			IsBody bool   `json:"isBody"`
		} `json:"active"`
		Expect     string `json:"expect"`
		StillInert bool   `json:"still_inert"`
	} `json:"close_restores_focus"`

	EscapeRestoresFocus overlayCloseResult `json:"escape_restores_focus"`
	BackdropRestores    overlayCloseResult `json:"backdrop_click_restores_focus"`

	Stacked struct {
		PaletteOpenBefore  bool          `json:"palette_open_before"`
		PaletteFocusBefore overlayActive `json:"palette_focus_before"`
		PaletteOpenAfter   bool          `json:"palette_open_after"`
		FixtureOpenAfter   bool          `json:"fixture_open_after"`
		ActiveAfter        overlayActive `json:"active_after"`
	} `json:"stacked_escape_closes_front_only"`

	VoiceSurvives struct {
		Present bool   `json:"present"`
		Open    bool   `json:"open"`
		Threw   string `json:"threw"`
	} `json:"voice_modal_survives_escape"`
}

type overlayCloseResult struct {
	Open   bool `json:"open"`
	Active struct {
		ID     string `json:"id"`
		IsBody bool   `json:"isBody"`
	} `json:"active"`
	Expect string `json:"expect"`
}

// TestOverlay_FocusContainmentInBrowser is the whole gate; the subtests read
// from the single browser run it performs, because launching Chrome and booting
// the dashboard costs seconds and every scenario shares that setup.
func TestOverlay_FocusContainmentInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot observe real focus, Tab or inert")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// The real dashboard — real index.html, real bundle, real app.css — with
	// nothing stubbed. The fixture dialog's form is static markup, so no
	// project, task or seeded state.db is needed to open it.
	s := New(t.TempDir(), 0, "")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/overlay_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("OVERLAY_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}

	var got overlayResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}

	// Preflight. Without these the assertions below would pass on a page that
	// never loaded the helper, or one sitting behind the login gate.
	if !got.Preflight.HelperPresent {
		t.Fatal("window.openOverlay is not defined on the loaded page — 00-overlay.js is not " +
			"in the served bundle, so nothing below could be testing what it claims")
	}
	if got.Preflight.LoginOverlayOpen {
		t.Fatal("the login gate is up; the fixture dialog was never reachable")
	}
	if n := len(got.Preflight.Focusables); n < 3 {
		t.Fatalf("the fixture dialog reports %d focusable controls (%v); wrapping first<->last "+
			"is only a real question with several, so this run would pass vacuously",
			n, got.Preflight.Focusables)
	}

	t.Run("opening a dialog moves focus into it", func(t *testing.T) {
		r := got.FocusStartsInside
		if !r.Active.InDialog {
			t.Errorf("after opening, focus is on %q (<%s>), outside the dialog — the user is "+
				"typing into the page the dialog is covering", r.Active.ID, r.Active.Tag)
		}
		if r.Active.ID != "enrollName" {
			t.Errorf("initial focus landed on %q, want the control the caller named (enrollName); "+
				"the focus: option is not being honoured", r.Active.ID)
		}
		// Without these a screen reader keeps reading the page behind as if it
		// were reachable, whatever the focus order does.
		if r.AriaModal != "true" {
			t.Errorf("aria-modal on the open dialog = %q, want \"true\"", r.AriaModal)
		}
		if r.Role != "dialog" {
			t.Errorf("role on the open dialog = %q, want \"dialog\"", r.Role)
		}
	})

	t.Run("Tab cycles back to the first control", func(t *testing.T) {
		r := got.TabCyclesForward
		if len(r.Sequence) == 0 {
			t.Fatal("no Tab presses recorded")
		}
		for i, a := range r.Sequence {
			if !a.InDialog {
				t.Fatalf("Tab press %d of %d left the dialog and focused %q (<%s>)",
					i+1, len(r.Sequence), a.ID, a.Tag)
			}
		}
		// Focus starts on the first control, so the n'th Tab in a dialog with n
		// focusables is the one that has to wrap — that press is the whole
		// assertion, and the extra press after it proves the cycle continues
		// rather than sticking.
		if r.Count < 2 || len(r.Sequence) <= r.Count {
			t.Fatalf("expected at least %d Tab presses recorded, got %d", r.Count+1, len(r.Sequence))
		}
		want := got.Preflight.Focusables[0]
		if wrap := r.Sequence[r.Count-1]; wrap.ID != want {
			t.Errorf("Tab press %d of a dialog with %d focusable controls focused %q, want it "+
				"wrapped round to the first control (%q).\n  full sequence: %s",
				r.Count, r.Count, wrap.ID, want, describeSeq(r.Sequence))
		}
		if next := r.Sequence[r.Count]; next.ID == r.Sequence[r.Count-1].ID {
			t.Errorf("Tab stopped advancing after the wrap; focus stuck on %q", next.ID)
		}
	})

	t.Run("Shift+Tab off the first control wraps to the last", func(t *testing.T) {
		a := got.ShiftTabWrapsBackward.Active
		if !a.InDialog {
			t.Fatalf("Shift+Tab from the first control left the dialog and focused %q (<%s>) — "+
				"this is the direction that lands on the page behind, because the browser's "+
				"default is to walk backwards out of the dialog", a.ID, a.Tag)
		}
		want := got.Preflight.Focusables[len(got.Preflight.Focusables)-1]
		if a.ID != "" && want != "" && a.ID != want {
			t.Errorf("Shift+Tab from the first control focused %q, want the last control (%q)", a.ID, want)
		}
	})

	t.Run("holding Tab never reaches the page behind", func(t *testing.T) {
		r := got.TabNeverEscapes
		if r.Escaped != nil {
			t.Errorf("Tab press %d escaped the dialog and focused %q (<%s>).\n"+
				"  This is the defect the task is about: the controls behind an open dialog stay "+
				"reachable, so a keyboard or screen-reader user can operate — and start a run "+
				"from — a page that is visually covered.", r.Steps, r.Escaped.ID, r.Escaped.Tag)
		}
	})

	t.Run("the page behind an open dialog is inert", func(t *testing.T) {
		r := got.BackgroundIsInert
		if !r.Found {
			t.Skip("background probe element not present")
		}
		if !r.HasInertAncestor {
			t.Errorf("a background control has no [inert] ancestor while a dialog is open")
		}
		// The attribute being set is not the same as it being enforced; this is
		// the half only a browser can answer.
		if r.FocusTook {
			t.Errorf("focus() on a background control succeeded while a dialog was open — " +
				"the background is not actually inert")
		}
	})

	// The three ways out of a dialog. Each is a separate path in the page, and
	// before this task only one of them could have restored focus at all.
	for _, tc := range []struct {
		name string
		r    overlayCloseResult
	}{
		{"Escape", got.EscapeRestoresFocus},
		{"a backdrop click", got.BackdropRestores},
	} {
		t.Run("closing with "+tc.name+" returns focus to the invoker", func(t *testing.T) {
			if tc.r.Open {
				t.Fatalf("%s did not close the dialog", tc.name)
			}
			if tc.r.Active.ID != tc.r.Expect {
				where := tc.r.Active.ID
				if tc.r.Active.IsBody {
					where = "<body> (the top of the document)"
				}
				t.Errorf("after closing with %s, focus is on %s, want the invoking element %q.\n"+
					"  A keyboard user who opens a dialog and dismisses it is otherwise put back "+
					"at the start of the page and has to Tab all the way to where they were.",
					tc.name, where, tc.r.Expect)
			}
		})
	}

	t.Run("closing with the dialog's own control returns focus to the invoker", func(t *testing.T) {
		r := got.CloseRestoresFocus
		if r.Active.ID != r.Expect {
			where := r.Active.ID
			if r.Active.IsBody {
				where = "<body> (the top of the document)"
			}
			t.Errorf("after closing, focus is on %s, want the invoking element %q", where, r.Expect)
		}
		if r.StillInert {
			t.Errorf("the page behind is still [inert] after the last dialog closed — " +
				"the whole dashboard is now unusable by keyboard and mouse alike")
		}
	})

	t.Run("Escape closes only the dialog in front", func(t *testing.T) {
		r := got.Stacked
		if !r.PaletteOpenBefore {
			t.Skip("the command palette did not open over the fixture; nothing stacked to test")
		}
		if !r.PaletteFocusBefore.InDialog {
			t.Errorf("focus did not move into the palette opened over the dialog; it stayed on %q",
				r.PaletteFocusBefore.ID)
		}
		if r.PaletteOpenAfter {
			t.Errorf("Escape did not close the palette in front")
		}
		if !r.FixtureOpenAfter {
			t.Errorf("Escape closed the dialog *underneath* instead of the one in front — " +
				"the user is left looking at a palette they cannot dismiss")
		}
		if !r.ActiveAfter.InDialog {
			t.Errorf("after dismissing the palette, focus is on %q rather than back inside the "+
				"dialog it was opened from", r.ActiveAfter.ID)
		}
	})

	// The regression the hand-written Escape chain carried for as long as it
	// existed. Worth an assertion of its own because it is silent: nothing
	// fails, the modal simply stops existing.
	t.Run("Escape does not destroy the voice modal", func(t *testing.T) {
		r := got.VoiceSurvives
		if !r.Present {
			t.Fatal("#voiceModalBackdrop is gone from the document after two Escape presses — " +
				"the Escape handler is removing a static node instead of hiding it, and the " +
				"modal cannot be opened again for the life of the page")
		}
		if r.Threw != "" {
			t.Errorf("openVoiceModal() threw after Escape: %s", r.Threw)
		}
		if !r.Open {
			t.Errorf("the voice modal did not open after an Escape press")
		}
	})
}

func describeSeq(seq []overlayActive) string {
	out := ""
	for i, a := range seq {
		if i > 0 {
			out += " -> "
		}
		if a.ID == "" {
			out += "<" + a.Tag + ">"
		} else {
			out += a.ID
		}
	}
	return out
}
