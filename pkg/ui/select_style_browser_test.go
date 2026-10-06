package ui

// Browser gate for the dashboard's <select> boxes (Task 20355).
//
// What was wrong. Of the 46 selects the dashboard draws, 37 used .form-select,
// which drew a themed box and chevron — including on its two list boxes, which
// have nothing to drop down. The other nine drew the platform's own control:
// the five .filter-selects kept the native arrow (and, through an undefined
// `var(--fg)`, took whatever text colour their container had), the Replay
// tab's select borrowed .form-input, and the GitHub App panel's three used a
// class, `.input`, that app.css never defined, so on the dark theme they were
// white boxes with black text, as were the text fields beside them. Every open
// list was the platform popup: square-cornered, in the platform's highlight
// blue, and on the light scheme the page never declared. A list box's chosen
// row was white text on light grey.
//
// What app.css does now, and why each piece is shaped the way it is:
//
//   - Every select gets the look from the element, not a class, so a new select
//     cannot come out native because someone picked the wrong class name.
//   - The chevron, the room for it and the one-line layout hang off
//     `select:not([multiple])`. Its specificity (0,1,1) beats the single-class
//     rules those selects also carry — .form-input's `background` shorthand
//     would otherwise erase the chevron and its `padding` put the label under
//     it — and :not([multiple]) keeps a dropdown arrow off a list box.
//   - :root declares color-scheme per theme. That is what themes the parts CSS
//     cannot reach: the platform popup where it is still used, list-box
//     selection, checkboxes and scrollbars.
//   - Where the browser has it and the primary pointer is not a finger,
//     `appearance: base-select` makes the open list page content, styled like
//     the header's project dropdown: surface, border, radius, shadow, the
//     checked option in the accent. Phones keep the platform picker, which is
//     built for touch; the media query says `not (pointer: coarse)` rather than
//     `(pointer: fine)` so a pointerless headless Chrome — this test's — draws
//     what a desktop does.
//   - base-select changes three things the classic control did for free, each
//     undone explicitly: it sizes the line from the inherited 1.5 line-height
//     and a 24px floor (selects came out taller than the inputs beside them),
//     it lets a long label wrap or run under the chevron (hence nowrap and
//     `overflow: clip` at the content box), and an empty select collapses —
//     which is why the picker icon is kept as a zero-width strut rather than
//     hidden, and the flex gap before it zeroed.
//   - An open base-select picker moves focus onto its <option>s, so keys typed
//     into it reach 18-shortcuts.js with an OPTION as the target: `t` toggled
//     the theme mid-type-ahead, digits switched tabs, and Escape closed the
//     dialog behind the list as well as the list. The handler now leaves an
//     OPTION's keys alone.
//
// Skips when Chrome or node is unavailable, like the other browser gates here.
// The picker and keyboard subtests skip on a Chrome without base-select, where
// the list is a platform popup no page handler ever sees.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type selectStyleTokens struct {
	BG      string `json:"bg"`
	Border  string `json:"border"`
	Text    string `json:"text"`
	Surface string `json:"surface"`
	Accent  string `json:"accent"`
	Radius  string `json:"radius"`
}

type selectStyle struct {
	ID              string  `json:"id"`
	Cls             string  `json:"cls"`
	Multiple        bool    `json:"multiple"`
	Appearance      string  `json:"appearance"`
	Background      string  `json:"background"`
	BackgroundImage string  `json:"background_image"`
	Border          string  `json:"border"`
	Color           string  `json:"color"`
	Radius          string  `json:"radius"`
	PaddingRight    float64 `json:"padding_right"`
	FontFamily      string  `json:"font_family"`
}

func (s selectStyle) name() string {
	if s.ID != "" {
		return "#" + s.ID
	}
	return "select." + strings.ReplaceAll(s.Cls, " ", ".")
}

type selectThemeResult struct {
	Theme       string            `json:"theme"`
	ColorScheme string            `json:"color_scheme"`
	BodyFont    string            `json:"body_font"`
	Tokens      selectStyleTokens `json:"tokens"`
	Selects     []selectStyle     `json:"selects"`
}

type selectKeyState struct {
	Open           bool   `json:"open"`
	DialogOpen     bool   `json:"dialog_open"`
	Theme          string `json:"theme"`
	Tab            string `json:"tab"`
	ActiveTag      string `json:"active_tag"`
	ActiveInSelect bool   `json:"active_in_select"`
	Value          string `json:"value"`
}

type selectStyleResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Styles  []selectThemeResult `json:"styles"`
	Heights struct {
		FormSelect   float64 `json:"form_select"`
		FormInput    float64 `json:"form_input"`
		EmptySelect  float64 `json:"empty_select"`
		GhSelect     float64 `json:"gh_select"`
		GhInput      float64 `json:"gh_input"`
		FilterSelect float64 `json:"filter_select"`
		LongSelect   float64 `json:"long_select"`
		LongWidth    float64 `json:"long_width"`
	} `json:"heights"`

	BaseSelect struct {
		CSSSupports bool `json:"css_supports"`
		Applied     bool `json:"applied"`
	} `json:"base_select"`

	Picker *struct {
		Opened bool `json:"opened"`
		Style  struct {
			Background       string `json:"background"`
			Border           string `json:"border"`
			Radius           string `json:"radius"`
			SelectBorderOpen string `json:"select_border_open"`
			CheckedColor     string `json:"checked_color"`
		} `json:"style"`
	} `json:"picker"`

	Keyboard *struct {
		Before      selectKeyState `json:"before"`
		AfterType   selectKeyState `json:"after_type"`
		AfterEscape selectKeyState `json:"after_escape"`
	} `json:"keyboard"`

	Pick *struct {
		Reopened     bool   `json:"reopened"`
		Value        string `json:"value"`
		OpenAfter    bool   `json:"open_after"`
		DialogOpen   bool   `json:"dialog_open"`
		ChangeEvents int    `json:"change_events"`
	} `json:"pick"`

	EscapeFromClosedSelect *selectKeyState `json:"escape_from_closed_select"`
}

// selectStyleMinSelects is a floor, not a count: index.html and the deferred
// panels the driver mounts (Task 20386) hold 39 selects, and the driver adds 5.
// Far fewer means the page did not assemble and every per-select assertion
// below would pass on an empty list.
const selectStyleMinSelects = 30

// TestSelects_FitThePageDesign is the whole gate; the subtests read from one
// browser run, because launching Chrome and booting the dashboard costs seconds
// and every scenario shares that setup.
func TestSelects_FitThePageDesign(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot resolve computed style")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// The real dashboard with nothing stubbed. The fixture dialog is static
	// markup, so no project or seeded state.db is needed.
	s := New(t.TempDir(), 0, "")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Bounded, so a stalled Chrome cannot hold the package until its timeout
	// (Task 20340).
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/select_style_browser.js"), chrome, srv.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("SELECT_STYLE_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}

	var got selectStyleResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}
	if len(got.Styles) != 2 {
		t.Fatalf("got %d theme measurements, want dark and light", len(got.Styles))
	}

	t.Run("every select wears the theme", func(t *testing.T) {
		for _, th := range got.Styles {
			if n := len(th.Selects); n < selectStyleMinSelects {
				t.Fatalf("%s: only %d selects measured; the page did not assemble", th.Theme, n)
			}
			// The platform draws the popup, list-box selection, checkboxes and
			// scrollbars from this, not from any colour the page sets.
			if th.ColorScheme != th.Theme {
				t.Errorf("%s theme: the root's color-scheme is %q, so the parts of every "+
					"control CSS cannot style are drawn for the other theme", th.Theme, th.ColorScheme)
			}
			for _, sel := range th.Selects {
				if sel.Background != th.Tokens.BG || sel.Border != th.Tokens.Border || sel.Color != th.Tokens.Text {
					t.Errorf("%s theme: %s is background %s, border %s, text %s; the theme's fields "+
						"are %s, %s and %s", th.Theme, sel.name(), sel.Background, sel.Border,
						sel.Color, th.Tokens.BG, th.Tokens.Border, th.Tokens.Text)
				}
				if sel.Radius != th.Tokens.Radius {
					t.Errorf("%s theme: %s has radius %s, the page's is %s",
						th.Theme, sel.name(), sel.Radius, th.Tokens.Radius)
				}
				if sel.FontFamily != th.BodyFont {
					t.Errorf("%s theme: %s is set in %q, not the page's %q",
						th.Theme, sel.name(), sel.FontFamily, th.BodyFont)
				}
				if sel.Multiple {
					// A list box shows its options; a dropdown arrow on one
					// promises a popup that never opens.
					if sel.BackgroundImage != "none" {
						t.Errorf("%s theme: list box %s paints %s", th.Theme, sel.name(), sel.BackgroundImage)
					}
					continue
				}
				if sel.Appearance != "none" && sel.Appearance != "base-select" {
					t.Errorf("%s theme: %s has appearance %q, so the platform draws it",
						th.Theme, sel.name(), sel.Appearance)
				}
				if !strings.Contains(sel.BackgroundImage, "url(") {
					t.Errorf("%s theme: %s has no chevron (background-image %s)",
						th.Theme, sel.name(), sel.BackgroundImage)
				}
				if sel.PaddingRight < 24 {
					t.Errorf("%s theme: %s reserves %.0fpx on the right, so its label runs under the chevron",
						th.Theme, sel.name(), sel.PaddingRight)
				}
			}
		}
	})

	t.Run("selects line up with the fields beside them", func(t *testing.T) {
		h := got.Heights
		for _, c := range []struct {
			what      string
			got, want float64
		}{
			{"a .form-select beside a .form-input", h.FormSelect, h.FormInput},
			{"an empty .form-select (the Replay tab before any task finished)", h.EmptySelect, h.FormSelect},
			{"a GitHub App panel select (.input) beside its text field", h.GhSelect, h.GhInput},
			{"a .filter-select whose label is wider than the box", h.LongSelect, h.FilterSelect},
		} {
			if c.got < c.want-0.5 || c.got > c.want+0.5 {
				t.Errorf("%s is %.1fpx tall, want %.1fpx", c.what, c.got, c.want)
			}
		}
		if h.LongWidth > 130 {
			t.Errorf("a .filter-select with a long label grew to %.0fpx, past its 130px cap", h.LongWidth)
		}
	})

	if got.BaseSelect.CSSSupports && !got.BaseSelect.Applied {
		t.Fatal("this Chrome supports appearance: base-select but the dashboard's selects do not " +
			"use it, so every open list is still the platform popup")
	}
	skipUnlessBaseSelect := func(t *testing.T) {
		t.Helper()
		if !got.BaseSelect.Applied {
			t.Skip("this Chrome predates appearance: base-select; the open list is the platform's own popup")
		}
	}
	dark := got.Styles[0].Tokens

	t.Run("the open list is styled like the page's dropdowns", func(t *testing.T) {
		skipUnlessBaseSelect(t)
		if got.Picker == nil || !got.Picker.Opened {
			t.Fatal("clicking the select did not open its picker")
		}
		p := got.Picker.Style
		if p.Background != dark.Surface || p.Border != dark.Border || p.Radius != dark.Radius {
			t.Errorf("the picker is background %s, border %s, radius %s; the page's dropdowns are %s, %s, %s",
				p.Background, p.Border, p.Radius, dark.Surface, dark.Border, dark.Radius)
		}
		if p.SelectBorderOpen != dark.Accent {
			t.Errorf("an open select's border is %s, not the accent %s", p.SelectBorderOpen, dark.Accent)
		}
		if p.CheckedColor != dark.Accent {
			t.Errorf("the checked option is %s, not the accent %s", p.CheckedColor, dark.Accent)
		}
	})

	t.Run("keys typed into an open list stay in the list", func(t *testing.T) {
		skipUnlessBaseSelect(t)
		k := got.Keyboard
		if k == nil || !k.Before.Open {
			t.Fatal("the picker was not open when the keys were sent")
		}
		if k.Before.ActiveTag != "OPTION" {
			// The premise of the guard in 18-shortcuts.js. If a future Chrome
			// keeps focus on the <select>, the INPUT/SELECT check covers it and
			// the guard is dead code — worth knowing, not worth failing over.
			t.Logf("focus in the open picker is on %s, not an OPTION", k.Before.ActiveTag)
		}
		a := k.AfterType
		if a.Theme != k.Before.Theme {
			t.Errorf("typing `t` into the open list switched the theme from %s to %s", k.Before.Theme, a.Theme)
		}
		if a.Tab != k.Before.Tab {
			t.Errorf("typing `2` into the open list switched the tab from %s to %s", k.Before.Tab, a.Tab)
		}
		if !a.Open || !a.DialogOpen {
			t.Errorf("typing into the open list closed it (open=%v) or its dialog (open=%v)", a.Open, a.DialogOpen)
		}
		e := k.AfterEscape
		if e.Open {
			t.Error("Escape did not close the open list")
		}
		if !e.DialogOpen {
			t.Error("Escape in the open list also closed the dialog behind it")
		}
		if !e.ActiveInSelect {
			t.Errorf("after Escape focus is on %s, not back on the select", e.ActiveTag)
		}
	})

	t.Run("a keyboard pick fires change and Escape still closes the dialog", func(t *testing.T) {
		skipUnlessBaseSelect(t)
		p := got.Pick
		if p == nil || !p.Reopened {
			t.Fatal("the picker did not reopen for the pick")
		}
		if p.Value == "" || p.OpenAfter || !p.DialogOpen {
			t.Errorf("ArrowDown+Enter left value %q, list open=%v, dialog open=%v; want a new value, "+
				"the list closed and the dialog open", p.Value, p.OpenAfter, p.DialogOpen)
		}
		if p.ChangeEvents != 1 {
			t.Errorf("the pick fired %d change events, want 1", p.ChangeEvents)
		}
		if e := got.EscapeFromClosedSelect; e == nil || e.DialogOpen {
			t.Error("Escape from a closed, focused select no longer closes the dialog")
		}
	})
}
