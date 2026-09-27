package ui

// A long project list on a phone, measured in a real browser (Task 20300).
//
// Everything asserted here is a layout fact — a box's right edge against the
// viewport's, a panel's height against the fold — and testdata/domshim.js
// implements no box model, so it reports zero for every rect and would pass
// this file unconditionally. Only an engine that lays the page out at 390px
// can tell a list that fits from one hanging off the screen.
//
// Skips when Chrome or node is unavailable, like the other browser gates here.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

// mobileProjectCount is large enough that the header dropdown cannot fit on a
// phone however it is styled: 24 rows at ~33px is ~790px against an 844px
// viewport that has already spent ~100px on the header. The fix is a height
// cap and a scroll, so the test needs a list that provably exceeds any
// reasonable cap.
const mobileProjectCount = 24

// phoneWidth/narrowPhoneWidth are the two viewports the driver measures at.
// 390px is an iPhone 12/13/14; 320px is the narrowest phone still in use and
// the width at which a hard-coded 320px max-width cannot fit inside a padded
// card. Both are below the 767px breakpoint where the mobile rules apply.
const (
	phoneWidth       = 390
	narrowPhoneWidth = 320
)

// namedProjectDir is setupProjectDir with a caller-chosen directory name. The
// dashboard shows a project by its basename (multiui.ProjectEntry.Name), so
// the name is only controllable through the path — and this test needs one
// specific long, unbroken name rather than another mkdtemp slug.
func namedProjectDir(t *testing.T, name, goal string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	seedMigratedDB(t, dir) // skip the migration replay; see dbtemplate_test.go
	if _, err := state.Init(dir, goal, 0); err != nil {
		t.Fatalf("state.Init(%s): %v", dir, err)
	}
	return dir
}

// pauseForUsageCap marks the project in dir as paused on a subscription cap
// that lifts in an hour, with detail as the reason's wording.
func pauseForUsageCap(t *testing.T, dir, detail string) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	ps.SetPaused(pausereason.NewUntil(pausereason.CodeUsageCap, detail, time.Now().Add(time.Hour)))
	if err := ps.Save(); err != nil {
		t.Fatalf("save %s: %v", dir, err)
	}
}

// hideProjectAt hides the project at path for this hub's (anonymous) viewer,
// addressing it by its index in /api/projects as the dashboard does.
func hideProjectAt(t *testing.T, ts *httptest.Server, path string) {
	t.Helper()
	idx := -1
	for i, p := range getProjects(t, nil, ts.URL).Projects {
		if p.Path == path {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("%s is not in /api/projects, so it cannot be hidden", path)
	}
	resp := postHidden(t, nil, ts.URL, idx, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hiding %s: POST /api/projects/%d/hidden = %d", path, idx, resp.StatusCode)
	}
}

type overflowPage struct {
	ExpectedWidth int `json:"expected_width"`
	InnerWidth    int `json:"inner_width"`
	InnerHeight   int `json:"inner_height"`
	ScrollWidth   int `json:"scroll_width"`
	ClientWidth   int `json:"client_width"`
	OverflowPx    int `json:"overflow_px"`
}

type overflowWidest struct {
	OverPx int    `json:"over_px"`
	Tag    string `json:"tag"`
	ID     string `json:"id"`
	Cls    string `json:"cls"`
	Right  int    `json:"right"`
	Width  int    `json:"width"`
}

func (w *overflowWidest) String() string {
	if w == nil {
		return "nothing"
	}
	return fmt.Sprintf("<%s id=%q class=%q> right=%d width=%d (%dpx past the edge)",
		w.Tag, w.ID, w.Cls, w.Right, w.Width, w.OverPx)
}

type overflowDropdown struct {
	Present             bool   `json:"present"`
	Open                bool   `json:"open"`
	Items               int    `json:"items"`
	Height              int    `json:"height"`
	Top                 int    `json:"top"`
	Bottom              int    `json:"bottom"`
	Left                int    `json:"left"`
	Right               int    `json:"right"`
	OverflowY           string `json:"overflow_y"`
	ScrollHeight        int    `json:"scroll_height"`
	ClientHeight        int    `json:"client_height"`
	Scrollable          bool   `json:"scrollable"`
	ViewportH           int    `json:"viewport_h"`
	ViewportW           int    `json:"viewport_w"`
	LiveViewportW       int    `json:"live_viewport_w"`
	BelowFoldPx         int    `json:"below_fold_px"`
	RightOverflowPx     int    `json:"right_overflow_px"`
	LastItemBottom      *int   `json:"last_item_bottom"`
	LastItemBelowFoldPx *int   `json:"last_item_below_fold_px"`
}

type overflowLastItem struct {
	Reachable bool   `json:"reachable"`
	Why       string `json:"why"`
	X         int    `json:"x"`
	Y         int    `json:"y"`
	Bottom    int    `json:"bottom"`
}

type overflowCards struct {
	Present         bool   `json:"present"`
	Count           int    `json:"count"`
	PausedRows      int    `json:"paused_rows"`
	WorstOverflowPx int    `json:"worst_overflow_px"`
	WorstName       string `json:"worst_name"`
	InnerOverflowPx int    `json:"inner_overflow_px"`
	InnerWho        string `json:"inner_who"`
}

type mobileOverflowResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	MultiProject bool `json:"multi_project"`

	Closed struct {
		Page     overflowPage     `json:"page"`
		Widest   *overflowWidest  `json:"widest"`
		Dropdown overflowDropdown `json:"dropdown"`
	} `json:"closed"`

	Grid struct {
		Page   overflowPage    `json:"page"`
		Widest *overflowWidest `json:"widest"`
		Cards  overflowCards   `json:"cards"`
	} `json:"grid"`

	Open struct {
		Page     overflowPage     `json:"page"`
		Dropdown overflowDropdown `json:"dropdown"`
		LastItem overflowLastItem `json:"last_item"`
	} `json:"open"`

	Narrow struct {
		Page   overflowPage    `json:"page"`
		Widest *overflowWidest `json:"widest"`
		Cards  overflowCards   `json:"cards"`
	} `json:"narrow"`

	NarrowOpen struct {
		Page     overflowPage     `json:"page"`
		Dropdown overflowDropdown `json:"dropdown"`
		LastItem overflowLastItem `json:"last_item"`
	} `json:"narrow_open"`

	HiddenList struct {
		Page   overflowPage    `json:"page"`
		Widest *overflowWidest `json:"widest"`
		Rows   struct {
			Present         bool   `json:"present"`
			Count           int    `json:"count"`
			WorstOverflowPx int    `json:"worst_overflow_px"`
			WorstName       string `json:"worst_name"`
		} `json:"rows"`
	} `json:"hidden_list"`

	Desktop struct {
		Page     overflowPage     `json:"page"`
		Dropdown overflowDropdown `json:"dropdown"`
		LastItem overflowLastItem `json:"last_item"`
		Anchored *struct {
			ButtonLeft   int `json:"button_left"`
			DropdownLeft int `json:"dropdown_left"`
			Delta        int `json:"delta"`
		} `json:"anchored"`
	} `json:"desktop"`

	TabStrip []struct {
		Width int          `json:"width"`
		Page  overflowPage `json:"page"`
		Strip tabStrip     `json:"strip"`
	} `json:"tab_strip"`
}

// tabStrip is TAB_STRIP in testdata/mobile_overflow_browser.js.
type tabStrip struct {
	Present     bool     `json:"present"`
	Tabs        int      `json:"tabs"`
	Right       int      `json:"right"`
	ScrollWidth int      `json:"scroll_width"`
	ClientWidth int      `json:"client_width"`
	ScrollbarPx int      `json:"scrollbar_px"`
	Hidden      []string `json:"hidden"`
	Stranded    []string `json:"stranded"`
	Below       []string `json:"below"`
}

// TestMobileLongProjectList_DoesNotOverflow is the whole gate; the subtests
// read from one browser run, because launching Chrome and booting the
// dashboard costs seconds and every scenario shares that setup.
func TestMobileLongProjectList_DoesNotOverflow(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot measure layout")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry root of this test's own. TestMain isolates $HOME for the
	// package, but that is one registry shared by every test in it, and several
	// of them call multiui.AddPathsOwned — so in a full-package run their
	// projects appear in this dashboard's list too. This test asserts on an
	// exact roster and lays out whatever names it is given, so inherited
	// entries both break the count and make the geometry depend on which tests
	// ran first. It passed alone and failed at 26 rows in the suite before
	// this line existed.
	t.Setenv(multiui.EnvRoot, t.TempDir())

	// A fleet, with the names a fleet actually has. The project name is the
	// directory's basename, so the last one carries a long unbroken slug — no
	// spaces anywhere — because that is the input that makes a name refuse to
	// shrink and drags the card wider than the screen. A name with spaces
	// wraps on its own and would prove nothing.
	primary := setupProjectDir(t, "primary goal", nil)
	// One project is paused, for the reason a subscription cap gives, so the
	// grid draws a .proj-pause row: it carries its own max-width and is one of
	// the widths under test. Stored in the project's state rather than patched
	// into the page. The driver used to patch its cached roster and re-render,
	// and any /api/projects response landing afterwards — the Projects tab's
	// own fetch takes seconds under a loaded -race run — redrew the grid
	// without it (Task 20344).
	pauseForUsageCap(t, primary,
		"weekly subscription cap reached at 98% of the five-hour window")
	others := make([]string, 0, mobileProjectCount)
	for i := 1; i < mobileProjectCount-1; i++ {
		goal := fmt.Sprintf("goal for project %d — long enough to need truncating on a narrow screen", i)
		others = append(others, setupProjectDir(t, goal, nil))
	}
	// Underscores, not hyphens. CSS offers a line-break opportunity after a
	// hyphen, so a hyphenated name wraps by itself and would prove nothing;
	// `word-break: normal` gives an underscored name no break opportunity at
	// all, and plenty of real project directories are named that way.
	others = append(others, namedProjectDir(t,
		"internal_platform_observability_ingest_pipeline_rollout_2026",
		"a goal long enough that it has to be truncated rather than widen the card"))
	// And one more that this viewer has hidden, for the hidden-projects
	// dialog, with a name just as unbreakable. It is a project of its own, not
	// one of the mobileProjectCount above: hidden projects leave the grid and
	// the dropdown, so hiding one of those would change the very list every
	// other scenario measures.
	hidden := namedProjectDir(t,
		"internal_platform_observability_ingest_pipeline_archive_2019",
		"a goal for a project this viewer no longer wants to see")
	others = append(others, hidden)
	ts := newTestServer(t, primary, others)

	// Hidden through the API the dialog's own Unhide button reverses, before
	// the browser starts, so every roster the page ever receives already says
	// so. The driver used to set the flag on its cached copy instead, which
	// the next roster to arrive silently undid; in CI that left the dialog
	// empty (Task 20344).
	hideProjectAt(t, ts, hidden)

	// Bounded: a driver whose Chrome stalls would otherwise hold this test,

	// and every pkg/ui test after it, until the package timeout (Task 20340).

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)

	defer cancel()

	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/mobile_overflow_browser.js"), chrome, ts.URL)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	if os.Getenv("MOBILE_OVERFLOW_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}

	var got mobileOverflowResults
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s", got.Error.Message)
	}

	// Preflight. Without a multi-project page and a populated dropdown, every
	// assertion below would pass on an empty document.
	if !got.MultiProject {
		t.Fatal("the page is not in multi-project mode, so the header selector never " +
			"rendered and nothing below is testing what it claims")
	}
	if n := got.Closed.Dropdown.Items; n != mobileProjectCount {
		t.Fatalf("the header dropdown holds %d rows, want %d — the roster did not "+
			"arrive, so the list under test is not long", n, mobileProjectCount)
	}
	// The driver names the viewport widths it emulates and this file names them
	// again in its failure messages. If the two drift, every message below
	// reports a width that was never used — so fail on the mismatch rather
	// than emit a confidently wrong number.
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"grid", got.Grid.Page.ExpectedWidth, phoneWidth},
		{"narrow", got.Narrow.Page.ExpectedWidth, narrowPhoneWidth},
	} {
		if c.got != c.want {
			t.Fatalf("%s scenario ran at %dpx but this test reports %dpx: "+
				"testdata/mobile_overflow_browser.js and the constants here have "+
				"drifted apart", c.name, c.got, c.want)
		}
	}

	t.Run("the page does not scroll sideways", func(t *testing.T) {
		// A phone has no horizontal scrollbar to drag: anything past the right
		// edge is unreachable, and the whole page slides under a finger that
		// meant to scroll down. 1px of tolerance for subpixel rounding.
		for _, c := range []struct {
			name string
			page overflowPage
			who  *overflowWidest
		}{
			{"landing", got.Closed.Page, got.Closed.Widest},
			{"projects tab", got.Grid.Page, got.Grid.Widest},
			{"projects tab at 320px", got.Narrow.Page, got.Narrow.Widest},
			{"selector open", got.Open.Page, nil},
			{"selector open at 320px", got.NarrowOpen.Page, nil},
		} {
			if c.page.OverflowPx > 1 {
				t.Errorf("%s: the document is %dpx wider than the %dpx viewport, so it "+
					"scrolls sideways on a phone. Widest offender: %s",
					c.name, c.page.OverflowPx, c.page.ClientWidth, c.who.String())
			}
			// The zoom-out. `width=device-width` plus content that does not fit
			// makes Chrome scale the whole page down until it does, so the
			// layout viewport ends up wider than the device. The user does not
			// see a scrollbar — they see every control on the page shrink.
			// Checked separately from overflow_px because it is a different
			// symptom with a different report, and because it is what makes
			// every later measurement in a broken run look healthy.
			if c.page.InnerWidth > c.page.ExpectedWidth+1 {
				t.Errorf("%s: the layout viewport is %dpx wide on a %dpx device — the "+
					"page overflowed and the browser zoomed the entire interface out to "+
					"make it fit, shrinking every control on screen",
					c.name, c.page.InnerWidth, c.page.ExpectedWidth)
			}
		}
	})

	t.Run("project cards stay inside the screen", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			cards overflowCards
		}{
			{fmt.Sprintf("%dpx", phoneWidth), got.Grid.Cards},
			{fmt.Sprintf("%dpx", narrowPhoneWidth), got.Narrow.Cards},
		} {
			if !c.cards.Present {
				t.Fatalf("%s: the project grid never rendered", c.name)
			}
			if c.cards.Count == 0 {
				t.Fatalf("%s: the grid holds no cards", c.name)
			}
			// The paused row carries its own fixed max-width, so a run where it
			// never rendered is not evidence that the width is right.
			if c.cards.PausedRows == 0 {
				t.Fatalf("%s: no .proj-pause row rendered, so the pause-reason width "+
					"is untested and a clean result here means nothing", c.name)
			}
			if c.cards.WorstOverflowPx > 1 {
				t.Errorf("%s: a project card reaches %dpx past the right edge of the "+
					"screen (widest is %q)", c.name, c.cards.WorstOverflowPx, c.cards.WorstName)
			}
			if c.cards.InnerOverflowPx > 1 {
				t.Errorf("%s: %s spills %dpx out of its own card — a fixed max-width "+
					"that does not fit inside a padded card at this viewport",
					c.name, c.cards.InnerWho, c.cards.InnerOverflowPx)
			}
		}
	})

	t.Run("the header dropdown is capped and scrolls", func(t *testing.T) {
		for _, c := range []struct {
			name string
			d    overflowDropdown
		}{
			{fmt.Sprintf("%dpx", phoneWidth), got.Open.Dropdown},
			{fmt.Sprintf("%dpx", narrowPhoneWidth), got.NarrowOpen.Dropdown},
		} {
			d := c.d
			if !d.Open {
				t.Fatalf("%s: clicking the selector did not open the dropdown; the rest "+
					"of this subtest is measuring a hidden element", c.name)
			}
			// The cap is the fix. Without one, 24 rows grow a ~840px panel that
			// starts below a sticky header, so its tail is off the bottom of an
			// 844px phone — and because the header is sticky, scrolling the page
			// takes the dropdown with it and the tail never arrives.
			if d.BelowFoldPx > 0 {
				t.Errorf("%s: the open dropdown ends %dpx below the fold (height %d, "+
					"viewport %d): it is not height-capped, and it hangs out of a "+
					"position:sticky header so no page scroll can bring the end of the "+
					"list into view", c.name, d.BelowFoldPx, d.Height, d.ViewportH)
			}
			// A cap alone would be worse than the bug: it would clip the tail
			// away with no way to see it. The panel has to scroll in its own
			// right. Only meaningful because the fixture is longer than any
			// sane cap — 24 rows against a cap measured in hundreds of pixels.
			if !d.Scrollable {
				t.Errorf("%s: the dropdown is not scrollable (overflow-y:%s, scrollHeight "+
					"%d, clientHeight %d) yet holds %d rows — capped without a scroll, "+
					"the projects past the cap are simply gone",
					c.name, d.OverflowY, d.ScrollHeight, d.ClientHeight, d.Items)
			}
			if d.RightOverflowPx > 1 {
				t.Errorf("%s: the dropdown reaches %dpx past the right edge of the %dpx "+
					"viewport; it is wider than the room left by the button it hangs from",
					c.name, d.RightOverflowPx, d.ViewportW)
			}
			if d.Left < -1 {
				t.Errorf("%s: the dropdown starts at x=%d, off the left edge of the "+
					"screen — it was pushed left to fit on the right and ran out the "+
					"other side", c.name, d.Left)
			}
		}
	})

	t.Run("every project in the list can be reached", func(t *testing.T) {
		// The point of the whole task: with a long list, can a finger actually
		// land on the last project? elementFromPoint is the browser's own hit
		// test, run after scrolling the pane to its end.
		for _, c := range []struct {
			name string
			item overflowLastItem
		}{
			{fmt.Sprintf("%dpx", phoneWidth), got.Open.LastItem},
			{fmt.Sprintf("%dpx", narrowPhoneWidth), got.NarrowOpen.LastItem},
		} {
			if !c.item.Reachable {
				t.Errorf("%s: the last project in the dropdown cannot be tapped (%s at "+
					"x=%d y=%d) — with %d projects the end of the list is off-screen "+
					"and nothing scrolls it into view",
					c.name, c.item.Why, c.item.X, c.item.Y, mobileProjectCount)
			}
		}
	})

	t.Run("desktop keeps the dropdown anchored to its button", func(t *testing.T) {
		// The mobile rules re-anchor the panel to the header and pin it to both
		// screen edges, using !important to beat an inline style. Nothing stops
		// a rule like that leaking upward except a test at a desktop width.
		d := got.Desktop.Dropdown
		if !d.Open {
			t.Fatal("the dropdown did not open at 1280px")
		}
		a := got.Desktop.Anchored
		if a == nil {
			t.Fatal("the driver could not locate the selector button at 1280px")
		}
		if a.Delta < -1 || a.Delta > 1 {
			t.Errorf("at 1280px the dropdown's left edge is %dpx from the button's "+
				"(button at %d, panel at %d): it should hang directly off the button, "+
				"so the mobile rule that re-anchors it to the header and spans the "+
				"screen has leaked above the 767px breakpoint",
				a.Delta, a.ButtonLeft, a.DropdownLeft)
		}
		// The cap is deliberately not mobile-only: 24 rows is ~840px, which
		// does not fit a 900px laptop window either.
		if d.BelowFoldPx > 0 {
			t.Errorf("at 1280x900 the dropdown still ends %dpx below the fold (height %d)",
				d.BelowFoldPx, d.Height)
		}
		if !d.Scrollable {
			t.Errorf("at 1280px the dropdown holds %d rows but does not scroll "+
				"(overflow-y:%s, scrollHeight %d, clientHeight %d)",
				d.Items, d.OverflowY, d.ScrollHeight, d.ClientHeight)
		}
		if !got.Desktop.LastItem.Reachable {
			t.Errorf("at 1280px the last project cannot be clicked (%s)", got.Desktop.LastItem.Why)
		}
		if d.RightOverflowPx > 1 {
			t.Errorf("at 1280px the dropdown itself reaches %dpx past the right edge",
				d.RightOverflowPx)
		}
	})

	t.Run("desktop does not scroll sideways", func(t *testing.T) {
		// The navigation strip is twenty-odd tabs, and was only made
		// scrollable between 480px and 768px — so at every desktop width the
		// whole page scrolled sideways, by ~650px at 1280px (Task 20349).
		p := got.Desktop.Page
		if p.OverflowPx > 1 {
			t.Errorf("at %dpx the document is %dpx wider than the viewport, so the page "+
				"scrolls sideways", p.ClientWidth, p.OverflowPx)
		}
	})

	t.Run("desktop shows every tab without a scrollbar", func(t *testing.T) {
		// Task 20349 fixed the page overflow by letting the strip scroll inside
		// the header, which drew a scrollbar under the tabs at every desktop
		// width, the reporter's 1920px screen included (Task 20351). The strip
		// wraps instead: into a row per group when it does not fit on one.
		if len(got.TabStrip) == 0 {
			t.Fatal("the driver measured the tab strip at no desktop width")
		}
		for _, m := range got.TabStrip {
			s, p := m.Strip, m.Page
			if !s.Present || s.Tabs == 0 {
				t.Fatalf("at %dpx the driver found no #tabNav or no tabs in it, so nothing "+
					"here was measured", m.Width)
			}
			if p.OverflowPx > 1 {
				t.Errorf("at %dpx the document is %dpx wider than the viewport, so the page "+
					"scrolls sideways", m.Width, p.OverflowPx)
			}
			if s.Right > p.ClientWidth+1 {
				t.Errorf("at %dpx #tabNav ends at %dpx, past the %dpx viewport",
					m.Width, s.Right, p.ClientWidth)
			}
			if s.ScrollWidth > s.ClientWidth+1 || s.ScrollbarPx > 0 {
				t.Errorf("at %dpx #tabNav holds %dpx of tabs in %dpx and draws a %dpx "+
					"scrollbar: the strip overflows its own box instead of wrapping",
					m.Width, s.ScrollWidth, s.ClientWidth, s.ScrollbarPx)
			}
			if len(s.Hidden) > 0 {
				t.Errorf("at %dpx %d of %d tabs cannot be clicked where they are drawn: %s",
					m.Width, len(s.Hidden), s.Tabs, strings.Join(s.Hidden, ", "))
			}
			if len(s.Stranded) > 0 {
				t.Errorf("at %dpx the %s label ends one row of the strip while its tabs "+
					"start the next: the strip wraps mid-group rather than between groups",
					m.Width, strings.Join(s.Stranded, " and "))
			}
			if len(s.Below) > 0 {
				t.Errorf("at %dpx header controls sit level with or below the tab strip "+
					"(%s): the strip is no longer the header's last row, and the "+
					"header grows a row for them", m.Width, strings.Join(s.Below, ", "))
			}
		}
	})

	t.Run("the hidden-projects dialog fits too", func(t *testing.T) {
		// The roster is drawn in three places and this is the third. Its name
		// row is the only one with no truncation or wrapping of any kind, so a
		// fix applied to the grid alone would leave the same overflow one tab
		// away — which is how this class of bug has come back before.
		//
		// Since Task 20328 these rows live in a dialog rather than on the
		// Settings page, so the driver opens it before measuring.
		r := got.HiddenList.Rows
		if !r.Present {
			t.Fatal("there is no hidden-projects list node, so nothing here was measured")
		}
		if r.Count == 0 {
			t.Fatal("no hidden project rendered in the dialog, though the fleet has one " +
				"hidden; a clean result below would be vacuous")
		}
		if r.WorstOverflowPx > 1 {
			t.Errorf("at %dpx a hidden project's name overflows its own box by %dpx "+
				"(%q): the row squeezes the box to fit but the name has no break "+
				"opportunity, so the text runs straight out through the side",
				narrowPhoneWidth, r.WorstOverflowPx, r.WorstName)
		}
		// As with #tabNav on desktop, no document-width assertion here. The
		// Settings tab does overflow at 320px — by 116px — but the offender is
		// an unwrapped <code> block (the agent-enrolment snippet), measured
		// identically on the parent commit and nothing to do with the project
		// list. Fixing it belongs to whoever owns that panel.
	})

	t.Run("no project element is the widest thing on the page", func(t *testing.T) {
		// A targeted report for this task's own surface. The sweep above fails
		// on any overflow; this one says when the offender is a project row,
		// which is the difference between "this change regressed" and "some
		// other panel did".
		for _, c := range []struct {
			name string
			w    *overflowWidest
		}{
			{fmt.Sprintf("%dpx", phoneWidth), got.Grid.Widest},
			{fmt.Sprintf("%dpx", narrowPhoneWidth), got.Narrow.Widest},
		} {
			if c.w != nil && c.w.OverPx > 1 && strings.Contains(c.w.Cls, "proj-") {
				t.Errorf("at %s a project element is the widest thing on the page: %s",
					c.name, c.w.String())
			}
		}
	})
}
