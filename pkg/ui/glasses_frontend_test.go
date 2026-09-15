package ui

// The display-glasses page, driven as a live document (Task 20237).
//
// Every other gate on assets/glasses.html greps it as text, and text cannot
// express the two things that were actually broken: swiping sideways moved the
// selection once and then stuck, and the minute poll rebuilt the screen from
// scratch — throwing away the wearer's focus and scroll offset each time.
// Both are properties of a running tree, so these tests extract the page's
// inline script and run it in node against testdata/glassesdom.js, press the
// keys the glasses actually send, and read back where the cursor ended up.
//
// The device is the reason the fix looks the way it does: the glasses OS turns
// every band and temple gesture into an arrow-key or Enter keydown aimed at
// document.activeElement and provides no focus navigation of its own, so the
// page owns the cursor entirely.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// glassesScenarios returns every scenario's raw result.
//
// The whole file is driven once per test binary, not once per test. Each of
// these tests asks about a different scenario, but the harness has always run
// all of them — so a per-test invocation forked one node process per test to
// recompute an identical map, two dozen times over, in a package whose
// WebSocket timing tests already fail under load. Running it once is both
// cheaper and the only version where "scenario X threw" is reported once
// rather than by every test in the file.
//
// Safe to share: the run reads the shipped page and writes nothing a scenario
// can observe, so every caller was already getting a byte-identical map.
func glassesScenarios(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	r := glassesRunOnce()
	if r.skip != "" {
		t.Skip(r.skip)
	}
	if r.err != nil {
		t.Fatalf("%v", r.err)
	}
	return r.results
}

type glassesRunResult struct {
	results map[string]json.RawMessage
	skip    string
	err     error
}

var glassesRunOnce = sync.OnceValue(runGlassesScenarios)

func runGlassesScenarios() glassesRunResult {
	node, err := exec.LookPath("node")
	if err != nil {
		return glassesRunResult{skip: "node not installed; cannot drive the glasses page"}
	}

	m := glassesScriptRe.FindStringSubmatch(glassesPageSource())
	if m == nil {
		return glassesRunResult{err: errors.New("no inline <script> in glasses.html — the " +
			"extraction broke, or the page stopped being self-contained")}
	}

	// Not t.TempDir(): this run outlives any one test. The script is only
	// needed while node reads it, so the directory goes when node is done.
	dir, err := os.MkdirTemp("", "cloop-glasses-*")
	if err != nil {
		return glassesRunResult{err: fmt.Errorf("temp dir: %w", err)}
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "glasses.js")
	if err := os.WriteFile(path, []byte(m[1]), 0o644); err != nil {
		return glassesRunResult{err: fmt.Errorf("write script: %w", err)}
	}
	shim, err := filepath.Abs("testdata/glassesdom.js")
	if err != nil {
		return glassesRunResult{err: fmt.Errorf("resolve shim: %w", err)}
	}
	scenarios, err := filepath.Abs("testdata/glasses_scenarios.js")
	if err != nil {
		return glassesRunResult{err: fmt.Errorf("resolve scenarios: %w", err)}
	}

	cmd := exec.Command(node, scenarios, shim, path)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = string(ee.Stderr)
		}
		return glassesRunResult{err: fmt.Errorf("running the scenarios failed: %w\nstdout:\n%s\nstderr:\n%s",
			err, out, stderr)}
	}

	var results map[string]json.RawMessage
	if err := json.Unmarshal(out, &results); err != nil {
		return glassesRunResult{err: fmt.Errorf("scenario output is not JSON: %w\n%s", err, out)}
	}
	if len(results) == 0 {
		return glassesRunResult{err: errors.New("no scenarios ran — the harness is disabled, not passing")}
	}
	for name, raw := range results {
		var probe struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.Error != "" {
			return glassesRunResult{err: fmt.Errorf("scenario %s threw:\n%s", name, probe.Error)}
		}
	}
	return glassesRunResult{results: results}
}

var glassesScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

func glassesScenario(t *testing.T, results map[string]json.RawMessage, name string, into any) {
	t.Helper()
	raw, ok := results[name]
	if !ok {
		t.Fatalf("scenario %q did not run", name)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decoding %s: %v\n%s", name, err, raw)
	}
}

// TestGlassesSwipeWalksTheFocusRing is the reported bug. A sideways swipe has
// to advance the selection every time and wrap at the end — not land on the
// first control once and then sit there, which is what the engine's own
// fallback does with a single column of full-width rows: it looks for
// something beside the focused row and there is nothing beside it.
func TestGlassesSwipeWalksTheFocusRing(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var fwd struct {
		Start   string   `json:"start"`
		Stops   []string `json:"stops"`
		Painted []string `json:"painted"`
		Ring    []string `json:"ring"`
	}
	glassesScenario(t, results, "swipe_right_walks_the_ring", &fwd)

	// The selection has to be painted by the page, not left to :focus alone.
	// The ring is the only cursor this device has, and a runtime that declines
	// to focus a <button> would otherwise leave the wearer with none at all —
	// see TestGlassesCursorSurvivesAHostileFocusModel.
	if strings.Join(fwd.Painted, ",") != strings.Join(fwd.Stops, ",") {
		t.Errorf("the painted selection %v does not track the focused one %v; the wearer's ring "+
			"and the page's idea of the cursor have come apart", fwd.Painted, fwd.Stops)
	}

	if fwd.Start == "<body>" {
		t.Error("nothing has focus once the first screen has loaded — the wearer's first swipe " +
			"has no defined starting point, and a pinch has nothing to activate")
	}
	if len(fwd.Ring) < 3 {
		t.Fatalf("focus ring = %v, want the refresh control and one stop per project", fwd.Ring)
	}
	for i, stop := range fwd.Stops {
		prev := fwd.Start
		if i > 0 {
			prev = fwd.Stops[i-1]
		}
		if stop == prev {
			t.Fatalf("swipe %d left focus on %q: the selection is stuck.\nstart %q, stops %v",
				i+1, stop, fwd.Start, fwd.Stops)
		}
	}
	// Continuing to swipe one way must come back round: on a device whose only
	// correction is another swipe, a ring with an end is a trap.
	seen := map[string]int{}
	for _, s := range fwd.Stops {
		seen[s]++
	}
	if len(seen) != len(fwd.Ring) {
		t.Errorf("six swipes visited %d of %d controls (%v) — the ring does not wrap",
			len(seen), len(fwd.Ring), fwd.Stops)
	}

	var back struct {
		Before string   `json:"before"`
		Back   []string `json:"back"`
	}
	glassesScenario(t, results, "swipe_left_walks_back", &back)
	for i, stop := range back.Back {
		prev := back.Before
		if i > 0 {
			prev = back.Back[i-1]
		}
		if stop == prev {
			t.Fatalf("swipe-left %d stayed on %q — this is the exact reported failure: "+
				"left no longer moves to the previous element.\nfrom %q, stops %v",
				i+1, stop, back.Before, back.Back)
		}
	}
	// Forward then back must retrace, not wander off somewhere new.
	if back.Back[0] == back.Before {
		t.Errorf("left from %q went to %q", back.Before, back.Back[0])
	}

	var consumed struct {
		Right bool `json:"right"`
		Left  bool `json:"left"`
		Other bool `json:"other"`
	}
	glassesScenario(t, results, "arrow_keys_are_consumed", &consumed)
	if !consumed.Right || !consumed.Left {
		t.Errorf("a handled arrow key kept its default action (right=%v left=%v); the engine "+
			"then also acts on it and fights the selection this page just moved",
			consumed.Right, consumed.Left)
	}
	if consumed.Other {
		t.Error("a key the page does not handle was swallowed anyway — that suppresses whatever " +
			"the device would have done with it")
	}
}

// TestGlassesReadsEverySpellingOfAGesture is Task 20242, and the reason the
// previous fix was inert on the hardware while passing everywhere else.
//
// The tell was in the report: a sideways swipe scrolled the tasks page
// sideways. A handler that runs calls preventDefault, and a prevented arrow key
// cannot scroll — so the handler was never matching the events the device
// sends. The glasses are not a keyboard; they synthesise key events from band
// and captouch gestures, and an engine in that class may send the legacy
// 'Right' name, leave key as 'Unidentified' and fill only keyCode, or set code
// alone. Matching one spelling is matching none of them.
func TestGlassesReadsEverySpellingOfAGesture(t *testing.T) {
	t.Parallel()

	var got map[string]struct {
		Forward   []string `json:"forward"`
		Back      string   `json:"back"`
		Prevented bool     `json:"prevented"`
	}
	glassesScenario(t, glassesScenarios(t), "every_spelling_of_a_swipe_steers", &got)

	if len(got) < 4 {
		t.Fatalf("only %d spellings exercised; the point is that no single one is trusted", len(got))
	}
	modern, ok := got["modern"]
	if !ok {
		t.Fatal("the modern spelling was not exercised")
	}
	for name, run := range got {
		for i, stop := range run.Forward {
			prev := ""
			if i > 0 {
				prev = run.Forward[i-1]
			}
			if stop == "<none>" {
				t.Fatalf("%s: swipe %d selected nothing — this spelling is not recognised at all, "+
					"so the device's own handling runs instead and the page never steers", name, i+1)
			}
			if stop == prev {
				t.Fatalf("%s: swipe %d stayed on %q; the selection is stuck", name, i+1, stop)
			}
		}
		if !run.Prevented {
			t.Errorf("%s: the gesture kept its default action. On the tasks page that default is a "+
				"horizontal scroll, which is exactly what the wearer reported seeing", name)
		}
		if len(run.Forward) > 1 && run.Back != run.Forward[len(run.Forward)-2] {
			t.Errorf("%s: swiping back landed on %q, want %q — left must retrace right",
				name, run.Back, run.Forward[len(run.Forward)-2])
		}
		// Every spelling means the same gesture, so every spelling must walk the
		// same ring. A fallback that drifted would be worse than none.
		if strings.Join(run.Forward, ",") != strings.Join(modern.Forward, ",") {
			t.Errorf("%s walked %v but the modern spelling walked %v", name, run.Forward, modern.Forward)
		}
	}

	var typed struct {
		Before    string `json:"before"`
		After     string `json:"after"`
		Prevented bool   `json:"prevented"`
	}
	glassesScenario(t, glassesScenarios(t), "an_ordinary_key_is_left_alone", &typed)
	if typed.After != typed.Before || typed.Prevented {
		t.Errorf("a plain letter moved the cursor %q -> %q (prevented=%v); the keyCode fallback has "+
			"become a net that catches ordinary typing on the phone the glasses tether through",
			typed.Before, typed.After, typed.Prevented)
	}
}

// TestGlassesCursorSurvivesAHostileFocusModel covers the other way the previous
// fix could be inert on hardware it cannot be tested against: it read the
// selection back out of document.activeElement, so a runtime that will not
// focus a <button>, or that re-aims focus itself after every gesture, produced
// exactly the reported symptom — the first control selected once, then nothing,
// because every swipe found "no cursor" and restarted from the top of the ring.
//
// The page keeps the selection in a variable now and paints it itself, so both
// runtimes steer. focus() is still called; it is just no longer believed.
func TestGlassesCursorSurvivesAHostileFocusModel(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	for _, tc := range []struct{ scenario, runtime string }{
		{"cursor_survives_a_runtime_that_will_not_focus", "a runtime whose focus() does nothing"},
		{"cursor_survives_a_runtime_that_reclaims_focus", "a runtime that re-aims focus after every gesture"},
	} {
		var got struct {
			Stops []string `json:"stops"`
			Focus string   `json:"focus"`
			Title string   `json:"title"`
		}
		glassesScenario(t, results, tc.scenario, &got)

		for i, stop := range got.Stops {
			prev := "p:alpha"
			if i > 0 {
				prev = got.Stops[i-1]
			}
			if stop == prev || stop == "<none>" {
				t.Fatalf("under %s, swipe %d left the selection on %q — stops %v.\nThis is the "+
					"reported failure exactly: the first item selected once, then nothing.",
					tc.runtime, i+1, stop, got.Stops)
			}
		}
		// The proof that the page acted on its own cursor rather than on focus:
		// gamma is where the selection walked to, alpha is where the runtime's
		// focus was sitting.
		if got.Title != "gamma" {
			t.Errorf("under %s, a pinch opened %q; the wearer can only see the painted selection, "+
				"so that is what a pinch has to activate (focus was on %q)",
				tc.runtime, got.Title, got.Focus)
		}
	}
}

// TestGlassesGestureHandlerCannotBeSwallowed: the handler is a capture listener
// so nothing downstream can consume the gesture before the page sees it, and so
// defaultPrevented cannot already be set by the time it looks.
func TestGlassesGestureHandlerCannotBeSwallowed(t *testing.T) {
	t.Parallel()

	var got struct {
		Before string `json:"before"`
		After  string `json:"after"`
	}
	glassesScenario(t, glassesScenarios(t), "a_swallowed_event_still_steers", &got)

	if got.After == got.Before {
		t.Errorf("a listener on the focused row stopped the gesture reaching the page (cursor stayed "+
			"%q) — the handler is back in the bubble phase", got.Before)
	}
}

// TestGlassesSwipeAfterAScrollLandsOnScreen is the "after a vertical scroll"
// qualifier in the report, which is load-bearing. Up and down move the page and
// deliberately not the cursor, so after a scroll the two are in different
// places; the next sideways swipe must continue from what is in front of the
// wearer rather than drag the whole column back to a row they left behind.
func TestGlassesSwipeAfterAScrollLandsOnScreen(t *testing.T) {
	t.Parallel()

	var got struct {
		Start     string   `json:"start"`
		Landed    string   `json:"landed"`
		Visible   []string `json:"visible"`
		NaiveStep string   `json:"naiveStep"`
	}
	glassesScenario(t, glassesScenarios(t), "swipe_after_a_scroll_lands_on_screen", &got)

	if len(got.Visible) == 0 {
		t.Fatal("the scenario scrolled every control off screen; it no longer tests anything")
	}
	if got.Landed == got.Start {
		t.Errorf("the swipe did not move the cursor at all (still %q)", got.Start)
	}
	if !hasStop(got.Visible, got.Landed) {
		t.Errorf("after scrolling, a swipe put the cursor on %q, which is off screen. On screen: %v.\n"+
			"The wearer sees no ring move and the column jumps to a row they scrolled past.",
			got.Landed, got.Visible)
	}
	if got.Landed == got.NaiveStep {
		t.Errorf("the cursor stepped to %q, the row after the one the wearer scrolled away from, "+
			"rather than re-anchoring to what is on screen", got.NaiveStep)
	}
}

// TestGlassesHasNoHorizontalAxis is the second half of Task 20242: "swiping left
// and right now moves the horizontal scroll bar, which should not be there in
// the first place."
//
// It was there. Measured in Chromium at 600x600, the tasks page reported
// scrollWidth 586 against clientWidth 585, and 586 against 305 at the narrowest
// viewport tried — the same 586 every time, because the overflow is one
// unbreakable token, not a width. Task titles here carry paths and image refs
// (ghcr.io/blechschmidt/cloop-harness:latest) and Go identifiers
// (OrchestratorTaskTimeoutMinutesDefault); the project list, whose names are one
// short word, stayed clean, which is why the report names only the tasks page.
//
// A grep, because the node shim models no layout and CI has no browser. It
// checks the two declarations that make the axis impossible rather than that
// any particular page is currently narrow enough.
func TestGlassesHasNoHorizontalAxis(t *testing.T) {
	t.Parallel()

	src := glassesPageSource()

	if !regexp.MustCompile(`(?s)html,\s*body\s*\{[^}]*overflow-x:\s*hidden`).MatchString(src) {
		t.Error("glasses.html no longer refuses horizontal overflow on the root. One column of " +
			"full-width rows has nothing to the side of it, and a sideways gesture spent scrolling " +
			"is a gesture not spent moving the selection")
	}
	// The rule that stops the overflow existing, rather than only hiding it: a
	// clipped title is still unreadable.
	wrap := regexp.MustCompile(`(?s)\.row\s*\.name[^{]*\{[^}]*overflow-wrap:\s*anywhere`).MatchString(src) ||
		regexp.MustCompile(`(?s)\{[^}]*overflow-wrap:\s*anywhere[^}]*\}`).MatchString(src)
	if !wrap {
		t.Error("nothing breaks a long token in a task title any more; a path or an identifier with " +
			"no space in it is wider than the column at every viewport the device reports")
	}
	for _, sel := range []string{".row .name", ".row .meta", "#sub"} {
		if !strings.Contains(src, sel) {
			t.Errorf("the wrapping rule no longer names %s; that is where the overflowing text is", sel)
		}
	}
}

// TestGlassesVerticalSwipeStillScrolls guards the half of the gesture map the
// wearer explicitly asked to keep. Up and down are the reading axis: a long
// task result is scrolled, not tabbed through. They only become selection keys
// on a screen that fits, where they would otherwise do nothing at all.
func TestGlassesVerticalSwipeStillScrolls(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var scrolls struct {
		Before    string `json:"before"`
		After     string `json:"after"`
		Prevented bool   `json:"prevented"`
	}
	glassesScenario(t, results, "updown_scrolls_while_the_page_scrolls", &scrolls)
	if scrolls.Prevented {
		t.Error("ArrowDown was swallowed on a scrollable page: swiping down no longer scrolls, " +
			"which is the behaviour that already worked and was asked to stay")
	}
	if scrolls.After != scrolls.Before {
		t.Errorf("ArrowDown moved focus %q -> %q while the page could still scroll",
			scrolls.Before, scrolls.After)
	}

	var fits struct {
		Before string `json:"before"`
		After  string `json:"after"`
	}
	glassesScenario(t, results, "updown_moves_focus_when_nothing_scrolls", &fits)
	if fits.After == fits.Before {
		t.Errorf("on a screen with nothing to scroll, ArrowDown did nothing at all (focus stayed %q)",
			fits.Before)
	}
}

// TestGlassesPinchActivatesTheFocusedRow covers the other half of the input
// surface. A pinch arrives as Enter aimed at whatever holds focus; if that is
// the body — a cold start, or a screen that has just been rebuilt — it has to
// hand the cursor back rather than be dropped, because the wearer has no other
// key to press.
func TestGlassesPinchActivatesTheFocusedRow(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var open struct {
		Focused    string   `json:"focused"`
		Title      string   `json:"title"`
		Rows       []string `json:"rows"`
		FocusAfter string   `json:"focusAfter"`
	}
	glassesScenario(t, results, "pinch_activates_the_focused_row", &open)
	if open.Title != "alpha" {
		t.Errorf("after pinching the focused project the title is %q, want the project's name", open.Title)
	}
	if len(open.Rows) != 3 {
		t.Errorf("task list = %v, want the three tasks of the project that was activated", open.Rows)
	}
	if open.FocusAfter == "<body>" || open.FocusAfter == open.Focused {
		t.Errorf("focus after opening the project = %q; arriving on a new screen must leave the "+
			"cursor on its first row", open.FocusAfter)
	}

	var lost struct {
		After string `json:"after"`
	}
	glassesScenario(t, results, "pinch_recovers_a_lost_cursor", &lost)
	if lost.After == "<body>" {
		t.Error("a pinch with nothing focused was dropped; on a device with one button that is a " +
			"dead end the wearer cannot get out of")
	}
}

// TestGlassesRefreshIsSmooth is the second half of the task. The poll used to
// blank the list, print "Loading…" and rebuild every row from an HTML string,
// which reset both the scroll offset and the wearer's place in the list once a
// minute. Reconciling by key keeps the nodes, and keeping the nodes keeps both.
func TestGlassesRefreshIsSmooth(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var kept struct {
		FocusBefore string   `json:"focusBefore"`
		FocusAfter  string   `json:"focusAfter"`
		Reused      bool     `json:"reused"`
		Msg         string   `json:"msg"`
		Rows        []string `json:"rows"`
	}
	glassesScenario(t, results, "refresh_keeps_focus_and_nodes", &kept)
	if kept.FocusBefore == "<body>" {
		t.Fatal("the scenario never established focus; it is not testing anything")
	}
	if kept.FocusAfter != kept.FocusBefore {
		t.Errorf("the poll moved the cursor from %q to %q — a wearer reading the list loses "+
			"their place once a minute", kept.FocusBefore, kept.FocusAfter)
	}
	if !kept.Reused {
		t.Error("the refresh replaced every row node; nothing that hangs off a node survives that, " +
			"including focus and the scroll offset")
	}
	if kept.Msg != "" {
		t.Errorf("a background refresh printed %q — that is the view resetting, which is what the "+
			"task asked to stop", kept.Msg)
	}

	var watch struct {
		Seen []struct {
			Rows int    `json:"rows"`
			Msg  string `json:"msg"`
		} `json:"seen"`
	}
	glassesScenario(t, results, "refresh_never_blanks_the_list", &watch)
	if len(watch.Seen) == 0 {
		t.Fatal("no samples taken across the refresh")
	}
	for i, s := range watch.Seen {
		if s.Rows == 0 {
			t.Fatalf("the list was empty at sample %d of %d during a refresh", i+1, len(watch.Seen))
		}
		if strings.Contains(s.Msg, "Loading") {
			t.Fatalf("the page said %q at sample %d during a background refresh", s.Msg, i+1)
		}
	}
}

// TestGlassesFocusSurvivesItsRowLeaving covers the one case node reuse cannot:
// the focused row itself going away, because a task changed status out from
// under a filter or a project was hidden. Dropping to the top of the document
// is the worst available answer when the only correction is swiping all the
// way back down.
func TestGlassesFocusSurvivesItsRowLeaving(t *testing.T) {
	t.Parallel()

	var got struct {
		FocusBefore string   `json:"focusBefore"`
		FocusAfter  string   `json:"focusAfter"`
		Rows        []string `json:"rows"`
	}
	glassesScenario(t, glassesScenarios(t), "focus_survives_its_row_disappearing", &got)

	if got.FocusAfter == "<body>" {
		t.Fatalf("the focused row (%q) disappeared and took the cursor with it; rows now %v",
			got.FocusBefore, got.Rows)
	}
	if got.FocusAfter == got.FocusBefore {
		t.Fatalf("focus is still reported on %q, which is no longer in the list %v",
			got.FocusAfter, got.Rows)
	}
	// It should land where the missing row was, not at the top.
	if want := "p:gamma"; got.FocusAfter != want {
		t.Errorf("focus landed on %q, want %q — the row that took the vacated position",
			got.FocusAfter, want)
	}
}

// TestGlassesRefreshKeepsThePagedWindow: pressing More and then waiting a
// minute must not silently collapse the list back to one page. The refresh
// re-reads the window the wearer actually has open.
func TestGlassesRefreshKeepsThePagedWindow(t *testing.T) {
	t.Parallel()

	var got struct {
		AfterOpen     int `json:"afterOpen"`
		AfterMore     int `json:"afterMore"`
		AfterRefresh  int `json:"afterRefresh"`
		RequestsField []struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		} `json:"requests"`
	}
	glassesScenario(t, glassesScenarios(t), "refresh_keeps_the_paged_window", &got)

	if got.AfterOpen == 0 || got.AfterMore <= got.AfterOpen {
		t.Fatalf("More did not page forward: %d rows then %d", got.AfterOpen, got.AfterMore)
	}
	if got.AfterRefresh != got.AfterMore {
		t.Errorf("the poll collapsed the list from %d rows back to %d", got.AfterMore, got.AfterRefresh)
	}
	if n := len(got.RequestsField); n < 3 {
		t.Fatalf("expected open, more and refresh requests; got %d", n)
	}
	last := got.RequestsField[len(got.RequestsField)-1]
	if last.Offset != 0 || last.Limit < got.AfterMore {
		t.Errorf("the refresh asked for offset=%d limit=%d, which cannot restore the %d rows on screen",
			last.Offset, last.Limit, got.AfterMore)
	}
}

// TestGlassesRingSkipsHiddenControls: Back and More are display:none until they
// apply. A stop on the ring that the wearer cannot see is a swipe that appears
// to do nothing, which is indistinguishable from the bug this all started with.
func TestGlassesRingSkipsHiddenControls(t *testing.T) {
	t.Parallel()

	var got struct {
		OnProjects []string `json:"onProjects"`
		OnTasks    []string `json:"onTasks"`
	}
	glassesScenario(t, glassesScenarios(t), "hidden_controls_are_not_stops", &got)

	for _, hidden := range []string{"#back", "#more"} {
		for _, stop := range got.OnProjects {
			if stop == hidden {
				t.Errorf("%s is a stop on the first screen, where it is not displayed: %v",
					hidden, got.OnProjects)
			}
		}
	}
	if !hasStop(got.OnTasks, "#back") {
		t.Errorf("Back is not reachable by swiping on the task list (%v) — the only way out of "+
			"the screen is unreachable", got.OnTasks)
	}
	if !hasStop(got.OnTasks, "f:done") {
		t.Errorf("the status filters are not on the ring: %v", got.OnTasks)
	}
}

// TestGlassesFilterKeepsItsChip: activating a filter replaces every row, and
// the chip the wearer just pinched has to stay under the cursor so the next
// swipe continues from the filter strip.
func TestGlassesFilterKeepsItsChip(t *testing.T) {
	t.Parallel()

	var got struct {
		Reached      bool     `json:"reached"`
		FocusAfter   string   `json:"focusAfter"`
		PaintedAfter string   `json:"paintedAfter"`
		SameChipNode bool     `json:"sameChipNode"`
		Rows         []string `json:"rows"`
	}
	glassesScenario(t, glassesScenarios(t), "filter_keeps_the_chip_under_the_cursor", &got)

	if !got.Reached {
		t.Fatal("swiping never reached the Done chip: the filter strip cannot be driven by gesture " +
			"at all, which is the only way the wearer has to reach it")
	}
	if got.FocusAfter != "f:done" {
		t.Errorf("after pinching the Done filter the cursor is on %q, want the chip itself", got.FocusAfter)
	}
	// Activating a filter rewrites every chip's class attribute. That write goes
	// through setClass, which re-asserts the cursor marker for exactly this
	// reason — otherwise the selection would silently stop being drawn.
	if got.PaintedAfter != "f:done" {
		t.Errorf("the selection is painted on %q after the filter strip was repainted; rewriting a "+
			"class attribute scrubbed the cursor off the node the wearer is looking at", got.PaintedAfter)
	}
	if !got.SameChipNode {
		t.Error("the filter strip was rebuilt rather than patched, so the chip under the cursor " +
			"is a different node than the one that was activated")
	}
	for _, row := range got.Rows {
		if row == "t:1" {
			t.Errorf("the Done filter still lists a pending task: %v", got.Rows)
			break
		}
	}
}

// TestGlassesDetailRefreshesInPlace: a task detail is the screen most likely to
// be open while its content changes, and the one where a reset is most costly —
// the wearer is part way down a result that is still being written.
func TestGlassesDetailRefreshesInPlace(t *testing.T) {
	t.Parallel()

	var got struct {
		FocusBefore string `json:"focusBefore"`
		FocusAfter  string `json:"focusAfter"`
		Reused      bool   `json:"reused"`
		Sub         string `json:"sub"`
		Body        string `json:"body"`
	}
	glassesScenario(t, glassesScenarios(t), "detail_refreshes_in_place", &got)

	if !got.Reused {
		t.Error("the detail pane was rebuilt on refresh, dropping the scroll offset of a wearer " +
			"reading a result that is still growing")
	}
	if got.FocusAfter != got.FocusBefore {
		t.Errorf("the cursor moved from %q to %q across a detail refresh", got.FocusBefore, got.FocusAfter)
	}
	if !strings.Contains(got.Body, "shipped") || !strings.Contains(got.Sub, "done") {
		t.Errorf("the detail did not pick up the task finishing: sub=%q body=%q", got.Sub, got.Body)
	}
}

// TestGlassesDetailShowsExecutor: the wearable reports where a task ran, and a
// host run is distinguishable from a sandboxed one (Task 20244).
//
// The hub's claim is that it never spawns a harness on the host. The glasses
// are the surface with the least room to explain anything, so the host case has
// to carry its warning in the text as well as in the class — a wearer in
// daylight may not be able to rely on the colour.
func TestGlassesDetailShowsExecutor(t *testing.T) {
	t.Parallel()

	var got struct {
		Sandboxed          string `json:"sandboxed"`
		SandboxedHost      bool   `json:"sandboxedHost"`
		HostText           string `json:"hostText"`
		HostFlagged        bool   `json:"hostFlagged"`
		Reused             bool   `json:"reused"`
		UnattributedHidden bool   `json:"unattributedHidden"`
	}
	glassesScenario(t, glassesScenarios(t), "detail_shows_executor", &got)

	if !strings.Contains(got.Sandboxed, "docker-1") {
		t.Errorf("the detail pane does not name the executor: %q", got.Sandboxed)
	}
	if got.SandboxedHost {
		t.Error("a container-placed task was flagged as a host run — a false alarm " +
			"on the one signal the wearer is meant to act on")
	}
	if !strings.Contains(got.HostText, "HOST") {
		t.Errorf("a host run does not say so in the text: %q", got.HostText)
	}
	if !got.HostFlagged {
		t.Error("a host run carries no .host class, so it renders in the same " +
			"colour as every other block")
	}
	if !got.Reused {
		t.Error("adding the executor block turned the detail refresh back into a " +
			"rebuild, dropping the wearer's scroll offset")
	}
	if !got.UnattributedHidden {
		t.Error("a task with no attribution renders an empty Executor block — a " +
			"blank where the host warning would be reads as reassurance")
	}
}

// TestGlassesTitlesAreTextNotMarkup: rows are built as nodes now rather than
// concatenated into an HTML string, which retires the hand-rolled escaper every
// interpolated project and task title used to depend on.
func TestGlassesTitlesAreTextNotMarkup(t *testing.T) {
	t.Parallel()

	var got struct {
		Text  string `json:"text"`
		Nasty string `json:"nasty"`
		Nodes int    `json:"nodes"`
	}
	glassesScenario(t, glassesScenarios(t), "markup_in_a_title_stays_text", &got)

	if !strings.Contains(got.Text, got.Nasty) {
		t.Errorf("a project named %q rendered as %q — the name is being transformed on its way "+
			"to the screen", got.Nasty, got.Text)
	}
	if got.Nodes > 3 {
		t.Errorf("the row grew to %d children: markup in the name was parsed rather than shown", got.Nodes)
	}
	if strings.Contains(glassesPageSource(), ".innerHTML") {
		t.Error("glasses.html assigns innerHTML again; the page builds nodes so that no title " +
			"ever has to be escaped by hand")
	}
}

// TestGlassesShimTracksTheMarkup keeps the shim honest. It hand-builds the
// page's element tree, and a tree that has drifted from the document would let
// these tests pass against a page that no longer exists.
func TestGlassesShimTracksTheMarkup(t *testing.T) {
	t.Parallel()

	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`).FindAllStringSubmatch(glassesPageSource(), -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no ids found in glasses.html")
	}

	shim, err := os.ReadFile("testdata/glassesdom.js")
	if err != nil {
		t.Fatalf("read shim: %v", err)
	}
	modelled := map[string]bool{}
	for _, m := range regexp.MustCompile(`node\('[a-z]+', '([a-zA-Z0-9_-]+)'`).FindAllStringSubmatch(string(shim), -1) {
		modelled[m[1]] = true
	}

	for id := range declared {
		if !modelled[id] {
			t.Errorf("glasses.html declares #%s, which testdata/glassesdom.js does not model — "+
				"the scenarios are running against a different page than the one shipped", id)
		}
	}
	for id := range modelled {
		if !declared[id] {
			t.Errorf("the shim models #%s, which glasses.html no longer declares", id)
		}
	}
}

func hasStop(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ── adding a task (Task 20243) ──────────────────────────────────────────────

// TestGlassesAddButtonReachableWithoutAMicrophone is the reported gap: "on the
// Meta glasses' view, I don't see any button to add tasks."
//
// The device that filed it is the one that cannot record — Meta lists
// microphone, camera and text input as unsupported for Ray-Ban Display web
// apps — so before this the only add-a-task affordance hid itself there and
// left a line of grey text in its place. This drives the no-microphone runtime
// and asserts three things: the button is a stop in the focus ring, the screen
// behind it offers rows that can actually be pinched, and the cursor lands on
// one of them.
func TestGlassesAddButtonReachableWithoutAMicrophone(t *testing.T) {
	t.Parallel()

	var r struct {
		OnTasks []string `json:"onTasks"`
		Title   string   `json:"title"`
		Rows    []string `json:"rows"`
		RowText []string `json:"rowText"`
		Note    string   `json:"note"`
		Ring    []string `json:"ring"`
		Cursor  string   `json:"cursor"`
	}
	glassesScenario(t, glassesScenarios(t), "add_button_offered_without_a_microphone", &r)

	if !hasString(r.OnTasks, "#add") {
		t.Fatalf("no way to add a task on a device that cannot record: the task list's ring is %v.\n"+
			"The button has to be there whether or not a microphone exists — the rows behind it "+
			"do not need one.", r.OnTasks)
	}
	if r.Title != "Add task" {
		t.Errorf("pinching the button opened %q rather than the Add screen", r.Title)
	}
	if len(r.Rows) == 0 {
		t.Fatal("the Add screen offered nothing at all — a button leading to an empty screen is " +
			"worse than the missing button it replaced")
	}
	for _, row := range r.Rows {
		if !strings.HasPrefix(row, "q:") {
			t.Errorf("unexpected row %q on the Add screen; want only ready-made rows", row)
		}
	}
	if !hasString(r.Ring, r.Rows[0]) {
		t.Errorf("the first ready-made row is not reachable by swiping; ring = %v", r.Ring)
	}
	if r.Cursor != r.Rows[0] {
		t.Errorf("the cursor should open on the first row so one pinch does something useful; "+
			"it is on %q", r.Cursor)
	}
	if len(r.RowText) == 0 || strings.TrimSpace(r.RowText[0]) == "" {
		t.Errorf("a ready-made row rendered with no text: %v", r.RowText)
	}
	if !strings.Contains(strings.ToLower(r.Note), "phone") {
		t.Errorf("the Add screen still has to name the one way to say something new — opening the\n"+
			"same link on the paired phone. Got: %q", r.Note)
	}
}

// TestGlassesAddScreenLeadsWithSpeech: where a microphone exists it is the only
// way to add something the ready-made list does not already say, so it goes
// first and takes the cursor.
func TestGlassesAddScreenLeadsWithSpeech(t *testing.T) {
	t.Parallel()

	var r struct {
		Ring   []string `json:"ring"`
		Cursor string   `json:"cursor"`
		Note   string   `json:"note"`
		Rows   []string `json:"rows"`
	}
	glassesScenario(t, glassesScenarios(t), "add_screen_leads_with_speech_when_possible", &r)

	if !hasString(r.Ring, "#dictate") {
		t.Errorf("with a microphone, speech must be offered on the Add screen; ring = %v", r.Ring)
	}
	if r.Cursor != "#dictate" {
		t.Errorf("the cursor should open on speech when it works, not %q", r.Cursor)
	}
	if r.Note != "" {
		t.Errorf("a working microphone should need no explanation, got %q", r.Note)
	}
	if len(r.Rows) == 0 {
		t.Error("the ready-made rows should still be offered alongside speech — they are the " +
			"faster answer for the work they already name")
	}
}

// TestGlassesAddButtonTracksTheCredential: a read-only link must not draw the
// button at all. Every row behind it posts, and a control whose only outcome is
// a refusal is worse than no control on a display with no error console.
func TestGlassesAddButtonTracksTheCredential(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var ro struct {
		Ring []string `json:"ring"`
		Note string   `json:"note"`
	}
	glassesScenario(t, results, "add_button_absent_for_a_read_only_link", &ro)
	if hasString(ro.Ring, "#add") {
		t.Errorf("a read-only link was offered the Add button; ring = %v", ro.Ring)
	}
	if ro.Note != "" {
		t.Errorf("no explanation is warranted for a link that may not add anything, got %q", ro.Note)
	}

	// ...but a hub with no speech backend is a different case entirely: the
	// ready-made rows work there, so the button must survive.
	var noSpeech struct {
		OnTasks []string `json:"onTasks"`
		Ring    []string `json:"ring"`
		Note    string   `json:"note"`
		Rows    []string `json:"rows"`
	}
	glassesScenario(t, results, "add_button_survives_a_hub_with_no_speech", &noSpeech)
	if !hasString(noSpeech.OnTasks, "#add") {
		t.Errorf("a hub with no speech backend lost the Add button; ring = %v", noSpeech.OnTasks)
	}
	if hasString(noSpeech.Ring, "#dictate") {
		t.Errorf("speech offered against a hub that cannot transcribe; ring = %v", noSpeech.Ring)
	}
	if noSpeech.Note != "" {
		t.Errorf("the microphone note is about this device, not about the hub; got %q", noSpeech.Note)
	}
	if len(noSpeech.Rows) == 0 {
		t.Error("no ready-made rows offered, so the surviving button leads nowhere")
	}
}

// TestGlassesReadyMadeTaskRoundTrip drives the second way in end to end: pinch
// a row, confirm, one task posted — carrying the brief the row holds but never
// shows, which is what makes a one-pinch task more than a bare title.
func TestGlassesReadyMadeTaskRoundTrip(t *testing.T) {
	t.Parallel()

	var r struct {
		ConfirmRows     []string `json:"confirmRows"`
		Shown           string   `json:"shown"`
		CursorOnConfirm string   `json:"cursorOnConfirm"`
		Posted          []struct {
			URL  string `json:"url"`
			Body string `json:"body"`
		} `json:"posted"`
		View string `json:"view"`
	}
	glassesScenario(t, glassesScenarios(t), "add_ready_made_task_round_trip", &r)

	if !hasString(r.ConfirmRows, "act:confirm") || !hasString(r.ConfirmRows, "act:discard") {
		t.Fatalf("a ready-made row must go through the same confirmation a transcript does — "+
			"one stray pinch must not file work. Rows: %v", r.ConfirmRows)
	}
	if r.CursorOnConfirm != "act:confirm" {
		t.Errorf("the cursor should land on Add; it is on %q", r.CursorOnConfirm)
	}
	if !strings.Contains(r.Shown, "Fix the failure in task #2") {
		t.Errorf("the confirmation must show what is about to be created, got %q", r.Shown)
	}

	var created string
	var posts int
	for _, p := range r.Posted {
		if strings.HasSuffix(p.URL, "/tasks") {
			created = p.Body
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("want exactly one POST to /api/glasses/tasks, got %d: %+v", posts, r.Posted)
	}
	if !strings.Contains(created, "Fix the failure in task #2") {
		t.Errorf("the picked title did not reach the hub: %s", created)
	}
	if !strings.Contains(created, "description") || !strings.Contains(created, "recorded result") {
		t.Errorf("the row's brief must travel with it — a bare \"fix task 2\" invites the blind "+
			"re-run that produced the failure. Body: %s", created)
	}
}

// TestGlassesAddButtonWaitsForItsOwnProject is this dashboard's oldest bug
// class arriving on the wearable. Two ready-made rows name a failure by id, so
// a button offered before the newly-opened project's rows have landed would
// hand the wearer the *previous* project's repair job — and creating it would
// file work against the wrong plan under a title that names a task in another
// one.
func TestGlassesAddButtonWaitsForItsOwnProject(t *testing.T) {
	t.Parallel()

	type visit struct {
		During []string `json:"during"`
		Rows   []string `json:"rows"`
	}
	var r struct {
		Alpha visit `json:"alpha"`
		Beta  visit `json:"beta"`
	}
	glassesScenario(t, glassesScenarios(t), "add_button_waits_for_this_projects_rows", &r)

	for name, v := range map[string]visit{"first": r.Alpha, "second": r.Beta} {
		if hasString(v.During, "#add") {
			t.Errorf("on the %s project the Add button was offered before its rows arrived; "+
				"ring = %v", name, v.During)
		}
		if len(v.Rows) == 0 {
			t.Fatalf("the %s project's Add screen has no rows at all", name)
		}
	}
	if len(r.Beta.Rows) != 1 || !strings.Contains(r.Beta.Rows[0], "#9") {
		t.Errorf("the second project's Add screen is showing the first project's rows: %v",
			r.Beta.Rows)
	}
}

// TestGlassesAddScreenDoesNotPoll: the minute refresh rebuilds the list it is
// looking at, and on this screen that would move the cursor out from under a
// wearer part way through choosing.
func TestGlassesAddScreenDoesNotPoll(t *testing.T) {
	t.Parallel()

	var r struct {
		Before int      `json:"before"`
		After  int      `json:"after"`
		Rows   []string `json:"rows"`
		Cursor string   `json:"cursor"`
	}
	glassesScenario(t, glassesScenarios(t), "add_screen_does_not_poll", &r)

	if r.After != r.Before {
		t.Errorf("the Add screen issued %d request(s) on the minute tick; it should issue none",
			r.After-r.Before)
	}
	if len(r.Rows) == 0 {
		t.Error("the rows did not survive the tick")
	}
	if !strings.HasPrefix(r.Cursor, "q:") {
		t.Errorf("the cursor moved off the row the wearer had selected, onto %q", r.Cursor)
	}
}

// ── dictation (Task 20238) ──────────────────────────────────────────────────

// TestGlassesDictationOfferedOnlyWhenUsable covers the three ways the control
// must not appear, and the one way it must. The middle case is the device this
// page exists for: Meta's build guide lists camera, microphone and
// getUserMedia as unsupported for Ray-Ban Display web apps, so on the glasses
// themselves the page can never record and has to say so rather than put a
// dead stop in the focus ring.
func TestGlassesDictationOfferedOnlyWhenUsable(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	type view struct {
		Ring  []string `json:"ring"`
		Note  string   `json:"note"`
		Label string   `json:"label"`
	}

	var withMic view
	glassesScenario(t, results, "dictate_offered_when_a_microphone_exists", &withMic)
	if !hasString(withMic.Ring, "#dictate") {
		t.Errorf("with a microphone the dictate control must be reachable by swiping; ring = %v", withMic.Ring)
	}
	if withMic.Note != "" {
		t.Errorf("a working microphone should need no explanation, got %q", withMic.Note)
	}

	var noMic view
	glassesScenario(t, results, "dictate_explains_when_no_microphone", &noMic)
	if hasString(noMic.Ring, "#dictate") {
		t.Errorf("the glasses cannot record, so the control must not be a stop in the ring; ring = %v", noMic.Ring)
	}
	if !strings.Contains(strings.ToLower(noMic.Note), "phone") {
		t.Errorf("without a microphone the page must name the one thing that works — opening the\n"+
			"same link on the paired phone. Got: %q", noMic.Note)
	}

	// A control the credential cannot use, and a control the hub cannot serve,
	// are both worse than nothing on a 600x600 display.
	for _, name := range []string{
		"dictate_absent_for_a_read_only_link",
		"dictate_absent_when_hub_has_no_backend",
	} {
		var v view
		glassesScenario(t, results, name, &v)
		if hasString(v.Ring, "#dictate") {
			t.Errorf("%s: dictate control offered anyway; ring = %v", name, v.Ring)
		}
		if v.Note != "" {
			t.Errorf("%s: no explanation is warranted here, got %q", name, v.Note)
		}
	}
}

// TestGlassesDictationRoundTrip drives the whole circuit against the real page
// script: record, stop, confirm, create.
func TestGlassesDictationRoundTrip(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var r struct {
		Before         string   `json:"before"`
		Recording      string   `json:"recording"`
		ConfirmRows    []string `json:"confirmRows"`
		Heard          string   `json:"heard"`
		FocusOnConfirm string   `json:"focusOnConfirm"`
		MicReleased    int      `json:"micReleased"`
		Posted         []struct {
			URL  string `json:"url"`
			Body string `json:"body"`
		} `json:"posted"`
	}
	glassesScenario(t, results, "dictate_round_trip_creates_a_task", &r)

	if r.Before == r.Recording {
		t.Errorf("the control must change once recording starts — on a display with no other\n"+
			"feedback it is the only sign the pinch registered. Both read %q", r.Before)
	}
	if !strings.Contains(r.Heard, "add a retention policy") {
		t.Errorf("the transcript must be shown before it becomes a task; screen read %q", r.Heard)
	}
	if !hasString(r.ConfirmRows, "act:confirm") || !hasString(r.ConfirmRows, "act:discard") {
		t.Errorf("confirmation needs both an Add and a Discard row, got %v", r.ConfirmRows)
	}
	if r.FocusOnConfirm != "act:confirm" {
		t.Errorf("focus should land on Add — it is why the wearer spoke, and the transcript\n"+
			"above it is not focusable. Got %q", r.FocusOnConfirm)
	}
	if r.MicReleased == 0 {
		t.Error("the microphone track was never stopped: the recording indicator would stay lit " +
			"through the upload, which reads as 'this page is still listening'")
	}

	var transcribed, created string
	for _, p := range r.Posted {
		switch {
		case strings.HasSuffix(p.URL, "/transcribe"):
			transcribed = p.Body
		case strings.HasSuffix(p.URL, "/tasks"):
			created = p.Body
		}
	}
	if transcribed != "form" {
		t.Errorf("audio must be posted as multipart form data, got %q", transcribed)
	}
	if !strings.Contains(created, "add a retention policy") {
		t.Errorf("the confirmed transcript must reach POST /api/glasses/tasks, got %q", created)
	}
}

// TestGlassesDictationDiscardCreatesNothing is the other half of confirming:
// a rejected transcript must leave no trace, and must land the wearer back
// where they can immediately try again.
func TestGlassesDictationDiscardCreatesNothing(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var r struct {
		Title     string   `json:"title"`
		Rows      []string `json:"rows"`
		TaskPosts int      `json:"taskPosts"`
		Ring      []string `json:"ring"`
	}
	glassesScenario(t, results, "dictate_discard_returns_to_the_add_screen", &r)

	if r.TaskPosts != 0 {
		t.Errorf("discard created %d task(s) — it must create none", r.TaskPosts)
	}
	for _, row := range r.Rows {
		if strings.HasPrefix(row, "act:") {
			t.Errorf("still on the confirmation screen after discarding: rows = %v", r.Rows)
			break
		}
	}
	if r.Title != "Add task" {
		t.Errorf("discarding should return to the Add screen, where trying again is one pinch "+
			"away; landed on %q instead", r.Title)
	}
	if !hasString(r.Ring, "#dictate") {
		t.Errorf("after discarding, the wearer should be able to try again; ring = %v", r.Ring)
	}
}

// hasString is a local helper: the package already has a contains() over
// authz.Permission, and these assertions are over ring/row labels.
func hasString(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}

// TestGlassesDictationReleasesTheMicrophone covers the lifecycle bugs that are
// invisible to a grep and expensive in practice: a wearable whose microphone
// stays live after the wearer has moved on, and a recorder left behind a
// button that says it is idle.
func TestGlassesDictationReleasesTheMicrophone(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var away struct {
		MicReleased   int    `json:"micReleased"`
		RecorderState string `json:"recorderState"`
		Label         string `json:"label"`
		Uploads       int    `json:"uploads"`
	}
	glassesScenario(t, results, "dictate_navigating_away_releases_the_mic", &away)

	if away.MicReleased == 0 {
		t.Error("leaving the Add screen while recording left the microphone track live — the " +
			"phone's recording indicator stays lit for the rest of the session")
	}
	if away.RecorderState == "recording" {
		t.Error("the MediaRecorder is still running after navigating away")
	}
	if away.Uploads != 0 {
		t.Errorf("navigating away uploaded %d recording(s); abandoning must not transcribe", away.Uploads)
	}

	var dbl struct {
		Starts int    `json:"starts"`
		Label  string `json:"label"`
	}
	glassesScenario(t, results, "dictate_double_press_starts_one_recorder", &dbl)
	if dbl.Starts > 1 {
		t.Errorf("a double pinch called getUserMedia %d times: the first recorder is orphaned "+
			"with its microphone track unreachable", dbl.Starts)
	}
}

// TestGlassesDictationDropsAStaleTranscript is the bug class this dashboard has
// fixed eight times over, arriving in a new place: a response for a screen the
// wearer has already left must not repaint the one they are on.
func TestGlassesDictationDropsAStaleTranscript(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var r struct {
		View string   `json:"view"`
		Rows []string `json:"rows"`
	}
	glassesScenario(t, results, "dictate_stale_transcript_is_dropped", &r)

	if r.View == "Add this task?" {
		t.Error("a transcript that resolved after the wearer navigated back seized the screen")
	}
	for _, row := range r.Rows {
		if strings.HasPrefix(row, "act:") {
			t.Errorf("confirmation rows rendered onto a screen the wearer had left: %v", r.Rows)
			break
		}
	}
}

// TestGlassesDictationSurvivesThePoll: the page refreshes itself once a
// minute, and that refresh must not repaint a control the wearer is currently
// speaking into — losing the red Stop styling mid-sentence leaves no
// indication that the microphone is still open.
func TestGlassesDictationSurvivesThePoll(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var r struct {
		LabelBefore string `json:"labelBefore"`
		LabelAfter  string `json:"labelAfter"`
		RecBefore   bool   `json:"recBefore"`
		RecAfter    bool   `json:"recAfter"`
	}
	glassesScenario(t, results, "dictate_poll_does_not_disturb_recording", &r)

	if !r.RecBefore {
		t.Fatal("the control never entered the recording state — the scenario proves nothing")
	}
	if !r.RecAfter {
		t.Error("the minute poll cleared the recording styling while a recording was live")
	}
	if r.LabelBefore != r.LabelAfter {
		t.Errorf("the poll relabelled a live control: %q -> %q", r.LabelBefore, r.LabelAfter)
	}
}

// TestGlassesDictationRefusesSilence is a bug found by recording actual
// silence against the live endpoint, not by reading the code: Whisper answered
// a two-second empty clip with "Thank you." — and would have made that a task.
//
// The response carries nothing that distinguishes it. Measured against Groq's
// whisper-large-v3-turbo, no_speech_prob is 0.0000 for digital silence and for
// real speech alike, and avg_logprob differed by less than the gap between two
// real sentences. So the check has to be client-side, on the samples, before
// the upload happens at all.
func TestGlassesDictationRefusesSilence(t *testing.T) {
	t.Parallel()
	results := glassesScenarios(t)

	var quiet struct {
		Uploads int    `json:"uploads"`
		Msg     string `json:"msg"`
		Label   string `json:"label"`
	}
	glassesScenario(t, results, "dictate_silence_is_not_uploaded", &quiet)

	if quiet.Uploads != 0 {
		t.Errorf("a silent recording was uploaded (%d POSTs) — Whisper answers silence with a "+
			"stock phrase, so this becomes a task titled \"Thank you.\"", quiet.Uploads)
	}
	if quiet.Msg == "" {
		t.Error("nothing told the wearer why nothing happened")
	}

	// The guard must not simply block everything.
	var loud struct {
		Uploads int      `json:"uploads"`
		Rows    []string `json:"rows"`
	}
	glassesScenario(t, results, "dictate_sound_is_uploaded", &loud)
	if loud.Uploads == 0 {
		t.Error("audio containing sound was not uploaded — the silence guard is too aggressive")
	}
	if !hasString(loud.Rows, "act:confirm") {
		t.Errorf("a real recording did not reach the confirmation screen: %v", loud.Rows)
	}
}

// TestGlassesSidewaysTouchWalksTheRing is Task 20279 in the shim, so that CI —
// which has no browser — still fails if the touch recogniser is removed.
//
// Its companion in glasses_browser_test.go drives real Chromium and is the
// stronger gate: the synthesised click after a touch, touch-action and layout
// all belong to the browser. This one cannot see any of that. What it can see
// is the property the whole fix turns on — that a fingertip moving sideways
// steers the cursor at all — and that is worth having everywhere.
//
// The evidence for driving it this way rather than with press(): the one real
// Ray-Ban Display session on record contains a pinch delivered as Enter/13 and
// no key of any spelling for a swipe, not even an unrecognised one, which the
// handler logs. The device speaks touch.
func TestGlassesSidewaysTouchWalksTheRing(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var fwd struct {
		Start string   `json:"start"`
		Stops []string `json:"stops"`
		Back  []string `json:"back"`
		Ring  []string `json:"ring"`
	}
	glassesScenario(t, results, "sideways_touch_walks_the_ring", &fwd)

	if len(fwd.Ring) < 3 {
		t.Fatalf("focus ring = %v, want the refresh control and one stop per project", fwd.Ring)
	}
	if fwd.Start == "<none>" {
		t.Error("nothing is selected once the first screen has loaded; the wearer's first " +
			"swipe has no defined starting point")
	}
	for i, stop := range fwd.Stops {
		prev := fwd.Start
		if i > 0 {
			prev = fwd.Stops[i-1]
		}
		if stop == prev {
			t.Fatalf("touch swipe %d left the cursor on %q: the selection is stuck.\n"+
				"start %q, stops %v\nthis is the wearer's report — one gesture lands and "+
				"the next does nothing", i+1, stop, fwd.Start, fwd.Stops)
		}
	}
	// "Swiping left or right does not move to the previous element anymore" was
	// the other half of the report, so the reverse direction is its own check.
	for i, stop := range fwd.Back {
		prev := fwd.Stops[len(fwd.Stops)-1]
		if i > 0 {
			prev = fwd.Back[i-1]
		}
		if stop == prev {
			t.Errorf("swiping back %d left the cursor on %q: %v → %v",
				i+1, stop, fwd.Stops, fwd.Back)
		}
	}
}

// TestGlassesVerticalTouchIsLeftForReading holds the line the wearer drew
// themselves: "swiping up and down moves the scrollbar. That's good."
//
// The sideways recogniser must not claim the vertical axis on its way past. A
// fix that steered the cursor with every drag would break the one part of this
// page that was already working.
func TestGlassesVerticalTouchIsLeftForReading(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var v struct {
		Before    string `json:"before"`
		After     string `json:"after"`
		Prevented bool   `json:"prevented"`
	}
	glassesScenario(t, results, "vertical_touch_is_left_for_reading", &v)

	if v.After != v.Before {
		t.Errorf("a vertical drag moved the cursor %q → %q; that axis is for reading",
			v.Before, v.After)
	}
	if v.Prevented {
		t.Error("a vertical drag was consumed by the page, so it can no longer scroll — " +
			"the wearer asked to keep this gesture")
	}
}

// TestGlassesTapIsNotASwipe keeps the recogniser from eating a press.
//
// A fingertip never lands perfectly still, and the wearer's press of a control
// carries a few pixels of drift. Reading that as a swipe would move the cursor
// out from under the very control they were pressing.
func TestGlassesTapIsNotASwipe(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var tap struct {
		Before    string `json:"before"`
		After     string `json:"after"`
		Prevented bool   `json:"prevented"`
	}
	glassesScenario(t, results, "a_tap_is_not_a_swipe", &tap)

	if tap.After != tap.Before {
		t.Errorf("a few pixels of drift moved the cursor %q → %q: a press is being read "+
			"as a swipe", tap.Before, tap.After)
	}
	if tap.Prevented {
		t.Error("a tap was consumed by the gesture handler, so the control under the " +
			"wearer's finger never receives its click")
	}
}

// TestGlassesSidewaysTouchIsConsumed pins the suppression.
//
// A browser synthesises a click from a touch, and a swipe that happens to end
// over a row would otherwise open that row: the wearer asks for the next item
// and lands two screens away.
func TestGlassesSidewaysTouchIsConsumed(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var s struct {
		Prevented bool `json:"prevented"`
	}
	glassesScenario(t, results, "sideways_touch_is_consumed", &s)

	if !s.Prevented {
		t.Error("a sideways swipe was not consumed; the click the browser synthesises " +
			"from it will activate whatever the finger happened to stop over")
	}
}

// TestGlassesNavigationNeverLeavesTheRingUnanchored is the trail's own last
// entry, turned into an assertion.
//
// That session ends with `go → -1` on a ring of six: the wearer had opened a
// project, the view had switched, and for the whole of the fetch that followed
// the page offered six reachable controls and had selected none of them. The
// wearer loses the highlight — and because this device aims its key events at
// document.activeElement, the page also loses the only thing a gesture can be
// delivered to.
func TestGlassesNavigationNeverLeavesTheRingUnanchored(t *testing.T) {
	t.Parallel()

	results := glassesScenarios(t)

	var nav struct {
		Before string `json:"before"`
		During struct {
			Sel           string `json:"sel"`
			Focus         string `json:"focus"`
			Ring          int    `json:"ring"`
			AnchorScrolls int    `json:"anchorScrolls"`
		} `json:"during"`
		After string `json:"after"`
	}
	glassesScenario(t, results, "navigation_never_leaves_the_ring_unanchored", &nav)

	if nav.During.Ring == 0 {
		t.Fatalf("precondition: no controls on screen mid-navigation, so there is nothing "+
			"to anchor to: %+v", nav.During)
	}
	if nav.During.Sel == "<none>" {
		t.Errorf("the cursor was dropped while the view was loading: %d controls on screen, "+
			"none selected\nthis is the trail's `go → -1` on a ring of 6", nav.During.Ring)
	}
	if nav.During.Focus == "<body>" {
		t.Errorf("focus fell to the body while the view was loading (%d controls on screen)\n"+
			"on this device that is not cosmetic: key events are aimed at "+
			"document.activeElement, so an unfocused page has nowhere to receive the "+
			"next gesture", nav.During.Ring)
	}
	if nav.After == "<none>" {
		t.Error("the cursor was still missing once the task list had landed")
	}
	// The cure must not cost what Task 20237 bought. reanchor() runs on the
	// minute poll too, and it lands on Refresh, which is in the header: a
	// selection that scrolled would drag a wearer reading a long task result
	// back to the top once a minute.
	if nav.During.AnchorScrolls > 0 {
		t.Errorf("re-anchoring scrolled the page (%d scrollIntoView calls); this runs on the "+
			"minute poll, so it would yank the wearer's viewport to the header",
			nav.During.AnchorScrolls)
	}
}
