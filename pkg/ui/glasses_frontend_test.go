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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// glassesScenarios extracts the page's script, runs the scenarios in node and
// returns each one's raw result.
func glassesScenarios(t *testing.T) map[string]json.RawMessage {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the glasses page")
	}

	script := extractGlassesScript(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "glasses.js")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	shim, err := filepath.Abs("testdata/glassesdom.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/glasses_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}

	cmd := exec.Command(node, scenarios, shim, path)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}

	var results map[string]json.RawMessage
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	if len(results) == 0 {
		t.Fatal("no scenarios ran — the harness is disabled, not passing")
	}
	for name, raw := range results {
		var probe struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.Error != "" {
			t.Fatalf("scenario %s threw:\n%s", name, probe.Error)
		}
	}
	return results
}

var glassesScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

func extractGlassesScript(t *testing.T) string {
	t.Helper()
	m := glassesScriptRe.FindStringSubmatch(glassesPageSource())
	if m == nil {
		t.Fatal("no inline <script> in glasses.html — the extraction broke, or the page stopped being self-contained")
	}
	return m[1]
}

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
		Start string   `json:"start"`
		Stops []string `json:"stops"`
		Ring  []string `json:"ring"`
	}
	glassesScenario(t, results, "swipe_right_walks_the_ring", &fwd)

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
		FocusAfter   string   `json:"focusAfter"`
		SameChipNode bool     `json:"sameChipNode"`
		Rows         []string `json:"rows"`
	}
	glassesScenario(t, glassesScenarios(t), "filter_keeps_the_chip_under_the_cursor", &got)

	if got.FocusAfter != "f:done" {
		t.Errorf("after pinching the Done filter the cursor is on %q, want the chip itself", got.FocusAfter)
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
