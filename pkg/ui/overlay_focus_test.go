package ui

// Structural gate for overlay focus containment (Task 20288).
//
// The behaviour itself — Tab cycling, the inert background, focus returning to
// the invoking element — is asserted in overlay_focus_browser_test.go, which
// drives real Chromium. None of it is observable in testdata/domshim.js: the
// shim models no layout, so it has no notion of what is focusable, and no key
// routing, so Tab does nothing.
//
// What *is* checkable cheaply, and is what this file does, is that every
// overlay on the page goes through the shared helper. That is the invariant
// that rots: a new dialog is added months from now, its author copies the
// nearest neighbour's `el.style.display = 'flex'`, and it ships with no focus
// containment at all — on a runner with no browser, where the gate above it
// skips. So these assertions have to hold without one.

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// overlayMechanics are the four show/hide mechanics 00-overlay.js implements.
// The page uses three of them because its CSS already did; the helper honours
// whichever a dialog declares rather than imposing a fourth.
var overlayMechanics = map[string]bool{
	"flex":          true,
	"block":         true,
	"class:open":    true,
	"class:visible": true,
}

// overlayRootRe matches an opening <div> tag. Overlays are all divs; if that
// ever stops being true the id/class test below still decides, and a non-div
// overlay would simply not be seen — so overlayLikeID is deliberately broad.
var overlayRootRe = regexp.MustCompile(`<div\b[^>]*>`)

var (
	attrIDRe        = regexp.MustCompile(`\bid="([^"]*)"`)
	attrClassRe     = regexp.MustCompile(`\bclass="([^"]*)"`)
	attrDataOverlay = regexp.MustCompile(`\bdata-overlay="([^"]*)"`)
)

// overlayLikeID reports whether an element's id or class names it as a dialog
// root. Both spellings the page uses are covered: an id ending in "overlay" in
// either case convention (`td-overlay`, `loginOverlay`) and a class token
// ending in "backdrop" (`modal-backdrop`, `voice-modal-backdrop`), which is how
// the four that have no -overlay id spell themselves.
//
// Deliberately a name test rather than a style test. A style test ("is it
// position:fixed with a dim background") would miss exactly the dialog that
// forgot the styling — which is a real case: .modal-backdrop had no CSS rule at
// all until this task added one.
func overlayLikeID(id, class string) bool {
	if l := strings.ToLower(id); strings.HasSuffix(l, "overlay") {
		return true
	}
	for _, tok := range strings.Fields(class) {
		if strings.HasSuffix(strings.ToLower(tok), "backdrop") {
			return true
		}
	}
	return false
}

// dashboardOverlays returns every overlay root declared in index.html, keyed by
// id, with its declared mechanic.
func dashboardOverlays(t *testing.T) map[string]string {
	t.Helper()
	html := loadAssets().page.contents
	out := map[string]string{}
	for _, tag := range overlayRootRe.FindAllString(html, -1) {
		id, class := "", ""
		if m := attrIDRe.FindStringSubmatch(tag); m != nil {
			id = m[1]
		}
		if m := attrClassRe.FindStringSubmatch(tag); m != nil {
			class = m[1]
		}
		if !overlayLikeID(id, class) {
			continue
		}
		if id == "" {
			t.Errorf("an overlay root has no id, so nothing can open or close it:\n  %s", tag)
			continue
		}
		mech := ""
		if m := attrDataOverlay.FindStringSubmatch(tag); m != nil {
			mech = m[1]
		}
		out[id] = mech
	}
	return out
}

// TestDashboard_OverlaysDeclareAMechanic is the half of the gate that catches a
// dialog added to the markup but never wired to the helper. Without the
// data-overlay attribute openOverlay() would fall back to display:flex, which
// is wrong for the seven that show themselves with a class and would leave them
// permanently invisible.
func TestDashboard_OverlaysDeclareAMechanic(t *testing.T) {
	overlays := dashboardOverlays(t)
	if len(overlays) < 20 {
		t.Fatalf("found only %d overlay roots in index.html; the dashboard has ~25, so the "+
			"detection above has drifted and this whole gate is now passing vacuously", len(overlays))
	}
	for _, id := range sortedKeys(overlays) {
		mech := overlays[id]
		if mech == "" {
			t.Errorf("overlay #%s has no data-overlay attribute.\n"+
				"  Every dialog declares how it shows itself so the shared helper in "+
				"assets/js/00-overlay.js can honour it. Add one of: flex, block, "+
				"class:open, class:visible — matching what this overlay's CSS already does.", id)
			continue
		}
		if !overlayMechanics[mech] {
			t.Errorf("overlay #%s declares data-overlay=%q, which 00-overlay.js does not implement.\n"+
				"  Known mechanics: %s", id, mech, strings.Join(sortedKeys(overlayMechanics), ", "))
		}
	}
}

// Direct-manipulation shapes. (a) is the chained form, (b) the variable form —
// `const ov = document.getElementById('x-overlay')` and then `ov.style.display`
// some lines later, which is how most of the page was written before this task.
var (
	overlayShowHideChained = `\.(style\.display\s*=|classList\.(add|remove|toggle)\s*\(\s*['"](open|visible)['"])`
	overlayVarAssignRe     = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*document\.getElementById\(\s*['"]([^'"]+)['"]\s*\)`)
	overlayNewFuncRe       = regexp.MustCompile(`^\s*(?:window\.[\w$]+\s*=\s*function|function\s+[\w$]+|[\w$]+\s*=\s*function)`)
)

// TestDashboard_OverlaysUseTheSharedHelper is the half that catches a dialog
// wired to the markup but still hand-rolling its own show/hide — the way every
// one of them was written before this task, and the way the next one will be
// written unless something fails.
//
// It is the reason the helper can promise anything at all: focus restoration
// works only if *every* path out of a dialog runs closeOverlay(), so a single
// `el.style.display = 'none'` left behind silently reopens the hole.
func TestDashboard_OverlaysUseTheSharedHelper(t *testing.T) {
	overlays := dashboardOverlays(t)

	// The helper itself is the one place allowed to touch these directly.
	const helper = "assets/js/00-overlay.js"
	inBundle := false
	for _, f := range bundleFiles {
		if f == helper {
			inBundle = true
		}
	}
	if !inBundle {
		t.Fatalf("%s is not in bundleFiles, so the shared helper is never served and "+
			"every openOverlay() call on the page is a ReferenceError", helper)
	}

	// Compiled once for all files rather than per line: the naive form is 25
	// overlays x ~14k lines of compiles and turns a structural gate into a
	// five-second one.
	chained := make(map[string]*regexp.Regexp, len(overlays))
	for id := range overlays {
		chained[id] = regexp.MustCompile(`getElementById\(\s*['"]` + regexp.QuoteMeta(id) + `['"]\s*\)` + overlayShowHideChained)
	}

	for _, file := range bundleFiles {
		if file == helper {
			continue
		}
		b, err := assetFS.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		lines := strings.Split(string(b), "\n")

		for i, line := range lines {
			// (a) the chained form: getElementById('x-overlay').style.display = ...
			for _, id := range sortedKeys(overlays) {
				if chained[id].MatchString(line) {
					t.Errorf("%s:%d shows or hides #%s directly:\n    %s\n%s",
						file, i+1, id, strings.TrimSpace(line), overlayHelperAdvice)
				}
			}

			// (b) the variable form, bounded to the enclosing function so a
			// reused name like `ov` in the next function over is not blamed.
			m := overlayVarAssignRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			varName, id := m[1], m[2]
			if _, isOverlay := overlays[id]; !isOverlay {
				continue
			}
			use := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + overlayShowHideChained)
			for j := i + 1; j < len(lines) && j < i+40; j++ {
				if overlayNewFuncRe.MatchString(lines[j]) {
					break // left the function the variable belongs to
				}
				if use.MatchString(lines[j]) {
					t.Errorf("%s:%d shows or hides #%s directly through %q (assigned at line %d):\n    %s\n%s",
						file, j+1, id, varName, i+1, strings.TrimSpace(lines[j]), overlayHelperAdvice)
				}
			}
		}
	}
}

const overlayHelperAdvice = "  Use openOverlay(id, {dismiss: closeFn, focus: sel}) and closeOverlay(id) from\n" +
	"  assets/js/00-overlay.js instead. They are what marks the page behind the dialog\n" +
	"  inert, cycles Tab inside it, and returns focus to whatever opened it — a direct\n" +
	"  style/class change does none of that, and a keyboard user ends up operating the\n" +
	"  controls underneath a dialog that is visually covering them (Task 20288)."

// TestDashboard_EscapeGoesThroughTheOverlayStack guards the third close path.
//
// A dialog has three ways out — its own button, a backdrop click, and Escape —
// and the first two already run the dialog's close function. Escape used to be
// a hand-written chain in 18-shortcuts.js that reached into six overlays by id
// and toggled their classes itself, which meant it both missed the other
// nineteen and, for the six it had, would skip any focus restoration added to
// their close functions. Routing it through dismissTopOverlay() is what makes
// the three paths one path.
func TestDashboard_EscapeGoesThroughTheOverlayStack(t *testing.T) {
	b, err := assetFS.ReadFile("assets/js/18-shortcuts.js")
	if err != nil {
		t.Fatalf("read shortcuts fragment: %v", err)
	}
	src := string(b)

	// Anchor on the document-level listener, not on the first Escape branch in
	// the file: the command palette's own input has one too, and it legitimately
	// calls closeCommandPalette() directly — it *is* that dialog's close path.
	// The branch this gate is about is the global one.
	lis := strings.Index(src, "\ndocument.addEventListener('keydown'")
	if lis < 0 {
		t.Fatal("no document-level keydown listener in 18-shortcuts.js; the global key handler " +
			"has moved and this gate no longer reads it")
	}
	global := braceBlockFrom(src, lis)
	esc := strings.Index(global, "e.key === 'Escape'")
	if esc < 0 {
		t.Fatal("the global keydown listener no longer has an Escape branch")
	}
	branch := braceBlockFrom(global, esc)
	if branch == "" {
		t.Fatal("could not find the body of the global Escape branch in 18-shortcuts.js")
	}

	if !strings.Contains(branch, "dismissTopOverlay()") {
		t.Errorf("the Escape branch does not call dismissTopOverlay().\n"+
			"  Escape must close the frontmost dialog through that dialog's own close\n"+
			"  function, so it cannot skip the focus restoration the button and backdrop\n"+
			"  paths get. Branch was:\n%s", branch)
	}
	// The specific regression: `document.querySelector('.voice-modal-backdrop').remove()`
	// deleted a static node, so the first Escape anywhere on the page destroyed
	// the voice modal for the life of the document.
	if strings.Contains(branch, ".remove()") {
		t.Errorf("the Escape branch removes a node from the DOM. Overlays are static markup " +
			"that is hidden, never destroyed — removing one makes the next open throw on a null.")
	}
}

// TestDashboard_OverlayHelperIsExported keeps the helper reachable. It is used
// from inline onclick attributes' close functions and from fragments that load
// long after it, so it has to be on window, not just in the IIFE.
func TestDashboard_OverlayHelperIsExported(t *testing.T) {
	b, err := assetFS.ReadFile("assets/js/00-overlay.js")
	if err != nil {
		t.Fatalf("read overlay helper: %v", err)
	}
	src := string(b)
	for _, fn := range []string{"openOverlay", "closeOverlay", "dismissTopOverlay", "isOverlayOpen", "topOverlay"} {
		if !strings.Contains(src, "window."+fn+" ") && !strings.Contains(src, "window."+fn+"=") {
			t.Errorf("00-overlay.js does not expose %s on window", fn)
		}
	}
}

// braceBlockFrom returns the { ... } block that starts at or after from,
// balanced. Bounding the Escape assertions to the branch itself matters: a
// fixed-size window runs past the branch into the rest of the key handler,
// where an unrelated classList.remove() would be read as the DOM-removal
// regression this gate exists to catch.
func braceBlockFrom(src string, from int) string {
	open := strings.Index(src[from:], "{")
	if open < 0 {
		return ""
	}
	open += from
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
