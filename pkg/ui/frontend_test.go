package ui

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// serverSource is the full Go source of pkg/ui/server.go, embedded at build
// time so the architectural tests can grep it without depending on the test
// process's working directory (other tests in the package call t.Chdir into
// temp dirs).
//
//go:embed server.go
var serverSource string

// The cloop dashboard is a single embedded HTML/CSS/JS string (`dashboardHTML`
// in pkg/ui/server.go). Frontend behaviour is therefore impossible to assert
// end-to-end from Go without a real browser, but the *structural* invariants
// that matter most (and that have regressed repeatedly — Tasks 163, 168,
// 20033, 20065) can be checked by parsing the embedded source:
//
//   1. The HTML is well-formed enough to load.
//   2. Every inline `onclick="fn(...)"` handler resolves to a function that
//      is reachable from the global scope. The dashboard wraps its entire
//      <script> body in an IIFE, so handlers defined with `function fn(...)`
//      inside that IIFE are NOT reachable from inline onclick attributes:
//      they must be declared as `window.fn = function ...` (or assigned
//      after the IIFE). This rule has been violated repeatedly (most
//      recently Task 20065) and silently breaks buttons.
//   3. No inline `onclick="..."` attribute interpolates `JSON.stringify(...)`
//      (Tasks 163, 20033). That bug ships unescaped double-quotes into an
//      attribute value and snaps HTML parsing.
//   4. Every `getElementById('foo')` references either a literal `id="foo"`
//      in the HTML or an ID that is created dynamically in JS via
//      `<el>.id = 'foo'`. A getElementById against a vanished ID is the
//      typical signature of a deleted-DOM-with-zombie-JS bug.
//   5. Every WebSocket type the backend broadcasts has a frontend case
//      handler — drift here means silent UX regressions.
//   6. Every /api/* URL referenced from the frontend is a registered route.

// extractOnclickHandlers returns the set of distinct identifier names that
// appear as the *first call* in an inline `onclick="..."` attribute.
//
// We only look at simple-call handlers (`onclick="fn(...)"`) — guard
// patterns like `onclick="if(event.target===this)closeFoo()"` are common
// for backdrop dismissals; the closeFoo() identifier is still extracted
// because `event.target` is the literal expression, but we don't try to
// chase nested calls. JS keywords (`if`, `event`, `document`, `location`,
// `window`, `return`) are filtered out.
func extractOnclickHandlers(html string) map[string]struct{} {
	re := regexp.MustCompile(`onclick="([a-zA-Z_$][a-zA-Z0-9_$]*)`)
	out := map[string]struct{}{}
	keywords := map[string]bool{
		"if": true, "for": true, "while": true, "return": true,
		"event": true, "document": true, "window": true, "location": true,
		"true": true, "false": true, "null": true, "undefined": true,
		"this": true, "void": true, "new": true,
	}
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		name := m[1]
		if keywords[name] {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// extractWindowExposures returns the set of identifiers assigned to
// `window.<name> = ...` — these are the functions reachable from inline
// `onclick=...` handlers because they live on the global object, escaping
// the IIFE that wraps the dashboard script.
func extractWindowExposures(js string) map[string]struct{} {
	re := regexp.MustCompile(`window\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(js, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// findIIFEBoundsForMainScript returns the [start, end) byte offsets of the
// main `(function() { 'use strict'; ... })();` wrapper inside dashboardHTML.
// Functions defined *inside* this range with bare `function fn(...)` syntax
// are NOT visible to inline onclick handlers; they must be exposed on
// `window.fn`.
//
// We find this by anchoring on the literal `'use strict';` marker the main
// IIFE opens with. The error-boundary IIFE that precedes it doesn't use
// `'use strict';` on its own line, so the anchor is unambiguous.
func findIIFEBoundsForMainScript(html string) (int, int, bool) {
	marker := "(function() {\n'use strict';"
	start := strings.Index(html, marker)
	if start < 0 {
		return 0, 0, false
	}
	i := start + len("(function() {\n")
	depth := 1
	for i < len(html) && depth > 0 {
		c := html[i]
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				if i+3 < len(html) && html[i:i+4] == "})()" {
					return start, i + 4, true
				}
				return start, i + 1, true
			}
		}
		i++
	}
	return start, i, depth == 0
}

// TestDashboard_BasicWellFormedness sanity-checks the embedded dashboard
// HTML — DOCTYPE, balanced top-level tags, and the major panel containers
// that the JS unconditionally pokes into.
func TestDashboard_BasicWellFormedness(t *testing.T) {
	if !strings.HasPrefix(dashboardHTML, "<!DOCTYPE html>") {
		t.Fatal("dashboard must start with <!DOCTYPE html>")
	}
	pairs := []struct{ open, close string }{
		{"<html", "</html>"},
		{"<head>", "</head>"},
		{"<body>", "</body>"},
	}
	for _, p := range pairs {
		o := strings.Count(dashboardHTML, p.open)
		c := strings.Count(dashboardHTML, p.close)
		if o != c {
			t.Errorf("unbalanced %s/%s: open=%d close=%d", p.open, p.close, o, c)
		}
	}
	openScript := strings.Count(dashboardHTML, "<script")
	closeScript := strings.Count(dashboardHTML, "</script>")
	if openScript != closeScript {
		t.Errorf("unbalanced <script> tags: open=%d close=%d", openScript, closeScript)
	}
	requiredIDs := []string{
		"tab-overview", "tab-tasks", "tab-kanban", "tab-replay",
		"tab-provider-calls", "tab-analytics", "tab-deps",
	}
	for _, id := range requiredIDs {
		if !strings.Contains(dashboardHTML, `id="`+id+`"`) {
			t.Errorf("dashboard missing required tab id=%q", id)
		}
	}
}

// TestDashboard_OnclickHandlers_AllReachable enforces the architectural
// invariant that every inline `onclick="fn(...)"` resolves to a function
// reachable from the global scope. With the main script body wrapped in an
// IIFE, this means the function must either:
//   - be assigned to `window.fn = ...`, or
//   - live in a top-level <script> outside the IIFE (rare).
//
// Bare `function fn() {}` *inside* the IIFE is unreachable from inline
// `onclick=` and silently breaks the button. Catches regressions like
// Tasks 20033 and 20065.
func TestDashboard_OnclickHandlers_AllReachable(t *testing.T) {
	handlers := extractOnclickHandlers(dashboardHTML)
	exposed := extractWindowExposures(dashboardHTML)

	legitGlobals := map[string]bool{
		"alert": true,
	}

	var missing []string
	for name := range handlers {
		if _, ok := exposed[name]; ok {
			continue
		}
		if legitGlobals[name] {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("inline onclick handlers reference functions not exposed on "+
			"window (will throw ReferenceError when clicked because the main "+
			"<script> is wrapped in an IIFE):\n  %s\n"+
			"Fix: declare them as `window.%s = function() { ... }` instead of "+
			"bare `function %s(...)`.", strings.Join(missing, "\n  "),
			missing[0], missing[0])
	}
}

// TestDashboard_NoJSONStringifyInQuotedOnclick is a grep-level guard against
// the recurring "JSON.stringify inside a double-quoted HTML attribute" bug
// (Tasks 163, 20033). That pattern produces strings like
// `onclick="fn("hello")"` which the HTML parser truncates at the first `"`,
// silently destroying the handler.
//
// Allowed exception: `JSON.stringify(x).replace(/"/g,'&quot;')` — that
// pattern HTML-escapes the quotes after stringifying, which is safe because
// the browser decodes `&quot;` only after attribute boundaries are resolved.
//
// The recommended fix is to use `data-*` attributes plus `addEventListener`,
// or to pass a numeric index instead of a string.
func TestDashboard_NoJSONStringifyInQuotedOnclick(t *testing.T) {
	// Find each `onclick=` hit, then scan ahead in the raw source looking for
	// `JSON.stringify(` before any `>` (end of opening tag — though in a JS
	// string literal we may not see one for many chars). We can't rely on a
	// bounded character class because the safe form contains the literal
	// `"` inside `.replace(/"/g,'&quot;')`, which would prematurely terminate
	// any `[^"]` match.
	var bad []string
	idx := 0
	for {
		i := strings.Index(dashboardHTML[idx:], `onclick=`)
		if i < 0 {
			break
		}
		start := idx + i
		// Look at a 300-char window after the onclick=. Big enough to span
		// any reasonable inline handler.
		end := start + 300
		if end > len(dashboardHTML) {
			end = len(dashboardHTML)
		}
		window := dashboardHTML[start:end]
		idx = start + 1
		// Stop at the first `'` or `\\` that closes the JS string concat —
		// actually, since we live inside a Go string literal that builds
		// JS, attribute end markers are unreliable. Just check the window.
		if !strings.Contains(window, "JSON.stringify") {
			continue
		}
		if strings.Contains(window, "&quot;") {
			continue // HTML-escaped — safe
		}
		bad = append(bad, window)
	}
	if len(bad) > 0 {
		t.Errorf("found %d inline onclick attribute(s) calling JSON.stringify "+
			"without HTML-escaping the quotes — this snaps HTML parsing when "+
			"the result contains quotes. Use data-* attributes + addEventListener, "+
			"pass a numeric index and look up the string client-side, or follow "+
			"the JSON.stringify with .replace(/\"/g,'&quot;'). First match:\n%s",
			len(bad), bad[0])
	}
}

// TestDashboard_GetElementById_AllIDsExist verifies that every literal
// `getElementById('foo')` either matches an `id="foo"` somewhere in the
// HTML or is created dynamically via `<el>.id = 'foo'`. A ghost ID
// is a strong signal that a panel was removed but a JS reference was
// not — the kind of dead-code bug a UI test suite should catch.
func TestDashboard_GetElementById_AllIDsExist(t *testing.T) {
	gei := regexp.MustCompile(`getElementById\(['"]([a-zA-Z0-9_-]+)['"]\)`)
	idAttr := regexp.MustCompile(`\bid="([a-zA-Z0-9_-]+)"`)
	dynID := regexp.MustCompile(`\.id\s*=\s*['"]([a-zA-Z0-9_-]+)['"]`)

	defined := map[string]bool{}
	for _, m := range idAttr.FindAllStringSubmatch(dashboardHTML, -1) {
		defined[m[1]] = true
	}
	for _, m := range dynID.FindAllStringSubmatch(dashboardHTML, -1) {
		defined[m[1]] = true
	}

	missing := map[string]bool{}
	for _, m := range gei.FindAllStringSubmatch(dashboardHTML, -1) {
		if !defined[m[1]] {
			missing[m[1]] = true
		}
	}
	if len(missing) > 0 {
		ids := make([]string, 0, len(missing))
		for id := range missing {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("getElementById references %d ID(s) that are neither "+
			"declared via id=\"...\" in HTML nor created dynamically via "+
			"el.id=\"...\":\n  %s\nThe panel may have been removed but the "+
			"JS reference left behind.", len(ids), strings.Join(ids, "\n  "))
	}
}

// TestDashboard_SwitchTabExposedAndAllTargetsExist verifies the tab-switching
// contract holds: every `switchTab('name')` call has a matching `tab-name`
// panel in the HTML, and `switchTab` itself is reachable from inline
// onclick. A renamed tab without a corresponding panel rename produces a
// silent no-op when clicked.
func TestDashboard_SwitchTabExposedAndAllTargetsExist(t *testing.T) {
	if !strings.Contains(dashboardHTML, `window.switchTab = function`) {
		t.Fatal("window.switchTab is not assigned — inline tab clicks will throw")
	}
	re := regexp.MustCompile(`switchTab\(['"]([a-zA-Z0-9_-]+)['"]\)`)
	tabs := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(dashboardHTML, -1) {
		tabs[m[1]] = struct{}{}
	}
	for tab := range tabs {
		if !strings.Contains(dashboardHTML, `id="tab-`+tab+`"`) {
			t.Errorf("switchTab(%q) called but no <div id=\"tab-%s\"> exists "+
				"— tab click will appear as a no-op", tab, tab)
		}
	}
}

// TestDashboard_ServedAtRoot smoke-tests the actual HTTP path: GET / must
// 200 with the dashboard body. This catches handler-registration
// regressions that the static-string tests can't.
func TestDashboard_ServedAtRoot(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0, "")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html…", ct)
	}
}

// TestDashboard_MainIIFEHasUseStrict verifies the wrapper IIFE we rely on
// for the reachability test above still exists — if someone removes the
// IIFE (a reasonable future refactor!), the reachability test silently
// becomes a no-op because every `function fn()` becomes globally reachable.
// This pins the assumption explicitly so the architectural test stays
// load-bearing.
func TestDashboard_MainIIFEHasUseStrict(t *testing.T) {
	_, _, ok := findIIFEBoundsForMainScript(dashboardHTML)
	if !ok {
		t.Fatalf("main script IIFE (anchored on `'use strict';`) not found — " +
			"if you intentionally removed the IIFE wrapper, delete this test " +
			"AND the reachability test, since both rely on the IIFE invariant.")
	}
}

// readServerSource returns the embedded pkg/ui/server.go source so tests can
// grep the Go side (the wsMessage{Type:…} broadcaster sites and
// mux.HandleFunc routes) alongside the embedded dashboardHTML.
func readServerSource(t *testing.T) string {
	t.Helper()
	if serverSource == "" {
		t.Fatal("server.go embed is empty — build configuration may have changed")
	}
	return serverSource
}

// extractWSBroadcastTypes returns every literal string used in the source as
// `wsMessage{Type: "<name>", ...}`. Those are the types the backend pushes to
// connected clients (over both WebSocket and SSE).
func extractWSBroadcastTypes(src string) map[string]struct{} {
	re := regexp.MustCompile(`wsMessage\{\s*Type:\s*"([a-zA-Z0-9_]+)"`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// extractRealtimeCaseHandlers returns every `case '<name>':` label found in
// the source. We rely on the convention that realtime types are lowercase
// snake_case and never include digits, which distinguishes them from the
// status-color switches (`'done'`, `'in_progress'`, …) that also share the
// file. Status-only labels are filtered via a denylist in the caller.
func extractRealtimeCaseHandlers(src string) map[string]struct{} {
	re := regexp.MustCompile(`case '([a-z_]+)':`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// TestDashboard_WSBroadcastTypesHandled enforces that every WebSocket event
// type the backend broadcasts is handled by the frontend's realtime switch.
// Drift here means real-time UX silently regresses — a new server-side event
// is published, every client receives it, and the switch falls through with
// no action. Caught the missing `task_stuck` handler on first run.
func TestDashboard_WSBroadcastTypesHandled(t *testing.T) {
	src := readServerSource(t)
	broadcast := extractWSBroadcastTypes(src)
	handled := extractRealtimeCaseHandlers(src)

	// Status strings and other case-labels that aren't realtime event types.
	// These appear in render() helpers (status colors, label maps, format
	// switches) and would never be valid realtime types.
	denylist := map[string]bool{
		"done": true, "in_progress": true, "failed": true, "skipped": true,
		"timed_out": true, "pending": true,
		"pass":      true, "warn": true, "fail": true,
		"feature": true, "bug": true, "refactor": true, "doc": true, "infra": true,
		"low":      true, "medium": true, "high": true,
		"ticket": true, "pr": true, "issue": true, "other": true,
	}
	filteredHandled := map[string]struct{}{}
	for k := range handled {
		if !denylist[k] {
			filteredHandled[k] = struct{}{}
		}
	}

	var missing []string
	for k := range broadcast {
		if _, ok := filteredHandled[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("backend broadcasts WebSocket types that the frontend does not "+
			"handle in handleRealtimeMsg — events are silently dropped:\n  %s\n"+
			"Add a `case '%s':` branch to handleRealtimeMsg in pkg/ui/server.go.",
			strings.Join(missing, "\n  "), missing[0])
	}
}

// extractRegisteredRoutes returns every URL literal passed to mux.HandleFunc.
// Method prefixes ("GET ", "POST ", ...) are stripped so the returned set
// contains canonical paths like "/api/tasks" or "/api/tasks/{id}".
func extractRegisteredRoutes(src string) map[string]struct{} {
	re := regexp.MustCompile(`mux\.HandleFunc\("(?:[A-Z]+\s+)?(/[^"]+)"`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// extractFrontendAPICalls returns the set of `/api/...` URL paths the frontend
// JS references via api(), fetch(), pUrl(), new EventSource, or new
// WebSocket. Templated portions (`'/api/tasks/' + id`) are normalised to a
// `{id}` placeholder so they can be matched against the registered patterns.
func extractFrontendAPICalls(src string) map[string]struct{} {
	out := map[string]struct{}{}
	// Concatenation form first, so we can drop the bare literal afterwards:
	// '/api/tasks/' + id  → record "/api/tasks/{id}"  (and the prefix
	// '/api/tasks/' must be removed from the literal set below, since
	// it isn't actually a callable endpoint on its own).
	concatPrefixes := map[string]bool{}
	re2 := regexp.MustCompile(`['"](/api/[a-zA-Z0-9/_-]+/)['"]\s*\+`)
	for _, m := range re2.FindAllStringSubmatch(src, -1) {
		out[m[1]+"{id}"] = struct{}{}
		concatPrefixes[m[1]] = true
	}
	// Direct literal: "/api/foo" inside any string context.
	re := regexp.MustCompile(`['"](/api/[a-zA-Z0-9/_-]+)['"]`)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		if concatPrefixes[m[1]] {
			continue // already represented by the {id} form
		}
		out[m[1]] = struct{}{}
	}
	return out
}

// routeMatches returns true if `call` (e.g. "/api/tasks/{id}") is served by
// the registered route `route` (e.g. "/api/tasks/{id}"). Both can contain
// `{param}` placeholders.
func routeMatches(call, route string) bool {
	if call == route {
		return true
	}
	pat := regexp.QuoteMeta(route)
	pat = regexp.MustCompile(`\\\{[a-zA-Z0-9_]+\\\}`).ReplaceAllString(pat, `[^/]+`)
	// Also normalise the call so {id} inside it matches `[^/]+` in the route.
	callPat := regexp.QuoteMeta(call)
	callPat = regexp.MustCompile(`\\\{[a-zA-Z0-9_]+\\\}`).ReplaceAllString(callPat, `[^/]+`)
	// Two regexes are equivalent if they match each other's literal forms.
	if ok, _ := regexp.MatchString("^"+pat+"$", call); ok {
		return true
	}
	if ok, _ := regexp.MatchString("^"+callPat+"$", route); ok {
		return true
	}
	return false
}

// TestDashboard_APIEndpoints_AllRegistered verifies every `/api/...` URL the
// frontend hits is served by a registered route. A frontend call to a route
// that doesn't exist surfaces as a 404 only when the affected button is
// clicked — exactly the kind of silent rot a UI test suite should flag. The
// reverse direction (server routes never called) is intentionally NOT
// asserted: many endpoints are only invoked from optional flows or from
// sub-paths the regex can't catch.
func TestDashboard_APIEndpoints_AllRegistered(t *testing.T) {
	src := readServerSource(t)
	routes := extractRegisteredRoutes(src)
	calls := extractFrontendAPICalls(src)

	// Endpoints called as `'/api/foo/' + id + '/bar'` — these come out of
	// the extractor as "/api/foo/{id}" but the trailing segment is lost.
	// List them here so the test stays useful without making the call
	// extractor much more complex.
	knownDynamic := []string{
		"/api/tasks/{id}/blocker",
		"/api/tasks/{id}/details",
		"/api/replay-runs/{id}",
		"/api/provider-calls/{id}",
		"/api/provider-calls/{id}/replay",
		"/api/projects/{idx}/run",
		"/api/projects/{idx}/stop",
		"/api/kb/{id}",
	}
	for _, r := range knownDynamic {
		routes[r] = struct{}{}
	}
	// Endpoints called from non-JS surfaces (e.g. the SSE event stream
	// `/api/events`) that nonetheless appear as literals; nothing to do.

	var unmatched []string
	for c := range calls {
		// Skip URL fragments that aren't real endpoints (e.g. "/api/" alone).
		if c == "/api/" {
			continue
		}
		found := false
		for r := range routes {
			if routeMatches(c, r) {
				found = true
				break
			}
		}
		if !found {
			unmatched = append(unmatched, c)
		}
	}
	sort.Strings(unmatched)
	if len(unmatched) > 0 {
		t.Errorf("frontend references %d API endpoint(s) with no matching "+
			"mux.HandleFunc registration — clicks will surface as 404s:\n  %s",
			len(unmatched), strings.Join(unmatched, "\n  "))
	}
}

// TestDashboard_NoDuplicateTabIDs guards against accidental id clashes that
// snap getElementById and the tab-switching contract.
func TestDashboard_NoDuplicateTabIDs(t *testing.T) {
	re := regexp.MustCompile(`\bid="(tab-[a-zA-Z0-9_-]+)"`)
	seen := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(dashboardHTML, -1) {
		seen[m[1]]++
	}
	var dupes []string
	for id, n := range seen {
		if n > 1 {
			dupes = append(dupes, id)
		}
	}
	sort.Strings(dupes)
	if len(dupes) > 0 {
		t.Errorf("duplicate tab id(s) in dashboard HTML — switchTab will "+
			"surface only the first match:\n  %s", strings.Join(dupes, "\n  "))
	}
}

// TestDashboard_SingleMainIIFE verifies there is exactly one main IIFE
// wrapper (the one anchored on `'use strict';`). If a second one creeps in,
// the reachability test silently splits its coverage in half because each
// IIFE has its own scope.
func TestDashboard_SingleMainIIFE(t *testing.T) {
	count := strings.Count(dashboardHTML, "(function() {\n'use strict';")
	if count != 1 {
		t.Errorf("expected exactly one main `'use strict';` IIFE wrapper, found %d", count)
	}
}
