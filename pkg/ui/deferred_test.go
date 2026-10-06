package ui

import (
	"regexp"
	"strings"
	"testing"
)

// TestDeferredScriptsAreOnDemand pins what makes a deferred script cost a
// first paint nothing (Task 20366): it is served at a content-addressed URL,
// named in a <meta> for the code that loads it, and fetched by nothing the
// browser loads unasked. And, because it runs outside the bundle's IIFE, it
// puts nothing on window but its entry point.
func TestDeferredScriptsAreOnDemand(t *testing.T) {
	set := loadAssets()
	if len(deferredScripts) == 0 || len(set.deferred) != len(deferredScripts) {
		t.Fatalf("%d deferred scripts declared, %d built", len(deferredScripts), len(set.deferred))
	}
	eager := map[string]bool{}
	for _, m := range assetRefRe.FindAllStringSubmatch(set.page.contents, -1) {
		eager[m[1]] = true
	}
	globalAssign := regexp.MustCompile(`window\.([A-Za-z_$][\w$]*)\s*=[^=]`)
	for _, d := range deferredScripts {
		stem := strings.TrimSuffix(d.token, ".js")
		meta := regexp.MustCompile(`<meta name="cloop-` + regexp.QuoteMeta(stem) + `-src" content="(/assets/` +
			regexp.QuoteMeta(stem) + `\.[0-9a-f]{16}\.js)">`).FindStringSubmatch(set.page.contents)
		if meta == nil {
			t.Errorf("%s: the page names no cloop-%s-src <meta>", d.token, stem)
			continue
		}
		url := meta[1]
		a := set.byPath[url]
		if a == nil {
			t.Errorf("%s: %s, which the <meta> names, is not served", d.token, url)
			continue
		}
		if eager[url] {
			t.Errorf("%s is referenced by a src or href, so every first paint fetches it", url)
		}
		if a.contents != set.deferred[d.token].served {
			t.Errorf("%s serves something other than the stripped %s", url, d.path)
		}
		var globals []string
		for _, m := range globalAssign.FindAllStringSubmatch(set.deferred[d.token].raw, -1) {
			globals = append(globals, m[1])
		}
		if len(globals) != 1 {
			t.Errorf("%s assigns %d names on window (%v), want exactly its entry point", d.path, len(globals), globals)
		}
		if !strings.HasPrefix(strings.TrimSpace(stripLeadingComments(set.deferred[d.token].raw)), "(function () {") {
			t.Errorf("%s is not wrapped in an IIFE, so its helpers would be globals", d.path)
		}
	}
}

// stripLeadingComments drops the //-comment header a fragment opens with.
func stripLeadingComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "//") {
			return strings.Join(lines[i:], "\n")
		}
	}
	return ""
}

// mountedFunctions returns the names a deferred script hands mountPanel — the
// keys of the object literal in its `h.mount({...}` call — or nil when it
// never calls it.
func mountedFunctions(src string) map[string]bool {
	m := regexp.MustCompile(`h\.mount\(\{([^}]*)\}`).FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	out := map[string]bool{}
	for _, f := range strings.Split(m[1], ",") {
		if i := strings.Index(f, ":"); i >= 0 {
			f = f[:i]
		}
		if f = strings.TrimSpace(f); f != "" {
			out[f] = true
		}
	}
	return out
}

// TestDeferredPanelsRouteEveryAction pins the wiring that replaced inline
// handlers in the markup Task 20386 moved into deferred scripts. A deferred
// script may put nothing on window, so its markup names its handlers in
// data-act, data-change, data-input, data-enter and data-dismiss, and
// mountPanel looks each name up among the functions the panel mounts. A name
// the panel does not mount is a control that throws on every press — the bug
// class of Tasks 20033 and 20065, moved somewhere the old gate cannot see.
func TestDeferredPanelsRouteEveryAction(t *testing.T) {
	set := loadAssets()
	exposed := extractWindowExposures(dashboardSource)
	routed := regexp.MustCompile(`data-(?:act|change|input|enter|dismiss)="([A-Za-z_$][\w$]*)"`)
	inline := regexp.MustCompile(`\bon(?:click|change|input|keydown|submit)="(?:if\(event\.target===this\))?([A-Za-z_$][\w$]*)`)
	mounting := 0
	for _, d := range deferredScripts {
		src := set.deferred[d.token].raw
		fns := mountedFunctions(src)
		if fns == nil {
			// The panels before Task 20386 (members.js, harness.js, …) draw
			// into markup the page already has and dispatch their own
			// controls; mountPanel does not route them.
			continue
		}
		names := routed.FindAllStringSubmatch(src, -1)
		mounting++
		for _, n := range names {
			if !fns[n[1]] {
				t.Errorf("%s: a control names %q, which its panel does not mount — pressing it throws", d.path, n[1])
			}
		}
		// What inline handlers the moved markup still has must reach a
		// function on window, like any inline handler on the page: the
		// panel's own functions are not there.
		for _, m := range inline.FindAllStringSubmatch(src, -1) {
			name := m[1]
			if name == "this" || name == "event" || name == "document" || name == "window" {
				continue
			}
			if _, ok := exposed[name]; !ok || fns[name] {
				t.Errorf("%s: an inline handler calls %q, which is not on window — use a data-act the "+
					"panel mounts instead", d.path, name)
			}
		}
	}
	if mounting < 7 {
		t.Fatalf("only %d deferred scripts mount markup; the seven of Task 20386 should, so this gate "+
			"has gone vacuous", mounting)
	}
}

// TestDeferredTabsAndShimsResolve checks the other two ends of the move. Every
// tab openDeferredTab loads is an empty panel in index.html — the markup
// arrives with its script — that the script mounts into; and every
// panelAct('<panel>', '<fn>') a bundled control calls names a deferred script
// that mounts that function.
func TestDeferredTabsAndShimsResolve(t *testing.T) {
	set := loadAssets()
	m := regexp.MustCompile(`const DEFERRED_TABS = \[([^\]]*)\]`).FindStringSubmatch(set.bundle)
	if m == nil {
		t.Fatal("01-overview.js no longer declares DEFERRED_TABS; this gate reads it")
	}
	tabs := regexp.MustCompile(`'([a-z-]+)'`).FindAllStringSubmatch(m[1], -1)
	if len(tabs) < 6 {
		t.Fatalf("DEFERRED_TABS names %d tabs, want the six of Task 20386", len(tabs))
	}
	for _, tb := range tabs {
		name := tb[1]
		d, ok := set.deferred[name+".js"]
		if !ok {
			t.Errorf("tab %s is deferred but no deferred script %s.js exists", name, name)
			continue
		}
		if !strings.Contains(set.renderedPage, `<div id="tab-`+name+`" class="tab-panel"></div>`) {
			t.Errorf("index.html's tab-%s panel is not empty: its markup belongs in %s.js, or first "+
				"paint carries it", name, name)
		}
		if !regexp.MustCompile(`h\.mount\(\{[^}]*\}, '` + regexp.QuoteMeta(name) + `'`).MatchString(d.raw) {
			t.Errorf("%s.js does not mount into tab-%s, so opening the tab shows nothing", name, name)
		}
		if fns := mountedFunctions(d.raw); !fns["open"] {
			t.Errorf("%s.js mounts no open(), which openDeferredTab runs on every visit", name)
		}
	}

	shims := regexp.MustCompile(`panelAct\(\\?'([a-z]+)\\?',\s*\\?'([A-Za-z_$][\w$]*)\\?'`)
	calls := shims.FindAllStringSubmatch(set.renderedPage+set.bundle+deferredSource(), -1)
	if len(calls) < 8 {
		t.Fatalf("found %d panelAct calls; the executor cards alone make seven, so this gate has gone vacuous",
			len(calls))
	}
	for _, c := range calls {
		d, ok := set.deferred[c[1]+".js"]
		if !ok {
			t.Errorf("panelAct('%s', '%s') names no deferred script", c[1], c[2])
			continue
		}
		if !mountedFunctions(d.raw)[c[2]] {
			t.Errorf("panelAct('%s', '%s'): %s.js does not mount %s, so the control does nothing",
				c[1], c[2], c[1], c[2])
		}
	}
}
