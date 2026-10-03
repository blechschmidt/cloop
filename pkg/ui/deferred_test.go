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
