package ui

// Tests for the stylesheet comment stripper (cssstrip.go).
//
// As with the script stripper, the property that matters is "nothing else
// changed". Beyond the hand-made traps below, the shipped sheet is parsed by
// Chrome both ways whenever a Chrome is installed, and the rules the browser
// ends up holding must be identical.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStripCSSComments_Cases(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"a comment on its own lines goes, its line breaks stay",
			"a { color: red; }\n/* one\n   two */\nb { color: blue; }\n",
			"a { color: red; }\n\n\nb { color: blue; }\n"},
		{"a comment after a declaration goes, the spacing before it stays",
			"a { height: 1vh;  /* fallback */\n}\n",
			"a { height: 1vh;  \n}\n"},
		{"at the very start and the very end",
			"/* head */a{}/* tail */",
			"a{}"},
		{"a comment between two tokens stays: deleting it would join them",
			"a/**/b { margin: 1px/**/2px; }\n",
			"a/**/b { margin: 1px/**/2px; }\n"},
		{"whitespace on one side is enough",
			"a /**/b { margin: 1px/**/ 2px; }\n",
			"a b { margin: 1px 2px; }\n"},
		{"comment-like text inside strings is content",
			"a::before { content: \"/* no */\"; } b::after { content: '*/ /*'; }\n/* gone */\n",
			"a::before { content: \"/* no */\"; } b::after { content: '*/ /*'; }\n\n"},
		{"an escaped quote does not end a string",
			"a::before { content: \"say \\\" /* still text */\"; }\n",
			"a::before { content: \"say \\\" /* still text */\"; }\n"},
		{"an unquoted url is an address, slashes and stars included",
			"a { background: url(/img/*x*/.png) /* gone */; }\n",
			"a { background: url(/img/*x*/.png) ; }\n"},
		{"url in any case, with space before the address",
			"a { b: URL(  /x/*y*/z ); }\n",
			"a { b: URL(  /x/*y*/z ); }\n"},
		{"a quoted url is a function with a string",
			"a { b: url( \"/*x*/\" ) /* gone */; }\n",
			"a { b: url( \"/*x*/\" ) ; }\n"},
		{"-url( and myurl( are ordinary functions",
			"a { b: -url( /* gone */ ); c: myurl( /* gone */ ); }\n",
			"a { b: -url(  ); c: myurl(  ); }\n"},
		{"inside at-rules and nesting",
			"@media (min-width: 1px) { /* gone */\n  a { b: c; } }\n",
			"@media (min-width: 1px) { \n  a { b: c; } }\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := stripCSSComments(c.in)
			if err != nil {
				t.Fatalf("stripCSSComments: %v", err)
			}
			if got != c.want {
				t.Errorf("got\n%q\nwant\n%q", got, c.want)
			}
			if strings.Count(got, "\n") != strings.Count(c.in, "\n") {
				t.Error("the line count changed; line N of the served sheet would not be line N of app.css")
			}
		})
	}
}

// TestStripCSSComments_Refuses covers what the stripper does not model: it
// must return its input unchanged, with an error, rather than guess.
func TestStripCSSComments_Refuses(t *testing.T) {
	cases := map[string]string{
		"unterminated comment":         "a {}\n/* open\n",
		"unterminated string":          "a::before { content: \"open }\n",
		"a string broken by a newline": "a::before { content: 'one\ntwo'; }\n/* x */\n",
		// An escape can spell url( or a quote, so the lexer would misread
		// what follows it.
		"an escape outside a string": ".a\\/b { c: d; }\n/* x */\n",
		"unterminated url":           "a { b: url(/x }\n",
		"a url holding a quote":      "a { b: url(/x'y) }\n/* x */\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := stripCSSComments(in)
			if err == nil {
				t.Fatalf("stripped %q without complaint to %q", in, got)
			}
			if !errors.Is(err, errCSSStrip) {
				t.Errorf("refusal %v is not errCSSStrip", err)
			}
			if got != in {
				t.Error("a refusal must return the input unchanged")
			}
		})
	}
}

// TestServedStylesheetIsStripped pins that the shipped sheet strips cleanly —
// that the stripper did not decline and ship the comments after all — and
// that app.css's comments all have the whitespace that lets them go.
func TestServedStylesheetIsStripped(t *testing.T) {
	a := loadAssets()
	want, err := stripCSSComments(a.css)
	if err != nil {
		t.Fatalf("app.css cannot be stripped, so it ships with its comments: %v", err)
	}
	if a.servedCSS != want {
		t.Fatal("the served stylesheet is not the stripped one")
	}
	if i := strings.Index(a.servedCSS, "/*"); i >= 0 {
		line := strings.Count(a.servedCSS[:i], "\n") + 1
		t.Errorf("a comment survives at line %d of the served sheet: it touches a token on both sides, "+
			"so it cannot be removed without changing how the line tokenizes — put a space beside it", line)
	}
	if strings.Count(a.servedCSS, "\n") != strings.Count(a.css, "\n") {
		t.Error("stripping changed the line count")
	}
	var served *staticAsset
	for url, asset := range a.byPath {
		if strings.HasPrefix(url, "/assets/app.") && strings.HasSuffix(url, ".css") {
			served = asset
		}
	}
	if served == nil || served.contents != a.servedCSS {
		t.Error("the app.css asset does not carry the stripped stylesheet")
	}
}

// TestStripCSSComments_MatchesChrome parses the shipped sheet with and without
// its comments in a real browser and requires the same rules either way. It
// skips without Chrome or node.
func TestStripCSSComments_MatchesChrome(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	a := loadAssets()
	dir := t.TempDir()
	rawPath, strippedPath := filepath.Join(dir, "raw.css"), filepath.Join(dir, "stripped.css")
	if err := os.WriteFile(rawPath, []byte(a.css), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strippedPath, []byte(a.servedCSS), 0o644); err != nil {
		t.Fatal(err)
	}
	// Bounded, like every browser driver here: a Chrome that stalls must not
	// hold the package until its timeout (Task 20340).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/cssstrip_oracle.js"),
		chrome, rawPath, strippedPath).Output()
	if err != nil {
		t.Fatalf("oracle: %v\n%s", err, out)
	}
	var res struct {
		Rules         int              `json:"rules"`
		StrippedRules int              `json:"stripped_rules"`
		Mismatches    []map[string]any `json:"mismatches"`
		CanaryCaught  bool             `json:"canary_caught"`
		UserAgent     string           `json:"user_agent"`
		Error         string           `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("oracle output: %v\n%s", err, out)
	}
	if res.Error != "" {
		t.Fatalf("oracle failed: %s", res.Error)
	}
	if !res.CanaryCaught {
		t.Fatal("the oracle reports `1px/**/2px` and `1px2px` as the same rules, so it cannot tell a " +
			"stripper that changed the sheet from one that did not")
	}
	if res.Rules < 100 {
		t.Fatalf("Chrome found only %d rules in app.css; the comparison would pass vacuously", res.Rules)
	}
	if res.Rules != res.StrippedRules || len(res.Mismatches) > 0 {
		t.Errorf("Chrome parses the stripped sheet differently: %d rules raw, %d stripped; first differences: %v",
			res.Rules, res.StrippedRules, res.Mismatches)
	}
	t.Logf("%d rules identical with and without comments (%s)", res.Rules, res.UserAgent)
}
