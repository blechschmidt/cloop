package ui

// Tests for the served bundle's comment stripper (jsstrip.go).
//
// The property that matters is not "comments are gone" but "nothing else
// changed": a template literal line mistaken for a comment would silently alter
// rendered markup and still parse. So beyond the table of hand-made traps, the
// shipped bundle itself is checked against acorn — a real parser — whenever one
// is available: the set of lines blanked must be exactly the set of whole-line
// comments acorn finds, and the token streams with and without them must be
// identical.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripJSLineComments_Cases(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"whole-line comments go, line breaks stay",
			"a();\n// one\n  // two\nb();\n",
			"a();\n\n\nb();\n"},
		{"a trailing comment stays",
			"a(); // keep\n",
			"a(); // keep\n"},
		{"comment-like text inside a multi-line template is content",
			"x = `\n// not a comment\n`;\n// gone\n",
			"x = `\n// not a comment\n`;\n\n"},
		{"inside a template expression the code is code, and nested templates nest",
			"x = `a ${ y({k: `\n// inner text\n`}) } b\n// outer text\n`;\n",
			"x = `a ${ y({k: `\n// inner text\n`}) } b\n// outer text\n`;\n"},
		{"a block comment hides // lines, and code after its close is code",
			"/* start\n// inside\n*/ a();\n// gone\n",
			"/* start\n// inside\n*/ a();\n\n"},
		{"strings holding slashes and backticks",
			"a('//', \"`\", '\\'');\n// gone\n",
			"a('//', \"`\", '\\'');\n\n"},
		{"a regex holding a backtick after an operator",
			"r = /`[^`]*`/g;\n// gone\n",
			"r = /`[^`]*`/g;\n\n"},
		{"a regex with a slash in a class",
			"r = /[/]x/;\n// gone\n",
			"r = /[/]x/;\n\n"},
		{"division after a value and a call",
			"x = (a + b) / 2 / c;\n// gone\n",
			"x = (a + b) / 2 / c;\n\n"},
		{"keyword-led regex",
			"return /`/.test(s);\n// gone\n",
			"return /`/.test(s);\n\n"},
		{"CRLF line endings are kept",
			"a();\r\n// gone\r\nb();\r\n",
			"a();\r\n\r\nb();\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := stripJSLineComments(c.in)
			if err != nil {
				t.Fatalf("stripJSLineComments: %v", err)
			}
			if got != c.want {
				t.Errorf("got\n%q\nwant\n%q", got, c.want)
			}
			if strings.Count(got, "\n") != strings.Count(c.in, "\n") {
				t.Error("the line count changed; browser stack traces would point at the wrong lines")
			}
		})
	}
}

// TestStripJSLineComments_Refuses covers the cases where the stripper must not
// guess, and so returns its input unchanged with an error.
func TestStripJSLineComments_Refuses(t *testing.T) {
	cases := map[string]string{
		// After `)` a slash is usually division, but `if (x) /re/` is a regex;
		// here the two readings disagree about whether a template opens.
		"ambiguous slash that decides a template": "if (x) /`/.test(y); z = `\n// ?\n`;\n",
		// A reading that only fails because of a *later* guess must not make
		// the first guess look safe: both slashes are regexes here, and read
		// as division the first one opens a template.
		"two slashes, one template": "if (ok) /`/.test(s); if (ok) /'/.test(t);\nx = `\n// ?\n`;\n",
		// `of` is an identifier here; no keyword list can settle it.
		"a variable named like a keyword":       "of / 2 + `/`\n// ?\n`;\n",
		"unterminated string":                   "a = 'oops\n// x\n",
		"line continuation in a string":         "a = 'one \\\ntwo';\n// x\n",
		"unterminated template at end of input": "a = `open\n// x\n",
		"unterminated block comment":            "/* open\n// x\n",
		"unterminated regex":                    "a = /oops\n// x\n",
		// Each of these ends a comment in JavaScript but not a line here.
		"a lone carriage return": "a();\n// one\rb();\n",
		"U+2028":                 "a();\n// one\u2028b();\n",
		"an HTML-like comment":   "a();\nx = y <!-- z\n// gone?\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := stripJSLineComments(in)
			if err == nil {
				t.Fatalf("stripped %q without complaint to %q", in, got)
			}
			if got != in {
				t.Error("a refusal must return the input unchanged")
			}
		})
	}
	// The same ambiguous slash with nothing riding on it is fine.
	if _, err := stripJSLineComments("if (x) y = a / b;\n// gone\n"); err != nil {
		t.Errorf("an ambiguity that changes nothing was refused: %v", err)
	}
	for _, name := range []string{"ambiguous slash that decides a template", "two slashes, one template", "a variable named like a keyword"} {
		if _, err := stripJSLineComments(cases[name]); !errors.Is(err, errJSAmbiguous) {
			t.Errorf("%s: refusal %v is not errJSAmbiguous", name, err)
		}
	}
	// A no-break space after `return` makes the word unreadable as a
	// keyword; the slash after it is explored both ways, and here both agree.
	if _, err := stripJSLineComments("return\u00a0/x/.test(s);\n// gone\n"); err != nil {
		t.Errorf("an agreeing ambiguity was refused: %v", err)
	}
	// Harmless ambiguity on many slashes stays cheap and accepted.
	many := strings.Repeat("x = (a) / (b) / (c) / d; ", 40) + "\n// gone\n"
	if out, err := stripJSLineComments(many); err != nil || strings.Contains(out, "gone") {
		t.Errorf("a line of many divisions after parentheses: %v", err)
	}
}

// TestServedBundleIsStripped pins that the shipped bundle strips cleanly —
// that the stripper did not decline and ship the comments after all.
func TestServedBundleIsStripped(t *testing.T) {
	a := loadAssets()
	want, err := stripJSLineComments(a.bundle)
	if err != nil {
		t.Fatalf("the dashboard bundle cannot be stripped, so it ships with its comments: %v", err)
	}
	if a.served != want {
		t.Fatal("the served bundle is not the stripped one")
	}
	if strings.Count(a.served, "\n") != strings.Count(a.bundle, "\n") {
		t.Error("stripping changed the line count")
	}
	if len(a.served) > len(a.bundle)*3/4 {
		t.Errorf("stripping saved only %d of %d bytes — has the stripper stopped matching comment lines?",
			len(a.bundle)-len(a.served), len(a.bundle))
	}
	var served *staticAsset
	for url, asset := range a.byPath {
		if strings.HasPrefix(url, "/assets/app.") && strings.HasSuffix(url, ".js") {
			served = asset
		}
	}
	if served == nil || served.contents != a.served {
		t.Error("the app.js asset does not carry the stripped bundle")
	}
}

// TestServedBoundaryIsStripped is the same pin for errboundary.js, which is
// served stripped since Task 20360. It is first-paint like the bundle, and the
// one script that has to run when the bundle cannot, so a stripper that
// declined it would cost bytes and one that mangled it would cost the error
// reporting the dashboard falls back on.
func TestServedBoundaryIsStripped(t *testing.T) {
	a := loadAssets()
	want, err := stripJSLineComments(a.boundary)
	if err != nil {
		t.Fatalf("errboundary.js cannot be stripped, so it ships with its comments: %v", err)
	}
	if a.servedBoundary != want {
		t.Fatal("the served error boundary is not the stripped one")
	}
	if strings.Count(a.servedBoundary, "\n") != strings.Count(a.boundary, "\n") {
		t.Error("stripping changed the line count, so a stack trace from the boundary points elsewhere")
	}
	if len(a.servedBoundary) > len(a.boundary)*3/4 {
		t.Errorf("stripping saved only %d of %d bytes — has the stripper stopped matching comment lines?",
			len(a.boundary)-len(a.servedBoundary), len(a.boundary))
	}
	var served *staticAsset
	for url, asset := range a.byPath {
		if strings.HasPrefix(url, "/assets/errboundary.") && strings.HasSuffix(url, ".js") {
			served = asset
		}
	}
	if served == nil || served.contents != a.servedBoundary {
		t.Error("the errboundary.js asset does not carry the stripped script")
	}
}

// findAcorn locates an acorn module directory: $CLOOP_ACORN, or one found in
// a node_modules nearby. Returns "" when there is none.
func findAcorn() string {
	if p := os.Getenv("CLOOP_ACORN"); p != "" {
		return p
	}
	for _, root := range []string{"/usr/lib/node_modules", "/usr/local/lib/node_modules"} {
		for _, rel := range []string{"acorn", "npm/node_modules/acorn"} {
			p := filepath.Join(root, rel)
			if _, err := os.Stat(filepath.Join(p, "package.json")); err == nil {
				return p
			}
		}
	}
	return ""
}

// TestStripJSLineComments_MatchesAcorn checks the shipped bundle against a
// real parser. It skips without node or acorn; CLOOP_ACORN names an acorn
// module directory to use.
func TestStripJSLineComments_MatchesAcorn(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	acorn := findAcorn()
	if acorn == "" {
		t.Skip("acorn not found; set CLOOP_ACORN to an acorn module directory to run this check")
	}
	a := loadAssets()
	// Both scripts the page loads; errboundary.js is served stripped too
	// since Task 20360, and every deferred script since Task 20366.
	scripts := []struct{ name, raw, served string }{
		{"app.js", a.bundle, a.served},
		{"errboundary.js", a.boundary, a.servedBoundary},
	}
	for token, d := range a.deferred {
		scripts = append(scripts, struct{ name, raw, served string }{token, d.raw, d.served})
	}
	for _, js := range scripts {
		dir := t.TempDir()
		rawPath, strippedPath := filepath.Join(dir, "raw.js"), filepath.Join(dir, "stripped.js")
		if err := os.WriteFile(rawPath, []byte(js.raw), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(strippedPath, []byte(js.served), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, mustAbs(t, "testdata/jsstrip_oracle.js"), acorn, rawPath, strippedPath).Output()
		if err != nil {
			t.Fatalf("%s oracle: %v\n%s", js.name, err, out)
		}
		var res struct {
			OK           bool             `json:"ok"`
			Blanked      int              `json:"blanked"`
			CommentLines int              `json:"comment_lines"`
			Mismatches   []map[string]any `json:"mismatches"`
			TokensEqual  bool             `json:"tokens_equal"`
			Error        string           `json:"error"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			t.Fatalf("%s oracle output: %v\n%s", js.name, err, out)
		}
		if res.Error != "" {
			t.Fatalf("%s oracle failed: %s", js.name, res.Error)
		}
		if !res.OK {
			t.Errorf("%s: the stripper disagrees with acorn: blanked %d lines, acorn finds %d whole-line comments; "+
				"tokens equal: %v; first mismatches: %v", js.name, res.Blanked, res.CommentLines, res.TokensEqual, res.Mismatches)
		}
		t.Logf("%s: blanked %d whole-line comments, all confirmed by acorn", js.name, res.Blanked)
	}
}
