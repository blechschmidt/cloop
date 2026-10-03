package ui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStripHTMLComments_Cases(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", "<p>a<!-- note -->b</p>", "<p>ab</p>"},
		{"multi-line", "<div>\n  <!-- one\n  two -->\n  <span>x</span>\n</div>", "<div>\n  \n  <span>x</span>\n</div>"},
		{"inside a quoted attribute", `<a title="<!-- not a comment -->">x</a>`, `<a title="<!-- not a comment -->">x</a>`},
		{"a > inside a quoted attribute", `<a title="a > b"><!-- c -->x</a>`, `<a title="a > b">x</a>`},
		{"script content is text", "<script>var s = '<!-- x -->';</script><!-- y -->", "<script>var s = '<!-- x -->';</script>"},
		{"style content is text", "<style>/* <!-- */</style>", "<style>/* <!-- */</style>"},
		{"textarea content is text", "<textarea><!-- kept --></textarea>", "<textarea><!-- kept --></textarea>"},
		{"pre is left alone", "<pre>a<!-- x -->b</pre><!-- y -->", "<pre>a<!-- x -->b</pre>"},
		{"end tag in another case", "<SCRIPT>x<!--y--></SCRIPT><!--z-->", "<SCRIPT>x<!--y--></SCRIPT>"},
		{"a bare less-than", "<p>1 < 2<!-- x --></p>", "<p>1 < 2</p>"},
		{"doctype kept", "<!DOCTYPE html><!-- x --><html></html>", "<!DOCTYPE html><html></html>"},
		{"a quote in an unquoted value", `<div title=a"b><!-- x -->y</div>`, `<div title=a"b>y</div>`},
		{"dashes inside", "<p><!-- a -- b ---></p>", "<p></p>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := stripHTMLComments(c.in)
			if err != nil {
				t.Fatalf("declined: %v", err)
			}
			if got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestStripHTMLComments_Refuses(t *testing.T) {
	for _, in := range []string{
		"<p><!-- never closed</p>",
		"<p><!--></p>",
		"<p><!---></p>",
		"<p><!-- closed --!> oddly --></p>",
		"<script>never closed",
		`<a title="never closed>x</a>`,
		"<p",
	} {
		got, err := stripHTMLComments(in)
		if !errors.Is(err, errHTMLStrip) {
			t.Errorf("%q: want a refusal, got %q, %v", in, got, err)
		}
		if got != in {
			t.Errorf("%q: a refusal must return the input unchanged", in)
		}
	}
}

// TestServedPageIsStripped pins that the shipped page strips cleanly — the
// stripper did not decline and ship the comments after all — and that nothing
// but comments went: every element ID is still there.
func TestServedPageIsStripped(t *testing.T) {
	a := loadAssets()
	if strings.Count(a.servedPage, "<!--") != 0 {
		i := strings.Index(a.servedPage, "<!--")
		t.Errorf("a comment survives at line %d of the served page", strings.Count(a.servedPage[:i], "\n")+1)
	}
	if a.page == nil || a.page.contents != a.servedPage {
		t.Fatal("the page asset does not carry the stripped page")
	}
	ids := regexp.MustCompile(`\bid="([^"]+)"`)
	want := ids.FindAllString(a.indexTmpl, -1)
	got := ids.FindAllString(a.servedPage, -1)
	if len(got) != len(want) || len(want) < 100 {
		t.Errorf("element IDs: %d in the template, %d served", len(want), len(got))
	}
	if len(a.servedPage) > len(a.indexTmpl)*95/100 {
		t.Errorf("served page %d B against a %d B template: the comments did not go", len(a.servedPage),
			len(a.indexTmpl))
	}
}

// TestStripHTMLComments_MatchesChrome parses the shipped page with and without
// its comments in a real browser and requires the same document either way. It
// skips without Chrome or node.
func TestStripHTMLComments_MatchesChrome(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	a := loadAssets()
	raw := a.renderedPage
	dir := t.TempDir()
	rawPath, strippedPath := filepath.Join(dir, "raw.html"), filepath.Join(dir, "stripped.html")
	if err := os.WriteFile(rawPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strippedPath, []byte(a.servedPage), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, mustAbs(t, "testdata/htmlstrip_oracle.js"),
		chrome, rawPath, strippedPath).Output()
	if err != nil {
		t.Fatalf("oracle: %v\n%s", err, out)
	}
	var res struct {
		Comments     int            `json:"comments"`
		CommentsLeft int            `json:"comments_left"`
		Elements     int            `json:"elements"`
		Diff         map[string]any `json:"diff"`
		CanaryCaught bool           `json:"canary_caught"`
		UserAgent    string         `json:"user_agent"`
		Error        string         `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("oracle output: %v\n%s", err, out)
	}
	if res.Error != "" {
		t.Fatalf("oracle failed: %s", res.Error)
	}
	if !res.CanaryCaught {
		t.Fatal("the oracle cannot tell a comment in <pre> replaced by a newline from one removed, so it " +
			"cannot tell a stripper that changed the page from one that did not")
	}
	if res.Comments < 100 || res.Elements < 1000 {
		t.Fatalf("Chrome found %d comments and %d elements; the comparison would pass vacuously",
			res.Comments, res.Elements)
	}
	if res.CommentsLeft != 0 || res.Diff != nil {
		t.Errorf("Chrome builds a different page from the stripped one (%d comments left): %v",
			res.CommentsLeft, res.Diff)
	}
	t.Logf("%d comments removed, %d elements identical (%s)", res.Comments, res.Elements, res.UserAgent)
}
