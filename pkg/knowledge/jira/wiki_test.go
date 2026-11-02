package jira

import (
	"strings"
	"testing"
	"time"
)

// TestRenderWiki: Data Center's wiki markup passes through, with what gives it
// structure made into the shape the chunker reads, and nothing it would
// misread left as it was.
func TestRenderWiki(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		shift int
		want  string
	}{
		{name: "headings shift, paragraphs and emphasis pass through",
			in: "h1. Steps\nRun *make deploy* from a _clean_ checkout.\nThen wait.\n\nh3. Notes\nNone.", shift: 1,
			want: "## Steps\n\nRun *make deploy* from a _clean_ checkout.\nThen wait.\n\n#### Notes\n\nNone."},
		{name: "numbered items are never headings, and nest",
			in:   "# first\n# second\n## second.a\n## second.b\n#* mixed\n# third\n* bullet\n** deeper\n- dash",
			want: "1. first\n2. second\n  1. second.a\n  2. second.b\n  - mixed\n3. third\n- bullet\n  - deeper\n- dash"},
		{name: "code and noformat blocks keep their text and language",
			in:   "Before\n{code:java}\n// # not a heading\nclass A {}\n{code}\nBetween {code:title=x.sh|language=bash}echo hi{code} after\n{noformat}\n----\nraw{noformat}",
			want: "Before\n\n```java\n// # not a heading\nclass A {}\n```\n\nBetween\n\n```bash\necho hi\n```\n\nafter\n\n```\n----\nraw\n```"},
		{name: "quotes",
			in:   "bq. A quoted line.\n{quote}\nfirst\nsecond\n{quote}\nafter",
			want: "> A quoted line.\n\n> first\n> second\n\nafter"},
		{name: "tables",
			in:   "||Host||Role||\n|db1|primary|\n|[db2|https://db2.example]|backup|",
			want: "| Host | Role |\n| --- | --- |\n| db1 | primary |\n| db2 | backup |"},
		{name: "a rule is a break, never a heading's underline",
			in:   "Title-ish line\n----\nNext paragraph\n===",
			want: "Title-ish line\n\nNext paragraph\n\\==="},
		{name: "links, mentions, images, monospace, macros, line breaks",
			in: "Ask [~alice] or [~accountid:5b10ac8d] about [the runbook|https://wiki.example/x] and [https://ci.example].\n" +
				"!screenshot.png! !https://img.example/a.gif|thumbnail! still here {{kubectl get pods}}\n" +
				"{color:red}red text{color} {panel:title=Careful|borderStyle=dashed}inside{panel} {anchor:top}\n" +
				"line one\\\\line two",
			want: "Ask @alice or @5b10ac8d about the runbook and https://ci.example.\nstill here `kubectl get pods`\n" +
				"red text Careful inside\nline one\nline two"},
		{name: "a line that would read as structure is escaped",
			in:   "#hashtag at the start\n```fence\n~~~tilde",
			want: "\\#hashtag at the start\n\\```fence\n\\~~~tilde"},
		{name: "a code block never closed is closed",
			in:   "{code:go}\nfunc main() {}",
			want: "```go\nfunc main() {}\n```"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := renderWiki(c.in, c.shift); got != c.want {
				t.Fatalf("renderWiki(%q) =\n%s\nwant\n%s", c.in, got, c.want)
			}
		})
	}
}

// TestRenderWikiIsBounded: markup is cut at maxWikiBytes, and read in time
// linear in its length however hostile — a line of a thousand tags, a code
// block never closed, a macro whose parameters never end. Measured as
// TestRenderADFIsBounded measures, and not under the race detector.
func TestRenderWikiIsBounded(t *testing.T) {
	saved := maxWikiBytes
	t.Cleanup(func() { maxWikiBytes = saved })
	maxWikiBytes = 64 << 10
	if out := renderWiki(strings.Repeat("words and more words\n", 20000), 0); len(out) > maxWikiBytes || len(out) < maxWikiBytes/2 {
		t.Fatalf("rendered %d bytes from markup cut at %d", len(out), maxWikiBytes)
	}
	maxWikiBytes = saved
	if raceDetector {
		t.Skip("timings under -race measure the detector; R-24 runs this without it")
	}
	fastest := func(in string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			renderWiki(in, 1)
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 1 << 12
	for name, build := range map[string]func(int) string{
		"tags on one line":        func(k int) string { return strings.Repeat("{quote}x{code}y{code}", k) },
		"a code block not closed": func(k int) string { return "{code}\n" + strings.Repeat("line {noformat}\n", k) },
		"parameters never ending": func(k int) string { return strings.Repeat("{code:"+strings.Repeat("p", 40), k) },
		"list items":              func(k int) string { return strings.Repeat("## item [~a] [b|c] !d.png!\n", k) },
		"table rows":              func(k int) string { return strings.Repeat("|a|b|c|\n", k) },
		"one long line":           func(k int) string { return strings.Repeat("word *b* _i_ {{m}} ", k) },
	} {
		small, large := fastest(build(n)), fastest(build(8*n))
		if large > 24*small+5*time.Millisecond {
			t.Errorf("%s: %d took %v, eight times as much %v: not linear in its length", name, n, small, large)
		}
	}
}
