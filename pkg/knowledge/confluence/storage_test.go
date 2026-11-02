package confluence

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// TestRenderStorage: what a page's storage format becomes — the text a person
// reads, shaped so the chunker's sections fall at its headings — and what of
// it is left out: macros' own output and parameters, images, attachments.
func TestRenderStorage(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string // substrings of the output, in order
		without []string
		exact   string
	}{
		{name: "headings and paragraphs",
			in:    `<h1>Deploy</h1><p>Run the <strong>deploy</strong>&nbsp;script.<br/>Then wait.</p><h3>Rollback</h3><p>Undo it.</p>`,
			exact: "# Deploy\n\nRun the deploy script.\nThen wait.\n\n### Rollback\n\nUndo it."},
		{name: "nested lists",
			in:    `<ol><li>Build<ul><li>unit</li><li>race</li></ul></li><li>Ship</li></ol>`,
			exact: "1. Build\n  - unit\n  - race\n2. Ship"},
		{name: "an ordered list's start", in: `<ol start="4"><li>four</li><li>five</li></ol>`, exact: "4. four\n5. five"},
		{name: "task lists",
			in: `<ac:task-list><ac:task><ac:task-id>1</ac:task-id><ac:task-status>complete</ac:task-status>` +
				`<ac:task-body>Write docs</ac:task-body></ac:task><ac:task><ac:task-id>2</ac:task-id>` +
				`<ac:task-status>incomplete</ac:task-status><ac:task-body>Review</ac:task-body></ac:task></ac:task-list>`,
			exact: "- [x] Write docs\n- [ ] Review"},
		{name: "tables",
			in: `<table><colgroup><col/></colgroup><tbody><tr><th>Env</th><th>Host</th></tr>` +
				`<tr><td><p>prod</p></td><td>a|b <code>x</code></td></tr></tbody></table>`,
			exact: "| Env | Host |\n| --- | --- |\n| prod | a\\|b `x` |"},
		{name: "a list in a cell", in: `<table><tr><td><ul><li>one</li><li>two</li></ul></td></tr></table>`,
			exact: "| one; two |"},
		{name: "the code macro, its language and its text as written",
			in: `<ac:structured-macro ac:name="code" ac:schema-version="1"><ac:parameter ac:name="language">go</ac:parameter>` +
				`<ac:parameter ac:name="title">main.go</ac:parameter><ac:plain-text-body><![CDATA[// a & b
func main() {
	fmt.Println("<hi>")
}]]></ac:plain-text-body></ac:structured-macro>`,
			exact: "```go\n// a & b\nfunc main() {\n\tfmt.Println(\"<hi>\")\n}\n```"},
		{name: "CDATA is not decoded", in: `<ac:structured-macro ac:name="noformat"><ac:plain-text-body><![CDATA[x &amp; y]]>` +
			`</ac:plain-text-body></ac:structured-macro>`, exact: "```\nx &amp; y\n```"},
		{name: "pre", in: `<pre>  indented
line</pre>`, exact: "```\n  indented\nline\n```"},
		{name: "a fence inside code does not end it",
			in:    "<pre>```\nnot the end\n```</pre>",
			exact: "```\n\\```\nnot the end\n\\```\n```"},
		{name: "macros are not run; their bodies are the page's",
			in: `<ac:structured-macro ac:name="toc"><ac:parameter ac:name="maxLevel">2</ac:parameter></ac:structured-macro>` +
				`<ac:structured-macro ac:name="info"><ac:parameter ac:name="title">Heads up</ac:parameter>` +
				`<ac:rich-text-body><p>Only on <em>Fridays</em>.</p></ac:rich-text-body></ac:structured-macro>` +
				`<ac:structured-macro ac:name="jira"><ac:parameter ac:name="jqlQuery">project = OPS</ac:parameter>` +
				`</ac:structured-macro><ac:structured-macro ac:name="html"><ac:plain-text-body><![CDATA[<script>x()</script>]]>` +
				`</ac:plain-text-body></ac:structured-macro>`,
			exact: "Only on Fridays."},
		{name: "images, attachments and emoticons are left out",
			in: `<p>Diagram: <ac:image ac:width="400"><ri:attachment ri:filename="arch.png"/></ac:image> ` +
				`<ac:emoticon ac:name="smile"/> done</p><ac:link><ri:attachment ri:filename="spec.pdf"/></ac:link>`,
			exact: "Diagram: done"},
		{name: "links keep their text, or the page's title",
			in: `<p>See <ac:link><ri:page ri:content-title="Rollback guide" ri:space-key="ENG"/></ac:link> and ` +
				`<ac:link><ri:page ri:content-title="X"/><ac:plain-text-link-body><![CDATA[the runbook]]></ac:plain-text-link-body>` +
				`</ac:link> and <a href="https://example.com/x">the site</a>.</p>`,
			exact: "See Rollback guide and the runbook and the site."},
		{name: "a time", in: `<p>Due <time datetime="2026-11-30" /> at the latest.</p>`, exact: "Due 2026-11-30 at the latest."},
		{name: "quotes", in: `<blockquote><p>first</p><p>second</p></blockquote>`, exact: "> first\n\n> second"},
		{name: "layouts are containers",
			in: `<ac:layout><ac:layout-section ac:type="two_equal"><ac:layout-cell><p>left</p></ac:layout-cell>` +
				`<ac:layout-cell><p>right</p></ac:layout-cell></ac:layout-section></ac:layout>`,
			exact: "left\n\nright"},
		{name: "ADF content is read once, its fallback not at all",
			in: `<ac:adf-extension><ac:adf-node type="panel"><ac:adf-attribute key="panel-type">note</ac:adf-attribute>` +
				`<ac:adf-content><p>panel text</p></ac:adf-content></ac:adf-node><ac:adf-fallback><div><p>panel text</p></div>` +
				`</ac:adf-fallback></ac:adf-extension>`,
			exact: "panel text"},
		{name: "text that would read as structure is escaped",
			in:    `<p># of users</p><p>---</p><p>===</p><p>` + "```" + `</p>`,
			exact: "\\# of users\n\n\\---\n\n\\===\n\n\\```"},
		{name: "a heading in a cell is text", in: `<table><tr><td><h2>Owner</h2><p>Ops</p></td></tr></table>`,
			exact: "| Owner Ops |"},
		{name: "code that starts a list item",
			in:   `<ul><li><pre>make</pre></li></ul>`,
			want: []string{"-\n", "  ```\n  make\n  ```"}},
		{name: "empty", in: ``, exact: ""},
		{name: "only markup", in: `<p></p><div><br/></div><ac:structured-macro ac:name="toc"/>`, exact: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderStorage(tc.in)
			if tc.exact != "" || (tc.want == nil && tc.without == nil) {
				if got != tc.exact {
					t.Fatalf("render =\n%s\n--- want ---\n%s", got, tc.exact)
				}
				return
			}
			rest := got
			for _, w := range tc.want {
				i := strings.Index(rest, w)
				if i < 0 {
					t.Fatalf("render =\n%s\n--- missing (in order) ---\n%s", got, w)
				}
				rest = rest[i+len(w):]
			}
		})
	}
}

// TestRenderStorageSectionsAreTheChunkersSections: the chunker cuts the
// rendered text at the page's headings, and a "#" in a code block is not one.
func TestRenderStorageSectionsAreTheChunkersSections(t *testing.T) {
	text := renderStorage(`<h1>Install</h1><p>Get it.</p><h2>Linux</h2>` +
		`<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[# not a heading
apt install cloop]]></ac:plain-text-body></ac:structured-macro><h2>macOS</h2><p>brew install cloop</p>`)
	chunks, _ := knowledge.ChunkDocument("Install", text, knowledge.ChunkOptions{})
	var headings []string
	for _, c := range chunks {
		headings = append(headings, c.Heading)
	}
	if got := strings.Join(headings, " | "); got != "Install | Install › Linux | Install › macOS" {
		t.Fatalf("chunk headings = %q", got)
	}
	if !strings.Contains(chunks[1].Text, "# not a heading") {
		t.Fatalf("the code block's comment went missing: %q", chunks[1].Text)
	}
}

// TestRenderStorageMalformed: input that is not well formed — never closed,
// closed out of order, nested past any page's depth, cut off, not UTF-8 — is
// read without a panic, in bounded time, and its text still comes out.
func TestRenderStorageMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "unclosed elements", in: `<p>one <b>bold <i>both<p>two<ul><li>item`, want: []string{"one bold both", "two", "- item"}},
		{name: "end tags out of order", in: `<p><b>x</p></b><div>y</span></div>`, want: []string{"x", "y"}},
		{name: "end tags that close nothing", in: `</p></table></ac:structured-macro>text`, want: []string{"text"}},
		{name: "a stray angle bracket", in: `<p>a < b and c > d</p>`, want: []string{"a < b and c > d"}},
		{name: "unknown and broken entities", in: `<p>&bogus; &#xZZ; &amp &lt;tag&gt;</p>`, want: []string{"&bogus;", "<tag>"}},
		{name: "unterminated CDATA", in: `<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[fmt.Println(1)`,
			want: []string{"fmt.Println(1)"}},
		{name: "unterminated comment", in: `<p>before</p><!-- never closed <p>hidden</p>`, want: []string{"before"}},
		{name: "a list item outside a list", in: `<li>loose</li>`, want: []string{"- loose"}},
		{name: "cells outside rows", in: `<table><td>a</td><td>b</td></table>`, want: []string{"| a |", "| b |"}},
		{name: "a row outside a table", in: `<tr><td>a</td></tr>`, want: []string{"| a |"}},
		{name: "scripts and styles are dropped", in: `<p>x</p><script>alert(1)</script><style>p{}</style><p>y</p>`,
			want: []string{"x", "y"}},
		{name: "invalid UTF-8 and NULs", in: "<p>ok\xff\xfe go\x00od</p>", want: []string{"ok", "good"}},
		{name: "attributes without quotes, and unknown elements", in: `<p class=x data-y>text<foo:bar>more</foo:bar></p>`,
			want: []string{"textmore"}},
		{name: "deep nesting", in: strings.Repeat("<div><span>", 5000) + "deep text" + strings.Repeat("</span></div>", 5000),
			want: []string{"deep text"}},
		{name: "deep lists", in: strings.Repeat("<ul><li>", 3000) + "bottom", want: []string{"bottom"}},
		{name: "a plaintext element", in: `<p>a</p><plaintext><p>b</p>`, want: []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderStorage(tc.in)
			if !utf8.ValidString(got) {
				t.Fatalf("the output is not UTF-8: %q", got)
			}
			if strings.ContainsRune(got, 0) {
				t.Fatalf("the output holds a NUL: %q", got)
			}
			rest := got
			for _, w := range tc.want {
				i := strings.Index(rest, w)
				if i < 0 {
					t.Fatalf("render = %q, missing %q (in order)", got, w)
				}
				rest = rest[i+len(w):]
			}
			if strings.Contains(got, "hidden") || strings.Contains(got, "alert") {
				t.Fatalf("render kept what it should drop: %q", got)
			}
		})
	}
}

// TestRenderStorageIsBounded: an enormous body is cut before it is read, and a
// hostile one — a tag per few bytes, end tags with nothing open, every
// paragraph deep in inline elements, items never closed — renders in time
// linear in its size. Linear is measured, not assumed from a wall clock: each
// input is rendered at n and at 8n elements, and eight times the elements may
// take at most 24 times as long — a quadratic renderer takes 64. Comparing two
// runs on one machine holds on a slow runner as on a fast one. Not under the
// race detector: it slows every element twentyfold, which buries the signal at
// any size a test can afford — R-24 runs this without it, in CI's
// requirements job.
func TestRenderStorageIsBounded(t *testing.T) {
	saved := maxStorageBytes
	t.Cleanup(func() { maxStorageBytes = saved })
	maxStorageBytes = 256 << 10
	big := strings.Repeat("<p>"+strings.Repeat("word ", 200)+"</p>", 1000) // ~1 MiB
	if out := renderStorage(big); len(out) > maxStorageBytes || len(out) < maxStorageBytes/2 {
		t.Fatalf("rendered %d bytes from a body cut at %d", len(out), maxStorageBytes)
	}
	maxStorageBytes = saved

	// fastest is the best of three renders: the least disturbed by the rest
	// of the machine.
	fastest := func(in string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			renderStorage(in)
			best = min(best, time.Since(start))
		}
		return best
	}
	if raceDetector {
		t.Skip("timings under -race measure the detector; R-24 runs this without it")
	}
	const n = 1 << 12
	for name, build := range map[string]func(int) string{
		"unclosed inline elements": func(k int) string { return strings.Repeat("<b>", k) },
		"end tags closing nothing": func(k int) string { return strings.Repeat("</td>", k) },
		"paragraphs at depth": func(k int) string {
			return strings.Repeat("<span>", 32) + strings.Repeat("<p>x</p>", k)
		},
		"items never closed":     func(k int) string { return strings.Repeat("<li>x", k) },
		"cells never closed":     func(k int) string { return "<table><tr>" + strings.Repeat("<td>x", k) },
		"nesting past the bound": func(k int) string { return strings.Repeat("<div>", k) + "x" },
		"text between tags":      func(k int) string { return strings.Repeat("<i>a</i> b ", k) },
	} {
		small, large := fastest(build(n)), fastest(build(8*n))
		if large > 24*small+5*time.Millisecond {
			t.Errorf("%s: %d elements took %v, eight times as many %v: not linear in its elements", name, n, small, large)
		}
	}
}
