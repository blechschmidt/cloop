package jira

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// ADF builders, for documents written as Go values.

func adfDoc(content ...any) map[string]any {
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

func adfNodeOf(typ string, attrs map[string]any, content ...any) map[string]any {
	n := map[string]any{"type": typ}
	if attrs != nil {
		n["attrs"] = attrs
	}
	if len(content) > 0 {
		n["content"] = content
	}
	return n
}

func adfText(s string, marks ...string) map[string]any {
	n := map[string]any{"type": "text", "text": s}
	for _, m := range marks {
		ms, _ := n["marks"].([]any)
		n["marks"] = append(ms, map[string]any{"type": m})
	}
	return n
}

func adfPara(content ...any) map[string]any { return adfNodeOf("paragraph", nil, content...) }

func adfItem(content ...any) map[string]any { return adfNodeOf("listItem", nil, content...) }

func mustADF(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRenderADF: what a person reads in a description or a comment comes out
// as the text the index holds — nested lists, code with its language,
// mentions, tables and the rest — and nothing that would read as structure
// to the chunker that is not structure.
func TestRenderADF(t *testing.T) {
	cases := []struct {
		name  string
		doc   any
		shift int
		want  string
	}{
		{name: "paragraphs, breaks, marks",
			doc: adfDoc(
				adfPara(adfText("Run "), adfText("make deploy", "code"), adfText(" from a "), adfText("clean", "strong", "em"),
					adfText(" checkout."), adfNodeOf("hardBreak", nil), adfText("Then wait.")),
				adfPara(adfText("A "), map[string]any{"type": "text", "text": "link's text",
					"marks": []any{map[string]any{"type": "link", "attrs": map[string]any{"href": "https://evil.example/x"}}}},
					adfText(" stays; its target does not."))),
			want: "Run `make deploy` from a clean checkout.\nThen wait.\n\nA link's text stays; its target does not."},
		{name: "headings shift under the issue's own",
			doc:   adfDoc(adfNodeOf("heading", map[string]any{"level": 1}, adfText("Steps")), adfPara(adfText("one")), adfNodeOf("heading", map[string]any{"level": 6}, adfText("Deep"))),
			shift: 1,
			want:  "## Steps\n\none\n\n###### Deep"},
		{name: "nested lists",
			doc: adfDoc(adfNodeOf("bulletList", nil,
				adfItem(adfPara(adfText("fruit")),
					adfNodeOf("orderedList", map[string]any{"order": 3},
						adfItem(adfPara(adfText("apple"))),
						adfItem(adfPara(adfText("pear")), adfNodeOf("bulletList", nil, adfItem(adfPara(adfText("williams"))))))),
				adfItem(adfPara(adfText("veg"))))),
			want: "- fruit\n  3. apple\n  4. pear\n    - williams\n- veg"},
		{name: "a code block keeps its language, its text as written, and cannot end early",
			doc: adfDoc(adfNodeOf("codeBlock", map[string]any{"language": "Bash"},
				adfText("# not a heading\nkubectl rollout status deploy/hub  \n```\necho &amp; done"))),
			want: "```bash\n# not a heading\nkubectl rollout status deploy/hub\n\\```\necho &amp; done\n```"},
		{name: "mentions, emoji, status, dates, smart links",
			doc: adfDoc(adfPara(
				adfNodeOf("mention", map[string]any{"id": "5b10ac8d82e05b22cc7d4ef5", "text": "@Alice Smith", "accessLevel": ""}),
				adfText(" and "), adfNodeOf("mention", map[string]any{"id": "x", "text": "Bob"}),
				adfText(" and "), adfNodeOf("mention", map[string]any{"id": "y"}),
				adfText(" "), adfNodeOf("emoji", map[string]any{"shortName": ":tada:", "text": "🎉"}),
				adfText(" "), adfNodeOf("emoji", map[string]any{"shortName": ":cloop:"}),
				adfText(" "), adfNodeOf("status", map[string]any{"text": "IN REVIEW", "color": "blue"}),
				adfText(" by "), adfNodeOf("date", map[string]any{"timestamp": "1767225600000"}),
				adfText(" see "), adfNodeOf("inlineCard", map[string]any{"url": "https://corp.atlassian.net/browse/ENG-7"}))),
			want: "@Alice Smith and @Bob and @user 🎉 :cloop: IN REVIEW by 2026-01-01 see https://corp.atlassian.net/browse/ENG-7"},
		{name: "a table with a header row, a list in a cell",
			doc: adfDoc(adfNodeOf("table", nil,
				adfNodeOf("tableRow", nil,
					adfNodeOf("tableHeader", nil, adfPara(adfText("Host"))), adfNodeOf("tableHeader", nil, adfPara(adfText("Role")))),
				adfNodeOf("tableRow", nil,
					adfNodeOf("tableCell", nil, adfPara(adfText("db|1"))),
					adfNodeOf("tableCell", nil, adfNodeOf("bulletList", nil, adfItem(adfPara(adfText("primary"))), adfItem(adfPara(adfText("backup")))))))),
			want: "| Host | Role |\n| --- | --- |\n| db\\|1 | primary; backup |"},
		{name: "quotes, panels, expands, rules",
			doc: adfDoc(
				adfNodeOf("blockquote", nil, adfPara(adfText("quoted")), adfPara(adfText("twice"))),
				adfNodeOf("panel", map[string]any{"panelType": "warning"}, adfPara(adfText("Mind the gap."))),
				adfNodeOf("rule", nil),
				adfNodeOf("expand", map[string]any{"title": "Details"}, adfPara(adfText("Hidden until opened.")))),
			want: "> quoted\n\n> twice\n\nMind the gap.\n\nDetails\n\nHidden until opened."},
		{name: "task and decision lists",
			doc: adfDoc(
				adfNodeOf("taskList", nil,
					adfNodeOf("taskItem", map[string]any{"state": "DONE", "localId": "1"}, adfText("write it")),
					adfNodeOf("taskItem", map[string]any{"state": "TODO"}, adfText("ship it"))),
				adfNodeOf("decisionList", nil, adfNodeOf("decisionItem", map[string]any{"state": "DECIDED"}, adfText("use JQL")))),
			want: "- [x] write it\n- [ ] ship it\n\n- use JQL"},
		{name: "media, placeholders and macros are not text; captions are",
			doc: adfDoc(
				adfNodeOf("mediaSingle", nil, adfNodeOf("media", map[string]any{"id": "abc", "type": "file", "alt": "x.png"}),
					adfNodeOf("caption", nil, adfText("The architecture."))),
				adfNodeOf("extension", map[string]any{"extensionKey": "toc"}),
				adfPara(adfNodeOf("placeholder", map[string]any{"text": "Type something"}), adfText("kept"))),
			want: "The architecture.\n\nkept"},
		{name: "a node this renderer does not know passes its text through",
			doc:  adfDoc(adfNodeOf("futureBlock", nil, adfPara(adfText("still read"))), adfPara(adfNodeOf("futureInline", nil, adfText("inline too")))),
			want: "still read\n\ninline too"},
		{name: "text that would read as structure is escaped",
			doc:  adfDoc(adfPara(adfText("# not a heading")), adfPara(adfText("---")), adfPara(adfText("```fence"))),
			want: "\\# not a heading\n\n\\---\n\n\\```fence"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := renderADF(mustADF(t, c.doc), c.shift); got != c.want {
				t.Fatalf("renderADF =\n%s\nwant\n%s", got, c.want)
			}
		})
	}
}

// TestRenderADFMalformed: a document that is not what ADF promises —
// attributes of the wrong type, keys in any order, content that is not a
// list, nesting past any document's depth, JSON cut off — is read without a
// panic, and its text still comes out.
func TestRenderADFMalformed(t *testing.T) {
	deep := strings.Repeat(`{"type":"bulletList","content":[{"type":"listItem","content":[`, 600) +
		`{"type":"paragraph","content":[{"type":"text","text":"bottom"}]}` + strings.Repeat(`]}]}`, 600)
	cases := []struct {
		name, in string
		want     []string
	}{
		{"attributes of the wrong type", `{"type":"doc","content":[{"type":"heading","attrs":{"level":"2"},"content":[{"type":"text","text":"Two"}]},` +
			`{"type":"orderedList","attrs":{"order":{"x":1}},"content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"a"}]}]}]},` +
			`{"type":"codeBlock","attrs":{"language":42},"content":[{"type":"text","text":"x"}]}]}`, []string{"## Two", "1. a", "```42"}},
		{"type after content", `{"content":[{"content":[{"text":"late","type":"text"}],"type":"paragraph"}],"type":"doc"}`, []string{"late"}},
		{"content that is not a list", `{"type":"doc","content":[{"type":"paragraph","content":"oops"},{"type":"paragraph","content":[{"type":"text","text":"scanned"}]}]}`,
			[]string{"scanned"}},
		{"cut off", `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"first"}]},{"type":"paragraph","content":[{"type":"text","text":"sec`,
			[]string{"first"}},
		{"nesting past the bound", deep, []string{"bottom"}},
		{"not UTF-8", "{\"type\":\"doc\",\"content\":[{\"type\":\"paragraph\",\"content\":[{\"type\":\"text\",\"text\":\"ok \xff\"}]}]}", []string{"ok"}},
		{"a table cell with no row", `{"type":"doc","content":[{"type":"table","content":[{"type":"tableCell","content":[{"type":"paragraph","content":[{"type":"text","text":"lonely"}]}]}]}]}`,
			[]string{"| lonely |"}},
		{"list items outside a list", `{"type":"doc","content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"stray"}]}]}]}`,
			[]string{"- stray"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := renderADF([]byte(c.in), 0)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Fatalf("renderADF = %q, want %q in it", got, w)
				}
			}
		})
	}
}

// TestRenderADFIsBounded: a document past maxADFBytes is read for its text by
// a scan that builds no tree, and the renderer takes time linear in a
// document's nodes, however it is built. Linear is measured as the Confluence
// storage renderer's is: each input at n and at 8n nodes, the larger allowed
// at most 24 times as long — a quadratic renderer takes 64. Not under the race
// detector, whose slowdown buries the signal; R-24 runs it without.
func TestRenderADFIsBounded(t *testing.T) {
	saved := maxADFBytes
	t.Cleanup(func() { maxADFBytes = saved })
	maxADFBytes = 64 << 10
	var paras []any
	for i := 0; i < 2000; i++ {
		paras = append(paras, adfPara(adfText(fmt.Sprintf("word%d and more", i))))
	}
	big := mustADF(t, adfDoc(paras...))
	if len(big) <= maxADFBytes {
		t.Fatalf("the test document is %d bytes, not past %d", len(big), maxADFBytes)
	}
	out := renderADF(big, 0)
	if !strings.Contains(out, "word0 and more\n\nword1 and more") || !strings.Contains(out, "word1999") {
		t.Fatalf("the scanned document lost its text: %.200q", out)
	}
	maxADFBytes = saved

	fastest := func(in []byte) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			renderADF(in, 1)
			best = min(best, time.Since(start))
		}
		return best
	}
	if raceDetector {
		t.Skip("timings under -race measure the detector; R-24 runs this without it")
	}
	const n = 1 << 11
	nested := func(k int, open, close string) []byte {
		return []byte(`{"type":"doc","content":[` + strings.Repeat(open, k) + `{"type":"text","text":"x"}` + strings.Repeat(close, k) + `]}`)
	}
	repeated := func(k int, node string) []byte {
		return []byte(`{"type":"doc","content":[` + strings.Repeat(node+",", k-1) + node + `]}`)
	}
	for name, build := range map[string]func(int) []byte{
		"paragraphs": func(k int) []byte {
			return repeated(k, `{"type":"paragraph","content":[{"type":"text","text":"a b"}]}`)
		},
		"list items": func(k int) []byte {
			return []byte(`{"type":"doc","content":[{"type":"bulletList","content":[` + strings.Repeat(
				`{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"a"}]}]},`, k-1) +
				`{"type":"listItem","content":[]}]}]}`)
		},
		"table cells": func(k int) []byte {
			return []byte(`{"type":"doc","content":[{"type":"table","content":[{"type":"tableRow","content":[` +
				strings.Repeat(`{"type":"tableCell","content":[{"type":"paragraph","content":[{"type":"text","text":"c"}]}]},`, k-1) +
				`{"type":"tableCell"}]}]}]}`)
		},
		"nesting past the bound": func(k int) []byte {
			return nested(k/8, `{"type":"blockquote","content":[`, `]}`)
		},
		"text runs": func(k int) []byte { return repeated(k, `{"type":"text","text":"a "}`) },
	} {
		small, large := fastest(build(n)), fastest(build(8*n))
		if large > 24*small+5*time.Millisecond {
			t.Errorf("%s: %d nodes took %v, eight times as many %v: not linear in its nodes", name, n, small, large)
		}
	}
}

// TestADFSectionsAreTheChunkersSections: an issue's description and comments
// fall into the chunker's sections, a description's own headings under
// "Description", each comment under its author and date.
func TestADFSectionsAreTheChunkersSections(t *testing.T) {
	ss := &session{s: settings{deployment: DeploymentCloud}}
	is := &issue{ID: "1", Key: "ENG-1", Fields: issueFields{Summary: "Deploys",
		Description: mustADF(t, adfDoc(adfPara(adfText("Why.")), adfNodeOf("heading", map[string]any{"level": 1}, adfText("Steps")),
			adfNodeOf("codeBlock", nil, adfText("# not a heading")))),
		Status: &named{Name: "Done"}}}
	comments := []comment{{ID: "2", Author: &struct {
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}{DisplayName: "Alice"}, Body: mustADF(t, adfDoc(adfPara(adfText("Shipped.")))), Created: "2026-10-01T09:12:00.000+0000"}}
	text := ss.renderIssue(is, "ENG", "Engineering", comments, true)
	chunks, _ := knowledge.ChunkDocument("ENG-1 Deploys", text, knowledge.ChunkOptions{})
	var headings []string
	for _, c := range chunks {
		headings = append(headings, c.Heading)
	}
	want := " | Description | Description › Steps | Comments › Alice, 2026-10-01 09:12 UTC"
	if got := strings.Join(headings, " | "); got != want {
		t.Fatalf("chunk headings = %q, want %q\n%s", got, want, text)
	}
	if !strings.Contains(chunks[2].Text, "# not a heading") || !strings.Contains(chunks[0].Text, "Status: Done") {
		t.Fatalf("chunks = %+v", chunks)
	}
}
