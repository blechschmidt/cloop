package ui

// The static half of Task 20408: no markup the hub serves carries code.
//
// The hub's policy is script-src 'self'. Under it an inline handler or an
// inline script does not run, so one that slips back in is a control that
// silently does nothing — or, before the policy, was the hole a project name
// holding &quot; walked through. These gates fail at the commit that adds one,
// in every place one could come from: the two HTML documents under assets/,
// every script the front ends are built from (a JS string that builds markup
// is markup), and every Go string literal in the two packages whose HTML the
// hub writes itself. The browser regression in xss_browser_test.go is the
// other half: it clicks everything with hostile data on the page and counts
// what the policy reports.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// startTag is one start tag of a document: its name, its attribute names
// (lower-cased) and its text, for messages.
type startTag struct {
	name, text string
	attrs      []string
}

// startTags reads the start tags of doc the way the HTML tokenizer does
// (WHATWG HTML 13.2.5), as far as attributes go: a name runs to whitespace,
// '/', '>' or '=', a value is double-quoted, single-quoted or bare, and the
// next attribute may follow a closing quote or a '/' with no space between —
// class="x"onclick="…" and <svg/onload=…> are each a tag with a handler, as a
// browser reads them. Comments are skipped. What it does not model — raw text
// in script and style elements, character references — cannot add an
// attribute to a tag.
func startTags(doc string) []startTag {
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
	var out []startTag
	for i := 0; i < len(doc); i++ {
		if strings.HasPrefix(doc[i:], "<!--") {
			end := strings.Index(doc[i+4:], "-->")
			if end < 0 {
				break
			}
			i += 4 + end + 2
			continue
		}
		if doc[i] != '<' || i+1 >= len(doc) || !(doc[i+1]|0x20 >= 'a' && doc[i+1]|0x20 <= 'z') {
			continue
		}
		j := i + 1
		for j < len(doc) && !space(doc[j]) && doc[j] != '/' && doc[j] != '>' {
			j++
		}
		tag := startTag{name: strings.ToLower(doc[i+1 : j])}
		for j < len(doc) && doc[j] != '>' {
			if space(doc[j]) || doc[j] == '/' {
				j++
				continue
			}
			// An '=' that starts a name is part of it.
			k := j + 1
			for k < len(doc) && !space(doc[k]) && doc[k] != '/' && doc[k] != '>' && doc[k] != '=' {
				k++
			}
			tag.attrs = append(tag.attrs, strings.ToLower(doc[j:k]))
			for j = k; j < len(doc) && space(doc[j]); j++ {
			}
			if j >= len(doc) || doc[j] != '=' {
				continue
			}
			for j++; j < len(doc) && space(doc[j]); j++ {
			}
			if j < len(doc) && (doc[j] == '"' || doc[j] == '\'') {
				end := strings.IndexByte(doc[j+1:], doc[j])
				if end < 0 {
					j = len(doc)
					break
				}
				j += end + 2
				continue
			}
			for j < len(doc) && !space(doc[j]) && doc[j] != '>' {
				j++
			}
		}
		tag.text = doc[i:min(j+1, len(doc))]
		out = append(out, tag)
		i = j
	}
	return out
}

// inlineHandlersInHTML lists every on* attribute in an HTML document.
func inlineHandlersInHTML(doc string) []string {
	var out []string
	for _, tag := range startTags(doc) {
		for _, a := range tag.attrs {
			if strings.HasPrefix(a, "on") && len(a) > 2 {
				out = append(out, a+" in "+truncate(tag.text, 120))
			}
		}
	}
	return out
}

// jsHandlerRe matches an attribute-shaped handler in script source — what a
// string that builds markup contains: on<event>= where an attribute can
// start (after whitespace, a '/', a quote, or an interpolation's '}'), its
// value quoted, escaped or not, or bare; in any case, as the HTML parser
// reads attribute names. A bare value or another case only without
// whitespace around the '=', which is how markup is written and code is not:
// so property assignments (el.onclick = fn) and variables (const once = 1)
// are left alone, as is a query string's &online=1. jsSetAttrRe matches the
// other way to install one, setAttribute('on…') (or setAttributeNS).
var (
	jsHandlerRe = regexp.MustCompile(`(?:^|[\s/"'}` + "`" + `])(?:on[a-z]+\s*=\s*\\?["'` + "`" + `]|(?i:on[a-z]+)=(?:\\?["'` + "`" + `]|[^\s"'` + "`" + `=<>\\]))`)
	jsSetAttrRe = regexp.MustCompile(`(?i)setAttribute(?:NS)?\(\s*(?:[^,()]*,\s*)?['"` + "`" + `]on[a-z]`)
)

// frontEndScripts is every script a front end is built from, as written:
// the bundle's fragments, the error boundary, the deferred panels and the
// page scripts, keyed by path.
func frontEndScripts(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(assetFS, "assets/js", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		b, err := assetFS.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 40 {
		t.Fatalf("found %d scripts under assets/js; there are ~50, so the walk is reading the wrong tree", len(out))
	}
	return out
}

// TestNoInlineEventHandlers: no on* attribute in either HTML document, none in
// a string any script builds markup from, and none in a Go string literal of
// the packages that write HTML.
func TestNoInlineEventHandlers(t *testing.T) {
	var found []string
	for _, p := range []string{"assets/index.html", "assets/glasses.html"} {
		b, err := assetFS.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range inlineHandlersInHTML(string(b)) {
			found = append(found, p+": "+h)
		}
	}
	for p, src := range frontEndScripts(t) {
		for i, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // prose about the old handlers, not markup
			}
			if jsHandlerRe.MatchString(line) || jsSetAttrRe.MatchString(line) {
				found = append(found, p+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	// And the markup the hub writes from Go: the sign-in documents, error
	// pages. A tag split across literals is judged by the literal it starts in.
	for _, lit := range goStringLiterals(t) {
		for _, h := range inlineHandlersInHTML(lit.value) {
			found = append(found, lit.pos+": "+h)
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d inline event handler(s). The hub's policy does not run them, so each is a control "+
			"that does nothing; name an action instead — data-action=\"name\" (or data-action-<event>) with "+
			"its argument in data-arg, registered with act() in the bundle (00-core.js):\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
}

// TestInlineHandlerGateCatchesTheShapes proves the detectors above on the
// shapes they exist for — an attribute in markup however a browser would
// still read it as one, each quoting a script string can build one with,
// setAttribute — and on what they must let through.
func TestInlineHandlerGateCatchesTheShapes(t *testing.T) {
	for _, doc := range []string{
		`<div onclick="x()">`,
		`<button class="b" ONCLICK='x()'>`,
		`<input title="a > b" oninput=x()>`,
		`<img src=x onerror="alert(1)">`,
		`<a class="x"onclick="go()">`,
		`<svg/onload=alert(1)>`,
		`<p title='x'/onMouseOver=go()>`,
		"<b\nonfocus\n=\ngo()>",
	} {
		if len(inlineHandlersInHTML(doc)) == 0 {
			t.Errorf("the HTML detector missed %s", doc)
		}
	}
	for _, doc := range []string{
		`<div data-action="x" title="onclick=x()">`,
		`<p>use onclick= nowhere</p>`,
		`<!-- <div onclick="x()"> -->`,
		`<a href="/x?online=1" data-on="y">`,
	} {
		if got := inlineHandlersInHTML(doc); len(got) != 0 {
			t.Errorf("the HTML detector flagged %s: %v", doc, got)
		}
	}
	for _, line := range []string{
		`'<b onclick="go()">'`,
		`"<b onclick=\"go()\">"`,
		"`<b onchange='go()'>`",
		`'<b onClick="go()">'`,
		`'<body ONLOAD="go()">'`,
		`'<img src=x onerror=go()>'`,
		`'<svg/onload=go()>'`,
		`'<a class="x"onclick="go()">'`,
		"`<b ${attrs}onclick=go()>`",
		`h += ' onclick="go()"';`,
		`el.setAttribute('onerror', code)`,
		`el.setAttribute("onClick", code)`,
		`el.setAttributeNS(null, 'onload', code)`,
	} {
		if !jsHandlerRe.MatchString(line) && !jsSetAttrRe.MatchString(line) {
			t.Errorf("the script detector missed %s", line)
		}
	}
	for _, line := range []string{
		`el.onclick = () => go();`,
		`x.onload = fn;`,
		`x.onClick=fn;`,
		`'data-action="go"'`,
		`msg.textContent === 'x'`,
		`const onlyOnce = flag;`,
		`fetch('/api/x?online=1&once=2')`,
		`el.setAttribute('data-on', 'x')`,
	} {
		if jsHandlerRe.MatchString(line) || jsSetAttrRe.MatchString(line) {
			t.Errorf("the script detector flagged code: %s", line)
		}
	}
}

// goLiteral is a Go string literal's value and where it is.
type goLiteral struct{ pos, value string }

// goStringLiterals returns every string literal in the non-test Go files of
// pkg/ui and pkg/oidcauth, the packages that write HTML themselves: the
// sign-in documents, an error page.
func goStringLiterals(t *testing.T) []goLiteral {
	t.Helper()
	var out []goLiteral
	for _, dir := range []string{".", filepath.Join("..", "oidcauth")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out = append(out, goLiteral{fset.Position(lit.Pos()).String(), v})
					}
				}
				return true
			})
		}
	}
	if len(out) < 1000 {
		t.Fatalf("found %d string literals in pkg/ui and pkg/oidcauth; there are thousands, so the scan is "+
			"reading the wrong files", len(out))
	}
	return out
}

// scriptTagRe matches a script start tag; scriptTagOK reports whether one
// loads a file or carries a nonce, which are the only kinds the policy runs.
var scriptTagRe = regexp.MustCompile(`(?i)<script\b[^>]*>`)

func scriptTagOK(tag string) bool {
	l := strings.ToLower(tag)
	return strings.Contains(l, " src=") || strings.Contains(l, " nonce=")
}

// TestNoInlineScripts: every script element the hub can serve loads a file —
// or would carry a per-response nonce, of which there are none today. Checked
// in the two HTML documents, in every front-end script (one building a script
// element from a string), and in every Go string literal of pkg/ui and
// pkg/oidcauth, the packages that write HTML (the sign-in documents, an error
// page). A tag split across literals is judged by the literal it starts in,
// which errs towards reporting it.
func TestNoInlineScripts(t *testing.T) {
	var found []string
	for _, p := range []string{"assets/index.html", "assets/glasses.html"} {
		b, err := assetFS.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range scriptTagRe.FindAllString(string(b), -1) {
			if !scriptTagOK(tag) {
				found = append(found, p+": "+tag)
			}
		}
	}
	for p, src := range frontEndScripts(t) {
		for i, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, tag := range scriptTagRe.FindAllString(line, -1) {
				if !scriptTagOK(tag) {
					found = append(found, p+":"+strconv.Itoa(i+1)+": "+tag)
				}
			}
		}
	}

	literals := 0
	for _, lit := range goStringLiterals(t) {
		for _, loc := range regexp.MustCompile(`(?i)<script\b`).FindAllStringIndex(lit.value, -1) {
			literals++
			rest := lit.value[loc[0]:]
			if end := strings.IndexByte(rest, '>'); end >= 0 {
				rest = rest[:end+1]
			}
			if !scriptTagOK(rest + " ") {
				found = append(found, lit.pos+": "+truncate(rest, 80))
			}
		}
	}
	if literals < 2 {
		t.Fatalf("found %d script tags in Go string literals; the two sign-in documents have one each, so "+
			"the scan is reading the wrong files", literals)
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d inline script(s). The hub's policy (script-src 'self') does not run them: serve the "+
			"code as an asset and carry any value it needs in a data attribute:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
}
