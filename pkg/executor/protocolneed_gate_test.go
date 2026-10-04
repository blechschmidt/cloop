package executor

// protocolneed_gate_test.go keeps every "this device speaks too old a
// protocol" sentence in protocolneed.go (Task 20371).
//
// The defect it guards against was not one wrong message but a dozen copies of
// one: each refusal was written where it was raised, each ended with "upgrade
// the agent with `cloop executor agent install --upgrade`", and each was wrong
// in the same way on a hub running an unreleased build — the one deployment
// that hit them. Fixing the copies would leave the next refusal to be written
// the old way, so this test reads the source instead: every string literal in
// pkg/ and cmd/ (constant concatenations folded, so a message split across `+`
// is read whole) and every script and page under pkg/ui/assets, looking for a
// sentence that states a protocol requirement. One outside the helper fails the
// build, naming the file and line.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// protocolNeedHelperFile is the one file allowed to state a requirement.
const protocolNeedHelperFile = "pkg/executor/protocolneed.go"

// protocolRequirementPatterns recognise a sentence stating which protocol a
// device needs: "needs v15", "(needs v%d)", "protocol v16 or later",
// "requires v2", "v2 or newer", "predates the probe (v9)".
var protocolRequirementPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bneeds?\b\W{0,3}(?:protocol\s+)?v(?:%d|\d+)\b`),
	regexp.MustCompile(`(?i)\bprotocol\s+v(?:%d|\d+)\s+or\s+(?:later|newer)\b`),
	regexp.MustCompile(`(?i)\brequires?\s+(?:protocol\s+)?v(?:%d|\d+)\b`),
	regexp.MustCompile(`(?i)\bv(?:%d|\d+)\s+or\s+newer\b`),
	regexp.MustCompile(`(?i)predates[^"]{0,80}\(v(?:%d|\d+)\)`),
}

// protocolNeedAllowlist names the literals that match a pattern and are not a
// hub refusal of a device's protocol. Each says why. Keep it short: an entry
// here is a sentence nobody will rewrite when the advice changes.
var protocolNeedAllowlist = []struct {
	file, contains, reason string
}{
	{
		file:     "pkg/executor/install/verify.go",
		contains: "control plane requires v%d or newer",
		reason: "the device's own installer refusing a staged binary below the protocol floor of the " +
			"binary doing the install; it runs on the device, where HubBuild is the device's build and " +
			"the hub's upgrade path does not apply, and its remedy (--force, or another binary) is not " +
			"an upgrade",
	},
}

// gateFinding is one literal that matched.
type gateFinding struct {
	file string
	line int
	text string
}

// TestProtocolRefusalsGoThroughTheHelper is the gate.
func TestProtocolRefusalsGoThroughTheHelper(t *testing.T) {
	root := gateModuleRoot(t)
	var findings []gateFinding
	scanned := 0

	walk := func(dir string, want func(rel string) bool) {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if path != filepath.Join(root, dir) &&
					(name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
					return filepath.SkipDir
				}
				return nil
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
			if !want(rel) {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found, err := scanForProtocolRequirements(rel, src)
			if err != nil {
				t.Errorf("%s: %v", rel, err)
				return nil
			}
			scanned++
			findings = append(findings, found...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	goSource := func(rel string) bool {
		return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
	}
	walk("pkg", goSource)
	walk("cmd", goSource)
	walk("pkg/ui/assets", func(rel string) bool {
		return strings.HasSuffix(rel, ".js") || strings.HasSuffix(rel, ".html")
	})
	// A walk that silently found nothing would pass vacuously.
	if scanned < 500 {
		t.Fatalf("scanned only %d files under %s; the gate is not reading the source tree", scanned, root)
	}

	used := make([]bool, len(protocolNeedAllowlist))
	var report strings.Builder
	for _, f := range findings {
		allowed := false
		for i, a := range protocolNeedAllowlist {
			if f.file == a.file && strings.Contains(f.text, a.contains) {
				allowed, used[i] = true, true
			}
		}
		if !allowed {
			report.WriteString("\n  " + f.file + ":" + strconv.Itoa(f.line) + ": " + strconv.Quote(f.text))
		}
	}
	if report.Len() > 0 {
		t.Errorf("these strings state a protocol requirement outside %s:%s\n\n"+
			"Compose a refusal of a device's protocol with executor.NeedsProtocol (or ProtocolShortfall "+
			"plus AgentUpgradePath, or ProtocolDrop), which names the protocol the device speaks, the one "+
			"the hub needs, and the remedy that works for this hub's build. A literal that is genuinely not "+
			"such a refusal belongs in protocolNeedAllowlist, with the reason.",
			protocolNeedHelperFile, report.String())
	}
	for i, ok := range used {
		if !ok {
			a := protocolNeedAllowlist[i]
			t.Errorf("allowlist entry %s %q matches nothing any more; remove it", a.file, a.contains)
		}
	}
}

// scanForProtocolRequirements reports the strings in one source file that
// match a protocol-requirement pattern. rel is the slash-separated path from
// the module root; the helper's own file reports nothing.
func scanForProtocolRequirements(rel string, src []byte) ([]gateFinding, error) {
	if rel == protocolNeedHelperFile {
		return nil, nil
	}
	var strs []gateFinding
	switch {
	case strings.HasSuffix(rel, ".go"):
		var err error
		if strs, err = goStrings(rel, src); err != nil {
			return nil, err
		}
	case strings.HasSuffix(rel, ".js"):
		strs = jsStrings(rel, string(src))
	case strings.HasSuffix(rel, ".html"):
		strs = htmlText(rel, string(src))
	default:
		return nil, nil
	}
	var out []gateFinding
	for _, s := range strs {
		for _, re := range protocolRequirementPatterns {
			if re.MatchString(s.text) {
				out = append(out, s)
				break
			}
		}
	}
	return out, nil
}

// goStrings lists a Go file's string literals, each maximal run of literals
// joined by `+` folded into one string.
func goStrings(rel string, src []byte) ([]gateFinding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []gateFinding
	visit := func(pos token.Pos, s string) {
		out = append(out, gateFinding{file: rel, line: fset.Position(pos).Line, text: s})
	}
	walkGoStrings(f, visit)
	return out, nil
}

// walkGoStrings visits every string literal under n. A chain of `+` is
// flattened first, so "a " + "b" + x + "c" visits "a b" and "c": the literals
// a reader sees as one message are matched as one.
func walkGoStrings(n ast.Node, visit func(token.Pos, string)) {
	ast.Inspect(n, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if x.Op != token.ADD {
				return true
			}
			var run []string
			var runPos token.Pos
			flush := func() {
				if len(run) > 0 {
					visit(runPos, strings.Join(run, ""))
					run = nil
				}
			}
			for _, op := range flattenAdd(x) {
				if s, ok := goStringLit(op); ok {
					if len(run) == 0 {
						runPos = op.Pos()
					}
					run = append(run, s)
					continue
				}
				flush()
				walkGoStrings(op, visit)
			}
			flush()
			return false
		case *ast.BasicLit:
			if s, ok := goStringLit(x); ok {
				visit(x.Pos(), s)
			}
		}
		return true
	})
}

// flattenAdd lists the operands of a chain of `+`, in order, through
// parentheses.
func flattenAdd(e ast.Expr) []ast.Expr {
	switch x := e.(type) {
	case *ast.ParenExpr:
		if b, ok := x.X.(*ast.BinaryExpr); ok && b.Op == token.ADD {
			return flattenAdd(b)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return append(flattenAdd(x.X), flattenAdd(x.Y)...)
		}
	}
	return []ast.Expr{e}
}

func goStringLit(e ast.Expr) (string, bool) {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// jsStrings lists a script's string literals, outside comments, each run of
// literals joined by `+` folded into one string. A template literal's ${…}
// parts read as "…". The tokenizer knows enough JavaScript to skip comments and
// regular-expression literals, which is all it needs to find the strings.
func jsStrings(rel, src string) []gateFinding {
	type tok struct {
		kind byte // 's' string, '+' plus, 'x' anything else
		text string
		line int
	}
	var toks []tok
	line := 1
	prevSig := byte(0) // last significant code character, for telling a regex from a division
	prevWord := ""     // last identifier, for `return /re/`
	i := 0
	n := len(src)
	readString := func(q byte) string {
		var b strings.Builder
		i++ // opening quote
		depth := 0
		for i < n {
			c := src[i]
			if c == '\n' {
				line++
			}
			if q == '`' && depth > 0 {
				switch c {
				case '{':
					depth++
				case '}':
					depth--
				}
				i++
				continue
			}
			switch {
			case c == '\\' && i+1 < n:
				if src[i+1] == '\n' {
					line++
				}
				b.WriteByte(src[i+1])
				i += 2
				continue
			case c == q:
				i++
				return b.String()
			case q != '`' && c == '\n':
				// Unterminated; stop at the line end rather than swallow the file.
				i++
				return b.String()
			case q == '`' && c == '$' && i+1 < n && src[i+1] == '{':
				b.WriteString("…")
				depth = 1
				i += 2
				continue
			}
			b.WriteByte(c)
			i++
		}
		return b.String()
	}
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i < n && !(src[i] == '*' && i+1 < n && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
		case c == '/' && jsRegexAllowed(prevSig, prevWord):
			// A regular-expression literal: skip it, classes and escapes
			// included, so a quote inside one does not open a string.
			i++
			inClass := false
			for i < n && src[i] != '\n' {
				ch := src[i]
				if ch == '\\' {
					i += 2
					continue
				}
				if ch == '[' {
					inClass = true
				} else if ch == ']' {
					inClass = false
				} else if ch == '/' && !inClass {
					i++
					break
				}
				i++
			}
			for i < n && isJSIdent(src[i]) { // flags
				i++
			}
			toks = append(toks, tok{kind: 'x', line: line})
			prevSig, prevWord = 'r', ""
		case c == '\'' || c == '"' || c == '`':
			start := line
			s := readString(c)
			toks = append(toks, tok{kind: 's', text: s, line: start})
			prevSig, prevWord = 's', ""
		case c == '+':
			if i+1 < n && (src[i+1] == '+' || src[i+1] == '=') {
				toks = append(toks, tok{kind: 'x', line: line})
				i += 2
				prevSig, prevWord = '=', ""
				continue
			}
			toks = append(toks, tok{kind: '+', line: line})
			prevSig, prevWord = '+', ""
			i++
		case isJSIdent(c):
			j := i
			for j < n && isJSIdent(src[j]) {
				j++
			}
			toks = append(toks, tok{kind: 'x', line: line})
			prevSig, prevWord = 'a', src[i:j]
			i = j
		default:
			toks = append(toks, tok{kind: 'x', line: line})
			prevSig, prevWord = c, ""
			i++
		}
	}

	var out []gateFinding
	for k := 0; k < len(toks); k++ {
		if toks[k].kind != 's' {
			continue
		}
		text, at := toks[k].text, toks[k].line
		for k+2 < len(toks) && toks[k+1].kind == '+' && toks[k+2].kind == 's' {
			text += toks[k+2].text
			k += 2
		}
		out = append(out, gateFinding{file: rel, line: at, text: text})
	}
	return out
}

// jsRegexAllowed reports whether a '/' after the given token starts a regular
// expression rather than a division.
func jsRegexAllowed(prevSig byte, prevWord string) bool {
	switch prevWord {
	case "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await":
		return true
	}
	if prevSig == 0 {
		return true
	}
	return strings.IndexByte("(,=:[!&|?{};+-*%<>~^", prevSig) >= 0
}

func isJSIdent(c byte) bool {
	return c == '_' || c == '$' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}

// htmlText lists a page's lines with its comments removed: the served page
// strips them, and the text an operator reads is what is left.
func htmlText(rel, src string) []gateFinding {
	var b bytes.Buffer
	for {
		start := strings.Index(src, "<!--")
		if start < 0 {
			b.WriteString(src)
			break
		}
		end := strings.Index(src[start:], "-->")
		if end < 0 {
			b.WriteString(src[:start])
			break
		}
		b.WriteString(src[:start])
		// Keep the line count right.
		b.WriteString(strings.Repeat("\n", strings.Count(src[start:start+end], "\n")))
		src = src[start+end+3:]
	}
	var out []gateFinding
	for i, l := range strings.Split(b.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, gateFinding{file: rel, line: i + 1, text: l})
		}
	}
	return out
}

// gateModuleRoot finds the directory holding go.mod above the test's working
// directory.
func gateModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// TestProtocolGateScannerCatchesBypasses proves the scanner rather than the
// tree: messages written to slip past it — split across `+`, in a script, in
// a page — are caught, and the same text in the helper's own file is not.
func TestProtocolGateScannerCatchesBypasses(t *testing.T) {
	goSrc := []byte(`package x

import "fmt"

func refuse(v int) error {
	return fmt.Errorf("agent speaks protocol v%d; revocation "+
		"needs "+"v%d", v, 2)
}

func split(v int) string {
	return fmt.Sprint(v) + " is too old: the device requires " + "protocol v15"
}

var raw = ` + "`" + `install it on an agent of protocol v16 or later` + "`" + `

const parenthesised = ("speaks v%d, " + ("v2 or ")) + "newer is needed"

// A comment saying an agent needs v14 is not a message.
var fine = "the agent speaks protocol v14"
`)
	found, err := scanForProtocolRequirements("pkg/somewhere/refuse.go", goSrc)
	if err != nil {
		t.Fatal(err)
	}
	wantGo := []string{
		"revocation needs v%d",
		"requires protocol v15",
		"protocol v16 or later",
		"v2 or newer",
	}
	for _, w := range wantGo {
		if !findingContains(found, w) {
			t.Errorf("the scanner missed %q in Go source; found %+v", w, found)
		}
	}
	if len(found) != len(wantGo) {
		t.Errorf("the scanner reported %d Go strings, want %d (the comment and the plain sentence are "+
			"not requirements): %+v", len(found), len(wantGo), found)
	}

	jsSrc := `// needs v14 in a comment is fine
const re = /it's not a string/g;
function chip(d) {
  return d.old ? '<b>agent too old (needs ' +
    'v14)</b>' : "predates the probe " + ` + "`(v9) on ${d.name}`" + `;
}
/* the agent requires v2 — still a comment */
`
	found, err = scanForProtocolRequirements("pkg/ui/assets/js/99-test.js", []byte(jsSrc))
	if err != nil {
		t.Fatal(err)
	}
	if !findingContains(found, "needs v14") {
		t.Errorf("the scanner missed a requirement split across + in a script: %+v", found)
	}
	if !findingContains(found, "predates the probe (v9) on …") {
		t.Errorf("the scanner missed a requirement in a template literal: %+v", found)
	}
	if len(found) != 2 {
		t.Errorf("the scanner reported %d script strings, want 2 (comments are not messages): %+v",
			len(found), found)
	}
	// Each run is reported where it starts, so a finding can be gone to.
	for i, want := range []int{4, 5} {
		if i < len(found) && found[i].line != want {
			t.Errorf("finding %q is reported on line %d, want %d", found[i].text, found[i].line, want)
		}
	}

	html := "<p>Fine.</p>\n<!-- this agent needs v14 -->\n<span>Upgrade: needs v9</span>\n"
	found, err = scanForProtocolRequirements("pkg/ui/assets/index.html", []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].line != 3 {
		t.Errorf("the page scan reported %+v, want the one uncommented line, line 3", found)
	}

	// The helper itself is where these sentences belong.
	found, err = scanForProtocolRequirements(protocolNeedHelperFile, goSrc)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("the helper's own file was flagged: %+v", found)
	}
}

func findingContains(found []gateFinding, s string) bool {
	for _, f := range found {
		if strings.Contains(f.text, s) {
			return true
		}
	}
	return false
}
