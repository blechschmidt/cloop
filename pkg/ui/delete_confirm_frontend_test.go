package ui

// Every DELETE the dashboard sends is asked for first (Task 20422).
//
// Two did not ask: deleting a knowledge-base entry and revoking a project's
// repository grant each went to the API on one click — and the GitHub App
// panel's controls were routed from a listener on the whole document, so a
// revoke control injected anywhere on the page revoked a grant. The threat
// model (① Browser ↔ hub) leans on this: markup a missed escape lets through
// can name a registered action, so what bounds such a click is that a
// destructive one asks, inside the panel it belongs to.
//
// TestDashboard_EveryDeleteIsConfirmed reads every script the front ends are
// built from and holds each DELETE to one of two shapes: a confirm() call
// ahead of it in a function enclosing it, or the confirm button of a
// confirmation dialog that is the only control naming its action.
// TestDashboard_DeletesAskFirst clicks the two that did not ask through the
// real bundle under node.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// confirmedByDialog names the actions that send a DELETE from the confirm
// button of a dialog another action opened, and the dialog. Their own
// function does not ask, because asking is what the dialog is.
var confirmedByDialog = map[string]string{
	"submitDeleteProject": "delproj-overlay",
	"executeDeleteTask":   "delete-modal-overlay",
	"submitRemoveFeature": "delfeat-overlay",
}

// TestDashboard_EveryDeleteIsConfirmed: no script the hub serves sends a
// DELETE that nobody confirmed.
func TestDashboard_EveryDeleteIsConfirmed(t *testing.T) {
	index, err := assetFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	units := gateUnits(t)
	var sites []deleteSite
	for i := range units {
		u := &units[i]
		if u.toks, err = lexForGate(u.src); err != nil {
			t.Fatalf("%s: %v — the gate's lexer cannot read it, so it cannot vouch for its DELETEs", u.name, err)
		}
		found, err := deleteSitesIn(u.toks)
		if err != nil {
			t.Fatalf("%s: %v", u.name, err)
		}
		for i := range found {
			found[i].file = u.where(found[i].line)
		}
		sites = append(sites, found...)
		for _, bad := range indirectMethods(u.toks) {
			t.Errorf("%s calls apiMethod with a method that is not a string literal: a DELETE sent that "+
				"way is one this gate cannot see — name the method", u.where(bad))
		}
	}
	// 20 DELETE sites at Task 20422; far fewer means the scan went blind.
	if len(sites) < 15 {
		t.Fatalf("found %d DELETE requests in the dashboard's scripts; there are ~20, so the scan has gone vacuous", len(sites))
	}

	usedDialogs := map[string]bool{}
	for _, s := range sites {
		if s.confirmed {
			continue
		}
		overlay, ok := confirmedByDialog[s.action]
		if !ok {
			where := "a function"
			if s.fn != "" {
				where = s.fn
			}
			if s.action != "" {
				where = "action " + s.action
			}
			t.Errorf("%s sends a DELETE from %s without asking first: put `if (!confirm('…')) return;` "+
				"ahead of it, naming what is about to go — or, for a dialog's confirm button, list the action "+
				"and its dialog in confirmedByDialog", s.file, where)
			continue
		}
		usedDialogs[s.action] = true
		for _, problem := range dialogOnlyTrigger(string(index), s.action, overlay, units) {
			t.Errorf("%s sends a DELETE from %s, whose confirmation is dialog #%s, but %s", s.file, s.action, overlay, problem)
		}
	}
	t.Logf("%d DELETE requests in %d scripts; %d sent from a confirmation dialog's button", len(sites), len(units), len(usedDialogs))
	for action := range confirmedByDialog {
		if !usedDialogs[action] {
			t.Errorf("confirmedByDialog lists %s, which sends no DELETE any more: remove the entry", action)
		}
	}
}

// gateUnit is a script the browser runs as one: the bundle, whose fragments
// only parse together — 00-core.js opens the IIFE the last one closes — or a
// file of its own.
type gateUnit struct {
	name   string
	src    string
	starts []gateFragment
	toks   []gateTok
}

// gateFragment is a file and the line of its unit it starts on.
type gateFragment struct {
	file string
	line int
}

// where names a line of the unit by its file and the file's own line.
func (u gateUnit) where(line int) string {
	for i := len(u.starts) - 1; i >= 0; i-- {
		if line >= u.starts[i].line {
			return fmt.Sprintf("%s:%d", u.starts[i].file, line-u.starts[i].line+1)
		}
	}
	return fmt.Sprintf("%s:%d", u.name, line)
}

// gateUnits is every script the front ends run: the bundle, concatenated in
// bundleFiles' order as static.go serves it, and every other script alone.
func gateUnits(t *testing.T) []gateUnit {
	t.Helper()
	scripts := frontEndScripts(t)
	var bundle strings.Builder
	bu := gateUnit{name: "bundle"}
	line := 1
	inBundle := map[string]bool{}
	for _, f := range bundleFiles {
		src, ok := scripts[f]
		if !ok {
			t.Fatalf("bundle fragment %s is not among the scripts", f)
		}
		inBundle[f] = true
		bu.starts = append(bu.starts, gateFragment{file: f, line: line})
		bundle.WriteString(src)
		line += strings.Count(src, "\n")
	}
	bu.src = bundle.String()
	units := []gateUnit{bu}
	var rest []string
	for p := range scripts {
		if !inBundle[p] {
			rest = append(rest, p)
		}
	}
	sort.Strings(rest)
	for _, p := range rest {
		units = append(units, gateUnit{name: p, src: scripts[p], starts: []gateFragment{{file: p, line: 1}}})
	}
	return units
}

// TestDeleteGateReadsTheShapes holds the gate's reading to small programs, so
// a gate gone blind fails here rather than passing everything.
func TestDeleteGateReadsTheShapes(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string // per DELETE: "confirmed", or "fn:<name>"/"action:<name>" when not
	}{
		{"asks first", `function a(id){ if (!confirm('Delete '+id+'?')) return; apiMethod('DELETE', '/x/'+id); }`,
			[]string{"confirmed"}},
		{"does not ask", `function a(id){ apiMethod('DELETE', '/x/'+id).then(d => {}); }`,
			[]string{"fn:a"}},
		{"asks after", `function a(){ apiMethod('DELETE', '/x'); confirm('late'); }`, []string{"fn:a"}},
		{"asks in another function", `function b(){ if (!confirm('?')) return; } function a(){ apiMethod('DELETE','/x') }`,
			[]string{"fn:a"}},
		{"asks in the enclosing function", `function a(ids){ if (!window.confirm('all?')) return; ids.forEach(i => h.apiMethod('DELETE', '/x/' + i)); }`,
			[]string{"confirmed"}},
		{"asks inside the promise", `function a(){ return load().then(p => { if (!confirm(p)) return; return apiMethod('DELETE','/x'); }); }`,
			[]string{"confirmed"}},
		{"another object's confirm", `function a(){ if (!dlg.confirm('?')) return; apiMethod('DELETE','/x'); }`,
			[]string{"fn:a"}},
		{"a registered action", `act('submitX', function() { apiMethod('DELETE', '/x'); });`, []string{"action:submitX"}},
		{"a registered arrow", `act('submitY', () => { apiMethod('DELETE', '/y'); }, NUM);`, []string{"action:submitY"}},
		{"strings and comments are not requests, any case of the method is",
			"// apiMethod('DELETE')\nconst s = \"DELETEd\"; /* 'DELETE' */\n" +
				"function a(){ return 'delete me'.length + fetch('/x', {method: 'delete'}); }",
			[]string{"fn:a"}},
		{"templates, regexes and braces", "const t = `${a ? '{' : '}'}x${`${b}`}`; const r = /['\"{]/g;\n" +
			"function a(){ const n = x / 2 / y; apiMethod('DELETE', `/x/${n}`); }", []string{"fn:a"}},
		{"a block is not a function", `function a(){ if (x) { apiMethod('DELETE','/x'); } }`, []string{"fn:a"}},
		{"a confirm elsewhere in the bundle does not count",
			`(function(){ function b(){ if (!confirm('x')) return; } document.addEventListener('click', function(ev){ apiMethod('DELETE','/x'); }); })();`,
			[]string{"fn:"}},
		{"another action's confirm does not count",
			`act('a', function(){ if (!confirm('?')) return; }); act('b', function(){ apiMethod('DELETE','/x'); });`,
			[]string{"action:b"}},
		{"a method's own confirm counts",
			`const o = { remove: function(id) { if (!confirm(id)) return; apiMethod('DELETE', '/x/' + id); } };`,
			[]string{"confirmed"}},
	}
	for _, c := range cases {
		toks, err := lexForGate(c.src)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		sites, err := deleteSitesIn(toks)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var got []string
		for _, s := range sites {
			switch {
			case s.confirmed:
				got = append(got, "confirmed")
			case s.action != "":
				got = append(got, "action:"+s.action)
			default:
				got = append(got, "fn:"+s.fn)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: read %v, want %v", c.name, got, c.want)
		}
	}
	if bad := indirectMethods(mustLex(t, `function f(m){ apiMethod(m, '/x'); apiMethod('GET', '/y'); }`)); len(bad) != 1 {
		t.Errorf("a non-literal method was reported %d times, want once", len(bad))
	}
	if bad := indirectMethods(mustLex(t, `function apiMethod(method, url){ return apiMethod(method, url, null, true); }`)); len(bad) != 0 {
		t.Errorf("apiMethod's own replay was reported: %v", bad)
	}
}

func mustLex(t *testing.T, src string) []gateTok {
	t.Helper()
	toks, err := lexForGate(src)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

// TestDashboard_DeletesAskFirst clicks the two DELETEs that did not ask
// (Task 20422) through the bundle's dispatcher, under node: deleting a
// knowledge-base entry and revoking a repository grant. Declined, nothing is
// sent; accepted, the DELETE is; and a revoke control outside the GitHub App
// panel, or naming what the page is not showing, neither asks nor sends.
func TestDashboard_DeletesAskFirst(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	shim, _ := filepath.Abs("testdata/domshim.js")
	scenarios, _ := filepath.Abs("testdata/delete_confirm_scenarios.js")
	cmd := exec.Command(node, scenarios, shim, bundle, "delete_confirmations")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenario failed: %v\n%s\n%s", err, out, stderr)
	}
	var res map[string]struct {
		Error string `json:"error"`
		Tried []struct {
			Label string   `json:"label"`
			Asked []string `json:"asked"`
			Error string   `json:"error"`
			Sent  []string `json:"sent"`
		} `json:"tried"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	r := res["delete_confirmations"]
	if r.Error != "" {
		t.Fatalf("the scenario threw: %s", r.Error)
	}
	want := []struct {
		label string
		asks  string // a word the question must name; "" when nothing may be asked
		sent  string // the DELETE sent, or ""
	}{
		{"kb declined", "Deploy runbook", ""},
		{"kb accepted", "Deploy runbook", "DELETE /api/kb/7"},
		{"kb unknown entry", "", ""},
		{"revoke outside the panel", "", ""},
		{"old revoke attribute outside the panel", "", ""},
		{"revoke declined", "acme/api", ""},
		{"revoke accepted", "acme/web", "DELETE /api/projects/0/repositories?grant=grant-api"},
		{"revoke unknown grant", "", ""},
	}
	if len(r.Tried) != len(want) {
		t.Fatalf("tried %d clicks, want %d: %+v", len(r.Tried), len(want), r.Tried)
	}
	for i, w := range want {
		got := r.Tried[i]
		if got.Label != w.label {
			t.Fatalf("attempt %d is %q, want %q", i, got.Label, w.label)
		}
		if got.Error != "" {
			t.Errorf("%s: the dispatcher threw %q", w.label, got.Error)
		}
		switch {
		case w.asks == "" && len(got.Asked) != 0:
			t.Errorf("%s: asked %q, want no question", w.label, got.Asked)
		case w.asks != "" && (len(got.Asked) != 1 || !strings.Contains(got.Asked[0], w.asks)):
			t.Errorf("%s: asked %q, want one question naming %q", w.label, got.Asked, w.asks)
		}
		var sent string
		if len(got.Sent) > 0 {
			sent = strings.Join(got.Sent, "; ")
		}
		if sent != w.sent {
			t.Errorf("%s: sent %q, want %q", w.label, sent, w.sent)
		}
	}
}

// ── the gate's reading of a script ──────────────────────────────────────────

// gateTok is one token of a script as far as the DELETE gate reads one.
type gateTok struct {
	kind byte // 'i' word, 's' string literal, 't' template, 'n' number, 'r' regex, 'p' punctuator
	text string
	line int
}

// gateRegexKeywords are words after which a '/' starts a regular expression.
var gateRegexKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true,
}

func gateWordByte(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b >= 0x80
}

// lexForGate tokenizes a script: comments dropped, strings, templates and
// regular expressions kept whole, a template's ${…} expressions read as code.
// A '/' is division after a value — a word that is not a keyword, a literal,
// ')' or ']' — and a regular expression anywhere else.
func lexForGate(src string) ([]gateTok, error) {
	var toks []gateTok
	i, line := 0, 1
	prevValue := func() bool {
		if len(toks) == 0 {
			return false
		}
		switch p := toks[len(toks)-1]; p.kind {
		case 'n', 's', 't', 'r':
			return true
		case 'i':
			return !gateRegexKeywords[p.text]
		case 'p':
			return p.text == ")" || p.text == "]"
		}
		return false
	}
	var code func(inTemplate bool) error
	code = func(inTemplate bool) error {
		depth := 0
		for i < len(src) {
			c := src[i]
			switch {
			case c == '\n':
				line++
				i++
			case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				for i < len(src) && src[i] != '\n' {
					i++
				}
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				end := strings.Index(src[i+2:], "*/")
				if end < 0 {
					return fmt.Errorf("line %d: unterminated block comment", line)
				}
				line += strings.Count(src[i:i+end+4], "\n")
				i += end + 4
			case c == '\'' || c == '"':
				start, at := i, line
				for i++; i < len(src) && src[i] != c; i++ {
					if src[i] == '\\' {
						i++
					}
					if i < len(src) && src[i] == '\n' {
						if src[i-1] != '\\' {
							return fmt.Errorf("line %d: a string runs past its line", at)
						}
						line++
					}
				}
				if i >= len(src) {
					return fmt.Errorf("line %d: unterminated string", at)
				}
				toks = append(toks, gateTok{'s', src[start+1 : i], at})
				i++
			case c == '`':
				start, at := i, len(toks)
				toks = append(toks, gateTok{'t', "", line})
				for i++; ; {
					if i >= len(src) {
						return fmt.Errorf("line %d: unterminated template", line)
					}
					if src[i] == '\\' {
						if i+1 < len(src) && src[i+1] == '\n' {
							line++
						}
						i += 2
						continue
					}
					if src[i] == '\n' {
						line++
					}
					if src[i] == '`' {
						i++
						toks[at].text = src[start:i]
						break
					}
					if src[i] == '$' && i+1 < len(src) && src[i+1] == '{' {
						i += 2
						if err := code(true); err != nil {
							return err
						}
						continue
					}
					i++
				}
			case c == '/' && prevValue():
				toks = append(toks, gateTok{'p', "/", line})
				i++
			case c == '/':
				start, class := i, false
				for i++; ; i++ {
					if i >= len(src) || src[i] == '\n' {
						return fmt.Errorf("line %d: a regular expression runs past its line", line)
					}
					if src[i] == '\\' {
						i++
						continue
					}
					if class {
						class = src[i] != ']'
					} else if src[i] == '[' {
						class = true
					} else if src[i] == '/' {
						break
					}
				}
				for i++; i < len(src) && gateWordByte(src[i]); i++ {
				}
				toks = append(toks, gateTok{'r', src[start:i], line})
			case c >= '0' && c <= '9':
				start := i
				for i < len(src) && (gateWordByte(src[i]) || src[i] == '.') {
					i++
				}
				toks = append(toks, gateTok{'n', src[start:i], line})
			case gateWordByte(c):
				start := i
				for i < len(src) && gateWordByte(src[i]) {
					i++
				}
				toks = append(toks, gateTok{'i', src[start:i], line})
			case c == '=' && i+1 < len(src) && src[i+1] == '>':
				toks = append(toks, gateTok{'p', "=>", line})
				i += 2
			case c == '{':
				depth++
				toks = append(toks, gateTok{'p', "{", line})
				i++
			case c == '}':
				if inTemplate && depth == 0 {
					i++
					return nil
				}
				depth--
				toks = append(toks, gateTok{'p', "}", line})
				i++
			default:
				toks = append(toks, gateTok{'p', string(c), line})
				i++
			}
		}
		if inTemplate {
			return fmt.Errorf("line %d: unterminated template expression", line)
		}
		return nil
	}
	return toks, code(false)
}

// gateFunc is one function body: its braces' token indices, its name when it
// has one, the action it is registered as — act('name', function …) — when it
// is one, and whether it is a callback: an argument of a call.
type gateFunc struct {
	open, close  int
	name, action string
	callback     bool
}

// gateFunctions finds every function body in toks: the brace after `=>`, or
// after the parameter list of `function`, `function name` or a method `name`.
func gateFunctions(toks []gateTok) ([]gateFunc, error) {
	opener := make([]int, len(toks)) // a ')' → its '('
	type open struct {
		idx  int
		text string
		fn   *gateFunc
	}
	var stack []open
	var out []gateFunc
	punct := func(k int, s string) bool { return k >= 0 && k < len(toks) && toks[k].kind == 'p' && toks[k].text == s }
	word := func(k int) bool { return k >= 0 && k < len(toks) && toks[k].kind == 'i' }
	// registered reports the action k, a function's first token, is
	// registered as: act('name', <here>.
	registered := func(k int) string {
		if punct(k-1, ",") && k >= 4 && toks[k-2].kind == 's' && punct(k-3, "(") &&
			word(k-4) && (toks[k-4].text == "act" || toks[k-4].text == "actOn") {
			return toks[k-2].text
		}
		return ""
	}
	// classify fills in what kind of function starts at token k, given the
	// innermost bracket open around it.
	classify := func(f *gateFunc, k int, around *open) {
		if f.action = registered(k); f.action != "" {
			return
		}
		if (punct(k-1, "=") || punct(k-1, ":")) && word(k-2) {
			f.name = toks[k-2].text
			return
		}
		if around != nil && around.text == "(" && (punct(k-1, "(") || punct(k-1, ",")) {
			b := around.idx - 1
			f.callback = punct(b, ")") || punct(b, "]") || word(b) && !gateRegexKeywords[toks[b].text] &&
				toks[b].text != "if" && toks[b].text != "while" && toks[b].text != "for" && toks[b].text != "switch"
		}
	}
	for k, tk := range toks {
		if tk.kind != 'p' {
			continue
		}
		var around *open
		if len(stack) > 0 {
			around = &stack[len(stack)-1]
		}
		switch tk.text {
		case "(", "[":
			stack = append(stack, open{idx: k, text: tk.text})
		case ")", "]":
			want := map[string]string{")": "(", "]": "["}[tk.text]
			if around == nil || around.text != want {
				return nil, fmt.Errorf("line %d: unbalanced '%s'", tk.line, tk.text)
			}
			opener[k] = around.idx
			stack = stack[:len(stack)-1]
		case "{":
			o := open{idx: k, text: "{"}
			switch {
			case punct(k-1, "=>"):
				f := &gateFunc{open: k}
				start := k - 2
				if punct(k-2, ")") {
					start = opener[k-2]
				}
				classify(f, start, around)
				o.fn = f
			case punct(k-1, ")") && word(opener[k-1]-1):
				p := opener[k-1]
				switch w := toks[p-1].text; w {
				case "if", "for", "while", "switch", "catch", "with":
				case "function":
					f := &gateFunc{open: k}
					classify(f, p-1, around)
					o.fn = f
				default:
					f := &gateFunc{open: k, name: w}
					if p >= 2 && word(p-2) && toks[p-2].text == "function" {
						if f.action = registered(p - 2); f.action != "" {
							f.name = ""
						}
					}
					o.fn = f
				}
			}
			stack = append(stack, o)
		case "}":
			if around == nil || around.text != "{" {
				return nil, fmt.Errorf("line %d: unbalanced '}'", tk.line)
			}
			stack = stack[:len(stack)-1]
			if around.fn != nil {
				around.fn.close = k
				out = append(out, *around.fn)
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unbalanced: %d brackets never closed", len(stack))
	}
	return out, nil
}

// deleteSite is one DELETE a script sends: where (file is filled in by the
// caller, from line), from which function or action, and whether a confirm()
// call precedes it in a function enclosing it.
type deleteSite struct {
	file       string
	line       int
	fn, action string
	confirmed  bool
}

// deleteSitesIn finds every string literal naming the DELETE method — in any
// case: fetch upper-cases it — and judges each. A confirm() call counts when
// it precedes the DELETE in the function sending it, or in a function that
// one is a callback of, out to the first named function or registered action
// — never beyond, where a confirm() asks about something else.
func deleteSitesIn(toks []gateTok) ([]deleteSite, error) {
	funcs, err := gateFunctions(toks)
	if err != nil {
		return nil, err
	}
	var out []deleteSite
	for k, tk := range toks {
		if tk.kind != 's' || !strings.EqualFold(tk.text, "delete") {
			continue
		}
		s := deleteSite{line: tk.line}
		var enclosing []gateFunc
		for _, f := range funcs {
			if f.open < k && k < f.close {
				enclosing = append(enclosing, f)
			}
		}
		sort.Slice(enclosing, func(a, b int) bool { return enclosing[a].open > enclosing[b].open })
		if len(enclosing) > 0 {
			s.fn, s.action = enclosing[0].name, enclosing[0].action
		}
		for i, f := range enclosing {
			if i > 0 && f.name == "" && f.action == "" && !f.callback {
				break // a wrapper — the bundle's IIFE — whose confirm() asks about something else
			}
			for j := f.open + 1; j < k && !s.confirmed; j++ {
				s.confirmed = isConfirmCall(toks, j)
			}
			if !f.callback {
				break
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// isConfirmCall reports whether toks[j] starts confirm( or window.confirm(.
func isConfirmCall(toks []gateTok, j int) bool {
	if toks[j].kind != 'i' || toks[j].text != "confirm" || j+1 >= len(toks) || toks[j+1].text != "(" {
		return false
	}
	if j >= 1 && toks[j-1].kind == 'p' && toks[j-1].text == "." {
		return j >= 2 && toks[j-2].kind == 'i' && toks[j-2].text == "window"
	}
	return true
}

// indirectMethods lists the lines where apiMethod is called with a method
// that is not a string literal — outside apiMethod itself, which replays its
// own.
func indirectMethods(toks []gateTok) []int {
	funcs, err := gateFunctions(toks)
	if err != nil {
		return nil
	}
	var out []int
	for k := 0; k+2 < len(toks); k++ {
		if toks[k].kind != 'i' || toks[k].text != "apiMethod" || toks[k+1].text != "(" || toks[k+2].kind == 's' {
			continue
		}
		if k >= 1 && toks[k-1].text == "function" {
			continue // the definition
		}
		inside := false
		for _, f := range funcs {
			if f.name == "apiMethod" && f.open < k && k < f.close {
				inside = true
			}
		}
		if !inside {
			out = append(out, toks[k].line)
		}
	}
	return out
}

// dialogOnlyTrigger reports why the action's DELETE could be sent other than
// from the confirm button of dialog #overlay: a control in index.html naming
// it outside that dialog, markup built in a script naming it, a call of it by
// name, or no such control at all.
func dialogOnlyTrigger(index, action, overlay string, units []gateUnit) []string {
	var problems []string
	controls := 0
	for _, el := range htmlElements(index) {
		if el.attrs["data-action"] != action {
			continue
		}
		controls++
		inside := false
		for _, a := range el.ancestors {
			if a["id"] == overlay {
				_, inside = a["data-overlay"]
			}
		}
		if !inside {
			problems = append(problems, fmt.Sprintf("index.html names it on a <%s> outside that dialog", el.tag))
		}
	}
	if controls == 0 {
		problems = append(problems, "no control in index.html names it")
	}
	markup := regexp.MustCompile(`data-action=\\?["']` + regexp.QuoteMeta(action) + `\\?["']`)
	for _, u := range units {
		for k, tk := range u.toks {
			if (tk.kind == 's' || tk.kind == 't') && markup.MatchString(tk.text) {
				problems = append(problems, u.where(tk.line)+" builds a control naming it")
			}
			if tk.kind == 'i' && tk.text == action && k+1 < len(u.toks) && u.toks[k+1].text == "(" {
				problems = append(problems, u.where(tk.line)+" calls it by name")
			}
		}
	}
	return problems
}

// htmlElement is one element of a document: its tag, attributes, and every
// enclosing element's attributes, outermost first.
type htmlElement struct {
	tag       string
	attrs     map[string]string
	ancestors []map[string]string
}

var (
	htmlTagRe  = regexp.MustCompile(`<!--[\s\S]*?-->|<(/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	htmlAttrRe = regexp.MustCompile(`([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?`)
	htmlVoid   = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
		"img": true, "input": true, "link": true, "meta": true, "param": true, "source": true, "track": true, "wbr": true}
)

// htmlElements walks a well-formed document — the dashboard's own — keeping
// the stack of open elements.
func htmlElements(doc string) []htmlElement {
	type open struct {
		tag   string
		attrs map[string]string
	}
	var stack []open
	var out []htmlElement
	for _, m := range htmlTagRe.FindAllStringSubmatch(doc, -1) {
		if m[2] == "" {
			continue // a comment
		}
		tag := strings.ToLower(m[2])
		if m[1] == "/" {
			for n := len(stack) - 1; n >= 0; n-- {
				if stack[n].tag == tag {
					stack = stack[:n]
					break
				}
			}
			continue
		}
		attrs := map[string]string{}
		for _, a := range htmlAttrRe.FindAllStringSubmatch(m[3], -1) {
			attrs[strings.ToLower(a[1])] = a[2] + a[3] + a[4]
		}
		anc := make([]map[string]string, 0, len(stack))
		for _, o := range stack {
			anc = append(anc, o.attrs)
		}
		out = append(out, htmlElement{tag: tag, attrs: attrs, ancestors: anc})
		if !htmlVoid[tag] && !strings.HasSuffix(strings.TrimSpace(m[3]), "/") {
			stack = append(stack, open{tag: tag, attrs: attrs})
		}
	}
	return out
}
