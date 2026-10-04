package ui

// A static gate over the browser drivers in testdata/*_browser.js (Task 20372).
//
// Every browser test in this package runs a node script and waits for node to
// exit. Each driver's CDP client used to arm a 20-second timeout per command
// and never clear it when the reply arrived, so once a driver had printed its
// result node stayed alive until the last command's timer ran out — up to 20
// seconds of nothing, per driver, on every run of the race step. A driver that
// relies on the event loop draining is one forgotten timer, socket or Chrome
// helper away from the same idle, so each driver also exits explicitly.
//
// executor_virtual_browser.js went from 21 s to 0.9 s when its timers were
// first cleared (Task 20356); seven drivers still had the old client when this
// gate was written. It reads the source because the failure is silent at run
// time: an idling driver passes, just slowly, and nothing points at the
// timer.
//
// The rules, applied to node's own code (comments, strings, regular
// expressions and template-literal text are blanked first, so page code that
// a driver ships to Chrome inside a template is not node's):
//
//   - every setTimeout is a sleep — the whole body of a Promise executor whose
//     resolve it calls, so the timer is the thing awaited and cannot outlive
//     its purpose — or is unref()'d, or is kept in a variable that some
//     clearTimeout clears;
//   - every driver calls process.exit with something other than a bare 1, i.e.
//     it exits on success and not only on failure.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBrowserDriversReleaseNodeWhenDone(t *testing.T) {
	drivers, err := filepath.Glob(filepath.Join("testdata", "*_browser.js"))
	if err != nil {
		t.Fatal(err)
	}
	if len(drivers) < 10 {
		t.Fatalf("found %d drivers in testdata; the glob is wrong or the drivers moved", len(drivers))
	}
	for _, path := range drivers {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, problem := range driverIdleProblems(string(src)) {
			t.Errorf("%s: %s", path, problem)
		}
	}
}

// The gate must fail on what it was written for, or a quiet change to the
// scanner could leave it passing everything.
func TestBrowserDriverGuardCatchesIdlingDrivers(t *testing.T) {
	const good = `
const sleep = ms => new Promise(r => setTimeout(r, ms));
class CDP {
  send(method, params) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(method + ' timed out')), 20000);
      this.pending.set(1, {resolve: v => { clearTimeout(timer); resolve(v); }, reject});
    });
  }
}
async function connect() {
  await new Promise((ok, bad) => { setTimeout(() => bad(new Error('x')), 15000).unref(); });
  // setTimeout(() => {}, 20000) in a comment is not code
  const page = ` + "`setTimeout(() => location.reload(), 20000); const re = /'/;`" + `;
  const re = /setTimeout\(/g;
}
main().then(() => process.exit(0), () => process.exit(1));
`
	if p := driverIdleProblems(good); len(p) != 0 {
		t.Fatalf("a driver that sleeps, clears, unrefs and exits was flagged: %q", p)
	}

	cases := map[string]string{
		"armed per command and never cleared": `
class CDP {
  send(m) {
    return new Promise((resolve, reject) => {
      setTimeout(() => { if (this.pending.delete(1)) reject(new Error(m)); }, 20000);
    });
  }
}
main().then(() => process.exit(0));`,
		"kept in a variable nobody clears": `
const t = setTimeout(() => {}, 20000);
main().then(() => process.exit(0));`,
		"a race between a timer and an event": `
await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000); });
main().then(() => process.exit(0));`,
		"exits only on failure": `
const sleep = ms => new Promise(r => setTimeout(r, ms));
main().catch(err => { console.log(err); process.exit(1); });`,
		"never exits": `
const sleep = ms => new Promise(r => setTimeout(r, ms));
main();`,
	}
	for name, src := range cases {
		if p := driverIdleProblems(src); len(p) == 0 {
			t.Errorf("%s: the gate passed a driver it exists to catch", name)
		}
	}
}

var (
	setTimeoutCall = regexp.MustCompile(`\bsetTimeout\s*\(`)
	// new Promise(r => setTimeout(r, ms)) — the timer is the whole executor.
	sleepPrefix = regexp.MustCompile(`new\s+Promise\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*$`)
	assignedTo  = regexp.MustCompile(`(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*$`)
	unrefAfter  = regexp.MustCompile(`^\s*\.\s*unref\s*\(\s*\)`)
	exitCall    = regexp.MustCompile(`\bprocess\s*\.\s*exit\s*\(([^)]*)\)`)
)

// driverIdleProblems lists the ways a driver can keep node alive after its
// work is done.
func driverIdleProblems(src string) []string {
	code := maskJS(src)
	var problems []string
	lineOf := func(i int) int { return strings.Count(code[:i], "\n") + 1 }

	for _, loc := range setTimeoutCall.FindAllStringIndex(code, -1) {
		open := loc[1] - 1
		close := matchingParen(code, open)
		if close < 0 {
			problems = append(problems, fmt.Sprintf("line %d: cannot find the end of this setTimeout call", lineOf(loc[0])))
			continue
		}
		before, args, after := code[:loc[0]], code[open+1:close], code[close+1:]

		if unrefAfter.MatchString(after) {
			continue
		}
		if m := sleepPrefix.FindStringSubmatch(before); m != nil {
			resolve := m[1]
			if regexp.MustCompile(`^\s*`+regexp.QuoteMeta(resolve)+`\s*,`).MatchString(args) &&
				regexp.MustCompile(`^\s*\)`).MatchString(after) {
				continue
			}
		}
		if m := assignedTo.FindStringSubmatch(before); m != nil {
			cleared := regexp.MustCompile(`\bclearTimeout\s*\(\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*` +
				regexp.QuoteMeta(m[1]) + `\s*\)`)
			if cleared.MatchString(code) {
				continue
			}
			problems = append(problems, fmt.Sprintf("line %d: the timer kept in %q is never cleared, so it holds node "+
				"alive for its full span after the work it guards is done", lineOf(loc[0]), m[1]))
			continue
		}
		problems = append(problems, fmt.Sprintf("line %d: arms a timer it can neither clear nor unref — clear it when "+
			"the thing it guards arrives (keep the handle and clearTimeout it), or unref() it", lineOf(loc[0])))
	}

	exits := false
	for _, m := range exitCall.FindAllStringSubmatch(code, -1) {
		if strings.TrimSpace(m[1]) != "1" {
			exits = true
		}
	}
	if !exits {
		problems = append(problems, "never calls process.exit on success, so node waits for every handle "+
			"(a timer, the CDP socket, Chrome's stderr pipe held by a helper) to close by itself")
	}
	return problems
}

// matchingParen returns the index of the ')' closing the '(' at open, in code
// whose strings and comments are already blanked, or -1.
func matchingParen(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// maskJS returns src with comments, string literals, regular-expression
// literals and the text of template literals replaced by spaces (newlines
// kept, so offsets and line numbers still match the source). Code inside a
// template's ${…} is kept: that is node's code too.
//
// Whether a '/' starts a regular expression is decided the usual way, from
// the token before it. That can be fooled by contrived code; these drivers are
// this repository's own, and TestBrowserDriverGuardCatchesIdlingDrivers holds
// the masker to the shapes they use.
func maskJS(src string) string {
	out := []byte(src)
	n := len(out)
	blank := func(from, to int) {
		for k := from; k < to && k < n; k++ {
			if out[k] != '\n' {
				out[k] = ' '
			}
		}
	}
	type mode struct {
		template bool // in template-literal text
		depth    int  // braces open in this code region (a ${…} ends at depth 0)
	}
	stack := []mode{{}}
	var prev byte // last significant code character
	prevWord := ""
	regexAfterWord := map[string]bool{"return": true, "typeof": true, "instanceof": true, "in": true,
		"of": true, "new": true, "delete": true, "void": true, "throw": true, "case": true, "do": true,
		"else": true, "yield": true, "await": true}

	i := 0
	for i < n {
		top := &stack[len(stack)-1]
		c := out[i]
		if top.template {
			switch {
			case c == '\\':
				blank(i, i+2)
				i += 2
			case c == '`':
				blank(i, i+1)
				stack = stack[:len(stack)-1]
				prev, prevWord = 'a', ""
				i++
			case c == '$' && i+1 < n && out[i+1] == '{':
				blank(i, i+2)
				stack = append(stack, mode{})
				prev, prevWord = '{', ""
				i += 2
			default:
				blank(i, i+1)
				i++
			}
			continue
		}
		var next byte
		if i+1 < n {
			next = out[i+1]
		}
		switch {
		case c == '/' && next == '/':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = n - i
			}
			blank(i, i+end)
			i += end
		case c == '/' && next == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				end = n - i - 2
			}
			blank(i, i+2+end+2)
			i += 2 + end + 2
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && out[j] != c && out[j] != '\n' {
				if out[j] == '\\' {
					j++
				}
				j++
			}
			blank(i, j+1)
			prev, prevWord = 'a', ""
			i = j + 1
		case c == '`':
			blank(i, i+1)
			stack = append(stack, mode{template: true})
			i++
		case c == '/' && (prev == 0 || strings.IndexByte("(,=:[!&|?{};+-*%<>~^", prev) >= 0 ||
			(prev == 'a' && regexAfterWord[prevWord])):
			j, inClass := i+1, false
			for j < n && out[j] != '\n' {
				if out[j] == '\\' {
					j += 2
					continue
				}
				if out[j] == '[' {
					inClass = true
				} else if out[j] == ']' {
					inClass = false
				} else if out[j] == '/' && !inClass {
					break
				}
				j++
			}
			j++
			for j < n && (out[j] >= 'a' && out[j] <= 'z') {
				j++
			}
			blank(i, j)
			prev, prevWord = 'a', ""
			i = j
		case c == '{':
			top.depth++
			prev, prevWord = c, ""
			i++
		case c == '}':
			if len(stack) > 1 && top.depth == 0 {
				blank(i, i+1)
				stack = stack[:len(stack)-1]
				i++
				continue
			}
			top.depth--
			prev, prevWord = c, ""
			i++
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '_' || c == '$' || (c|0x20 >= 'a' && c|0x20 <= 'z') || (c >= '0' && c <= '9'):
			j := i
			for j < n && (out[j] == '_' || out[j] == '$' || (out[j]|0x20 >= 'a' && out[j]|0x20 <= 'z') ||
				(out[j] >= '0' && out[j] <= '9') || out[j] == '.' && c >= '0' && c <= '9') {
				j++
			}
			prev, prevWord = 'a', src[i:j]
			i = j
		default:
			prev, prevWord = c, ""
			i++
		}
	}
	return string(out)
}
