package ui

// jsstrip.go removes whole-line `//` comments from the dashboard's script
// bundle before it is served (Task 20341).
//
// # Why
//
// The first-paint budget (assetbudget_test.go) measured that 36% of the
// bundle's wire bytes were comment lines — prose written for the next
// maintainer, shipped to every browser that opens the dashboard. Each panel
// added since has had to argue for a budget raise, and the notes in that file
// asked, raise after raise, for the build step that stops shipping them. This
// is it: the source keeps its comments, the wire does not.
//
// # What it does, and deliberately does not do
//
// A line whose first non-blank characters begin a `//` comment — in code, not
// inside a string, template literal, regular expression or block comment — is
// replaced by an empty line. Nothing else changes: no minification, no
// renaming, no trailing-comment removal, and the line count is preserved so a
// stack trace from the browser (errboundary.js reports them) still points at
// the same line of the concatenated source.
//
// # Why it cannot be fooled by a slash
//
// Telling a comment from the inside of a template literal needs a lexer, and a
// JavaScript lexer has one decision it cannot make locally: whether a `/`
// starts a regular expression or is division. Guess wrong and the lexer can
// believe a backtick inside a regex opens a template, and from then on strip
// lines that were template *content* — silently changing rendered HTML.
//
// So this lexer does not guess. Every slash in code is read every way the
// grammar allows after the token before it (slashReadings): only as a regex
// after an operator or a keyword like `return`, only as division after an
// identifier or literal, and both ways after `)`, `}`, `++`/`--` or a word
// that is sometimes a keyword. The readings are followed to the end of their
// line (memoised by position and state, so the work stays linear in
// practice), and a line is accepted only when every reading that is valid
// JavaScript ends in the same state. Which reading the parser would really
// take then cannot matter, because the answer — which later lines are
// comments — is the same for all of them. A line whose valid readings
// disagree is refused.
//
// It also refuses what it does not model: a lone carriage return or U+2028 /
// U+2029 (each ends a comment in JavaScript but not a line here), and the
// legacy HTML-like comments `<!--` and `-->`. Refusal means the bundle ships
// with its comments: it costs bytes, never correctness.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// jsFrame is one template literal being lexed: whether the lexer is in one of
// its ${…} expressions, and how many braces deep inside that expression.
type jsFrame struct {
	inExpr bool
	depth  int
}

// jsTok classifies the previous significant token, which is what decides
// whether a following `/` can start a regular expression.
type jsTok int

const (
	tokStart   jsTok = iota // start of input, or after an operator/punctuator
	tokValue                // identifier, number or literal: `/` is division
	tokKeyword              // a keyword after which an expression follows
	tokParen                // `)`: division, except after if/while/for (…)
	tokBrace                // `}`: a block end (regex) or an object/expr end (division)
	tokIncDec               // `++`/`--`: postfix (division) or prefix (regex)
	tokEither               // a word that may be a keyword or an identifier
)

// jsRegexKeywords are keywords after which an expression — and so possibly a
// regular expression — begins.
var jsRegexKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true,
	"new": true, "delete": true, "void": true, "throw": true, "case": true,
	"do": true, "else": true,
}

// jsContextualWords are keywords in some positions and identifiers in others,
// so a slash after one could be either.
var jsContextualWords = map[string]bool{
	"of": true, "yield": true, "await": true, "let": true, "async": true,
	"static": true, "get": true, "set": true,
}

// slashReadings reports which readings of a `/` after prev are possible in
// valid JavaScript: division, a regular expression, or both.
func slashReadings(prev jsTok) (division, regex bool) {
	switch prev {
	case tokStart, tokKeyword:
		return false, true
	case tokValue:
		return true, false
	default: // tokParen, tokBrace, tokIncDec, tokEither
		return true, true
	}
}

// jsState is everything that carries from one line to the next. Strings,
// regular expressions and line comments cannot span lines, so they are not
// here; block comments and template literals can, and the previous token
// decides how the next line's first slash may be read.
type jsState struct {
	block  bool
	frames []jsFrame
	prev   jsTok
}

func (s jsState) clone() jsState {
	return jsState{block: s.block, frames: append([]jsFrame(nil), s.frames...), prev: s.prev}
}

// key renders the state for memoisation and comparison.
func (s jsState) key() string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(s.prev)))
	if s.block {
		b.WriteByte('B')
	}
	for _, f := range s.frames {
		if f.inExpr {
			b.WriteByte('e')
		} else {
			b.WriteByte('t')
		}
		b.WriteString(strconv.Itoa(f.depth))
		b.WriteByte(',')
	}
	return b.String()
}

// inCode reports whether the lexer is in plain code, outside any template.
func (s jsState) inCode() bool {
	return !s.block && len(s.frames) == 0
}

// inTemplateText reports whether the lexer is in the literal text of a
// template rather than in code.
func (s jsState) inTemplateText() bool {
	return len(s.frames) > 0 && !s.frames[len(s.frames)-1].inExpr
}

var (
	errJSAmbiguous = errors.New("ambiguous")
	errJSUnhandled = errors.New("unhandled syntax")
)

// maxJSLineWork bounds the readings explored for one line. A real line has a
// handful of slashes; anything that needs more than this is refused rather
// than analysed.
const maxJSLineWork = 1 << 16

// stripJSLineComments returns src with every whole-line // comment replaced
// by an empty line, or src unchanged and an error when it cannot prove the
// result correct. See the file comment.
func stripJSLineComments(src string) (string, error) {
	if i := strings.IndexAny(src, "  "); i >= 0 {
		return src, fmt.Errorf("%w: a U+2028/U+2029 line terminator at byte %d", errJSUnhandled, i)
	}
	for i := strings.IndexByte(src, '\r'); i >= 0; {
		if i+1 >= len(src) || src[i+1] != '\n' {
			return src, fmt.Errorf("%w: a carriage return without a line feed at byte %d", errJSUnhandled, i)
		}
		next := strings.IndexByte(src[i+1:], '\r')
		if next < 0 {
			break
		}
		i += 1 + next
	}

	lines := strings.SplitAfter(src, "\n")
	var out strings.Builder
	out.Grow(len(src))
	var st jsState
	for n, line := range lines {
		body := strings.TrimRight(line, "\r\n")
		if st.inCode() && strings.HasPrefix(strings.TrimLeft(body, " \t"), "//") {
			out.WriteString(line[len(body):]) // keep the line break, drop the comment
			continue
		}
		next, err := lexJSLine(st, body)
		if err != nil {
			return src, fmt.Errorf("line %d: %w", n+1, err)
		}
		st = next
		out.WriteString(line)
	}
	if !st.inCode() {
		return src, errors.New("the source ends inside a template literal or block comment")
	}
	return out.String(), nil
}

// lexJSLine returns the one state every valid reading of line ends in, when
// started from st.
func lexJSLine(st jsState, line string) (jsState, error) {
	lx := &jsLineLexer{line: line, memo: map[string][]jsState{}}
	ends, err := lx.from(st.clone(), 0)
	if err != nil {
		return st, err
	}
	switch len(ends) {
	case 0:
		return st, errors.New("no reading of the line is valid JavaScript (an unterminated string or regular expression)")
	case 1:
		return ends[0], nil
	default:
		return st, fmt.Errorf("%w: its readings with a / as division and as a regular expression end in different states", errJSAmbiguous)
	}
}

// jsLineLexer explores the readings of one line.
type jsLineLexer struct {
	line string
	memo map[string][]jsState
	work int
}

// from returns the distinct end states of every valid reading of the line
// from position i in state st. An error is a hard refusal; an invalid reading
// simply contributes no end state.
func (lx *jsLineLexer) from(st jsState, i int) ([]jsState, error) {
	memoKey := strconv.Itoa(i) + "|" + st.key()
	if ends, ok := lx.memo[memoKey]; ok {
		return ends, nil
	}
	lx.work++
	if lx.work > maxJSLineWork {
		return nil, fmt.Errorf("%w: too many readings to check", errJSAmbiguous)
	}
	ends, err := lx.scan(st, i)
	if err != nil {
		return nil, err
	}
	lx.memo[memoKey] = ends
	return ends, nil
}

// scan lexes deterministically until the line ends or a slash forces a
// choice, then follows every reading the grammar allows.
func (lx *jsLineLexer) scan(st jsState, i int) ([]jsState, error) {
	line := lx.line
	for i < len(line) {
		c := line[i]
		if st.block {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				return []jsState{st}, nil
			}
			st.block = false
			i += end + 2
			continue
		}
		if st.inTemplateText() {
			switch {
			case c == '\\':
				i += 2
			case c == '`':
				st.frames = st.frames[:len(st.frames)-1]
				st.prev = tokValue
				i++
			case c == '$' && i+1 < len(line) && line[i+1] == '{':
				st.frames[len(st.frames)-1] = jsFrame{inExpr: true}
				st.prev = tokStart
				i += 2
			default:
				i++
			}
			continue
		}
		switch {
		case strings.HasPrefix(line[i:], "<!--"):
			return nil, fmt.Errorf("%w: an HTML-like comment at column %d", errJSUnhandled, i+1)
		case strings.HasPrefix(line[i:], "-->") && strings.TrimSpace(line[:i]) == "":
			return nil, fmt.Errorf("%w: an HTML-like comment at column %d", errJSUnhandled, i+1)
		case c == ' ' || c == '\t':
			i++
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return []jsState{st}, nil // a trailing line comment
		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			st.block = true
			i += 2
		case c == '/':
			division, regex := slashReadings(st.prev)
			var ends []jsState
			if division {
				next := st.clone()
				next.prev = tokStart
				div, err := lx.from(next, i+1)
				if err != nil {
					return nil, err
				}
				ends = div
			}
			// A regular expression is a reading only if it closes on this line.
			if end, ok := scanJSRegex(line, i); regex && ok {
				next := st.clone()
				next.prev = tokValue
				re, err := lx.from(next, end)
				if err != nil {
					return nil, err
				}
				ends = mergeStates(ends, re)
			}
			return ends, nil
		case c == '\'' || c == '"':
			end, ok := scanJSString(line, i)
			if !ok {
				return nil, nil // not a valid reading
			}
			st.prev = tokValue
			i = end
		case c == '`':
			st.frames = append(st.frames, jsFrame{})
			i++
		case c == '{':
			if n := len(st.frames); n > 0 {
				st.frames[n-1].depth++
			}
			st.prev = tokStart
			i++
		case c == '}':
			if n := len(st.frames); n > 0 {
				if st.frames[n-1].depth == 0 {
					st.frames[n-1].inExpr = false // back to template text
					i++
					continue
				}
				st.frames[n-1].depth--
			}
			st.prev = tokBrace
			i++
		case c == ')':
			st.prev = tokParen
			i++
		case c == ']':
			st.prev = tokValue
			i++
		case (c == '+' || c == '-') && i+1 < len(line) && line[i+1] == c:
			st.prev = tokIncDec
			i += 2
		case isJSWordByte(c):
			j := i
			ascii := true
			for j < len(line) && isJSWordByte(line[j]) {
				if line[j] >= 0x80 {
					ascii = false
				}
				j++
			}
			switch word := line[i:j]; {
			case !ascii:
				// Unicode whitespace (a no-break space after `return`, say)
				// hides inside what this lexer reads as one word.
				st.prev = tokEither
			case jsRegexKeywords[word]:
				st.prev = tokKeyword
			case jsContextualWords[word]:
				st.prev = tokEither
			default:
				st.prev = tokValue
			}
			i = j
		default:
			st.prev = tokStart
			i++
		}
	}
	return []jsState{st}, nil
}

// mergeStates returns the union of two lists of end states, without repeats.
func mergeStates(a, b []jsState) []jsState {
	out := append([]jsState(nil), a...)
	for _, s := range b {
		dup := false
		for _, t := range out {
			if t.key() == s.key() {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// scanJSString returns the offset just past the string starting at line[i].
func scanJSString(line string, i int) (int, bool) {
	q := line[i]
	for j := i + 1; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case q:
			return j + 1, true
		}
	}
	return len(line), false
}

// scanJSRegex returns the offset just past the regular expression literal
// (flags included) starting at line[i].
func scanJSRegex(line string, i int) (int, bool) {
	inClass := false
	for j := i + 1; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if inClass {
				continue
			}
			k := j + 1
			for k < len(line) && (line[k] >= 'a' && line[k] <= 'z' || line[k] >= 'A' && line[k] <= 'Z') {
				k++
			}
			return k, true
		}
	}
	return len(line), false
}

// isJSWordByte reports whether b can be part of an identifier, keyword or
// number. Every byte of a multi-byte UTF-8 sequence counts: see scan for why
// a word holding any is treated as ambiguous.
func isJSWordByte(b byte) bool {
	return b == '_' || b == '$' || b == '.' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b >= 0x80
}
