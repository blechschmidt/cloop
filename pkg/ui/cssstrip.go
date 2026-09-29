package ui

// cssstrip.go removes comments from the dashboard's stylesheet before it is
// served (Task 20356).
//
// # Why
//
// jsstrip.go stopped the script shipping its comments; the stylesheet still
// did. At this commit its 150 comments were ~17 KB decoded and ~7.5 KB of its
// ~24 KB on the wire: prose for the next maintainer, downloaded by every
// browser before the dashboard can paint. The first-paint budget named this
// pass, raise after raise, as the lever (assetbudget_test.go). The source keeps
// its comments; the wire does not.
//
// # What it does, and deliberately does not do
//
// A comment is removed when whitespace, or the start or end of the sheet, is
// on at least one side of it. Its line breaks stay, so line N of the served
// sheet is line N of app.css, and nothing else changes: no minification, no
// reordering.
//
// A comment with a token hard against both sides stays. CSS drops comments
// while tokenizing, so `a/**/b` is two identifiers: deleting the comment would
// make them one, and a space would make a descendant combinator of them.
// Whitespace on either side is what makes removal a no-op for the tokenizer —
// it is a token boundary that stays in place, so the characters around the
// comment never meet, and no token can merge or new comment open across it.
//
// # What it refuses
//
// Comments are recognised only in code: not inside a string, and not inside an
// unquoted url(…), where css-syntax-3 reads `/*` as part of the address. It
// refuses what it does not model — a backslash outside a string (an escape
// can spell `url` or hide a quote), a string broken by a line end, a url(…)
// holding a quote or a parenthesis, and anything left unterminated. Refusal
// means the sheet ships with its comments: it costs bytes, never correctness.

import (
	"errors"
	"fmt"
	"strings"
)

// errCSSStrip marks a stylesheet the stripper declined to touch.
var errCSSStrip = errors.New("cssstrip: declined")

// stripCSSComments returns src without the comments it can prove removable,
// or src unchanged and an error naming the line it could not read.
func stripCSSComments(src string) (string, error) {
	refuse := func(at int, why string) (string, error) {
		return src, fmt.Errorf("%w: line %d: %s", errCSSStrip, strings.Count(src[:at], "\n")+1, why)
	}
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			n := strings.Index(src[i+2:], "*/")
			if n < 0 {
				return refuse(i, "unterminated comment")
			}
			end := i + 2 + n + 2
			if i == 0 || isCSSSpace(src[i-1]) || end == len(src) || isCSSSpace(src[end]) {
				b.WriteString(strings.Repeat("\n", strings.Count(src[i:end], "\n")))
			} else {
				b.WriteString(src[i:end])
			}
			i = end

		case c == '"' || c == '\'':
			j := i + 1
			for ; j < len(src) && src[j] != c; j++ {
				switch src[j] {
				case '\\':
					j++ // the escaped character, a line end included
				case '\n', '\r', '\f':
					return refuse(i, "a string broken by a line end")
				}
			}
			if j >= len(src) {
				return refuse(i, "unterminated string")
			}
			b.WriteString(src[i : j+1])
			i = j + 1

		case c == '\\':
			return refuse(i, "an escape outside a string")

		case c == '(' && endsWithURLIdent(src[:i]):
			// url( followed by a quote is a function taking a string, which
			// the cases above lex. Otherwise it is an unquoted address, which
			// runs to the next ')' and is copied whole.
			j := i + 1
			for j < len(src) && isCSSSpace(src[j]) {
				j++
			}
			if j < len(src) && (src[j] == '"' || src[j] == '\'') {
				b.WriteString(src[i:j])
				i = j
				continue
			}
			n := strings.IndexByte(src[j:], ')')
			if n < 0 {
				return refuse(i, "unterminated url(")
			}
			if strings.ContainsAny(src[j:j+n], "\"'(\\") {
				return refuse(i, "a url( holding a quote, a parenthesis or an escape")
			}
			b.WriteString(src[i : j+n+1])
			i = j + n + 1

		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), nil
}

// isCSSSpace reports whether c is CSS whitespace (css-syntax-3 §4.2, before
// the preprocessing that folds CR and FF into LF).
func isCSSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// endsWithURLIdent reports whether s ends with the identifier `url`, in any
// case, and not with a longer one that ends in it: `-url(` and `myurl(` are
// ordinary functions, whose arguments hold comments like any other code.
func endsWithURLIdent(s string) bool {
	if len(s) < 3 || !strings.EqualFold(s[len(s)-3:], "url") {
		return false
	}
	if len(s) == 3 {
		return true
	}
	p := s[len(s)-4]
	return !(p == '-' || p == '_' || p >= 0x80 ||
		p >= '0' && p <= '9' || p >= 'a' && p <= 'z' || p >= 'A' && p <= 'Z')
}
