package ui

// htmlstrip.go removes <!-- … --> comments from the dashboard's page before it
// is served (Task 20363), the way jsstrip.go and cssstrip.go do for its script
// and stylesheet.
//
// index.html carried 22 KB of comments, 7 KB of every first paint once
// gzipped: the last eager asset still shipping its prose. A comment node has no
// rendering and no script reads one, so deleting it outright — not replacing it
// with the newlines it spanned, which inside a white-space: pre element would
// add text — leaves the document a browser builds unchanged, and
// TestStripHTMLComments_MatchesChrome proves it with Chrome's own parser.
//
// The scanner is deliberately narrow. It tracks only what decides whether "<!--"
// starts a comment: tags, whose quoted attribute values may contain anything;
// the raw-text elements (script, style, textarea, title and their kind), whose
// content is text however it looks; and <pre>, left alone for good measure.
// Anything it cannot read the way the HTML tokenizer would — an unterminated
// comment, an abrupt "<!-->", a "--!>" close, an unclosed raw-text element — is
// refused, and the page ships as written.

import (
	"errors"
	"fmt"
	"strings"
)

var errHTMLStrip = errors.New("htmlstrip: declined")

// verbatimElements are copied with their content untouched: the raw-text and
// escapable-raw-text elements, where "<!--" is text, and pre.
var verbatimElements = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true, "xmp": true, "iframe": true,
	"noembed": true, "noframes": true, "noscript": true, "pre": true,
}

// stripHTMLComments returns src without its comments, or src unchanged and an
// error when it holds something the scanner cannot read with certainty.
func stripHTMLComments(src string) (string, error) {
	refuse := func(at int, why string) (string, error) {
		return src, fmt.Errorf("%w: line %d: %s", errHTMLStrip, strings.Count(src[:at], "\n")+1, why)
	}
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		if src[i] != '<' {
			j := strings.IndexByte(src[i:], '<')
			if j < 0 {
				b.WriteString(src[i:])
				break
			}
			b.WriteString(src[i : i+j])
			i += j
			continue
		}
		rest := src[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			body := rest[4:]
			if strings.HasPrefix(body, ">") || strings.HasPrefix(body, "->") {
				return refuse(i, "an abruptly closed comment")
			}
			n := strings.Index(body, "-->")
			if n < 0 {
				return refuse(i, "an unterminated comment")
			}
			if strings.Contains(body[:n], "--!>") {
				return refuse(i, "a comment closed by --!>")
			}
			i += 4 + n + 3

		case strings.HasPrefix(rest, "<!") || strings.HasPrefix(rest, "<?"):
			// A doctype, or a bogus comment: copied whole, up to the first '>'.
			n := strings.IndexByte(rest, '>')
			if n < 0 {
				return refuse(i, "an unterminated declaration")
			}
			b.WriteString(rest[:n+1])
			i += n + 1

		case len(rest) > 1 && (isASCIILetter(rest[1]) || rest[1] == '/'):
			end, name, ok := scanTag(rest)
			if !ok {
				return refuse(i, "an unterminated tag")
			}
			b.WriteString(rest[:end])
			i += end
			if rest[1] == '/' || !verbatimElements[name] {
				continue
			}
			// The element's content runs, as text, to its own end tag.
			close := indexFold(src[i:], "</"+name)
			if close < 0 {
				return refuse(i, "an unclosed <"+name+">")
			}
			b.WriteString(src[i : i+close])
			i += close

		default:
			// A '<' that starts nothing, such as "a < b" in text.
			b.WriteByte('<')
			i++
		}
	}
	return b.String(), nil
}

// scanTag reads one start or end tag at the start of s, returning the offset
// just past its '>' and its lower-cased name. As in the tokenizer, a quote opens
// a quoted value only straight after '=' (and any space), and such a value may
// contain '>' and "<!--"; anywhere else a quote is an ordinary character, and an
// unquoted value ends at the first '>'.
func scanTag(s string) (int, string, bool) {
	i := 1
	if i < len(s) && s[i] == '/' {
		i++
	}
	start := i
	for i < len(s) && !isHTMLSpace(s[i]) && s[i] != '>' && s[i] != '/' {
		i++
	}
	name := strings.ToLower(s[start:i])
	for i < len(s) {
		switch s[i] {
		case '>':
			return i + 1, name, true
		case '=':
			i++
			for i < len(s) && isHTMLSpace(s[i]) {
				i++
			}
			if i < len(s) && (s[i] == '"' || s[i] == '\'') {
				n := strings.IndexByte(s[i+1:], s[i])
				if n < 0 {
					return 0, "", false
				}
				i += n + 2
			}
		default:
			i++
		}
	}
	return 0, "", false
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isHTMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

// indexFold is strings.Index, ignoring ASCII case.
func indexFold(s, substr string) int {
	n := len(substr)
	for i := 0; i+n <= len(s); i++ {
		if strings.EqualFold(s[i:i+n], substr) {
			return i
		}
	}
	return -1
}
