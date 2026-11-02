package jira

// wiki.go turns Jira's wiki markup — what Jira Data Center's REST API v2
// writes descriptions and comments in — into the text the index holds (see
// text.go for its shape). It passes through mostly as written: the markup's
// emphasis (*bold*, _italic_, -strike-) reads well enough as it is. What
// changes is what gives the text its structure, and what the chunker would
// misread:
//
//	h1. … h6.         headings, shifted down to sit under the issue's own
//	* item, # item    "- item" and "1. item", nested by their depth — a "#"
//	                  item would otherwise read as a heading
//	{code} {noformat} fenced code blocks, the language kept
//	{quote}, bq.      "> " quotes
//	||head||head||    a table's header row, with a "| --- |" line under it
//	----              a paragraph break, never a heading's underline
//	\\                a line break
//	{{mono}}          `mono`
//
// An image (!file.png!) is dropped; a link is its text, a mention ([~name])
// "@name"; the {color}, {panel} and {anchor} macros' markup is dropped and
// their text kept, a panel's title too.
//
// It reads a line at a time and every pattern is a regular expression of
// Go's, which match in time linear in their input: no markup, however
// broken, makes it take longer than its length, and the input is cut at
// maxWikiBytes before it is read.

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxWikiBytes bounds the markup read. Jira keeps a text field to 32,767
// characters unless an administrator raises it; this is far past that. A
// variable only so that a test can show the cut without megabytes.
var maxWikiBytes = 8 << 20

var (
	wikiHeading  = regexp.MustCompile(`^[hH]([1-6])\.\s*(.*)$`)
	wikiQuote    = regexp.MustCompile(`^bq\.\s+(.*)$`)
	wikiItem     = regexp.MustCompile(`^([*#]+|-)\s+(.*)$`)
	wikiRule     = regexp.MustCompile(`^-{4,}$`)
	wikiImage    = regexp.MustCompile(`!(?:https?://[^\s!|]+|[^\s!|]+\.(?i:png|jpe?g|gif|bmp|svg|webp|tiff?))(?:\|[^!\n]*)?!`)
	wikiMention  = regexp.MustCompile(`\[~(?:accountid:)?([^\]\s|]+)\]`)
	wikiLinkText = regexp.MustCompile(`\[([^\[\]|\n]*[^\[\]|\n\s][^\[\]|\n]*)\|[^\[\]\n]+\]`)
	wikiBareLink = regexp.MustCompile(`\[\^?((?:https?|mailto|file):[^\[\]\s|]+|[^\[\]\s|]+\.[A-Za-z0-9]{1,8})\]`)
	wikiMono     = regexp.MustCompile(`\{\{([^{}\n]+?)\}\}`)
	wikiMacro    = regexp.MustCompile(`(?i)\{(?:color|panel|anchor|toc)(?::[^{}\n]*)?\}`)
	wikiTitle    = regexp.MustCompile(`(?i)(?:^|[:|])title=([^|}]*)`)
)

// renderWiki returns the text of wiki markup, its headings shift levels down.
func renderWiki(src string, shift int) string {
	if len(src) > maxWikiBytes {
		cut := maxWikiBytes
		for cut > 0 && !utf8.RuneStart(src[cut]) {
			cut--
		}
		src = src[:cut]
	}
	src = strings.ReplaceAll(src, "\r\n", "\n")
	src = strings.ReplaceAll(src, "\r", "\n")
	w := &wikiRenderer{shift: shift}
	for _, l := range strings.Split(src, "\n") {
		w.line(l)
	}
	return w.finish()
}

// Kinds of block a wikiRenderer writes.
const (
	wbNone = iota
	wbPara
	wbList
	wbTable
	wbQuote
)

type wikiRenderer struct {
	shift  int
	blocks [][]string
	// cur is the block being written, of kind kind.
	cur  []string
	kind int
	// code is the code block being read, ended by {codeEnd}.
	code    *strings.Builder
	codeEnd string
	lang    string
	// quote reports a {quote} open.
	quote bool
	// nums numbers a numbered list, a counter per depth.
	nums []int
}

// line reads one line of markup. Its offsets are found in an ASCII
// lower-cased copy, made once, so that a line full of tags is read in one
// pass rather than once per tag.
func (w *wikiRenderer) line(l string) {
	lower := asciiLower(l)
	last := len(strings.TrimRight(l, " \t")) // l[pos:] is blank once pos >= last
	pos := 0
	for {
		if w.code != nil {
			tag := "{" + w.codeEnd + "}"
			i := strings.Index(lower[pos:], tag)
			if i < 0 {
				w.code.WriteString(l[pos:])
				w.code.WriteByte('\n')
				return
			}
			w.code.WriteString(l[pos : pos+i])
			w.endCode()
			pos += i + len(tag)
		} else {
			start, end, name, lang := findBlockTag(lower, pos)
			if start < 0 {
				w.text(l[pos:])
				return
			}
			if start > pos {
				w.text(l[pos:start])
			}
			w.flush()
			if name == "quote" {
				w.quote = !w.quote
			} else {
				w.code, w.codeEnd, w.lang = &strings.Builder{}, name, lang
			}
			pos = end
		}
		if pos >= last {
			if w.code != nil && pos < len(l) {
				w.code.WriteByte('\n')
			}
			return
		}
	}
}

// asciiLower lower-cases s's ASCII letters only, so that every offset in it
// is an offset in s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// maxTagBytes bounds how far a macro's parameters are looked for.
const maxTagBytes = 512

// findBlockTag finds the first {code}, {code:…}, {noformat}, {noformat:…} or
// {quote} in lower at or after from, and returns where it starts and ends,
// which it is, and a code macro's language.
func findBlockTag(lower string, from int) (start, end int, name, lang string) {
	for from < len(lower) {
		i := strings.IndexByte(lower[from:], '{')
		if i < 0 {
			break
		}
		i += from
		rest := lower[i:]
		for _, tag := range []string{"code", "noformat", "quote"} {
			if !strings.HasPrefix(rest, "{"+tag) {
				continue
			}
			after := rest[len(tag)+1:]
			switch {
			case strings.HasPrefix(after, "}"):
				return i, i + len(tag) + 2, tag, ""
			case strings.HasPrefix(after, ":") && tag != "quote":
				close := strings.IndexByte(after[:min(len(after), maxTagBytes)], '}')
				if close < 0 {
					continue
				}
				return i, i + len(tag) + 2 + close, tag, codeLanguage(after[1:close])
			}
		}
		from = i + 1
	}
	return -1, -1, "", ""
}

// codeLanguage reads a code macro's language from its parameters: the first
// one without a name ("java"), or one named language.
func codeLanguage(params string) string {
	for _, p := range strings.Split(params, "|") {
		k, v, named := strings.Cut(p, "=")
		switch {
		case !named:
			return cleanLanguage(k)
		case strings.EqualFold(strings.TrimSpace(k), "language"):
			return cleanLanguage(v)
		}
	}
	return ""
}

// text reads a line, or part of one, outside a code block.
func (w *wikiRenderer) text(l string) {
	t := strings.TrimSpace(l)
	if t == "" {
		w.flush()
		return
	}
	if w.quote {
		w.start(wbQuote)
		for _, line := range inlineLines(t) {
			w.cur = append(w.cur, "> "+escapeLine(line))
		}
		return
	}
	if m := wikiHeading.FindStringSubmatch(t); m != nil {
		w.flush()
		level, _ := strconv.Atoi(m[1])
		if text := strings.Join(inlineLines(m[2]), " "); text != "" {
			w.blocks = append(w.blocks, []string{headingLine(level, w.shift, text)})
		}
		return
	}
	if m := wikiQuote.FindStringSubmatch(t); m != nil {
		w.flush()
		var quoted []string
		for _, line := range inlineLines(m[1]) {
			quoted = append(quoted, "> "+escapeLine(line))
		}
		if len(quoted) > 0 {
			w.blocks = append(w.blocks, quoted)
		}
		return
	}
	if wikiRule.MatchString(t) {
		w.flush()
		return
	}
	if m := wikiItem.FindStringSubmatch(t); m != nil {
		w.item(m[1], m[2])
		return
	}
	if strings.HasPrefix(t, "|") {
		w.row(t)
		return
	}
	w.start(wbPara)
	for _, line := range inlineLines(t) {
		w.cur = append(w.cur, escapeLine(line))
	}
}

// item writes a list item: markers are its depth, and the last one whether
// it is numbered.
func (w *wikiRenderer) item(markers, text string) {
	if w.kind != wbList {
		w.flush()
		w.nums = nil
	}
	w.start(wbList)
	depth := len(markers)
	numbered := markers[len(markers)-1] == '#'
	for len(w.nums) < depth {
		w.nums = append(w.nums, 0)
	}
	w.nums = w.nums[:depth]
	marker := "- "
	if numbered {
		w.nums[depth-1]++
		marker = strconv.Itoa(w.nums[depth-1]) + ". "
	} else {
		w.nums[depth-1] = 0
	}
	indent := strings.Repeat("  ", min(depth-1, maxIndentLevels))
	lines := inlineLines(text)
	if len(lines) == 0 {
		lines = []string{""}
	}
	for i, line := range lines {
		if i == 0 {
			w.cur = append(w.cur, strings.TrimRight(indent+marker+line, " "))
			continue
		}
		w.cur = append(w.cur, indent+"  "+line)
	}
}

// row writes a table row: "||a||b||" a header row, "|a|b|" any other.
func (w *wikiRenderer) row(t string) {
	if w.kind != wbTable {
		w.flush()
	}
	first := w.kind != wbTable
	w.start(wbTable)
	header := strings.HasPrefix(t, "||")
	t = strings.Join(inlineLines(t), " ")
	sep := "|"
	if header {
		sep = "||"
	}
	t = strings.TrimSuffix(strings.TrimPrefix(t, sep), sep)
	var cells []string
	for _, c := range strings.Split(t, sep) {
		cells = append(cells, strings.Trim(strings.TrimSpace(c), "|"))
	}
	w.cur = append(w.cur, tableLine(cells))
	if header && first {
		dashes := make([]string, len(cells))
		for i := range dashes {
			dashes[i] = "---"
		}
		w.cur = append(w.cur, tableLine(dashes))
	}
}

// inlineLines is a line's inline markup made text, split at its line breaks
// (\\), each line trimmed and the empty ones dropped.
func inlineLines(s string) []string {
	s = wikiImage.ReplaceAllString(s, "")
	s = wikiMention.ReplaceAllString(s, "@$1")
	s = wikiLinkText.ReplaceAllString(s, "$1")
	s = wikiBareLink.ReplaceAllString(s, "$1")
	s = wikiMono.ReplaceAllString(s, "`$1`")
	s = wikiMacro.ReplaceAllStringFunc(s, func(tag string) string {
		if m := wikiTitle.FindStringSubmatch(tag[1 : len(tag)-1]); m != nil && strings.HasPrefix(strings.ToLower(tag), "{panel") {
			return " " + strings.TrimSpace(m[1]) + " "
		}
		return ""
	})
	var out []string
	for _, part := range strings.Split(s, `\\`) {
		if part = strings.Join(strings.Fields(strings.Map(dropControl, part)), " "); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// start makes the block being written one of kind.
func (w *wikiRenderer) start(kind int) {
	if w.kind != kind {
		w.flush()
		w.kind = kind
	}
}

// flush ends the block being written.
func (w *wikiRenderer) flush() {
	if len(w.cur) > 0 {
		w.blocks = append(w.blocks, w.cur)
	}
	w.cur, w.kind = nil, wbNone
}

// endCode ends the open code block.
func (w *wikiRenderer) endCode() {
	if lines := codeLines(w.code.String(), w.lang); len(lines) > 0 {
		w.blocks = append(w.blocks, lines)
	}
	w.code, w.lang = nil, ""
}

// finish ends what is open — a code block never closed included — and returns
// the text.
func (w *wikiRenderer) finish() string {
	w.flush()
	if w.code != nil {
		w.endCode()
	}
	parts := make([]string, 0, len(w.blocks))
	for _, b := range w.blocks {
		parts = append(parts, strings.Join(b, "\n"))
	}
	return strings.ToValidUTF8(strings.Join(parts, "\n\n"), "�")
}
