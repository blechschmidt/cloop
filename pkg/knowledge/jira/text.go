package jira

// text.go holds what adf.go and wiki.go share: the shape of the text the index
// holds. It is the shape pkg/knowledge's chunker reads — Markdown-like, so a
// document's sections fall at its headings — and the shape the Confluence
// connector gives a page:
//
//	headings      "## Heading", a block of its own
//	paragraphs    blocks separated by a blank line; a hard break ends a line
//	lists         "- item", "1. item", "- [x] task", nested lists indented
//	tables        "| cell | cell |" a row a line, a "| --- |" line under a
//	              header row; a cell is one line of text
//	code blocks   fenced with ```, the language kept
//	quotes        "> " in front of every line
//
// A line of text that would read as structure — a "#" that would make it a
// heading, a run of "=" or "-" that would make the line above one, a fence
// that would open a code block — is escaped with a backslash.

import (
	"strconv"
	"strings"
	"unicode"
)

// renderRich renders a rich-text field as Jira wrote it: Atlassian Document
// Format (a JSON object) on Cloud, wiki markup (a JSON string) on Data Center.
// Its headings go shift levels below the heading it is placed under.
func renderRich(raw []byte, shift int) string {
	raw = trimJSONSpace(raw)
	switch {
	case len(raw) == 0:
		return ""
	case raw[0] == '{':
		return renderADF(raw, shift)
	case raw[0] == '"':
		s, ok := jsonString(raw)
		if !ok {
			return ""
		}
		return renderWiki(s, shift)
	}
	return ""
}

// trimJSONSpace trims JSON's white space from both ends of raw.
func trimJSONSpace(raw []byte) []byte {
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	for len(raw) > 0 && isSpace(raw[0]) {
		raw = raw[1:]
	}
	for len(raw) > 0 && isSpace(raw[len(raw)-1]) {
		raw = raw[:len(raw)-1]
	}
	return raw
}

// headingLine is a heading of level, shift levels down, at most six deep.
func headingLine(level, shift int, text string) string {
	level = min(max(level, 1)+max(shift, 0), 6)
	return strings.Repeat("#", level) + " " + text
}

// writeCollapsed appends s to b with every run of white space — line breaks
// and non-breaking spaces included — written as one space.
func writeCollapsed(b *strings.Builder, space *bool, s string) {
	for _, c := range s {
		if unicode.IsSpace(c) {
			if !*space {
				b.WriteByte(' ')
				*space = true
			}
			continue
		}
		if unicode.IsControl(c) {
			continue
		}
		b.WriteRune(c)
		*space = false
	}
}

func trimTrailingSpace(b *strings.Builder) {
	s := b.String()
	if t := strings.TrimRight(s, " "); len(t) != len(s) {
		b.Reset()
		b.WriteString(t)
	}
}

// escapeLine keeps a line of text from reading as structure to the chunker:
// a "#" that would make it a heading, a run of "=" or "-" that would make the
// line above one, a fence that would open a code block.
func escapeLine(l string) string {
	switch {
	case strings.HasPrefix(l, "#"), strings.HasPrefix(l, "```"), strings.HasPrefix(l, "~~~"):
		return "\\" + l
	case strings.Trim(l, "=") == "", len(l) >= 3 && strings.Trim(l, "-") == "":
		return "\\" + l
	case len(l) >= 3 && (strings.Trim(l, "*") == "" || strings.Trim(l, "_") == ""):
		return "\\" + l
	}
	return l
}

// paragraphLines splits a paragraph's text into its escaped, trimmed,
// non-empty lines.
func paragraphLines(text string) []string {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, escapeLine(l))
		}
	}
	return lines
}

// codeLines is a fenced code block of code in lang, or nothing for code that
// is only white space.
func codeLines(code, lang string) []string {
	code = strings.ReplaceAll(code, "\r\n", "\n")
	code = strings.ReplaceAll(code, "\r", "\n")
	code = strings.Trim(code, "\n")
	if strings.TrimSpace(code) == "" {
		return nil
	}
	lines := []string{"```" + cleanLanguage(lang)}
	for _, l := range strings.Split(code, "\n") {
		l = strings.TrimRight(l, " \t")
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			// A fence inside the code would end the block early.
			l = "\\" + t
		}
		lines = append(lines, strings.Map(dropControl, l))
	}
	return append(lines, "```")
}

// dropControl drops control characters but a tab.
func dropControl(c rune) rune {
	if c != '\t' && unicode.IsControl(c) {
		return -1
	}
	return c
}

// cleanLanguage keeps a code block's language to a short word.
func cleanLanguage(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 32 {
		return ""
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("+#-_.", c)) {
			return ""
		}
	}
	return s
}

// stripMarkers drops list markers, for a list flattened into a cell.
func stripMarkers(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		for _, m := range []string{"- [x] ", "- [ ] ", "- "} {
			l = strings.TrimPrefix(l, m)
		}
		if i := strings.Index(l, ". "); i > 0 && i < 8 {
			if _, err := strconv.Atoi(l[:i]); err == nil {
				l = l[i+2:]
			}
		}
		out = append(out, l)
	}
	return out
}

// tableLines renders rows, with a separator line under a header row that
// starts the table.
func tableLines(rows [][]string, header []bool) []string {
	var lines []string
	for i, row := range rows {
		lines = append(lines, tableLine(row))
		if i == 0 && header[i] {
			sep := make([]string, len(row))
			for j := range sep {
				sep[j] = "---"
			}
			lines = append(lines, tableLine(sep))
		}
	}
	return lines
}

// tableLine renders one row as "| a | b |", each cell one line, its pipes
// escaped.
func tableLine(cells []string) string {
	var b strings.Builder
	b.WriteString("|")
	for _, c := range cells {
		c = strings.Join(strings.Fields(c), " ")
		c = strings.ReplaceAll(c, "|", "\\|")
		b.WriteString(" ")
		b.WriteString(c)
		b.WriteString(" |")
	}
	return b.String()
}
