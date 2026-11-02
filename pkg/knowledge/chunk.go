package knowledge

import (
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// chunkerVersion is part of every content hash. Changing how documents are
// cut changes it, so every document is chunked again at its next sync instead
// of keeping chunks the current code would not make.
const chunkerVersion = "chunker-v1"

// ChunkOptions bounds chunks.
type ChunkOptions struct {
	// MaxTokens is the most a chunk may hold, estimated by EstimateTokens.
	// Defaults to 320; clamped to [32, 2048].
	MaxTokens int
	// OverlapTokens is how much of a chunk's end the next chunk of the same
	// section repeats, so a passage cut in two is still found whole in one of
	// them. Defaults to 48; clamped to [0, MaxTokens/4].
	OverlapTokens int
}

func (o ChunkOptions) normalized() ChunkOptions {
	if o.MaxTokens <= 0 {
		o.MaxTokens = 320
	}
	o.MaxTokens = min(max(o.MaxTokens, 32), 2048)
	if o.OverlapTokens < 0 {
		o.OverlapTokens = 0
	} else if o.OverlapTokens == 0 {
		o.OverlapTokens = 48
	}
	o.OverlapTokens = min(o.OverlapTokens, o.MaxTokens/4)
	return o
}

// Chunk is one piece of a document.
type Chunk struct {
	// Heading is the chunk's place in the document's outline, its headings
	// joined with " › " ("Install › Linux"); empty before the first heading.
	Heading string
	Text    string
	Tokens  int
}

// EstimateTokens estimates how many model tokens s is: one per four bytes,
// rounded up — the estimate the rest of cloop budgets prompts with, and the
// one an index meant to be quoted into prompts should be cut by.
func EstimateTokens(s string) int {
	return tokensOfLen(len(s))
}

// tokensOfLen is EstimateTokens for a text of n bytes.
func tokensOfLen(n int) int {
	return (n + 3) / 4
}

// ReadBody reads a document body a connector received — an HTTP response, a
// file — through pkg/boundedread: at most MaxBodyBytes, cut back to whole
// UTF-8 characters, and whether there was more.
func ReadBody(r io.Reader) (body string, truncated bool, err error) {
	b, truncated, err := boundedread.ReadTruncated(r, MaxBodyBytes)
	if err != nil {
		return "", false, err
	}
	if truncated {
		b = trimPartialRune(b)
	}
	return string(b), truncated, nil
}

// trimPartialRune drops a UTF-8 sequence cut off at the end of b.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size > 1 {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// section is the text under one heading.
type section struct {
	heading    string
	paragraphs []string
}

// ChunkDocument cuts a document into chunks: first at its headings, so no
// chunk spans two sections; then at its paragraphs, packing whole paragraphs
// into chunks of at most opts.MaxTokens; and only a paragraph too long for one
// chunk is cut further, at sentences, then words. Consecutive chunks of one
// section share opts.OverlapTokens of text. The title is not repeated in the
// chunks — the index keeps it beside each one. A document with a title and no
// body is one empty chunk, so its title is still found. capped reports a
// document cut short at MaxChunksPerDocument.
//
// Deterministic: the same title, body and options always give the same chunks,
// which is what lets a content hash stand for them.
func ChunkDocument(title, body string, opts ChunkOptions) (chunks []Chunk, capped bool) {
	opts = opts.normalized()
	var out []Chunk
	for _, sec := range splitSections(body) {
		for _, text := range packSection(sec.paragraphs, opts) {
			if len(out) == MaxChunksPerDocument {
				return out, true
			}
			out = append(out, Chunk{Heading: sec.heading, Text: text, Tokens: EstimateTokens(text)})
		}
	}
	if len(out) == 0 && strings.TrimSpace(title) != "" {
		out = append(out, Chunk{})
	}
	return out, false
}

// headingSeparator separates the headings of a chunk's outline.
const headingSeparator = " › "

// splitSections splits body into the text under each heading, recognising
// ATX headings ("## Title") and setext ones (a line underlined with = or at
// least three -).
func splitSections(body string) []section {
	lines := strings.Split(normalizeText(body), "\n")
	type level struct {
		depth int
		text  string
	}
	var (
		stack []level
		out   []section
		cur   section
		para  []string
	)
	endPara := func() {
		if len(para) > 0 {
			cur.paragraphs = append(cur.paragraphs, strings.Join(para, "\n"))
			para = nil
		}
	}
	startSection := func(depth int, text string) {
		endPara()
		if len(cur.paragraphs) > 0 {
			out = append(out, cur)
		}
		for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}
		stack = append(stack, level{depth, text})
		names := make([]string, len(stack))
		for i, l := range stack {
			names[i] = l.text
		}
		cur = section{heading: strings.Join(names, headingSeparator)}
	}
	inFence := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// A fenced code block is text: a "# comment" inside one is not a
		// heading.
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
		}
		if !inFence {
			if depth, text, ok := atxHeading(line); ok {
				startSection(depth, text)
				continue
			}
			if line != "" && len(para) == 0 && i+1 < len(lines) {
				if depth, ok := setextUnderline(lines[i+1]); ok {
					startSection(depth, line)
					i++
					continue
				}
			}
			if thematicBreak(line) {
				endPara()
				continue
			}
		}
		if line == "" {
			endPara()
			continue
		}
		para = append(para, line)
	}
	endPara()
	if len(cur.paragraphs) > 0 {
		out = append(out, cur)
	}
	return out
}

// normalizeText makes line breaks "\n", turns tabs and other control
// characters into spaces, collapses runs of spaces, and trims each line.
func normalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteRune('\n')
			space = false
			continue
		case r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		b.WriteRune(r)
		space = false
	}
	lines := strings.Split(b.String(), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}

// atxHeading recognises "# Title" through "###### Title".
func atxHeading(line string) (int, string, bool) {
	depth := 0
	for depth < len(line) && line[depth] == '#' {
		depth++
	}
	if depth == 0 || depth > 6 || depth == len(line) || line[depth] != ' ' {
		return 0, "", false
	}
	text := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(line[depth:]), "#"))
	if text == "" {
		return 0, "", false
	}
	return depth, text, true
}

// thematicBreak recognises a line that only separates: three or more of one
// of '-', '*' or '_', spaces allowed between them.
func thematicBreak(line string) bool {
	compact := strings.ReplaceAll(line, " ", "")
	if len(compact) < 3 {
		return false
	}
	c := compact[0]
	return (c == '-' || c == '*' || c == '_') && strings.Trim(compact, string(c)) == ""
}

// setextUnderline recognises the line under a setext heading: "===" for a
// first-level heading, "---" (three or more) for a second.
func setextUnderline(line string) (int, bool) {
	if line == "" {
		return 0, false
	}
	switch {
	case strings.Trim(line, "=") == "":
		return 1, true
	case len(line) >= 3 && strings.Trim(line, "-") == "":
		return 2, true
	}
	return 0, false
}

// packSection packs a section's paragraphs into chunk texts of at most
// opts.MaxTokens, consecutive ones overlapping by opts.OverlapTokens.
func packSection(paragraphs []string, opts ChunkOptions) []string {
	var units []string
	for _, p := range paragraphs {
		if EstimateTokens(p) <= opts.MaxTokens {
			units = append(units, p)
			continue
		}
		units = append(units, splitLong(p, opts.MaxTokens)...)
	}
	var (
		out []string
		cur strings.Builder
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, u := range units {
		if cur.Len() > 0 && tokensOfLen(cur.Len()+2+len(u)) <= opts.MaxTokens {
			cur.WriteString("\n\n")
			cur.WriteString(u)
			continue
		}
		prev := ""
		if cur.Len() > 0 {
			prev = cur.String()
		}
		flush()
		if tail := overlapTail(prev, opts.OverlapTokens, opts.MaxTokens-EstimateTokens(u)-1); tail != "" {
			cur.WriteString(tail)
			cur.WriteString(" ")
		}
		cur.WriteString(u)
	}
	flush()
	return out
}

// overlapTail returns the last whole words of text that fit in want tokens,
// and in room tokens beside the unit that follows them.
func overlapTail(text string, want, room int) string {
	budget := min(want, room)
	if text == "" || budget <= 0 {
		return ""
	}
	words := strings.Fields(text)
	n := 0
	start := len(words)
	for start > 0 {
		w := len(words[start-1]) + 1
		if (n+w+3)/4 > budget {
			break
		}
		n += w
		start--
	}
	return strings.Join(words[start:], " ")
}

// splitLong cuts a paragraph longer than max tokens into pieces of at most
// max tokens: at sentence ends where it can, between words where a sentence is
// too long, and inside a word only for a run of text with no spaces at all.
func splitLong(p string, max int) []string {
	var pieces []string
	for _, s := range sentences(p) {
		if EstimateTokens(s) <= max {
			pieces = append(pieces, s)
			continue
		}
		for _, w := range strings.Fields(s) {
			if EstimateTokens(w) <= max {
				pieces = append(pieces, w)
				continue
			}
			pieces = append(pieces, splitRunes(w, max*4)...)
		}
	}
	// Pack the pieces back up to max, joined by spaces.
	var (
		out []string
		cur strings.Builder
	)
	for _, piece := range pieces {
		if cur.Len() > 0 && tokensOfLen(cur.Len()+1+len(piece)) > max {
			out = append(out, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(piece)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// sentences splits p after each '.', '!' or '?' that ends a word, and at line
// breaks.
func sentences(p string) []string {
	var (
		out   []string
		start int
	)
	for i := 0; i < len(p); i++ {
		end := -1
		switch p[i] {
		case '\n':
			end = i
		case '.', '!', '?':
			if i+1 == len(p) || p[i+1] == ' ' || p[i+1] == '\n' {
				end = i + 1
			}
		}
		if end < 0 {
			continue
		}
		if s := strings.TrimSpace(p[start:end]); s != "" {
			out = append(out, s)
		}
		start = end
	}
	if s := strings.TrimSpace(p[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

// splitRunes cuts s into pieces of at most maxBytes bytes, on rune
// boundaries.
func splitRunes(s string, maxBytes int) []string {
	var out []string
	for len(s) > maxBytes {
		cut := maxBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		if cut == 0 {
			_, cut = utf8.DecodeRuneInString(s)
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}
