package confluence

// storage.go turns a page's body in Confluence's storage format into the text
// the index holds.
//
// Storage format is XHTML with Confluence's own elements in it: ac: for
// macros, links, images, task lists and layouts, ri: for what they point at.
// What a person reads on the page is kept, shaped the way pkg/knowledge's
// chunker reads text — Markdown-like, so its sections fall at the page's
// headings:
//
//	headings      "## Heading", a block of its own
//	paragraphs    blocks separated by a blank line; <br> breaks a line
//	lists         "- item", "1. item", "- [x] task", nested lists indented
//	tables        "| cell | cell |" a row a line, a "| --- |" line under a
//	              header row; a cell is one line of text
//	code blocks   fenced with ```, from <pre> and the code and noformat
//	              macros, whose language is kept
//	quotes        "> " in front of every line
//
// Macros are not run: a macro's parameters and whatever it would fetch or
// generate (a table of contents, a Jira query, an included page) are left out.
// The text an author wrote inside one — the body of an info panel, an expand,
// a page-properties table — is the page's own, and is kept. Images and
// attachments are left out, and so is a link's target: its text is kept.
//
// The input is not trusted to be well formed. It is read by the HTML5
// tokenizer, which never fails, and an element closed out of order, never
// closed, or nested past maxDepth is absorbed rather than refused: the text in
// it still reaches the index. Nothing recurses, so no input can exhaust the
// stack, and the input is cut at maxStorageBytes before it is read.

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

const (
	// maxStorageBytes bounds the storage-format body read. The index keeps
	// pkg/knowledge.MaxBodyBytes of text; markup is rarely less than half a
	// page's bytes, so this is past what any page that fits needs.
	maxStorageBytes = 8 << 20
	// maxDepth bounds element nesting. Elements past it are read as if
	// their tags were not there: their text is kept.
	maxDepth = 128
)

// renderStorage returns the text of a storage-format body.
func renderStorage(src string) string {
	if len(src) > maxStorageBytes {
		src = src[:maxStorageBytes]
	}
	r := newRenderer()
	z := html.NewTokenizer(strings.NewReader(src))
	z.AllowCDATA(true)
	for {
		switch tt := z.Next(); tt {
		case html.ErrorToken:
			return r.finish()
		case html.TextToken:
			raw := z.Raw()
			if bytes.HasPrefix(raw, []byte("<![CDATA[")) {
				// CDATA is text as written: the tokenizer would decode entities
				// in it, and "&amp;" in a code sample is not "&".
				body := raw[len("<![CDATA["):]
				body = bytes.TrimSuffix(body, []byte("]]>"))
				r.text(string(body))
				continue
			}
			r.text(string(z.Text()))
		case html.StartTagToken, html.SelfClosingTagToken:
			name, more := z.TagName()
			var attrs map[string]string
			for more {
				var k, v []byte
				k, v, more = z.TagAttr()
				switch key := string(k); key {
				case "ac:name", "start", "datetime", "ri:content-title", "ri:space-key", "ri:value":
					if attrs == nil {
						attrs = map[string]string{}
					}
					attrs[key] = string(v)
				}
			}
			r.open(string(name), attrs, tt == html.SelfClosingTagToken)
		case html.EndTagToken:
			name, _ := z.TagName()
			r.close(string(name))
		}
	}
}

// kind is what an open element does with what is inside it.
type kind int

const (
	// kInline is an element with no effect of its own (span, strong, a):
	// its text goes to the element around it.
	kInline kind = iota
	// kBlock is a block element with no frame of its own (p, div): it ends
	// the paragraph around it where it starts and where it ends.
	kBlock
	// kFlow holds blocks: the page itself, a list item, a table cell, a
	// quote, a macro's rich-text body, a table caption, a task.
	kFlow
	// kHeading collects one line of text.
	kHeading
	// kCode collects text as written: <pre>, a code macro's body.
	kCode
	// kList collects the lines of its items.
	kList
	// kTable collects rows, kRow cells.
	kTable
	kRow
	// kMacro is a macro: text directly in it is dropped, and only its
	// bodies are read.
	kMacro
	// kCapture collects text for the element around it to use — a code
	// macro's language, a task's status — and renders none.
	kCapture
	// kFallback renders its fallback text when nothing inside it wrote
	// any: a link with no body shows the title of the page it points to,
	// a <time> its date.
	kFallback
	// kIgnore drops everything in it.
	kIgnore
)

// role tells kFlow elements apart: where their blocks go when they close.
type role int

const (
	roleRoot role = iota
	roleItem
	roleCell
	roleQuote
	roleBody // a macro's rich-text body: its blocks go to the flow around it
	roleCaption
)

type frame struct {
	name string
	kind kind
	role role

	// kFlow: finished blocks, and the paragraph being written.
	blocks [][]string
	para   strings.Builder
	space  bool // para (or a heading's text) ends in a space, or is empty

	// kHeading.
	level int
	text  strings.Builder

	// kCode: the text, and the code macro's language.
	code strings.Builder
	lang string

	// kList.
	ordered bool
	next    int
	lines   []string

	// A list item's marker ("- ", "3. "), and a task's state.
	marker string
	task   bool
	done   bool
	// A table cell that is a header cell.
	header bool

	// kTable: rows, and whether each is a header row; kRow: cells, and
	// whether each is a header cell.
	rows      [][]string
	headerRow []bool
	cells     []string
	headCells []bool

	// kMacro: the macro's name ("code", "info").
	macro string
	// kCapture: what the text is for ("language", "status").
	capture string

	// kFallback.
	fallback string
	wrote    bool
}

type renderer struct {
	stack []*frame
	// opened counts the open frames of each element name, so an end tag that
	// closes nothing is dismissed without a walk down the stack.
	opened map[string]int
	// ignored counts the open kIgnore frames: while there is one, text and
	// elements are dropped.
	ignored int
}

func newRenderer() *renderer {
	root := &frame{name: "", kind: kFlow, role: roleRoot, space: true}
	return &renderer{stack: []*frame{root}, opened: map[string]int{}}
}

// voidElements never have content, whatever the input says.
var voidElements = map[string]bool{
	"br": true, "hr": true, "img": true, "col": true, "area": true, "base": true, "input": true,
	"link": true, "meta": true, "param": true, "source": true, "track": true, "wbr": true, "embed": true,
}

// ignoredElements are dropped with everything in them.
var ignoredElements = map[string]bool{
	"script": true, "style": true, "noscript": true, "template": true, "iframe": true, "object": true,
	"svg": true, "math": true, "head": true, "title": true, "textarea": true, "select": true,
	"button": true, "audio": true, "video": true, "canvas": true, "map": true,
	// Images, emoticons and attachments are not text; a placeholder is the
	// editor's prompt, not the author's.
	"ac:image": true, "ac:emoticon": true, "ac:placeholder": true, "ac:task-id": true, "ac:task-uuid": true,
	// ADF elements in storage format carry their content twice: once as
	// content, once as a fallback for old readers. The content is read.
	"ac:adf-fallback": true, "ac:adf-attribute": true, "ac:adf-parameter": true, "ac:adf-mark": true,
}

// blockElements end the paragraph around them.
var blockElements = map[string]bool{
	"p": true, "div": true, "section": true, "article": true, "header": true, "footer": true, "nav": true,
	"aside": true, "main": true, "figure": true, "figcaption": true, "address": true, "details": true,
	"summary": true, "center": true, "dl": true, "dt": true, "dd": true, "body": true, "html": true,
	"ac:layout": true, "ac:layout-section": true, "ac:layout-cell": true, "ac:task-body": true,
	"ac:adf-extension": true, "ac:adf-node": true, "ac:adf-content": true,
}

// codeMacros are the macros whose plain-text body is a code block.
var codeMacros = map[string]bool{"code": true, "noformat": true}

func (r *renderer) top() *frame { return r.stack[len(r.stack)-1] }

// ignoring reports whether text and elements are being dropped: inside an
// ignored element, or a macro's parameter.
func (r *renderer) ignoring() bool { return r.ignored > 0 }

// innermost returns the innermost frame matching ok, or nil.
func (r *renderer) innermost(ok func(*frame) bool) *frame {
	for i := len(r.stack) - 1; i >= 0; i-- {
		if ok(r.stack[i]) {
			return r.stack[i]
		}
	}
	return nil
}

// flow returns the innermost kFlow frame: the root at least.
func (r *renderer) flow() *frame {
	return r.innermost(func(f *frame) bool { return f.kind == kFlow })
}

// inCompact reports whether a frame that renders on one line — a list item, a
// table, a cell — is open: a heading there is text, not a section.
func (r *renderer) inCompact() bool {
	return r.innermost(func(f *frame) bool {
		return f.kind == kList || f.kind == kTable || f.kind == kRow || (f.kind == kFlow && (f.role == roleItem || f.role == roleCell))
	}) != nil
}

func (r *renderer) push(f *frame) {
	r.stack = append(r.stack, f)
	r.opened[f.name]++
	if f.kind == kIgnore {
		r.ignored++
	}
}

func (r *renderer) open(name string, attrs map[string]string, selfClosing bool) {
	if r.ignoring() {
		// Still tracked, so the ignored element's own end tag is the one
		// that ends it, not one of the same name inside it.
		if !selfClosing && !voidElements[name] && len(r.stack) < maxDepth {
			r.push(&frame{name: name, kind: kIgnore})
		}
		return
	}
	switch name {
	case "br":
		r.lineBreak()
		return
	case "hr":
		r.endParagraph()
		return
	case "time":
		if selfClosing {
			r.text(attrs["datetime"])
			return
		}
	case "ri:page":
		if f := r.innermost(func(f *frame) bool { return f.kind == kFallback }); f != nil && f.fallback == "" {
			f.fallback = attrs["ri:content-title"]
		}
	case "ri:space":
		if f := r.innermost(func(f *frame) bool { return f.kind == kFallback }); f != nil && f.fallback == "" {
			f.fallback = attrs["ri:space-key"]
		}
	case "ri:url":
		if f := r.innermost(func(f *frame) bool { return f.kind == kFallback }); f != nil && f.fallback == "" {
			f.fallback = attrs["ri:value"]
		}
	}
	if selfClosing || voidElements[name] {
		if blockElements[name] {
			r.endParagraph()
		}
		return
	}
	if len(r.stack) >= maxDepth {
		return
	}
	f := &frame{name: name, space: true}
	switch {
	case ignoredElements[name] || strings.HasPrefix(name, "ri:"):
		f.kind = kIgnore
	case name == "h1" || name == "h2" || name == "h3" || name == "h4" || name == "h5" || name == "h6":
		r.endParagraph()
		f.kind, f.level = kHeading, int(name[1]-'0')
	case name == "pre":
		r.endParagraph()
		f.kind = kCode
	case name == "blockquote":
		r.endParagraph()
		f.kind, f.role = kFlow, roleQuote
	case name == "ul" || name == "ol" || name == "ac:task-list":
		r.endParagraph()
		f.kind, f.ordered, f.next = kList, name == "ol", 1
		if n, err := strconv.Atoi(strings.TrimSpace(attrs["start"])); err == nil && name == "ol" && n >= 0 && n < 1_000_000 {
			f.next = n
		}
	case name == "li" || name == "ac:task":
		r.closeOpen(name, kList)
		r.endParagraph()
		f.kind, f.role, f.task = kFlow, roleItem, name == "ac:task"
		if list := r.innermost(func(f *frame) bool { return f.kind == kList }); list != nil && list.ordered {
			f.marker = strconv.Itoa(list.next) + ". "
			list.next++
		} else {
			f.marker = "- "
		}
	case name == "table":
		r.endParagraph()
		f.kind = kTable
	case name == "tr":
		r.closeOpen("tr", kTable)
		f.kind = kRow
	case name == "td" || name == "th":
		r.closeCell()
		f.kind, f.role, f.header = kFlow, roleCell, name == "th"
	case name == "caption":
		f.kind, f.role = kFlow, roleCaption
	case name == "ac:structured-macro" || name == "ac:macro":
		r.endParagraph()
		f.kind, f.macro = kMacro, strings.ToLower(strings.TrimSpace(attrs["ac:name"]))
	case name == "ac:parameter":
		f.kind = kIgnore
		if m := r.top(); m.kind == kMacro && codeMacros[m.macro] &&
			strings.EqualFold(strings.TrimSpace(attrs["ac:name"]), "language") {
			f.kind, f.capture = kCapture, "language"
		}
	case name == "ac:rich-text-body":
		r.endParagraph()
		f.kind, f.role = kFlow, roleBody
	case name == "ac:plain-text-body":
		f.kind = kIgnore
		if m := r.top(); m.kind == kMacro && codeMacros[m.macro] {
			f.kind, f.lang = kCode, m.lang
		}
	case name == "ac:task-status":
		f.kind, f.capture = kCapture, "status"
	case name == "ac:link" || name == "time":
		f.kind, f.fallback = kFallback, attrs["datetime"]
	case name == "code":
		f.kind = kInline
		if !r.inCode() {
			r.text("`")
		}
	case blockElements[name]:
		r.endParagraph()
		f.kind = kBlock
	default:
		f.kind = kInline
	}
	r.push(f)
}

// inCode reports whether text is being kept as written.
func (r *renderer) inCode() bool {
	return r.innermost(func(f *frame) bool { return f.kind == kCode }) != nil
}

// closeOpen closes an open element named name that a new one of the same name
// implicitly ends — an <li> left open when the next begins — but only within
// the innermost frame of kind container, so a nested list's item never closes
// its parent's.
func (r *renderer) closeOpen(name string, container kind) {
	if r.opened[name] == 0 {
		return
	}
	for i := len(r.stack) - 1; i > 0; i-- {
		f := r.stack[i]
		if f.kind == container {
			return
		}
		if f.name == name {
			r.popTo(i)
			return
		}
	}
}

// closeCell closes a cell left open when the next begins, within its row.
func (r *renderer) closeCell() {
	for i := len(r.stack) - 1; i > 0; i-- {
		f := r.stack[i]
		if f.kind == kRow || f.kind == kTable {
			return
		}
		if f.kind == kFlow && f.role == roleCell {
			r.popTo(i)
			return
		}
	}
}

func (r *renderer) close(name string) {
	if r.opened[name] == 0 {
		return
	}
	for i := len(r.stack) - 1; i > 0; i-- {
		if r.stack[i].name == name {
			r.popTo(i)
			return
		}
	}
}

// popTo closes every frame from the top down to and including stack[i].
func (r *renderer) popTo(i int) {
	for len(r.stack) > i {
		f := r.stack[len(r.stack)-1]
		r.stack = r.stack[:len(r.stack)-1]
		r.opened[f.name]--
		if f.kind == kIgnore {
			r.ignored--
		}
		r.finishFrame(f)
	}
}

// finish closes everything still open and returns the text.
func (r *renderer) finish() string {
	r.popTo(1)
	root := r.stack[0]
	endParagraphOf(root)
	parts := make([]string, 0, len(root.blocks))
	for _, b := range root.blocks {
		parts = append(parts, strings.Join(b, "\n"))
	}
	return strings.ToValidUTF8(strings.Join(parts, "\n\n"), "�")
}

// text writes text where it belongs: as written into code, collapsed into a
// paragraph or heading, nowhere inside a macro's own markup.
func (r *renderer) text(s string) {
	if s == "" || r.ignoring() {
		return
	}
	for i := len(r.stack) - 1; i >= 0; i-- {
		f := r.stack[i]
		switch f.kind {
		case kCode:
			f.code.WriteString(s)
			return
		case kCapture:
			f.text.WriteString(s)
			return
		case kHeading:
			writeCollapsed(&f.text, &f.space, s)
			return
		case kFlow:
			writeCollapsed(&f.para, &f.space, s)
			return
		case kMacro:
			// Text a macro holds outside its bodies is its markup.
			return
		case kList, kTable, kRow:
			// White space between a list's or a table's elements is
			// layout. Anything else there is malformed, and still the
			// page's: it goes to the text around the list.
			if strings.TrimSpace(s) == "" {
				return
			}
		case kFallback:
			if strings.TrimSpace(s) != "" {
				f.wrote = true
			}
		}
	}
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

// lineBreak is <br>: a new line in a paragraph, a space in a heading.
func (r *renderer) lineBreak() {
	for i := len(r.stack) - 1; i >= 0; i-- {
		f := r.stack[i]
		switch f.kind {
		case kCode:
			f.code.WriteByte('\n')
			return
		case kHeading:
			writeCollapsed(&f.text, &f.space, " ")
			return
		case kFlow:
			trimTrailingSpace(&f.para)
			if f.para.Len() > 0 {
				f.para.WriteByte('\n')
			}
			f.space = true
			return
		case kMacro, kList, kTable, kRow, kCapture:
			return
		}
	}
}

func trimTrailingSpace(b *strings.Builder) {
	s := b.String()
	if t := strings.TrimRight(s, " "); len(t) != len(s) {
		b.Reset()
		b.WriteString(t)
	}
}

// endParagraph ends the paragraph being written in the innermost flow.
func (r *renderer) endParagraph() { endParagraphOf(r.flow()) }

func endParagraphOf(f *frame) {
	text := strings.TrimSpace(f.para.String())
	f.para.Reset()
	f.space = true
	if text == "" {
		return
	}
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, escapeLine(l))
		}
	}
	if len(lines) > 0 {
		f.blocks = append(f.blocks, lines)
	}
}

// addBlock adds a finished block to the innermost flow.
func (r *renderer) addBlock(lines []string) {
	if len(lines) == 0 {
		return
	}
	f := r.flow()
	endParagraphOf(f)
	f.blocks = append(f.blocks, lines)
}

// finishFrame renders a frame that just closed into what is around it.
func (r *renderer) finishFrame(f *frame) {
	switch f.kind {
	case kBlock:
		r.endParagraph()
	case kInline:
		if f.name == "code" && !r.inCode() {
			r.text("`")
		}
	case kHeading:
		text := strings.TrimSpace(f.text.String())
		if text == "" {
			return
		}
		if r.inCompact() {
			r.text(" " + text + " ")
			return
		}
		r.addBlock([]string{strings.Repeat("#", f.level) + " " + text})
	case kCode:
		r.finishCode(f)
	case kCapture:
		owner := r.innermost(func(o *frame) bool {
			return (f.capture == "language" && o.kind == kMacro) || (f.capture == "status" && o.kind == kFlow && o.task)
		})
		if owner == nil {
			return
		}
		text := strings.TrimSpace(f.text.String())
		if f.capture == "language" {
			owner.lang = cleanLanguage(text)
		} else {
			owner.done = strings.EqualFold(text, "complete")
		}
	case kFallback:
		if !f.wrote && strings.TrimSpace(f.fallback) != "" {
			r.text(f.fallback)
		}
	case kList:
		if len(f.lines) == 0 {
			return
		}
		if item := r.flow(); item.role == roleItem {
			// A nested list is part of the item it is in.
			endParagraphOf(item)
			item.blocks = append(item.blocks, f.lines)
			return
		}
		if cell := r.flow(); cell.role == roleCell {
			r.text(" " + strings.Join(stripMarkers(f.lines), "; ") + " ")
			return
		}
		r.addBlock(f.lines)
	case kFlow:
		r.finishFlow(f)
	case kRow:
		if len(f.cells) == 0 {
			return
		}
		if t := r.innermost(func(o *frame) bool { return o.kind == kTable }); t != nil {
			header := true
			for _, h := range f.headCells {
				header = header && h
			}
			t.rows = append(t.rows, f.cells)
			t.headerRow = append(t.headerRow, header)
			return
		}
		r.addBlock([]string{tableLine(f.cells)})
	case kTable:
		lines := tableLines(f.rows, f.headerRow)
		if len(lines) == 0 {
			return
		}
		if cell := r.flow(); cell.role == roleCell {
			r.text(" " + strings.Join(lines, " ") + " ")
			return
		}
		r.addBlock(lines)
	}
}

// finishFlow places a closed flow's blocks.
func (r *renderer) finishFlow(f *frame) {
	endParagraphOf(f)
	switch f.role {
	case roleItem:
		marker := f.marker
		if f.task {
			marker = "- [ ] "
			if f.done {
				marker = "- [x] "
			}
		}
		var lines []string
		for _, b := range f.blocks {
			lines = append(lines, b...)
		}
		if len(lines) == 0 {
			return
		}
		if strings.HasPrefix(lines[0], "```") {
			// A fence must start its line: the marker goes on one of its own.
			lines = append([]string{""}, lines...)
		}
		for i := range lines {
			if i == 0 {
				lines[i] = strings.TrimSpace(marker + lines[i])
			} else {
				lines[i] = "  " + lines[i]
			}
		}
		if list := r.innermost(func(o *frame) bool { return o.kind == kList }); list != nil {
			list.lines = append(list.lines, lines...)
			return
		}
		r.addBlock(lines)
	case roleCell:
		var parts []string
		for _, b := range f.blocks {
			parts = append(parts, b...)
		}
		text := strings.Join(parts, " ")
		holder := r.innermost(func(o *frame) bool { return o.kind == kRow || o.kind == kTable })
		switch {
		case holder != nil && holder.kind == kRow:
			holder.cells = append(holder.cells, text)
			holder.headCells = append(holder.headCells, f.header)
		case holder != nil:
			// A cell with no row around it is a row of its own.
			holder.rows = append(holder.rows, []string{text})
			holder.headerRow = append(holder.headerRow, f.header)
		case text != "":
			r.text(" " + text + " ")
		}
	case roleQuote:
		for _, b := range f.blocks {
			quoted := make([]string, len(b))
			for i, l := range b {
				quoted[i] = "> " + l
			}
			r.addBlock(quoted)
		}
	default: // a macro's body, a caption
		if r.flow().role == roleCell || r.flow().role == roleItem {
			for _, b := range f.blocks {
				r.text(" " + strings.Join(b, " ") + " ")
			}
			return
		}
		for _, b := range f.blocks {
			r.addBlock(b)
		}
	}
}

// finishCode places a closed code block: fenced in a flow, inline in a cell.
func (r *renderer) finishCode(f *frame) {
	code := strings.ReplaceAll(f.code.String(), "\r\n", "\n")
	code = strings.ReplaceAll(code, "\r", "\n")
	code = strings.Trim(code, "\n")
	if strings.TrimSpace(code) == "" {
		return
	}
	if flow := r.flow(); flow.role == roleCell {
		r.text(" `" + strings.Join(strings.Fields(code), " ") + "` ")
		return
	}
	lang := f.lang
	if m := r.innermost(func(o *frame) bool { return o.kind == kMacro }); lang == "" && m != nil {
		lang = m.lang
	}
	lines := []string{"```" + lang}
	for _, l := range strings.Split(code, "\n") {
		l = strings.TrimRight(l, " \t")
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			// A fence inside the code would end the block early.
			l = "\\" + t
		}
		lines = append(lines, strings.Map(dropControl, l))
	}
	lines = append(lines, "```")
	r.addBlock(lines)
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

// escapeLine keeps a line of text from reading as structure to the chunker:
// a "#" that would make it a heading, a run of "=" or "-" that would make the
// line above one, a fence that would open a code block.
func escapeLine(l string) string {
	switch {
	case strings.HasPrefix(l, "#"), strings.HasPrefix(l, "```"), strings.HasPrefix(l, "~~~"):
		return "\\" + l
	case strings.Trim(l, "=") == "", len(l) >= 3 && strings.Trim(l, "-") == "":
		return "\\" + l
	}
	return l
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

// tableLines renders rows, with a separator line under each header row that
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
