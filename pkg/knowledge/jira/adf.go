package jira

// adf.go turns Atlassian Document Format — the JSON in which Jira Cloud's REST
// API v3 writes rich text: descriptions and comments — into the text the index
// holds (see text.go for its shape).
//
// What a person reads is kept: paragraphs, headings, bullet, numbered, task
// and decision lists, nested to any depth, tables, code blocks with their
// language, quotes, and the text inside panels, expands (their title too) and
// layouts. A mention is its name ("@Alice Smith"), an emoji its character, a
// date its day, a status its label, a smart link its URL. Images, files and
// macros' own output are left out, and so is a link's target: its text is
// kept.
//
// The input is not trusted to be well formed. A document up to maxADFBytes is
// decoded into a tree and walked with a stack of its own — nothing recurses,
// so no nesting can exhaust the stack — and nesting past maxADFDepth is read
// as if it were flat: its text still reaches the index. A node of a type the
// renderer does not know passes its content through. A document larger than
// maxADFBytes, or one that is not the JSON it claims to be, is read for its
// text alone, by a scan that builds no tree (scanADF).

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// maxADFBytes bounds the document decoded into a tree. Jira keeps a rich-text
// field to 32,767 characters unless an administrator raises it, which is far
// below this; a document past it is read for its text alone. A variable only
// so that a test can show the scan without building megabytes.
var maxADFBytes = 4 << 20

// maxADFDepth bounds the nesting the renderer gives structure to.
const maxADFDepth = 128

// adfNode is one node of a document.
type adfNode struct {
	Type    string    `json:"type"`
	Text    string    `json:"text"`
	Attrs   adfAttrs  `json:"attrs"`
	Marks   []adfMark `json:"marks"`
	Content []adfNode `json:"content"`
}

// adfAttrs are the attributes the renderer reads. Each takes whatever a
// document puts there: a number where a string belongs, or the reverse, is
// read; anything else is left empty rather than failing the document.
type adfAttrs struct {
	Level     flexInt    `json:"level"`
	Order     flexInt    `json:"order"`
	Language  flexString `json:"language"`
	Text      flexString `json:"text"`
	ShortName flexString `json:"shortName"`
	URL       flexString `json:"url"`
	Title     flexString `json:"title"`
	State     flexString `json:"state"`
	Timestamp flexString `json:"timestamp"`
}

type adfMark struct {
	Type string `json:"type"`
}

// flexString reads a string or a number, and leaves anything else empty.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	switch {
	case len(b) > 0 && b[0] == '"':
		if s, ok := jsonString(b); ok {
			*f = flexString(s)
		}
	case len(b) > 0 && (b[0] == '-' || b[0] >= '0' && b[0] <= '9'):
		*f = flexString(b)
	}
	return nil
}

// flexInt reads an integer, written as a number or a string, and leaves
// anything else zero.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		var ok bool
		if s, ok = jsonString(b); !ok {
			return nil
		}
	}
	if n, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && n > -1e9 && n < 1e9 {
		*f = flexInt(int(n))
	}
	return nil
}

// jsonString decodes a JSON string literal.
func jsonString(b []byte) (string, bool) {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return "", false
	}
	return s, true
}

// renderADF returns the text of an ADF document, its headings shift levels
// down.
func renderADF(raw []byte, shift int) string {
	if len(raw) > maxADFBytes {
		return scanADF(raw)
	}
	var root adfNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return scanADF(raw)
	}
	r := newADFRenderer(shift)
	type visit struct {
		n      *adfNode
		next   int
		pushed bool
		opened bool
	}
	stack := []visit{{n: &root}}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if !top.opened {
			top.opened = true
			var descend bool
			top.pushed, descend = r.open(top.n)
			if !descend {
				top.next = len(top.n.Content)
			}
		}
		if top.next < len(top.n.Content) {
			child := &top.n.Content[top.next]
			top.next++
			stack = append(stack, visit{n: child})
			continue
		}
		if top.pushed {
			r.pop()
		}
		stack = stack[:len(stack)-1]
	}
	return r.finish()
}

// akind is what an open frame does with what is inside it.
type akind int

const (
	// akFlow holds blocks: the document, a list item, a table cell, a
	// quote, a panel or an expand.
	akFlow akind = iota
	// akBlock ends the paragraph around it where it starts and where it
	// ends: a paragraph, a caption.
	akBlock
	// akHeading collects one line of text.
	akHeading
	// akCode collects text as written.
	akCode
	// akList collects the lines of its items.
	akList
	// akTable collects rows, akRow cells.
	akTable
	akRow
	// akInline has no effect of its own: a node the renderer does not know,
	// or one past maxADFDepth. Its text goes to the frame around it.
	akInline
)

// arole tells akFlow frames apart: where their blocks go when they close.
type arole int

const (
	arRoot arole = iota
	arItem
	arCell
	arQuote
	arBody // a panel's, an expand's: its blocks go to the flow around it
)

type aframe struct {
	kind akind
	role arole

	// akFlow: finished blocks, and the paragraph being written.
	blocks [][]string
	para   strings.Builder
	space  bool // para (or a heading's text) ends in a space, or is empty

	// akHeading.
	level int
	text  strings.Builder

	// akCode.
	code strings.Builder
	lang string

	// akList.
	ordered bool
	next    int
	lines   []string

	// A list item's marker ("- ", "3. "), and a task's state.
	marker string
	task   bool
	done   bool
	// A table cell that is a header cell.
	header bool

	// akTable: rows, and whether each is a header row; akRow: cells, and
	// whether each is a header cell.
	rows      [][]string
	headerRow []bool
	cells     []string
	headCells []bool
}

type adfRenderer struct {
	stack []*aframe
	shift int
}

func newADFRenderer(shift int) *adfRenderer {
	return &adfRenderer{stack: []*aframe{{kind: akFlow, role: arRoot, space: true}}, shift: shift}
}

func (r *adfRenderer) innermost(ok func(*aframe) bool) *aframe {
	for i := len(r.stack) - 1; i >= 0; i-- {
		if ok(r.stack[i]) {
			return r.stack[i]
		}
	}
	return nil
}

// flow returns the innermost akFlow frame: the root at least.
func (r *adfRenderer) flow() *aframe {
	return r.innermost(func(f *aframe) bool { return f.kind == akFlow })
}

// inCompact reports whether a frame that renders on one line is open — a
// list, a table, an item, a cell: a heading there is text, not a section.
func (r *adfRenderer) inCompact() bool {
	return r.innermost(func(f *aframe) bool {
		return f.kind == akList || f.kind == akTable || f.kind == akRow ||
			(f.kind == akFlow && (f.role == arItem || f.role == arCell))
	}) != nil
}

func (r *adfRenderer) inCode() bool {
	return r.innermost(func(f *aframe) bool { return f.kind == akCode }) != nil
}

// open starts node n: it writes what a leaf says, and pushes a frame for a
// node that holds others. It reports whether it pushed one, and whether n's
// content is to be read.
func (r *adfRenderer) open(n *adfNode) (pushed, descend bool) {
	switch n.Type {
	case "text":
		r.inlineText(n)
		return false, false
	case "hardBreak":
		r.lineBreak()
		return false, false
	case "rule":
		r.endParagraph()
		return false, false
	case "mention":
		name := strings.TrimSpace(string(n.Attrs.Text))
		if name == "" {
			name = "user"
		}
		if !strings.HasPrefix(name, "@") {
			name = "@" + name
		}
		r.text(name)
		return false, false
	case "emoji":
		r.text(firstOf(string(n.Attrs.Text), string(n.Attrs.ShortName)))
		return false, false
	case "status":
		r.text(string(n.Attrs.Text))
		return false, false
	case "date":
		r.text(adfDate(string(n.Attrs.Timestamp)))
		return false, false
	case "inlineCard":
		r.text(string(n.Attrs.URL))
		return false, false
	case "blockCard", "embedCard":
		r.endParagraph()
		r.text(string(n.Attrs.URL))
		r.endParagraph()
		return false, false
	case "media", "mediaInline", "mediaGroup", "placeholder", "extension", "inlineExtension":
		// Not text: a file, an image, an editor's prompt, a macro's output.
		return false, false
	}
	if len(r.stack) >= maxADFDepth {
		// Past the bound: read as if flat, so the text still reaches the
		// index.
		if n.Text != "" {
			r.inlineText(n)
		}
		return false, true
	}
	f := &aframe{space: true}
	switch n.Type {
	case "paragraph", "caption", "mediaSingle":
		r.endParagraph()
		f.kind = akBlock
	case "heading":
		r.endParagraph()
		f.kind, f.level = akHeading, min(max(int(n.Attrs.Level), 1), 6)
	case "codeBlock":
		r.endParagraph()
		f.kind, f.lang = akCode, string(n.Attrs.Language)
	case "blockquote":
		r.endParagraph()
		f.kind, f.role = akFlow, arQuote
	case "bulletList", "orderedList", "taskList", "decisionList":
		r.endParagraph()
		f.kind, f.ordered, f.next = akList, n.Type == "orderedList", 1
		if order := int(n.Attrs.Order); n.Type == "orderedList" && order >= 0 && order < 1_000_000 && order != 0 {
			f.next = order
		}
	case "listItem", "taskItem", "blockTaskItem", "decisionItem":
		r.endParagraph()
		f.kind, f.role = akFlow, arItem
		f.task = n.Type == "taskItem" || n.Type == "blockTaskItem"
		f.done = strings.EqualFold(string(n.Attrs.State), "DONE")
		f.marker = "- "
		if list := r.innermost(func(f *aframe) bool { return f.kind == akList }); list != nil && list.ordered {
			f.marker = strconv.Itoa(list.next) + ". "
			list.next++
		}
	case "table":
		r.endParagraph()
		f.kind = akTable
	case "tableRow":
		f.kind = akRow
	case "tableHeader", "tableCell":
		f.kind, f.role, f.header = akFlow, arCell, n.Type == "tableHeader"
	case "panel", "expand", "nestedExpand", "layoutSection", "layoutColumn", "bodiedExtension",
		"multiBodiedExtension", "extensionFrame", "syncBlock", "bodiedSyncBlock":
		r.endParagraph()
		f.kind, f.role = akFlow, arBody
		if title := strings.TrimSpace(string(n.Attrs.Title)); title != "" {
			writeCollapsed(&f.para, &f.space, title)
			endParagraphOf(f)
		}
	default:
		// "doc", and every type this renderer does not know: what it holds
		// is read, as if it were not there.
		if n.Text != "" {
			r.inlineText(n)
		}
		f.kind = akInline
	}
	r.stack = append(r.stack, f)
	return true, true
}

// inlineText writes a text node, in backquotes when it carries a code mark.
func (r *adfRenderer) inlineText(n *adfNode) {
	code := false
	for _, m := range n.Marks {
		code = code || m.Type == "code"
	}
	if code && !r.inCode() && strings.TrimSpace(n.Text) != "" {
		r.text("`" + n.Text + "`")
		return
	}
	r.text(n.Text)
}

// adfDate is a date node's day: its timestamp is milliseconds since the
// epoch, in UTC.
func adfDate(ts string) string {
	ms, err := strconv.ParseInt(strings.TrimSpace(ts), 10, 64)
	if err != nil || ms < -62135596800000 || ms > 253402300799999 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02")
}

// pop closes the innermost frame.
func (r *adfRenderer) pop() {
	f := r.stack[len(r.stack)-1]
	r.stack = r.stack[:len(r.stack)-1]
	r.finishFrame(f)
}

// finish closes everything still open and returns the text.
func (r *adfRenderer) finish() string {
	for len(r.stack) > 1 {
		r.pop()
	}
	root := r.stack[0]
	endParagraphOf(root)
	parts := make([]string, 0, len(root.blocks))
	for _, b := range root.blocks {
		parts = append(parts, strings.Join(b, "\n"))
	}
	return strings.ToValidUTF8(strings.Join(parts, "\n\n"), "�")
}

// text writes s where it belongs: as written into code, collapsed into a
// heading or a paragraph.
func (r *adfRenderer) text(s string) {
	if s == "" {
		return
	}
	for i := len(r.stack) - 1; i >= 0; i-- {
		f := r.stack[i]
		switch f.kind {
		case akCode:
			f.code.WriteString(s)
			return
		case akHeading:
			writeCollapsed(&f.text, &f.space, s)
			return
		case akFlow:
			writeCollapsed(&f.para, &f.space, s)
			return
		case akList, akTable, akRow:
			// White space between a list's or a table's parts is layout.
			// Anything else there is malformed, and still the document's: it
			// goes to the text around them.
			if strings.TrimSpace(s) == "" {
				return
			}
		}
	}
}

// lineBreak is a hard break: a new line in a paragraph, a space in a heading.
func (r *adfRenderer) lineBreak() {
	for i := len(r.stack) - 1; i >= 0; i-- {
		f := r.stack[i]
		switch f.kind {
		case akCode:
			f.code.WriteByte('\n')
			return
		case akHeading:
			writeCollapsed(&f.text, &f.space, " ")
			return
		case akFlow:
			trimTrailingSpace(&f.para)
			if f.para.Len() > 0 {
				f.para.WriteByte('\n')
			}
			f.space = true
			return
		case akList, akTable, akRow:
			return
		}
	}
}

// endParagraph ends the paragraph being written in the innermost flow.
func (r *adfRenderer) endParagraph() { endParagraphOf(r.flow()) }

func endParagraphOf(f *aframe) {
	text := strings.TrimSpace(f.para.String())
	f.para.Reset()
	f.space = true
	if lines := paragraphLines(text); len(lines) > 0 {
		f.blocks = append(f.blocks, lines)
	}
}

// addBlock adds a finished block to the innermost flow.
func (r *adfRenderer) addBlock(lines []string) {
	if len(lines) == 0 {
		return
	}
	f := r.flow()
	endParagraphOf(f)
	f.blocks = append(f.blocks, lines)
}

// finishFrame renders a frame that just closed into what is around it.
func (r *adfRenderer) finishFrame(f *aframe) {
	switch f.kind {
	case akBlock:
		r.endParagraph()
	case akHeading:
		text := strings.TrimSpace(f.text.String())
		if text == "" {
			return
		}
		if r.inCompact() {
			r.text(" " + text + " ")
			return
		}
		r.addBlock([]string{headingLine(f.level, r.shift, text)})
	case akCode:
		if flow := r.flow(); flow.role == arCell {
			if code := strings.Join(strings.Fields(f.code.String()), " "); code != "" {
				r.text(" `" + code + "` ")
			}
			return
		}
		r.addBlock(codeLines(f.code.String(), f.lang))
	case akList:
		if len(f.lines) == 0 {
			return
		}
		switch flow := r.flow(); flow.role {
		case arItem:
			// A nested list is part of the item it is in.
			endParagraphOf(flow)
			flow.blocks = append(flow.blocks, f.lines)
		case arCell:
			r.text(" " + strings.Join(stripMarkers(f.lines), "; ") + " ")
		default:
			r.addBlock(f.lines)
		}
	case akFlow:
		r.finishFlow(f)
	case akRow:
		if len(f.cells) == 0 {
			return
		}
		if t := r.innermost(func(o *aframe) bool { return o.kind == akTable }); t != nil {
			header := true
			for _, h := range f.headCells {
				header = header && h
			}
			t.rows = append(t.rows, f.cells)
			t.headerRow = append(t.headerRow, header)
			return
		}
		r.addBlock([]string{tableLine(f.cells)})
	case akTable:
		lines := tableLines(f.rows, f.headerRow)
		if len(lines) == 0 {
			return
		}
		if cell := r.flow(); cell.role == arCell {
			r.text(" " + strings.Join(lines, " ") + " ")
			return
		}
		r.addBlock(lines)
	}
}

// finishFlow places a closed flow's blocks.
func (r *adfRenderer) finishFlow(f *aframe) {
	endParagraphOf(f)
	switch f.role {
	case arItem:
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
		indent := r.listDepth() < maxIndentLevels
		for i := range lines {
			switch {
			case i == 0:
				lines[i] = strings.TrimSpace(marker + lines[i])
			case indent:
				lines[i] = "  " + lines[i]
			}
		}
		if list := r.innermost(func(o *aframe) bool { return o.kind == akList }); list != nil {
			list.lines = append(list.lines, lines...)
			return
		}
		r.addBlock(lines)
	case arCell:
		var parts []string
		for _, b := range f.blocks {
			parts = append(parts, b...)
		}
		text := strings.Join(parts, " ")
		holder := r.innermost(func(o *aframe) bool { return o.kind == akRow || o.kind == akTable })
		switch {
		case holder != nil && holder.kind == akRow:
			holder.cells = append(holder.cells, text)
			holder.headCells = append(holder.headCells, f.header)
		case holder != nil:
			// A cell with no row around it is a row of its own.
			holder.rows = append(holder.rows, []string{text})
			holder.headerRow = append(holder.headerRow, f.header)
		case text != "":
			r.text(" " + text + " ")
		}
	case arQuote:
		for _, b := range f.blocks {
			quoted := make([]string, len(b))
			for i, l := range b {
				quoted[i] = "> " + l
			}
			r.addBlock(quoted)
		}
	default: // a panel's, an expand's, a layout's
		if role := r.flow().role; role == arCell || role == arItem {
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

// maxIndentLevels bounds how deep a nested list's lines are indented: past
// it, they keep the indentation they have. The chunker reads lines trimmed,
// so indentation is for a person reading the text; a bound keeps a hostile
// nesting from growing the text by its depth on every line.
const maxIndentLevels = 16

// listDepth counts the open lists.
func (r *adfRenderer) listDepth() int {
	n := 0
	for _, f := range r.stack {
		if f.kind == akList {
			n++
		}
	}
	return n
}

// Bounds on scanADF's output, which reads a document too large, or too
// broken, for a tree.
const maxScanText = 2 * knowledge.MaxBodyBytes

// adfBlockTypes are the node types whose text scanADF starts on a paragraph
// of its own.
var adfBlockTypes = map[string]bool{
	"paragraph": true, "heading": true, "listItem": true, "taskItem": true, "decisionItem": true,
	"codeBlock": true, "blockquote": true, "tableRow": true, "tableCell": true, "tableHeader": true,
	"panel": true, "expand": true, "nestedExpand": true, "rule": true, "caption": true,
}

// scanADF is the text of a document read token by token, without a tree: its
// text nodes' text and its mentions' names in order, a paragraph break before
// each block. It stops where the JSON stops being JSON, or at maxScanText, and
// keeps what it read.
func scanADF(raw []byte) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	type container struct {
		object  bool
		wantKey bool
	}
	var (
		stack  []container
		key    string
		para   strings.Builder
		space  = true
		blocks []string
		size   int
	)
	flush := func() {
		if lines := paragraphLines(strings.TrimSpace(para.String())); len(lines) > 0 {
			block := strings.Join(lines, "\n")
			blocks = append(blocks, block)
			size += len(block) + 2
		}
		para.Reset()
		space = true
	}
	for size+para.Len() < maxScanText {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		inObject := len(stack) > 0 && stack[len(stack)-1].object
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				stack = append(stack, container{object: d == '{', wantKey: d == '{'})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].wantKey = true
				}
			}
			continue
		}
		if inObject && stack[len(stack)-1].wantKey {
			key, _ = tok.(string)
			stack[len(stack)-1].wantKey = false
			continue
		}
		if s, ok := tok.(string); ok && inObject {
			switch {
			case key == "type" && adfBlockTypes[s]:
				flush()
			case key == "type" && s == "hardBreak":
				para.WriteByte('\n')
				space = true
			case key == "text":
				writeCollapsed(&para, &space, s+" ")
			}
		}
		if inObject {
			stack[len(stack)-1].wantKey = true
		}
	}
	flush()
	return strings.ToValidUTF8(strings.Join(blocks, "\n\n"), "�")
}
