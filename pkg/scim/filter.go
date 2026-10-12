package scim

// The filter grammar (RFC 7644 §3.4.2.2), as a list query and a PATCH value
// path use it.
//
// Identity providers ask for very little of it — Entra ID and Okta both look a
// user up with `userName eq "…"`, Entra a group with `displayName eq "…"`, and
// the hub's own directory uses `externalId eq "…"` — but the grammar is parsed
// in full (and, or, not, grouping, value paths, every comparison operator), so
// a provider that asks for more gets an answer rather than a wrong one. What
// cannot be parsed is refused with invalidFilter: a filter silently read as
// "everything" would hand a provider the whole directory where it asked for
// one account.

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// maxFilterLen bounds a filter. A provider's longest is a userName lookup; a
// filter longer than this is not a query anybody needs.
const maxFilterLen = 4096

// maxFilterDepth bounds nesting, so a filter of a thousand parentheses costs a
// refusal and not a stack.
const maxFilterDepth = 32

// AttrPath names an attribute: optionally qualified by its schema URN, and
// optionally narrowed to one sub-attribute.
type AttrPath struct {
	// URN is the extension schema the attribute belongs to, canonically
	// spelt, or "" for a core or common attribute.
	URN string
	// Name is the attribute's name as written.
	Name string
	// Sub is the sub-attribute's name, or "".
	Sub string
}

func (p AttrPath) String() string {
	s := p.Name
	if p.URN != "" {
		s = p.URN + ":" + s
	}
	if p.Sub != "" {
		s += "." + p.Sub
	}
	return s
}

// definition returns the attribute's definition, or nil for one no schema
// defines.
func (p AttrPath) definition(kind Kind) *Attribute {
	if p.URN != "" {
		return kind.extension(p.URN).attr(p.Name)
	}
	return kind.definition(p.Name)
}

// Filter is a parsed filter expression.
type Filter struct {
	root node
	kind Kind
}

// node is one expression in a filter.
type node interface {
	match(obj map[string]any, kind Kind, elem *Attribute) bool
}

type (
	logicalNode struct {
		and         bool
		left, right node
	}
	notNode struct{ inner node }
	// compareNode is attrPath op value, or attrPath pr.
	compareNode struct {
		path  AttrPath
		op    string
		value any
	}
	// valuePathNode is attrPath[filter]: some element of a multi-valued
	// attribute satisfies the inner filter.
	valuePathNode struct {
		path  AttrPath
		inner node
	}
)

// ParseFilter parses a filter for resources of kind.
func ParseFilter(src string, kind Kind) (*Filter, error) {
	if len(src) > maxFilterLen {
		return nil, BadRequest(ErrInvalidFilter, "the filter is %d bytes; the limit is %d", len(src), maxFilterLen)
	}
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, kind: kind}
	n, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, BadRequest(ErrInvalidFilter, "unexpected %q after the end of the filter", p.peek().text)
	}
	return &Filter{root: n, kind: kind}, nil
}

// Matches reports whether a resource satisfies the filter.
func (f *Filter) Matches(obj map[string]any) bool {
	if f == nil || f.root == nil {
		return true
	}
	return f.root.match(obj, f.kind, nil)
}

// Equality reports the filter's single top-level comparison when it is
// nothing but `attr eq "string"` on a core or common attribute with no
// sub-attribute — the shape a storage layer can answer from an index. ok is
// false for anything else, which the caller then evaluates with Matches.
func (f *Filter) Equality() (attr, value string, ok bool) {
	if f == nil {
		return "", "", false
	}
	c, isCompare := f.root.(*compareNode)
	if !isCompare || c.op != "eq" || c.path.URN != "" || c.path.Sub != "" {
		return "", "", false
	}
	s, isString := c.value.(string)
	if !isString {
		return "", "", false
	}
	def := f.kind.definition(c.path.Name)
	if def == nil {
		return "", "", false
	}
	return def.Name, s, true
}

// ── evaluation ──────────────────────────────────────────────────────────────

func (n *logicalNode) match(obj map[string]any, kind Kind, elem *Attribute) bool {
	if n.and {
		return n.left.match(obj, kind, elem) && n.right.match(obj, kind, elem)
	}
	return n.left.match(obj, kind, elem) || n.right.match(obj, kind, elem)
}

func (n *notNode) match(obj map[string]any, kind Kind, elem *Attribute) bool {
	return !n.inner.match(obj, kind, elem)
}

func (n *valuePathNode) match(obj map[string]any, kind Kind, elem *Attribute) bool {
	def := n.path.definition(kind)
	raw, ok := lookupPath(obj, n.path, kind)
	if !ok {
		return false
	}
	for _, v := range asList(raw) {
		m, isObj := v.(map[string]any)
		if !isObj {
			continue
		}
		if n.inner.match(m, kind, def) {
			return true
		}
	}
	return false
}

func (n *compareNode) match(obj map[string]any, kind Kind, elem *Attribute) bool {
	var (
		values []any
		def    *Attribute
	)
	if elem != nil {
		// Inside a value path: the path names a sub-attribute of the
		// element being tested.
		def = elem.sub(n.path.Name)
		if v, ok := lookup(obj, n.path.Name); ok {
			values = asList(v)
		}
	} else {
		top := n.path.definition(kind)
		raw, ok := lookupPath(obj, AttrPath{URN: n.path.URN, Name: n.path.Name}, kind)
		if ok {
			def = top
			sub := n.path.Sub
			if sub == "" && top != nil && top.Type == "complex" && top.MultiValued {
				// A multi-valued complex attribute compared with no
				// sub-attribute is compared on its value (RFC 7644 §3.4.2.2).
				sub = "value"
			}
			for _, v := range asList(raw) {
				if sub == "" {
					values = append(values, v)
					continue
				}
				if m, isObj := v.(map[string]any); isObj {
					if sv, found := lookup(m, sub); found {
						values = append(values, asList(sv)...)
					}
				}
			}
			if sub != "" {
				def = top.sub(sub)
			}
		}
	}
	if n.op == "pr" {
		for _, v := range values {
			if present(v) {
				return true
			}
		}
		return false
	}
	caseExact := def != nil && def.CaseExact
	for _, v := range values {
		if compare(v, n.op, n.value, caseExact) {
			return true
		}
	}
	return false
}

// present reports whether v counts as a value for the pr operator.
func present(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// compare applies op between a resource value and a filter literal.
func compare(have any, op string, want any, caseExact bool) bool {
	switch w := want.(type) {
	case nil:
		switch op {
		case "eq":
			return have == nil
		case "ne":
			return have != nil
		}
		return false
	case bool:
		h, ok := boolValue(have)
		if !ok {
			return false
		}
		switch op {
		case "eq":
			return h == w
		case "ne":
			return h != w
		}
		return false
	case float64:
		h, ok := numberValue(have)
		if !ok {
			return false
		}
		switch op {
		case "eq":
			return h == w
		case "ne":
			return h != w
		case "gt":
			return h > w
		case "ge":
			return h >= w
		case "lt":
			return h < w
		case "le":
			return h <= w
		}
		return false
	case string:
		h, ok := have.(string)
		if !ok {
			return false
		}
		if !caseExact {
			h, w = strings.ToLower(h), strings.ToLower(w)
		}
		switch op {
		case "eq":
			return h == w
		case "ne":
			return h != w
		case "co":
			return strings.Contains(h, w)
		case "sw":
			return strings.HasPrefix(h, w)
		case "ew":
			return strings.HasSuffix(h, w)
		case "gt":
			return h > w
		case "ge":
			return h >= w
		case "lt":
			return h < w
		case "le":
			return h <= w
		}
	}
	return false
}

// boolValue reads a boolean the way Entra ID sends one: true, or "True".
func boolValue(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func numberValue(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

// asList returns v as a list: itself when it is one, else a list of one.
func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if v == nil {
		return nil
	}
	return []any{v}
}

// lookup reads a key case-insensitively, preferring an exact match.
func lookup(obj map[string]any, name string) (any, bool) {
	if v, ok := obj[name]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

// lookupKey is lookup returning the key as stored.
func lookupKey(obj map[string]any, name string) (string, bool) {
	if _, ok := obj[name]; ok {
		return name, true
	}
	for k := range obj {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}
	return "", false
}

// lookupPath reads the attribute a path names (its sub-attribute aside):
// a top-level key, or a key of the extension object the URN names.
func lookupPath(obj map[string]any, p AttrPath, kind Kind) (any, bool) {
	if p.URN == "" {
		return lookup(obj, p.Name)
	}
	ext, ok := lookup(obj, p.URN)
	if !ok {
		return nil, false
	}
	m, ok := ext.(map[string]any)
	if !ok {
		return nil, false
	}
	return lookup(m, p.Name)
}

// ── parsing ─────────────────────────────────────────────────────────────────

type tokKind int

const (
	tokWord tokKind = iota
	tokString
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
)

type token struct {
	kind tokKind
	text string // the word, or the decoded string
	raw  string
}

// tokenize splits a filter into words, quoted strings and brackets.
func tokenize(src string) ([]token, error) {
	var out []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{kind: tokLParen, text: "(", raw: "("})
			i++
		case c == ')':
			out = append(out, token{kind: tokRParen, text: ")", raw: ")"})
			i++
		case c == '[':
			out = append(out, token{kind: tokLBracket, text: "[", raw: "["})
			i++
		case c == ']':
			out = append(out, token{kind: tokRBracket, text: "]", raw: "]"})
			i++
		case c == '"':
			end := i + 1
			for end < len(src) {
				if src[end] == '\\' {
					end += 2
					continue
				}
				if src[end] == '"' {
					break
				}
				end++
			}
			if end >= len(src) {
				return nil, BadRequest(ErrInvalidFilter, "a quoted string in the filter is not closed")
			}
			raw := src[i : end+1]
			var s string
			if err := json.Unmarshal([]byte(raw), &s); err != nil {
				return nil, BadRequest(ErrInvalidFilter, "the filter string %s is not valid: %v", raw, err)
			}
			out = append(out, token{kind: tokString, text: s, raw: raw})
			i = end + 1
		default:
			end := i
			for end < len(src) && !strings.ContainsRune(" \t\r\n()[]\"", rune(src[end])) {
				end++
			}
			out = append(out, token{kind: tokWord, text: src[i:end], raw: src[i:end]})
			i = end
		}
	}
	return out, nil
}

type parser struct {
	toks []token
	pos  int
	kind Kind
}

func (p *parser) done() bool { return p.pos >= len(p.toks) }

func (p *parser) peek() token {
	if p.done() {
		return token{kind: tokWord, text: "", raw: "end of filter"}
	}
	return p.toks[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if !p.done() {
		p.pos++
	}
	return t
}

func (p *parser) keyword(word string) bool {
	t := p.peek()
	return !p.done() && t.kind == tokWord && strings.EqualFold(t.text, word)
}

// parseOr: or binds loosest.
func (p *parser) parseOr(depth int) (node, error) {
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("or") {
		p.next()
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		left = &logicalNode{and: false, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd(depth int) (node, error) {
	left, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("and") {
		p.next()
		right, err := p.parseUnary(depth)
		if err != nil {
			return nil, err
		}
		left = &logicalNode{and: true, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary(depth int) (node, error) {
	if depth > maxFilterDepth {
		return nil, BadRequest(ErrInvalidFilter, "the filter nests deeper than %d", maxFilterDepth)
	}
	if p.keyword("not") {
		p.next()
		if p.peek().kind != tokLParen {
			return nil, BadRequest(ErrInvalidFilter, `"not" must be followed by a parenthesised filter`)
		}
		inner, err := p.parseGroup(depth + 1)
		if err != nil {
			return nil, err
		}
		return &notNode{inner: inner}, nil
	}
	if p.peek().kind == tokLParen {
		return p.parseGroup(depth + 1)
	}
	return p.parseAttrExp(depth)
}

func (p *parser) parseGroup(depth int) (node, error) {
	p.next() // (
	inner, err := p.parseOr(depth)
	if err != nil {
		return nil, err
	}
	if p.next().kind != tokRParen {
		return nil, BadRequest(ErrInvalidFilter, "a parenthesis in the filter is not closed")
	}
	return inner, nil
}

func (p *parser) parseAttrExp(depth int) (node, error) {
	t := p.next()
	if t.kind != tokWord || t.text == "" {
		return nil, BadRequest(ErrInvalidFilter, "expected an attribute, found %s", t.raw)
	}
	path, err := ParseAttrPath(t.text, p.kind)
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tokLBracket {
		p.next()
		inner, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next().kind != tokRBracket {
			return nil, BadRequest(ErrInvalidFilter, "a value path's bracket is not closed")
		}
		return &valuePathNode{path: path, inner: inner}, nil
	}
	opTok := p.next()
	if opTok.kind != tokWord {
		return nil, BadRequest(ErrInvalidFilter, "expected an operator after %q, found %s", t.text, opTok.raw)
	}
	op := strings.ToLower(opTok.text)
	switch op {
	case "pr":
		return &compareNode{path: path, op: op}, nil
	case "eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le":
	default:
		return nil, BadRequest(ErrInvalidFilter, "%q is not a filter operator", opTok.text)
	}
	vt := p.next()
	value, err := literal(vt)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case bool, nil:
		if op != "eq" && op != "ne" {
			return nil, BadRequest(ErrInvalidFilter, "%s compares only with eq and ne", vt.raw)
		}
	}
	return &compareNode{path: path, op: op, value: value}, nil
}

// literal reads a comparison value: a string, true, false, null or a number.
func literal(t token) (any, error) {
	switch t.kind {
	case tokString:
		return t.text, nil
	case tokWord:
		switch strings.ToLower(t.text) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
		if f, err := strconv.ParseFloat(t.text, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, nil
		}
	}
	return nil, BadRequest(ErrInvalidFilter, "expected a value (a quoted string, true, false, null or a number), found %s", t.raw)
}

// ParseAttrPath parses an attribute path: [URN ":"] name ["." sub].
//
// An extension URN the kind defines is recognised whether a ":" or a "."
// follows it: Microsoft Entra ID spelt `…:enterprise:2.0:User.employeeNumber`
// before its compliance fixes. The core schema's own URN is accepted as a
// redundant qualifier and dropped.
func ParseAttrPath(word string, kind Kind) (AttrPath, error) {
	word = strings.TrimSpace(word)
	if word == "" {
		return AttrPath{}, BadRequest(ErrInvalidPath, "an attribute path is empty")
	}
	var urn, rest string
	if len(word) > 4 && strings.EqualFold(word[:4], "urn:") {
		matched := false
		candidates := []string{kind.coreSchema().ID}
		for _, s := range kind.extensions() {
			candidates = append(candidates, s.ID)
		}
		for _, c := range candidates {
			if len(word) > len(c)+1 && strings.EqualFold(word[:len(c)], c) &&
				(word[len(c)] == ':' || word[len(c)] == '.') {
				urn, rest, matched = c, word[len(c)+1:], true
				break
			}
		}
		if !matched {
			i := strings.LastIndexByte(word, ':')
			if i <= 0 || i == len(word)-1 {
				return AttrPath{}, BadRequest(ErrInvalidPath, "%q names no attribute after its schema", word)
			}
			urn, rest = word[:i], word[i+1:]
		}
		if strings.EqualFold(urn, kind.coreSchema().ID) {
			urn = ""
		}
	} else {
		rest = word
	}
	name, sub, _ := strings.Cut(rest, ".")
	if !validAttrName(name) {
		return AttrPath{}, BadRequest(ErrInvalidPath, "%q is not an attribute name", name)
	}
	if strings.Contains(rest, ".") && !validAttrName(sub) {
		return AttrPath{}, BadRequest(ErrInvalidPath, "%q is not a sub-attribute name", sub)
	}
	return AttrPath{URN: urn, Name: name, Sub: sub}, nil
}

// validAttrName: ATTRNAME = ALPHA *(nameChar), plus "$ref".
func validAttrName(s string) bool {
	if s == "$ref" {
		return true
	}
	if s == "" || len(s) > 128 {
		return false
	}
	for i, r := range s {
		switch {
		case r < 128 && unicode.IsLetter(r):
		case i > 0 && (r == '-' || r == '_' || (r >= '0' && r <= '9')):
		default:
			return false
		}
	}
	return true
}

// String renders a filter back, for an error message or the audit trail.
func (f *Filter) String() string {
	if f == nil || f.root == nil {
		return ""
	}
	return renderNode(f.root)
}

func renderNode(n node) string {
	switch t := n.(type) {
	case *logicalNode:
		op := "or"
		if t.and {
			op = "and"
		}
		return "(" + renderNode(t.left) + " " + op + " " + renderNode(t.right) + ")"
	case *notNode:
		return "not (" + renderNode(t.inner) + ")"
	case *valuePathNode:
		return t.path.String() + "[" + renderNode(t.inner) + "]"
	case *compareNode:
		if t.op == "pr" {
			return t.path.String() + " pr"
		}
		b, _ := json.Marshal(t.value)
		return fmt.Sprintf("%s %s %s", t.path.String(), t.op, b)
	}
	return ""
}
