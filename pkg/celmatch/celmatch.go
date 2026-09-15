// Package celmatch evaluates a strict subset of CEL against a claim set.
//
// It exists to answer one question — "may this workload identity be trusted?"
// — from an expression an operator typed into a settings form. That is the
// same job Google's workload identity federation gives its `attribute_condition`,
// and the syntax here is deliberately the syntax an operator would write there,
// because someone federating GitHub Actions has almost certainly read those
// docs.
//
// # Why a subset rather than cel-go
//
// This is a security gate, and the property that matters is that an operator
// who reads an expression and a machine that evaluates it reach the same
// conclusion. Full CEL is a large language: macros that bind variables
// (`all`, `exists`, `map`), dynamic dispatch, timestamp and duration
// arithmetic, protobuf well-known types, optional chaining. Every one of those
// is a way for the two readings to diverge, and none of them is needed to say
// "this repository, on this branch, in this environment".
//
// So the grammar below is closed. It accepts literals, identifiers, field
// selection, four string methods, membership, equality, and boolean
// connectives. Anything else is a *parse* error, surfaced when the rule is
// saved rather than when a pipeline presents a token — which is the whole
// point of refusing early. An operator who needs more than this is describing
// a policy the audit reader cannot check by eye, and should be writing several
// narrow rules instead of one wide one.
//
// # Failure is denial, never permission
//
// Compile refuses anything it does not fully understand. Eval returns an error
// — not false — when an expression references a claim that is absent or
// compares values of different types, and every caller is required to treat a
// non-nil error as "no match". There is deliberately no lenient mode: the
// failure modes of a trust policy are asymmetric, and an expression that
// evaluates to true because a claim was missing is the one outcome worth
// engineering against.
//
// # The conformance contract
//
// Being a subset is only safe in one direction. The operator who writes a rule
// takes their mental model from GitHub's and Google's OIDC documentation, both
// of which describe real CEL — so any expression this evaluator admits and CEL
// would deny is an authorization bypass that the operator cannot find by
// re-reading their own policy. Their policy means what they think it means;
// this evaluator is the thing that disagrees. The reverse costs nothing: a
// refusal is a denial with a clearer message.
//
// So the invariant, asserted in conformance_test.go, is one-directional:
//
//	celmatch admits  =>  real CEL admits
//
// It is held against cel.dev/cel-go rather than against anybody's reading of
// the specification. testdata/conformance.json is the corpus,
// testdata/celprobe is a nested module that runs it through the reference
// implementation, and testdata/conformance-table.txt is the side-by-side that
// results — currently ~50 rows where the two disagree, every one of them this
// package being stricter. FuzzCompile and FuzzEvalClaims extend the same
// invariant past the corpus using the oracle in oracle_test.go.
//
// Before changing any semantics here, read that table. Several of the
// divergences look like bugs and are not: no commutative absorption for
// `&&`/`||`, an error rather than false for cross-type equality, and a refusal
// rather than a verdict for a mixed-type list literal are all load-bearing.
package celmatch

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MaxExpressionBytes bounds the source an operator may submit. Expressions
// are typed into a form by a human; anything past this is either a mistake or
// an attempt to find a parser limit, and both are better refused at the door
// than discovered by the parser's recursion depth.
const MaxExpressionBytes = 4096

// maxDepth bounds parser recursion. The grammar is small and the parser is
// recursive descent, so a pathological nest of parentheses is the only way to
// reach a deep stack. 64 is far past any legible policy.
const maxDepth = 64

// ErrNoSuchKey reports a selector naming a claim the token did not carry.
//
// It is a distinct error because callers want to tell an operator the
// difference between "your expression is wrong" and "this token does not have
// that claim" — the second is routine when a workflow runs outside an
// environment, and reads as a typo if reported as a generic failure.
var ErrNoSuchKey = errors.New("celmatch: no such key")

// Program is a compiled expression. It is immutable after Compile and safe
// for concurrent use.
type Program struct {
	src  string
	root node
	// refs are the top-level claim names the expression reads, sorted. They
	// let the UI show which claims a rule depends on without re-parsing.
	refs []string
}

// Source returns the expression text the Program was compiled from.
func (p *Program) Source() string { return p.src }

// References returns the claim names the expression reads, sorted and
// deduplicated. Only selections rooted at the activation variable are
// reported; `assertion.repository` yields "repository".
func (p *Program) References() []string {
	out := make([]string, len(p.refs))
	copy(out, p.refs)
	return out
}

// RootVar is the name an expression uses to reach the token's claims. It
// matches the identifier Google's workload identity federation uses, so an
// expression written against those docs compiles here unchanged.
const RootVar = "assertion"

// Compile parses src and returns a Program, or an error describing the first
// thing it could not accept.
//
// The error is written for the operator who typed the expression, and names
// the byte offset, because a policy editor that says only "invalid" leaves
// someone bisecting a one-line expression by hand.
func Compile(src string) (*Program, error) {
	if len(src) > MaxExpressionBytes {
		return nil, fmt.Errorf("celmatch: expression is %d bytes, limit is %d",
			len(src), MaxExpressionBytes)
	}
	if strings.TrimSpace(src) == "" {
		return nil, errors.New("celmatch: expression is empty")
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, src: src}
	root, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if !p.atEnd() {
		return nil, p.errorf(p.peek().pos, "unexpected %s", p.peek().describe())
	}
	prog := &Program{src: src, root: root, refs: collectRefs(root)}
	return prog, nil
}

// Eval evaluates the program against claims and reports whether it matched.
//
// A non-nil error means the expression could not be evaluated — a missing
// claim, or a comparison between values of different types — and the caller
// must treat that as "no match". Eval never returns (true, non-nil error).
func (p *Program) Eval(claims map[string]any) (bool, error) {
	if p == nil || p.root == nil {
		return false, errors.New("celmatch: nil program")
	}
	v, err := p.root.eval(&activation{claims: claims})
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("celmatch: expression yielded %s, want bool", typeName(v))
	}
	return b, nil
}

// activation is the variable binding an expression is evaluated against.
type activation struct {
	claims map[string]any
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokInt
	tokPunct // one of  ( ) [ ] , . ! && || == != and the keyword `in`
)

type token struct {
	kind tokKind
	text string
	str  string // decoded value for tokString
	num  int64  // decoded value for tokInt
	pos  int
}

func (t token) describe() string {
	switch t.kind {
	case tokEOF:
		return "end of expression"
	case tokString:
		return "string " + strconv.Quote(t.str)
	case tokInt:
		return "number " + t.text
	case tokIdent:
		return "identifier " + strconv.Quote(t.text)
	default:
		return strconv.Quote(t.text)
	}
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"' || c == '\'':
			s, n, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokString, text: src[i : i+n], str: s, pos: i})
			i += n
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			// Reject 1.5 and 0x10 explicitly. Silently lexing "1" out of
			// "1.5" would leave a stray ".5" for the parser to complain
			// about somewhere unrelated to the actual mistake.
			if j < len(src) && (src[j] == '.' || isIdentChar(src[j])) {
				return nil, fmt.Errorf("celmatch: at byte %d: only decimal integers are supported", i)
			}
			n, err := strconv.ParseInt(src[i:j], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("celmatch: at byte %d: %v", i, err)
			}
			out = append(out, token{kind: tokInt, text: src[i:j], num: n, pos: i})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			word := src[i:j]
			if word == "in" {
				out = append(out, token{kind: tokPunct, text: "in", pos: i})
			} else {
				out = append(out, token{kind: tokIdent, text: word, pos: i})
			}
			i = j
		default:
			op := matchOperator(src[i:])
			if op == "" {
				return nil, fmt.Errorf("celmatch: at byte %d: unexpected character %q", i, string(c))
			}
			out = append(out, token{kind: tokPunct, text: op, pos: i})
			i += len(op)
		}
	}
	out = append(out, token{kind: tokEOF, pos: len(src)})
	return out, nil
}

// operators are matched longest-first so "==" is never read as two tokens.
var operators = []string{"&&", "||", "==", "!=", "(", ")", "[", "]", ",", ".", "!"}

func matchOperator(s string) string {
	for _, op := range operators {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	// A lone & or | is almost always a typo for && or ||; naming that is
	// more useful than "unexpected character".
	if strings.HasPrefix(s, "&") {
		return ""
	}
	return ""
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// lexString decodes a quoted string starting at src[start], returning the
// decoded value and the number of source bytes consumed.
//
// Escapes are the ones CEL shares with Go's rune literals minus the numeric
// forms: \\ \" \' \n \r \t. Numeric escapes are omitted because a claim
// matcher has no use for them and because \x and \u are where encoding
// confusion lives.
func lexString(src string, start int) (string, int, error) {
	quote := src[start]
	var b strings.Builder
	i := start + 1
	for i < len(src) {
		c := src[i]
		switch c {
		case quote:
			return b.String(), i - start + 1, nil
		case '\\':
			if i+1 >= len(src) {
				return "", 0, fmt.Errorf("celmatch: at byte %d: string ends in a backslash", i)
			}
			switch src[i+1] {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case '\'':
				b.WriteByte('\'')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				return "", 0, fmt.Errorf("celmatch: at byte %d: unsupported escape %q", i, src[i:i+2])
			}
			i += 2
		case '\n':
			return "", 0, fmt.Errorf("celmatch: at byte %d: string spans a newline", i)
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", 0, fmt.Errorf("celmatch: at byte %d: unterminated string", start)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
	src  string
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) atEnd() bool { return p.toks[p.pos].kind == tokEOF }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

func (p *parser) acceptPunct(text string) bool {
	if t := p.peek(); t.kind == tokPunct && t.text == text {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expectPunct(text string) error {
	if p.acceptPunct(text) {
		return nil
	}
	return p.errorf(p.peek().pos, "expected %q, found %s", text, p.peek().describe())
}

func (p *parser) errorf(pos int, format string, args ...any) error {
	return fmt.Errorf("celmatch: at byte %d: %s", pos, fmt.Sprintf(format, args...))
}

// parseExpr parses the lowest-precedence production: `||`.
func (p *parser) parseExpr(depth int) (node, error) {
	if depth > maxDepth {
		return nil, p.errorf(p.peek().pos, "expression nests deeper than %d levels", maxDepth)
	}
	left, err := p.parseAnd(depth + 1)
	if err != nil {
		return nil, err
	}
	for p.acceptPunct("||") {
		right, err := p.parseAnd(depth + 1)
		if err != nil {
			return nil, err
		}
		left = &orNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd(depth int) (node, error) {
	if depth > maxDepth {
		return nil, p.errorf(p.peek().pos, "expression nests deeper than %d levels", maxDepth)
	}
	left, err := p.parseRelation(depth + 1)
	if err != nil {
		return nil, err
	}
	for p.acceptPunct("&&") {
		right, err := p.parseRelation(depth + 1)
		if err != nil {
			return nil, err
		}
		left = &andNode{left: left, right: right}
	}
	return left, nil
}

// parseRelation parses `a == b`, `a != b` and `a in b`.
//
// Relations do not chain: `a == b == c` is refused rather than silently
// parsed left-associatively into a comparison against a bool, which is a
// mistake the operator meant as `a == b && b == c`.
func (p *parser) parseRelation(depth int) (node, error) {
	if depth > maxDepth {
		return nil, p.errorf(p.peek().pos, "expression nests deeper than %d levels", maxDepth)
	}
	left, err := p.parseUnary(depth + 1)
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t.kind != tokPunct {
		return left, nil
	}
	switch t.text {
	case "==", "!=", "in":
		p.next()
		right, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		var n node
		switch t.text {
		case "==":
			n = &eqNode{left: left, right: right, negate: false}
		case "!=":
			n = &eqNode{left: left, right: right, negate: true}
		default:
			n = &inNode{needle: left, haystack: right}
		}
		if nt := p.peek(); nt.kind == tokPunct && (nt.text == "==" || nt.text == "!=" || nt.text == "in") {
			return nil, p.errorf(nt.pos,
				"comparisons do not chain; write `a %s b && b %s c`", t.text, nt.text)
		}
		return n, nil
	}
	return left, nil
}

func (p *parser) parseUnary(depth int) (node, error) {
	if depth > maxDepth {
		return nil, p.errorf(p.peek().pos, "expression nests deeper than %d levels", maxDepth)
	}
	if p.acceptPunct("!") {
		inner, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		return &notNode{inner: inner}, nil
	}
	return p.parsePrimary(depth + 1)
}

func (p *parser) parsePrimary(depth int) (node, error) {
	if depth > maxDepth {
		return nil, p.errorf(p.peek().pos, "expression nests deeper than %d levels", maxDepth)
	}
	t := p.peek()
	switch {
	case t.kind == tokString:
		p.next()
		return &litNode{val: t.str}, nil
	case t.kind == tokInt:
		p.next()
		return &litNode{val: t.num}, nil
	case t.kind == tokIdent:
		p.next()
		switch t.text {
		case "true":
			return &litNode{val: true}, nil
		case "false":
			return &litNode{val: false}, nil
		}
		if t.text != RootVar {
			return nil, p.errorf(t.pos,
				"unknown identifier %q; claims are reached through %q (for example %s.repository)",
				t.text, RootVar, RootVar)
		}
		return p.parseSelectors(&rootNode{}, depth+1)
	case t.kind == tokPunct && t.text == "(":
		p.next()
		inner, err := p.parseExpr(depth + 1)
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		return p.parseSelectors(inner, depth+1)
	case t.kind == tokPunct && t.text == "[":
		return p.parseList(depth + 1)
	}
	return nil, p.errorf(t.pos, "expected a value, found %s", t.describe())
}

func (p *parser) parseList(depth int) (node, error) {
	open := p.peek().pos
	if err := p.expectPunct("["); err != nil {
		return nil, err
	}
	lst := &listNode{}
	if p.acceptPunct("]") {
		return lst, nil
	}
	for {
		el, err := p.parseExpr(depth + 1)
		if err != nil {
			return nil, err
		}
		lst.elems = append(lst.elems, el)
		if p.acceptPunct(",") {
			// Tolerate a trailing comma before ]: it is how a long
			// allowlist gets edited, and refusing it teaches nothing.
			if p.acceptPunct("]") {
				if err := checkHomogeneous(p, open, lst); err != nil {
					return nil, err
				}
				return lst, nil
			}
			continue
		}
		if err := p.expectPunct("]"); err != nil {
			return nil, err
		}
		if err := checkHomogeneous(p, open, lst); err != nil {
			return nil, err
		}
		return lst, nil
	}
}

// checkHomogeneous refuses a list literal whose literal elements are not all
// the same type.
//
// This is a load-bearing refusal rather than tidiness. `in` walks the list and
// compares element by element, and a comparison across types is an error — so
// without this check the verdict for a mixed allowlist depends on the order the
// operator happened to type it in. `assertion.repository_id in ["123456", 999]`
// admitted, because the match was found before the int was reached, while
// `assertion.repository_id in [123456, "123456"]` was undecidable, because it
// was not. Two spellings of one intent, two different authorization outcomes,
// and reordering an allowlist silently changes which one you get.
//
// Refusing at compile time collapses both to the same answer and delivers it
// when the rule is saved, which is this package's whole contract. It is also
// what real CEL does: its checker rejects `"123" in [123]` outright with "no
// matching overload for '@in' applied to '(string, list(int))'".
//
// Only literal elements can be checked here — `[assertion.a, "b"]` has a type
// nobody knows until evaluation — which is the same limit CEL's own checker
// has, and covers every allowlist an operator actually writes.
func checkHomogeneous(p *parser, pos int, lst *listNode) error {
	var want string
	for _, el := range lst.elems {
		lit, ok := el.(*litNode)
		if !ok {
			continue
		}
		got := typeName(lit.val)
		if want == "" {
			want = got
			continue
		}
		if got != want {
			return p.errorf(pos,
				"list mixes %s and %s elements; a comparison across types cannot "+
					"be decided, so whether this matches would depend on the order "+
					"the entries are written in — use one type per list",
				want, got)
		}
	}
	return nil
}

// celLiteralWords are the identifiers CEL's grammar treats as literals, which
// therefore cannot appear as a field name.
var celLiteralWords = map[string]bool{
	"true":  true,
	"false": true,
	"null":  true,
}

// stringMethods are the only calls the grammar admits. Each takes exactly one
// string argument and returns bool.
var stringMethods = map[string]bool{
	"startsWith": true,
	"endsWith":   true,
	"contains":   true,
	"matches":    true,
}

// parseSelectors consumes a chain of `.name` and `.method(arg)` suffixes.
func (p *parser) parseSelectors(base node, depth int) (node, error) {
	for p.acceptPunct(".") {
		name := p.next()
		if name.kind != tokIdent {
			return nil, p.errorf(name.pos, "expected a field name after '.', found %s", name.describe())
		}
		// `true`, `false` and `null` are CEL literals, so CEL's parser refuses
		// them in field position: `assertion.true` is "mismatched input 'true'
		// expecting IDENTIFIER". Accepting them here would mean compiling an
		// expression the operator's reference implementation rejects outright,
		// and evaluating it against a claim of that name if one ever existed.
		//
		// Only these three. CEL's *spec* reserves a longer list (`if`, `for`,
		// `return`, ...) but cel-go accepts those as field names and resolves
		// them at runtime, so refusing them would be strictness with no
		// divergence behind it — and would block a legitimate claim for nothing.
		if celLiteralWords[name.text] {
			return nil, p.errorf(name.pos,
				"%q is a CEL literal and cannot name a field; CEL itself refuses "+
					"to parse %s.%s", name.text, RootVar, name.text)
		}
		if !p.acceptPunct("(") {
			base = &selectNode{base: base, field: name.text}
			continue
		}
		if !stringMethods[name.text] {
			return nil, p.errorf(name.pos,
				"unsupported method %q; supported: contains, endsWith, matches, startsWith", name.text)
		}
		arg, err := p.parseExpr(depth + 1)
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(")"); err != nil {
			return nil, err
		}
		call := &callNode{recv: base, method: name.text, arg: arg}
		// matches() takes a regular expression, and a regular expression that
		// does not compile is a configuration error rather than a runtime one.
		// Requiring a literal is what makes that check possible here instead
		// of on the request path, and no real policy computes its own pattern.
		if name.text == "matches" {
			lit, ok := arg.(*litNode)
			if !ok {
				return nil, p.errorf(name.pos, "matches() requires a literal regular expression")
			}
			pat, ok := lit.val.(string)
			if !ok {
				return nil, p.errorf(name.pos, "matches() requires a string, found %s", typeName(lit.val))
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, p.errorf(name.pos, "matches(): %v", err)
			}
			call.re = re
		}
		base = call
	}
	return base, nil
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

type node interface {
	eval(a *activation) (any, error)
	children() []node
}

type litNode struct{ val any }

func (n *litNode) eval(*activation) (any, error) { return n.val, nil }
func (n *litNode) children() []node              { return nil }

// rootNode is the activation variable itself. It never evaluates: a bare
// `assertion` is rejected by Eval's bool check, and every legal use is under
// a selectNode which reads a.claims directly.
type rootNode struct{}

func (n *rootNode) eval(a *activation) (any, error) {
	return nil, errors.New("celmatch: " + RootVar + " is not a value; select a claim from it")
}
func (n *rootNode) children() []node { return nil }

type selectNode struct {
	base  node
	field string
}

func (n *selectNode) children() []node { return []node{n.base} }

func (n *selectNode) eval(a *activation) (any, error) {
	if _, ok := n.base.(*rootNode); ok {
		v, present := a.claims[n.field]
		if !present {
			return nil, fmt.Errorf("%w: the token carries no %q claim", ErrNoSuchKey, n.field)
		}
		return normalize(v)
	}
	base, err := n.base.eval(a)
	if err != nil {
		return nil, err
	}
	m, ok := base.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("celmatch: cannot select %q from %s", n.field, typeName(base))
	}
	v, present := m[n.field]
	if !present {
		return nil, fmt.Errorf("%w: no %q field", ErrNoSuchKey, n.field)
	}
	return normalize(v)
}

type callNode struct {
	recv   node
	method string
	arg    node
	re     *regexp.Regexp // pre-compiled for matches()
}

func (n *callNode) children() []node { return []node{n.recv, n.arg} }

func (n *callNode) eval(a *activation) (any, error) {
	recv, err := n.recv.eval(a)
	if err != nil {
		return nil, err
	}
	s, ok := recv.(string)
	if !ok {
		return nil, fmt.Errorf("celmatch: %s() applies to a string, not %s", n.method, typeName(recv))
	}
	if n.method == "matches" {
		return n.re.MatchString(s), nil
	}
	argv, err := n.arg.eval(a)
	if err != nil {
		return nil, err
	}
	arg, ok := argv.(string)
	if !ok {
		return nil, fmt.Errorf("celmatch: %s() takes a string, not %s", n.method, typeName(argv))
	}
	switch n.method {
	case "startsWith":
		return strings.HasPrefix(s, arg), nil
	case "endsWith":
		return strings.HasSuffix(s, arg), nil
	case "contains":
		return strings.Contains(s, arg), nil
	}
	return nil, fmt.Errorf("celmatch: unsupported method %q", n.method)
}

type listNode struct{ elems []node }

func (n *listNode) children() []node { return n.elems }

func (n *listNode) eval(a *activation) (any, error) {
	out := make([]any, 0, len(n.elems))
	for _, e := range n.elems {
		v, err := e.eval(a)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

type notNode struct{ inner node }

func (n *notNode) children() []node { return []node{n.inner} }

func (n *notNode) eval(a *activation) (any, error) {
	v, err := n.inner.eval(a)
	if err != nil {
		return nil, err
	}
	b, ok := v.(bool)
	if !ok {
		return nil, fmt.Errorf("celmatch: ! applies to a bool, not %s", typeName(v))
	}
	return !b, nil
}

// andNode and orNode short-circuit on the value that determines the result.
//
// They do *not* implement CEL's commutative absorption, where `false && error`
// is false regardless of evaluation order. That rule exists to make CEL
// insensitive to operand order; here it would mean an expression referencing a
// claim the token lacks could still match, and the whole point of this
// evaluator is that it cannot. An error on either side that is actually
// reached propagates.
type andNode struct{ left, right node }

func (n *andNode) children() []node { return []node{n.left, n.right} }

func (n *andNode) eval(a *activation) (any, error) {
	l, err := n.left.eval(a)
	if err != nil {
		return nil, err
	}
	lb, ok := l.(bool)
	if !ok {
		return nil, fmt.Errorf("celmatch: && applies to bools, not %s", typeName(l))
	}
	if !lb {
		return false, nil
	}
	r, err := n.right.eval(a)
	if err != nil {
		return nil, err
	}
	rb, ok := r.(bool)
	if !ok {
		return nil, fmt.Errorf("celmatch: && applies to bools, not %s", typeName(r))
	}
	return rb, nil
}

type orNode struct{ left, right node }

func (n *orNode) children() []node { return []node{n.left, n.right} }

func (n *orNode) eval(a *activation) (any, error) {
	l, err := n.left.eval(a)
	if err != nil {
		return nil, err
	}
	lb, ok := l.(bool)
	if !ok {
		return nil, fmt.Errorf("celmatch: || applies to bools, not %s", typeName(l))
	}
	if lb {
		return true, nil
	}
	r, err := n.right.eval(a)
	if err != nil {
		return nil, err
	}
	rb, ok := r.(bool)
	if !ok {
		return nil, fmt.Errorf("celmatch: || applies to bools, not %s", typeName(r))
	}
	return rb, nil
}

type eqNode struct {
	left, right node
	negate      bool
}

func (n *eqNode) children() []node { return []node{n.left, n.right} }

func (n *eqNode) eval(a *activation) (any, error) {
	l, err := n.left.eval(a)
	if err != nil {
		return nil, err
	}
	r, err := n.right.eval(a)
	if err != nil {
		return nil, err
	}
	eq, err := equals(l, r)
	if err != nil {
		return nil, err
	}
	return eq != n.negate, nil
}

type inNode struct{ needle, haystack node }

func (n *inNode) children() []node { return []node{n.needle, n.haystack} }

func (n *inNode) eval(a *activation) (any, error) {
	needle, err := n.needle.eval(a)
	if err != nil {
		return nil, err
	}
	hay, err := n.haystack.eval(a)
	if err != nil {
		return nil, err
	}
	list, ok := hay.([]any)
	if !ok {
		return nil, fmt.Errorf("celmatch: `in` needs a list on the right, not %s", typeName(hay))
	}
	// Scan the whole list for a match before reporting a type mismatch.
	//
	// A heterogeneous list is still an operator mistake worth naming — an
	// allowlist of ["main", 1] against a string claim must not quietly behave
	// like ["main"] — but naming it must not depend on where in the list the
	// odd element sits. Returning the first error instead made the verdict
	// order-sensitive: `x in ["123456", 999]` admitted and `x in [999,
	// "123456"]` was undecidable, for the same claim and the same intent.
	//
	// So a match anywhere wins, and a mismatch is only reported when there was
	// no match to find. That is order-independent, and it cannot admit anything
	// CEL would not: `equals` requires matching types, so a match here implies
	// the same element compares equal under CEL's own equality.
	//
	// A list *literal* cannot get this far heterogeneous — checkHomogeneous
	// refuses it when the rule is saved. This path is for a list that arrived
	// in a claim, where the operator controls neither the order nor the types.
	var mismatch error
	for _, el := range list {
		eq, err := equals(needle, el)
		if err != nil {
			if mismatch == nil {
				mismatch = err
			}
			continue
		}
		if eq {
			return true, nil
		}
	}
	if mismatch != nil {
		return nil, mismatch
	}
	return false, nil
}

// equals compares two values, refusing cross-type comparison.
//
// CEL itself returns false for `1 == "1"`. Here it is an error, because in a
// trust policy a type mismatch is always a mistake in the expression and
// "false" hides it until someone wonders why their rule never fires.
func equals(l, r any) (bool, error) {
	switch lv := l.(type) {
	case string:
		rv, ok := r.(string)
		if !ok {
			return false, typeMismatch(l, r)
		}
		return lv == rv, nil
	case int64:
		rv, ok := r.(int64)
		if !ok {
			return false, typeMismatch(l, r)
		}
		return lv == rv, nil
	case bool:
		rv, ok := r.(bool)
		if !ok {
			return false, typeMismatch(l, r)
		}
		return lv == rv, nil
	case []any:
		rv, ok := r.([]any)
		if !ok {
			return false, typeMismatch(l, r)
		}
		if len(lv) != len(rv) {
			return false, nil
		}
		for i := range lv {
			eq, err := equals(lv[i], rv[i])
			if err != nil || !eq {
				return false, err
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("celmatch: cannot compare %s", typeName(l))
}

func typeMismatch(l, r any) error {
	return fmt.Errorf("celmatch: cannot compare %s with %s", typeName(l), typeName(r))
}

// normalize maps a JSON-decoded claim onto the evaluator's value domain.
//
// JSON gives float64 for every number; a claim that is an integer in the token
// must compare equal to an integer literal in the expression, so whole floats
// become int64 and fractional ones are refused rather than silently truncated.
func normalize(v any) (any, error) {
	switch t := v.(type) {
	case nil:
		return nil, errors.New("celmatch: claim is null")
	case string, bool, int64, map[string]any:
		return t, nil
	case float64:
		if t != float64(int64(t)) {
			return nil, fmt.Errorf("celmatch: claim is the non-integer number %v", t)
		}
		return int64(t), nil
	case int:
		return int64(t), nil
	case []any:
		out := make([]any, 0, len(t))
		for _, el := range t {
			n, err := normalize(el)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	case []string:
		out := make([]any, 0, len(t))
		for _, el := range t {
			out = append(out, el)
		}
		return out, nil
	}
	return nil, fmt.Errorf("celmatch: claim has unsupported type %T", v)
}

func typeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case int64:
		return "int"
	case bool:
		return "bool"
	case []any:
		return "list"
	case map[string]any:
		return "map"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

// collectRefs walks the tree for `assertion.<name>` selections.
func collectRefs(root node) []string {
	seen := map[string]bool{}
	var walk func(n node)
	walk = func(n node) {
		if n == nil {
			return
		}
		if sel, ok := n.(*selectNode); ok {
			if _, isRoot := sel.base.(*rootNode); isRoot {
				seen[sel.field] = true
			}
		}
		for _, c := range n.children() {
			walk(c)
		}
	}
	walk(root)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
