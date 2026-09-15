package celmatch

import (
	"fmt"
	"strings"
)

// A deny-by-default oracle: an independent evaluator that models *CEL's*
// semantics rather than this package's, used to hold the one-directional
// invariant over fuzzer-generated input.
//
// The corpus in conformance.json pins the invariant against the real reference
// implementation, but a corpus only covers expressions someone thought to
// write. The fuzzer reaches the ones nobody did, and it cannot call cel-go —
// that lives in a nested module under testdata/ precisely so the hub does not
// depend on it. So the fuzzer needs an oracle it can link.
//
// The oracle is built to be an *upper bound on permissiveness*: it says "true"
// only when CEL would certainly say true, and says "unknown" whenever it cannot
// tell. That shape is what makes the assertion sound in one direction —
//
//	celmatch admits  =>  oracle says true
//
// — and it is why the oracle deliberately implements the permissive halves of
// CEL that this package refuses: cross-type equality yields false instead of an
// error, `!=` across types yields true, and `&&`/`||` apply the commutative
// absorption that lets `error || true` be true. Every one of those is a way for
// CEL to reach a verdict where celmatch gives up, and the oracle has to model
// them or it would flag the package's own strictness as a bug.
//
// Honest limitation: the oracle walks the AST that this package's parser
// produced, so a parser that mis-associates an operator would fool both. That
// is what the precedence cases in the corpus are for — they are checked against
// a real CEL parse. What the oracle covers is the evaluation semantics, which
// is where the type-confusion and missing-claim bypasses live.

// oval is an oracle value. unk means "CEL would reach some verdict here, but
// this oracle declines to guess which" — never "false".
type oval struct {
	v   any
	unk bool
}

var unknown = oval{unk: true}

func known(v any) oval { return oval{v: v} }

// tri is the oracle's verdict for a whole expression.
type tri int

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func (t tri) String() string {
	switch t {
	case triTrue:
		return "true"
	case triFalse:
		return "false"
	}
	return "unknown"
}

// oracleVerdict evaluates an expression the way CEL would, conservatively.
func oracleVerdict(n node, claims map[string]any) tri {
	r := oracleEval(n, claims)
	if r.unk {
		return triUnknown
	}
	b, ok := r.v.(bool)
	if !ok {
		// A non-bool result is not a policy. CEL produces the value happily;
		// it is the caller that cannot use it.
		return triUnknown
	}
	if b {
		return triTrue
	}
	return triFalse
}

func oracleEval(n node, claims map[string]any) oval {
	switch t := n.(type) {
	case *litNode:
		return known(t.val)

	case *rootNode:
		// The bare activation variable is a map, not a value a policy can use.
		return unknown

	case *selectNode:
		return oracleSelect(t, claims)

	case *callNode:
		return oracleCall(t, claims)

	case *listNode:
		out := make([]any, 0, len(t.elems))
		for _, e := range t.elems {
			v := oracleEval(e, claims)
			if v.unk {
				// One unknown element makes the whole list unusable for a
				// definite answer; `in` handles partial knowledge itself.
				return unknown
			}
			out = append(out, v.v)
		}
		return known(out)

	case *notNode:
		inner := oracleEval(t.inner, claims)
		if inner.unk {
			return unknown
		}
		b, ok := inner.v.(bool)
		if !ok {
			return unknown
		}
		return known(!b)

	case *andNode:
		// CEL's commutative absorption: a definite false anywhere wins, even
		// if the other side errored. Both sides are evaluated because the
		// oracle is pure.
		l, r := oracleTruth(t.left, claims), oracleTruth(t.right, claims)
		if l == triFalse || r == triFalse {
			return known(false)
		}
		if l == triTrue && r == triTrue {
			return known(true)
		}
		return unknown

	case *orNode:
		l, r := oracleTruth(t.left, claims), oracleTruth(t.right, claims)
		if l == triTrue || r == triTrue {
			return known(true)
		}
		if l == triFalse && r == triFalse {
			return known(false)
		}
		return unknown

	case *eqNode:
		l, r := oracleEval(t.left, claims), oracleEval(t.right, claims)
		if l.unk || r.unk {
			return unknown
		}
		eq := celEquals(l.v, r.v)
		return known(eq != t.negate)

	case *inNode:
		return oracleIn(t, claims)
	}
	return unknown
}

// oracleTruth is oracleEval narrowed to a boolean verdict, for the connectives.
func oracleTruth(n node, claims map[string]any) tri {
	v := oracleEval(n, claims)
	if v.unk {
		return triUnknown
	}
	b, ok := v.v.(bool)
	if !ok {
		return triUnknown
	}
	if b {
		return triTrue
	}
	return triFalse
}

func oracleSelect(t *selectNode, claims map[string]any) oval {
	var container map[string]any
	if _, isRoot := t.base.(*rootNode); isRoot {
		container = claims
	} else {
		base := oracleEval(t.base, claims)
		if base.unk {
			return unknown
		}
		m, ok := base.v.(map[string]any)
		if !ok {
			// Selecting a field from a non-map. CEL errors; the oracle
			// declines rather than claiming false.
			return unknown
		}
		container = m
	}
	raw, present := container[t.field]
	if !present {
		return unknown
	}
	// The same normalization this package applies, so the two evaluators share
	// a value domain. Anything normalize refuses (null, a fractional number, an
	// unrepresentable one) is a value CEL has and the oracle does not model.
	v, err := normalize(raw)
	if err != nil {
		return unknown
	}
	return known(v)
}

func oracleCall(t *callNode, claims map[string]any) oval {
	recv := oracleEval(t.recv, claims)
	if recv.unk {
		return unknown
	}
	s, ok := recv.v.(string)
	if !ok {
		return unknown
	}
	if t.method == "matches" {
		if t.re == nil {
			return unknown
		}
		return known(t.re.MatchString(s))
	}
	arg := oracleEval(t.arg, claims)
	if arg.unk {
		return unknown
	}
	a, ok := arg.v.(string)
	if !ok {
		return unknown
	}
	switch t.method {
	case "startsWith":
		return known(strings.HasPrefix(s, a))
	case "endsWith":
		return known(strings.HasSuffix(s, a))
	case "contains":
		return known(strings.Contains(s, a))
	}
	return unknown
}

func oracleIn(t *inNode, claims map[string]any) oval {
	needle := oracleEval(t.needle, claims)
	if needle.unk {
		return unknown
	}
	hay := oracleEval(t.haystack, claims)
	if hay.unk {
		return unknown
	}
	list, ok := hay.v.([]any)
	if !ok {
		// CEL's `in` also tests map keys; the subset has no map membership, so
		// the oracle declines rather than asserting a verdict.
		return unknown
	}
	for _, el := range list {
		if celEquals(needle.v, el) {
			return known(true)
		}
	}
	return known(false)
}

// celEquals is CEL's equality, which is total: values of different types are
// simply unequal rather than incomparable.
//
// That is the single most important difference from this package's equals(),
// which returns an error instead — and the difference the oracle exists to
// model, because it is how CEL reaches `false` (and, under `!=`, `true`) on
// comparisons celmatch refuses to decide.
func celEquals(l, r any) bool {
	switch lv := l.(type) {
	case string:
		rv, ok := r.(string)
		return ok && lv == rv
	case int64:
		rv, ok := r.(int64)
		return ok && lv == rv
	case bool:
		rv, ok := r.(bool)
		return ok && lv == rv
	case []any:
		rv, ok := r.([]any)
		if !ok || len(lv) != len(rv) {
			return false
		}
		for i := range lv {
			if !celEquals(lv[i], rv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		rv, ok := r.(map[string]any)
		if !ok || len(lv) != len(rv) {
			return false
		}
		for k, a := range lv {
			b, present := rv[k]
			if !present || !celEquals(a, b) {
				return false
			}
		}
		return true
	}
	return false
}

// describeClaims renders a claim set for a failure message, since a fuzz
// failure is only actionable if the input is reproducible from the output.
func describeClaims(claims map[string]any) string {
	var b strings.Builder
	first := true
	for k, v := range claims {
		if !first {
			b.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&b, "%s=%#v", k, v)
	}
	return "{" + b.String() + "}"
}
