package celmatch

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ghClaims is a realistic GitHub Actions OIDC claim set, decoded from JSON so
// the tests exercise the same float64-for-every-number shape a real token
// produces rather than a hand-built map of Go types.
//
// `repository_id` is a **string**, and that is not a typo. GitHub sends every
// one of its own claims as a JSON string — repository_id, actor_id, run_id,
// run_number, ref_protected — and only the standard JWT time claims (iat, exp,
// nbf) as JSON numbers. This fixture used to make repository_id a number, which
// meant the int-comparison tests below were passing against a token shape that
// does not exist, and the operator guide had come to recommend the one
// comparison that can never match. Use `iat` when a test needs a genuinely
// numeric claim.
func ghClaims(t *testing.T) map[string]any {
	t.Helper()
	const raw = `{
	  "sub": "repo:acme/tool:ref:refs/heads/main",
	  "repository": "acme/tool",
	  "repository_owner": "acme",
	  "repository_id": "123456",
	  "repository_visibility": "private",
	  "ref": "refs/heads/main",
	  "ref_type": "branch",
	  "ref_protected": "false",
	  "workflow": "release",
	  "workflow_ref": "acme/tool/.github/workflows/release.yml@refs/heads/main",
	  "job_workflow_ref": "acme/tool/.github/workflows/release.yml@refs/heads/main",
	  "actor": "dana",
	  "actor_id": "12",
	  "event_name": "push",
	  "runner_environment": "github-hosted",
	  "iss": "https://token.actions.githubusercontent.com",
	  "aud": "cloop",
	  "iat": 1632493567,
	  "exp": 1632493867
	}`
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return m
}

func TestCompileAndEval_Matches(t *testing.T) {
	t.Parallel()
	claims := ghClaims(t)

	cases := []struct {
		name string
		expr string
		want bool
	}{
		{"equality true", `assertion.repository == "acme/tool"`, true},
		{"equality false", `assertion.repository == "acme/other"`, false},
		{"inequality", `assertion.repository != "acme/other"`, true},
		{"and both true", `assertion.repository == "acme/tool" && assertion.ref == "refs/heads/main"`, true},
		{"and one false", `assertion.repository == "acme/tool" && assertion.ref == "refs/heads/dev"`, false},
		{"or first true", `assertion.ref == "refs/heads/main" || assertion.ref == "refs/heads/dev"`, true},
		{"or both false", `assertion.ref == "refs/heads/x" || assertion.ref == "refs/heads/y"`, false},
		{"not", `!(assertion.repository == "acme/other")`, true},
		{"in list hit", `assertion.ref in ["refs/heads/main", "refs/heads/release"]`, true},
		{"in list miss", `assertion.ref in ["refs/heads/dev"]`, false},
		{"empty list", `assertion.ref in []`, false},
		{"trailing comma in list", `assertion.ref in ["refs/heads/main",]`, true},
		{"startsWith", `assertion.ref.startsWith("refs/heads/")`, true},
		{"startsWith false", `assertion.ref.startsWith("refs/tags/")`, false},
		{"endsWith", `assertion.workflow_ref.endsWith("@refs/heads/main")`, true},
		{"contains", `assertion.workflow_ref.contains("/release.yml@")`, true},
		{"matches", `assertion.sub.matches("^repo:acme/[a-z]+:ref:refs/heads/main$")`, true},
		{"matches false", `assertion.sub.matches("^repo:evil/")`, false},
		// `iat` because it is one of the three claims GitHub actually sends as
		// a JSON number. repository_id looks numeric and is not; see ghClaims.
		{"int claim equality", `assertion.iat == 1632493567`, true},
		{"int claim inequality", `assertion.iat != 1`, true},
		{"int in list", `assertion.iat in [1632493567, 1632493868]`, true},
		// The numeric-looking GitHub claims, compared the way that works.
		{"string repository_id", `assertion.repository_id == "123456"`, true},
		{"string repository_id in list", `assertion.repository_id in ["123456", "999"]`, true},
		{"string actor_id", `assertion.actor_id == "12"`, true},
		{"stringified bool", `assertion.ref_protected == "false"`, true},
		{"parenthesised precedence", `(assertion.ref == "refs/heads/x" || assertion.ref == "refs/heads/main") && assertion.actor == "dana"`, true},
		{"precedence without parens", `assertion.ref == "refs/heads/x" || assertion.ref == "refs/heads/main" && assertion.actor == "dana"`, true},
		{"single quotes", `assertion.repository == 'acme/tool'`, true},
		{"bare true", `true`, true},
		{"bare false", `false`, false},
		{"method on parenthesised", `(assertion.ref).startsWith("refs/")`, true},
		{"realistic environment gate", `assertion.repository == "acme/tool" && assertion.ref.startsWith("refs/heads/") && assertion.event_name in ["push", "pull_request"]`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prog, err := Compile(tc.expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.expr, err)
			}
			got, err := prog.Eval(claims)
			if err != nil {
				t.Fatalf("Eval(%q): %v", tc.expr, err)
			}
			if got != tc.want {
				t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestCompile_RefusesWhatItDoesNotUnderstand(t *testing.T) {
	t.Parallel()
	// Every entry here is something full CEL would accept. Refusing at compile
	// time is the contract: an operator finds out when saving the rule, not
	// when a pipeline is denied in the middle of a release.
	cases := []struct {
		name string
		expr string
		// want is a substring the message must contain, so the error stays
		// actionable rather than merely non-nil.
		want string
	}{
		{"empty", "", "empty"},
		{"unknown identifier", `repository == "acme/tool"`, "unknown identifier"},
		{"unknown root", `claims.repository == "x"`, "unknown identifier"},
		{"macro", `assertion.groups.all(g, g == "x")`, "unsupported method"},
		{"exists macro", `assertion.groups.exists(g, g == "x")`, "unsupported method"},
		{"size", `assertion.repository.size() == 9`, "unsupported method"},
		{"arithmetic", `assertion.repository_id + 1 == 2`, "unexpected character"},
		{"comparison operator", `assertion.repository_id > 1`, "unexpected character"},
		{"ternary", `assertion.x ? 1 : 2`, "unexpected character"},
		{"index", `assertion.groups[0] == "x"`, "unexpected"},
		{"float", `assertion.x == 1.5`, "decimal integers"},
		{"hex", `assertion.x == 0x10`, "decimal integers"},
		{"unterminated string", `assertion.x == "abc`, "unterminated"},
		{"unclosed paren", `(assertion.x == "a"`, `expected ")"`},
		{"unclosed list", `assertion.x in ["a"`, `expected "]"`},
		{"trailing operator", `assertion.x == "a" &&`, "expected a value"},
		{"bare and", `assertion.x == "a" & assertion.y == "b"`, "unexpected character"},
		{"chained comparison", `assertion.a == assertion.b == assertion.c`, "do not chain"},
		{"bad regex", `assertion.x.matches("[")`, "matches()"},
		{"computed regex", `assertion.x.matches(assertion.y)`, "literal regular expression"},
		{"call on nothing", `startsWith("a")`, "unknown identifier"},
		{"dangling dot", `assertion.`, "expected a field name"},
		{"newline in string", "assertion.x == \"a\nb\"", "newline"},
		{"bad escape", `assertion.x == "a\qb"`, "unsupported escape"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(tc.expr)
			if err == nil {
				t.Fatalf("Compile(%q) accepted an expression it does not implement", tc.expr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Compile(%q) = %q, want it to mention %q", tc.expr, err, tc.want)
			}
		})
	}
}

func TestCompile_RefusesOversizeExpression(t *testing.T) {
	t.Parallel()
	expr := `assertion.x == "` + strings.Repeat("a", MaxExpressionBytes) + `"`
	if _, err := Compile(expr); err == nil {
		t.Fatal("Compile accepted an expression past MaxExpressionBytes")
	}
}

func TestCompile_RefusesDeepNesting(t *testing.T) {
	t.Parallel()
	expr := strings.Repeat("(", 200) + `true` + strings.Repeat(")", 200)
	_, err := Compile(expr)
	if err == nil {
		t.Fatal("Compile accepted an expression nested past maxDepth")
	}
	if !strings.Contains(err.Error(), "nests deeper") {
		t.Errorf("error = %q, want it to mention nesting depth", err)
	}
}

func TestEval_MissingClaimIsAnErrorNotFalse(t *testing.T) {
	t.Parallel()
	// The single most important property in this package. A rule that reads a
	// claim the token does not carry must not silently become a rule that
	// matches on the remaining conditions.
	claims := ghClaims(t)
	prog, err := Compile(`assertion.environment == "production"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ok, err := prog.Eval(claims)
	if err == nil {
		t.Fatal("Eval succeeded against a token with no `environment` claim")
	}
	if ok {
		t.Fatal("Eval returned true alongside an error")
	}
	if !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("error = %v, want it to wrap ErrNoSuchKey", err)
	}
}

func TestEval_MissingClaimUnderAndStillFails(t *testing.T) {
	t.Parallel()
	// CEL's commutative absorption would let `false && error` be false. This
	// evaluator deliberately does not implement it; a reached error propagates.
	claims := ghClaims(t)
	prog, err := Compile(`assertion.repository == "acme/tool" && assertion.environment == "prod"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := prog.Eval(claims); ok || err == nil {
		t.Fatalf("Eval = (%v, %v), want (false, error)", ok, err)
	}
}

func TestEval_ShortCircuitDoesNotReachTheMissingClaim(t *testing.T) {
	t.Parallel()
	// The converse: when the left operand already decides the result, the
	// right is never evaluated, so a rule guarded by a repository check does
	// not error out on tokens from other repositories.
	claims := ghClaims(t)
	prog, err := Compile(`assertion.repository == "other/repo" && assertion.environment == "prod"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ok, err := prog.Eval(claims)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if ok {
		t.Error("Eval = true, want false")
	}
}

func TestEval_TypeMismatchIsAnError(t *testing.T) {
	t.Parallel()
	claims := ghClaims(t)
	for _, expr := range []string{
		`assertion.repository == 1`,
		`assertion.repository == true`,
		`assertion.repository.startsWith(1)`,
		`!assertion.repository`,
		`assertion.repository && true`,
		`assertion.repository in assertion.repository`,
		// The mistake an operator actually makes: repository_id reads as a
		// number in GitHub's docs and arrives as a string, so the int-literal
		// form is the broken one. Real CEL answers `false` here and `true` for
		// the `!=`, which is why this must refuse rather than evaluate.
		`assertion.repository_id == 123456`,
		`assertion.repository_id != 123456`,
		`assertion.ref_protected == false`,
		// A string method and a membership test against a genuinely numeric
		// claim.
		`assertion.iat.startsWith("16")`,
		`assertion.iat in ["a"]`,
		`assertion.iat == "1632493567"`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			prog, err := Compile(expr)
			if err != nil {
				t.Fatalf("Compile(%q): %v", expr, err)
			}
			if ok, err := prog.Eval(claims); ok || err == nil {
				t.Fatalf("Eval(%q) = (%v, %v), want (false, error)", expr, ok, err)
			}
		})
	}
}

func TestEval_NonBooleanResultIsRefused(t *testing.T) {
	t.Parallel()
	prog, err := Compile(`assertion.repository`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := prog.Eval(ghClaims(t)); ok || err == nil {
		t.Fatalf("Eval = (%v, %v), want (false, error) for a non-bool expression", ok, err)
	}
}

func TestEval_NullClaimIsRefused(t *testing.T) {
	t.Parallel()
	prog, err := Compile(`assertion.environment == "prod"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// A claim present but null is different from an absent claim, and must
	// also not compare equal to anything.
	if ok, err := prog.Eval(map[string]any{"environment": nil}); ok || err == nil {
		t.Fatalf("Eval = (%v, %v), want (false, error)", ok, err)
	}
}

func TestEval_NestedClaimSelection(t *testing.T) {
	t.Parallel()
	// Some IdPs nest; the selector chain should work past the first level and
	// still refuse a missing leaf.
	claims := map[string]any{"ctx": map[string]any{"env": "prod"}}
	hit, err := Compile(`assertion.ctx.env == "prod"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := hit.Eval(claims); err != nil || !ok {
		t.Fatalf("Eval = (%v, %v), want (true, nil)", ok, err)
	}
	miss, err := Compile(`assertion.ctx.missing == "prod"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := miss.Eval(claims); ok || !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("Eval = (%v, %v), want (false, ErrNoSuchKey)", ok, err)
	}
}

func TestEval_ListClaim(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"groups": []any{"eng", "release"}}
	prog, err := Compile(`"release" in assertion.groups`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := prog.Eval(claims); err != nil || !ok {
		t.Fatalf("Eval = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestCompile_RefusesMixedTypeListLiteral(t *testing.T) {
	t.Parallel()
	// A mixed list made the verdict depend on the order the operator typed the
	// entries in: `x in ["123456", 999]` admitted because the match was found
	// before the int was reached, and `x in [999, "123456"]` was undecidable
	// because it was not. Same allowlist, same intent, two different answers.
	//
	// Both are now refused when the rule is saved, which is the only outcome
	// that does not depend on spelling.
	for _, expr := range []string{
		`assertion.repository_id in ["123456", 999]`,
		`assertion.repository_id in [999, "123456"]`,
		`assertion.ref in ["refs/heads/main", true]`,
		`assertion.x == ["a", 1]`,
		`assertion.x in [1, 2, "3",]`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(expr)
			if err == nil {
				t.Fatalf("Compile(%q) accepted a mixed-type list, whose verdict "+
					"depends on element order", expr)
			}
			if !strings.Contains(err.Error(), "mixes") {
				t.Errorf("error = %q, want it to name the mixed types", err)
			}
		})
	}
	// Homogeneous lists are unaffected, including the trailing comma that is
	// how a long allowlist gets edited.
	for _, expr := range []string{
		`assertion.ref in ["a", "b"]`,
		`assertion.ref in ["a",]`,
		`assertion.iat in [1, 2, 3]`,
		`assertion.ref in []`,
		`assertion.ref in [assertion.repository, "a"]`, // one element's type is not knowable until Eval
	} {
		t.Run("ok/"+expr, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(expr); err != nil {
				t.Errorf("Compile(%q) refused a homogeneous list: %v", expr, err)
			}
		})
	}
}

func TestEval_MembershipDoesNotDependOnElementOrder(t *testing.T) {
	t.Parallel()
	// The runtime half of the same property. A list that arrives in a *claim*
	// can be heterogeneous however the identity provider chose to order it, and
	// the operator controls neither. So a match anywhere must win, and a type
	// mismatch may only be reported when there was no match to find.
	claims := map[string]any{
		"forward": []any{"eng", float64(7)},
		"reverse": []any{float64(7), "eng"},
	}
	prog, err := Compile(`"eng" in assertion.forward`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	fwd, fwdErr := prog.Eval(claims)

	prog, err = Compile(`"eng" in assertion.reverse`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rev, revErr := prog.Eval(claims)

	if fwd != rev || (fwdErr == nil) != (revErr == nil) {
		t.Fatalf("membership depends on element order: forward=(%v, %v) reverse=(%v, %v)",
			fwd, fwdErr, rev, revErr)
	}
	if !fwd || fwdErr != nil {
		t.Fatalf("Eval = (%v, %v), want (true, nil): the string element is present "+
			"in both orderings", fwd, fwdErr)
	}

	// With no match, the mismatch is still reported rather than silently
	// answering false — an allowlist of ["eng", 7] must not behave like ["eng"].
	prog, err = Compile(`"nope" in assertion.reverse`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if ok, err := prog.Eval(claims); ok || err == nil {
		t.Fatalf("Eval = (%v, %v), want (false, error)", ok, err)
	}
}

func TestCompile_RefusesCELLiteralsAsFieldNames(t *testing.T) {
	t.Parallel()
	// CEL's parser refuses `assertion.true` outright: "mismatched input 'true'
	// expecting IDENTIFIER". Accepting it here would mean compiling an
	// expression the operator's own reference implementation rejects, and
	// evaluating it against a claim of that name if one ever existed.
	for _, expr := range []string{
		`assertion.true == "x"`,
		`assertion.false == "x"`,
		`assertion.null == "x"`,
		`assertion.ctx.true == "x"`,
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(expr); err == nil {
				t.Fatalf("Compile(%q) accepted a CEL literal as a field name", expr)
			}
		})
	}
	// Words the CEL *spec* reserves but cel-go accepts as field names are
	// accepted here too, so the subset is not gratuitously stricter than the
	// implementation an operator is reading about. Verified against cel-go in
	// testdata/cel-verdicts.json: each is a runtime "no such key", not a parse
	// error.
	for _, expr := range []string{
		`assertion.if == "x"`,
		`assertion.for == "x"`,
		`assertion.return == "x"`,
		`assertion.as == "x"`,
	} {
		t.Run("ok/"+expr, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(expr); err != nil {
				t.Errorf("Compile(%q) refused a name cel-go accepts: %v", expr, err)
			}
		})
	}
}

func TestReferences(t *testing.T) {
	t.Parallel()
	prog, err := Compile(`assertion.repository == "a" && assertion.ref in ["x"] && assertion.repository != "b"`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := prog.References()
	want := []string{"ref", "repository"}
	if len(got) != len(want) {
		t.Fatalf("References() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("References() = %v, want %v", got, want)
		}
	}
}

func TestSource(t *testing.T) {
	t.Parallel()
	const src = `assertion.repository == "acme/tool"`
	prog, err := Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if prog.Source() != src {
		t.Errorf("Source() = %q, want %q", prog.Source(), src)
	}
}

func TestProgram_IsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()
	prog, err := Compile(`assertion.repository == "acme/tool" && assertion.sub.matches("^repo:")`)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	claims := ghClaims(t)
	done := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func() {
			ok, err := prog.Eval(claims)
			done <- ok && err == nil
		}()
	}
	for i := 0; i < 16; i++ {
		if !<-done {
			t.Fatal("concurrent Eval disagreed with the sequential result")
		}
	}
}

// fuzzClaimSets are the activations every fuzzed expression is evaluated
// against. Several shapes rather than one, because the invariant this target
// holds is about the interaction between an expression and the claims it reads
// — a missing claim, a claim of the wrong type, a null, a nested map — and a
// single activation would leave most of those unreachable.
func fuzzClaimSets() []map[string]any {
	return []map[string]any{
		{}, // every selection is a missing claim
		{
			// Realistic GitHub: every claim a string, repository_id included.
			"repository":    "acme/tool",
			"repository_id": "123456",
			"ref":           "refs/heads/main",
			"ref_protected": "false",
			"head_ref":      "",
			"sub":           "repo:acme/tool:ref:refs/heads/main",
			"event_name":    "push",
		},
		{
			// The same names carrying other types, which is where equality and
			// membership have to decide what they cannot compare.
			"repository":    float64(1),
			"repository_id": float64(123456),
			"ref":           true,
			"sub":           []any{"a", float64(2)},
			"head_ref":      nil,
			"nested":        map[string]any{"k": "v", "deep": map[string]any{"leaf": "x"}},
			"frac":          1.5,
		},
		{
			"repository": "acme/tool",
			"list":       []any{"a", "b"},
			"mixed":      []any{float64(7), "a"},
			"empty":      map[string]any{},
			"emptylist":  []any{},
		},
	}
}

func FuzzCompile(f *testing.F) {
	// The parser reads operator-supplied text. It may reject anything, but it
	// must not panic, must not hand back a Program that then panics, and — the
	// property this target exists for — must never *admit* an expression that
	// real CEL would deny or refuse.
	//
	// The corpus in testdata/conformance.json pins that against the reference
	// implementation for expressions someone thought to write. This reaches the
	// ones nobody did, using the deny-by-default oracle in oracle_test.go,
	// which models CEL's permissive halves so that the package's own strictness
	// does not register as a bug.
	for _, seed := range []string{
		`assertion.repository == "acme/tool"`,
		`assertion.ref in ["a","b"]`,
		`!(assertion.a == "b") && assertion.c.matches("^x$")`,
		`((((true))))`,
		`assertion.`,
		`"`,
		`in in in`,
		// Seeds aimed at the invariant rather than the parser: each is a shape
		// where CEL and this evaluator are known to disagree, so the fuzzer
		// starts adjacent to the interesting region instead of having to
		// rediscover that `!=` and `||` are where permissiveness hides.
		`assertion.repository_id != 123456`,
		`assertion.missing == "x" || assertion.repository == "acme/tool"`,
		`assertion.repository_id in [123456, "123456"]`,
		`assertion.head_ref != "x"`,
		`!assertion.missing.startsWith("a")`,
		`assertion.nested.deep.leaf == "x"`,
		`assertion.true == "x"`,
		`"a" in assertion.nested`,
		`assertion.frac == 1`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, src string) {
		prog, err := Compile(src)
		if err != nil {
			// Refusing is always safe: a rule that does not compile is a rule
			// that never admits anything.
			return
		}
		if prog == nil {
			t.Fatal("Compile returned (nil, nil)")
		}

		for _, claims := range fuzzClaimSets() {
			ok, err := prog.Eval(claims)
			if ok && err != nil {
				t.Fatalf("Eval returned true alongside error %v\nexpr: %s", err, src)
			}
			if err != nil {
				continue
			}

			// Determinism. A second evaluation of an immutable Program against
			// the same claims must agree; a disagreement would mean state
			// leaked into a compiled rule, which is also shared across
			// concurrent requests.
			again, againErr := prog.Eval(claims)
			if againErr != nil || again != ok {
				t.Fatalf("Eval is not deterministic: got (%v, %v) then (%v, %v)\nexpr: %s",
					ok, err, again, againErr, src)
			}

			if !ok {
				// Denial needs no corroboration. The invariant is
				// one-directional on purpose: this evaluator is allowed to be
				// stricter than CEL anywhere, and usually is.
				continue
			}

			switch v := oracleVerdict(prog.root, claims); v {
			case triTrue:
				// CEL agrees this admits.
			default:
				t.Fatalf("AUTHORIZATION BYPASS: Eval admits an expression the "+
					"CEL oracle does not.\n"+
					"  expr:   %s\n"+
					"  claims: %s\n"+
					"  oracle: %s\n"+
					"The oracle only declines to say `true` when CEL would not, "+
					"or when it cannot tell — either way this evaluator has no "+
					"business admitting here. An operator writes their policy "+
					"against CEL's semantics; admitting past them is a bypass "+
					"they cannot find by re-reading their own rule.",
					src, describeClaims(claims), v)
			}
		}
	})
}

// FuzzEvalClaims fuzzes the other side of the boundary: the claim set.
//
// FuzzCompile varies the expression, which an operator writes. This varies the
// token, which the identity provider writes — and `normalize` is the only thing
// standing between arbitrary decoded JSON and the evaluator's value domain. A
// claim shape it mishandles is reachable by anyone who can get a token issued,
// which on a hub federating a public IdP is a larger set of people than the
// operators.
//
// The expressions are fixed and realistic, so a failure names a policy someone
// would plausibly have written rather than a curiosity.
func FuzzEvalClaims(f *testing.F) {
	policies := []string{
		`assertion.repository == "acme/tool"`,
		`assertion.repository_id == "123456"`,
		`assertion.repository_id == 123456`,
		`assertion.repository_id != 123456`,
		`assertion.ref.startsWith("refs/heads/")`,
		`assertion.ref in ["refs/heads/main", "refs/heads/release"]`,
		`assertion.repository == "acme/tool" && assertion.environment == "prod"`,
		`assertion.environment == "prod" || assertion.repository == "acme/tool"`,
		`!(assertion.repository == "evil/repo")`,
		`assertion.ctx.env == "prod"`,
		`"release" in assertion.groups`,
		`assertion.sub.matches("^repo:acme/tool:")`,
	}
	progs := make([]*Program, 0, len(policies))
	for _, p := range policies {
		prog, err := Compile(p)
		if err != nil {
			f.Fatalf("seed policy %q does not compile: %v", p, err)
		}
		progs = append(progs, prog)
	}

	for _, seed := range []string{
		`{"repository":"acme/tool","repository_id":"123456","ref":"refs/heads/main"}`,
		`{"repository":"acme/tool","environment":"prod","groups":["release"]}`,
		`{"repository":null,"repository_id":1.5,"ref":[],"ctx":{"env":"prod"}}`,
		`{"repository":{"nested":"map"},"groups":"not-a-list"}`,
		`{"repository_id":9007199254740993,"ref":1e400}`,
		`{}`,
		`{"repository":"acme/tool","ctx":{"env":{"deeper":"x"}}}`,
		`[]`,
		`null`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		var claims map[string]any
		if err := json.Unmarshal([]byte(raw), &claims); err != nil {
			return // not a claim set; the OIDC layer would never produce it
		}
		if claims == nil {
			return // `null` decodes to a nil map, which no verified token yields
		}
		for i, prog := range progs {
			ok, err := prog.Eval(claims)
			if ok && err != nil {
				t.Fatalf("Eval returned true alongside error %v\npolicy: %s\nclaims: %s",
					err, policies[i], raw)
			}
			if err != nil || !ok {
				continue
			}
			if v := oracleVerdict(prog.root, claims); v != triTrue {
				t.Fatalf("AUTHORIZATION BYPASS: a claim set admits past the CEL oracle.\n"+
					"  policy: %s\n"+
					"  claims: %s\n"+
					"  oracle: %s\n"+
					"The token shape decides this, and the token is written by the "+
					"identity provider, not by the operator whose policy it satisfies.",
					policies[i], raw, v)
			}
		}
	})
}
