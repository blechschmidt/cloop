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
func ghClaims(t *testing.T) map[string]any {
	t.Helper()
	const raw = `{
	  "sub": "repo:acme/tool:ref:refs/heads/main",
	  "repository": "acme/tool",
	  "repository_owner": "acme",
	  "repository_id": 123456,
	  "repository_visibility": "private",
	  "ref": "refs/heads/main",
	  "ref_type": "branch",
	  "workflow": "release",
	  "workflow_ref": "acme/tool/.github/workflows/release.yml@refs/heads/main",
	  "job_workflow_ref": "acme/tool/.github/workflows/release.yml@refs/heads/main",
	  "actor": "dana",
	  "event_name": "push",
	  "runner_environment": "github-hosted",
	  "iss": "https://token.actions.githubusercontent.com",
	  "aud": "cloop"
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
		{"int claim equality", `assertion.repository_id == 123456`, true},
		{"int claim inequality", `assertion.repository_id != 1`, true},
		{"int in list", `assertion.repository_id in [1, 123456]`, true},
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
		`assertion.repository_id == "123456"`,
		`assertion.repository == true`,
		`assertion.repository_id in ["a"]`,
		`assertion.repository.startsWith(1)`,
		`assertion.repository_id.startsWith("1")`,
		`!assertion.repository`,
		`assertion.repository && true`,
		`assertion.repository in assertion.repository`,
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

func FuzzCompile(f *testing.F) {
	// The parser reads operator-supplied text. It may reject anything, but it
	// must not panic, and it must not hand back a Program that then panics.
	for _, seed := range []string{
		`assertion.repository == "acme/tool"`,
		`assertion.ref in ["a","b"]`,
		`!(assertion.a == "b") && assertion.c.matches("^x$")`,
		`((((true))))`,
		`assertion.`,
		`"`,
		`in in in`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, src string) {
		prog, err := Compile(src)
		if err != nil {
			return
		}
		if prog == nil {
			t.Fatal("Compile returned (nil, nil)")
		}
		ok, err := prog.Eval(map[string]any{
			"repository": "acme/tool",
			"ref":        "refs/heads/main",
			"n":          float64(1),
			"list":       []any{"a"},
			"nested":     map[string]any{"k": "v"},
		})
		if ok && err != nil {
			t.Fatalf("Eval returned true alongside error %v", err)
		}
	})
}
