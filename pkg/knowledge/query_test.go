package knowledge

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestMatchExpressionQuotesEveryTerm: what a person types becomes quoted FTS5
// strings joined with OR — so FTS5 syntax typed into a search box is searched
// for, never run.
func TestMatchExpressionQuotesEveryTerm(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"rollback deploy", `"rollback" OR "deploy"`},
		{`how to "roll back" safely`, `"how" OR "to" OR "roll back" OR "safely"`},
		{"deploy*", `"deploy"*`},
		{"de* d**", `"de" OR "d"`},
		{"Deploy deploy DEPLOY", `"Deploy"`},
		{`title:secret`, `"title:secret"`},
		{`NEAR(a b) AND NOT c`, `"NEAR(a" OR "b)" OR "AND" OR "NOT" OR "c"`},
		{`say "unclosed phrase`, `"say" OR "unclosed phrase"`},
		{`a"b`, `"ab"`},
		{`- ^ * ( ) : rust`, `"rust"`},
		{"中文 检索", `"中文" OR "检索"`},
	} {
		got, err := MatchExpression(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("MatchExpression(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestMatchExpressionRefuses(t *testing.T) {
	for _, in := range []string{"", "   ", `"" -- *`, strings.Repeat("a", MaxQueryBytes+1), "\xff\xfe"} {
		if _, err := MatchExpression(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("MatchExpression(%q) = %v, want ErrInvalid", in, err)
		}
	}
	var many []string
	for i := 0; i < MaxQueryTerms+10; i++ {
		many = append(many, fmt.Sprintf("w%d", i))
	}
	got, err := MatchExpression(strings.Join(many, " "))
	if err != nil || strings.Count(got, " OR ")+1 != MaxQueryTerms {
		t.Fatalf("a query of %d words kept %d terms, want %d (%v)", len(many), strings.Count(got, " OR ")+1, MaxQueryTerms, err)
	}
}
