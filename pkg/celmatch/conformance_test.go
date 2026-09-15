package celmatch

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file holds pkg/celmatch against the reference CEL implementation.
//
// The package is a hand-written subset of CEL. The operator who types an
// expression into the rule editor takes their mental model from GitHub's and
// Google's OIDC documentation, both of which describe *real* CEL — so every
// expression where this evaluator says allow and real CEL would say deny or
// error is an authorization bypass the operator cannot find by re-reading their
// own policy. Their policy means what they think it means; the evaluator is the
// thing that disagrees.
//
// So the property asserted here is one-directional and deliberately asymmetric:
//
//	celmatch admits  =>  real CEL admits
//
// Stricter is free — every caller treats a non-nil error as a denial, so a
// refusal costs an operator a clearer error message at worst. Looser is a third
// party's pipeline spending this hub's Anthropic credential.
//
// The CEL column is not written by hand. testdata/celprobe is a nested module
// that runs the corpus through cel.dev/cel-go and writes
// testdata/cel-verdicts.json; a corpus case with no recorded verdict fails the
// test rather than going unchecked. That indirection is the point: the failure
// mode being guarded against is someone being confidently wrong about a corner
// of a language they have read about but not run, and a hand-authored
// "expected CEL" column would reproduce exactly that error.

var update = flag.Bool("update", false, "rewrite testdata/conformance-table.txt")

const (
	corpusFile   = "testdata/conformance.json"
	verdictsFile = "testdata/cel-verdicts.json"
	tableFile    = "testdata/conformance-table.txt"
)

// Verdicts. `allow` is the only one that admits; everything else is a denial,
// which is what makes the invariant a single implication rather than a matrix.
const (
	vAllow      = "allow"
	vDeny       = "deny"
	vError      = "error"
	vParseError = "parse_error"
	vNonBool    = "non_bool"
)

func admits(verdict string) bool { return verdict == vAllow }

type conformanceCase struct {
	Group  string `json:"group"`
	Expr   string `json:"expr"`
	Claims string `json:"claims"`
	Note   string `json:"note,omitempty"`
}

type conformanceCorpus struct {
	Claimsets map[string]map[string]any `json:"claimsets"`
	Cases     []conformanceCase         `json:"cases"`
}

type celVerdicts struct {
	Verdicts map[string]string `json:"verdicts"`
	Detail   map[string]string `json:"detail"`
}

func caseKey(group, expr, claims string) string {
	return group + "\x1f" + expr + "\x1f" + claims
}

func loadCorpus(t *testing.T) (*conformanceCorpus, *celVerdicts) {
	t.Helper()
	var corpus conformanceCorpus
	raw, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatalf("reading %s: %v", corpusFile, err)
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parsing %s: %v", corpusFile, err)
	}
	// The claim sets carry a _note for the human reader. It must not reach the
	// activation: an expression selecting it would get an answer no real token
	// would give, and the probe strips it too.
	for _, cs := range corpus.Claimsets {
		delete(cs, "_note")
	}

	var verdicts celVerdicts
	raw, err = os.ReadFile(verdictsFile)
	if err != nil {
		t.Fatalf("reading %s: %v (regenerate: cd testdata/celprobe && go run . -update)", verdictsFile, err)
	}
	if err := json.Unmarshal(raw, &verdicts); err != nil {
		t.Fatalf("parsing %s: %v", verdictsFile, err)
	}
	return &corpus, &verdicts
}

// evalCelmatch runs one case through this package and classifies the outcome.
//
// The root node is evaluated directly rather than through Eval so a non-bool
// result is distinguishable from a genuine evaluation failure. Eval folds the
// two together — correctly, since both are refusals — but the corpus is more
// useful to a reader when it says which one happened.
func evalCelmatch(expr string, claims map[string]any) (verdict, detail string) {
	prog, err := Compile(expr)
	if err != nil {
		return vParseError, err.Error()
	}
	v, err := prog.root.eval(&activation{claims: claims})
	if err != nil {
		return vError, err.Error()
	}
	b, ok := v.(bool)
	if !ok {
		return vNonBool, typeName(v)
	}
	if b {
		return vAllow, ""
	}
	return vDeny, ""
}

// TestConformance_NeverMorePermissiveThanCEL is the security assertion.
func TestConformance_NeverMorePermissiveThanCEL(t *testing.T) {
	t.Parallel()
	corpus, verdicts := loadCorpus(t)

	if len(corpus.Cases) == 0 {
		t.Fatal("corpus is empty")
	}
	for _, tc := range corpus.Cases {
		tc := tc
		t.Run(tc.Group+"/"+tc.Expr, func(t *testing.T) {
			t.Parallel()
			claims, ok := corpus.Claimsets[tc.Claims]
			if !ok {
				t.Fatalf("case references unknown claim set %q", tc.Claims)
			}
			k := caseKey(tc.Group, tc.Expr, tc.Claims)
			cel, recorded := verdicts.Verdicts[k]
			if !recorded {
				t.Fatalf("no recorded CEL verdict for this case — it has never been "+
					"checked against the reference implementation.\n"+
					"regenerate: cd testdata/celprobe && go run . -update\n"+
					"expr:   %s\nclaims: %s", tc.Expr, tc.Claims)
			}

			got, detail := evalCelmatch(tc.Expr, claims)

			if admits(got) && !admits(cel) {
				t.Errorf("AUTHORIZATION BYPASS: celmatch admits an expression real CEL does not.\n"+
					"  expr:     %s\n"+
					"  claims:   %s\n"+
					"  celmatch: %s\n"+
					"  real CEL: %s (%s)\n"+
					"  note:     %s\n"+
					"An operator reading GitHub's OIDC docs writes CEL. This evaluator "+
					"admitting where CEL refuses means their policy does not mean what "+
					"they think it means.",
					tc.Expr, tc.Claims, got, cel, verdicts.Detail[k], tc.Note)
			}
			_ = detail
		})
	}
}

// TestConformance_TableIsCurrent pins both columns.
//
// The invariant above only forbids one cell of the matrix. This golden table
// records every cell, so a change that turns a deny into an error, or narrows
// the subset further, shows up as a reviewable diff instead of being invisible
// — and so the places where the two implementations legitimately disagree stay
// enumerated rather than remembered.
func TestConformance_TableIsCurrent(t *testing.T) {
	t.Parallel()
	corpus, verdicts := loadCorpus(t)

	type row struct {
		group, expr, claims, cel, celmatch, detail, note string
	}
	rows := make([]row, 0, len(corpus.Cases))
	for _, tc := range corpus.Cases {
		claims := corpus.Claimsets[tc.Claims]
		k := caseKey(tc.Group, tc.Expr, tc.Claims)
		got, detail := evalCelmatch(tc.Expr, claims)
		rows = append(rows, row{
			group: tc.Group, expr: tc.Expr, claims: tc.Claims,
			cel: verdicts.Verdicts[k], celmatch: got, detail: detail, note: tc.Note,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].group != rows[j].group {
			return rows[i].group < rows[j].group
		}
		if rows[i].expr != rows[j].expr {
			return rows[i].expr < rows[j].expr
		}
		return rows[i].claims < rows[j].claims
	})

	var b strings.Builder
	b.WriteString("# GENERATED by TestConformance_TableIsCurrent. Regenerate:\n")
	b.WriteString("#   go test ./pkg/celmatch/ -run TestConformance_TableIsCurrent -update\n")
	b.WriteString("#\n")
	b.WriteString("# CEL is the reference implementation's verdict, from testdata/cel-verdicts.json.\n")
	b.WriteString("# SUBSET is this package's. They differ often; what must never appear is\n")
	b.WriteString("# SUBSET=allow against a CEL column that is not allow. A `!` marks a row\n")
	b.WriteString("# where the two disagree, and every one of those must be the subset being\n")
	b.WriteString("# stricter.\n#\n")

	// A same/differs count up front is the number a reviewer actually wants:
	// it says how far the subset has drifted from CEL in aggregate, and a jump
	// in it is worth reading the diff for even when the invariant still holds.
	same, differs := 0, 0
	for _, r := range rows {
		if r.cel == r.celmatch {
			same++
		} else {
			differs++
		}
	}
	fmt.Fprintf(&b, "# %d cases: %d agree, %d differ (all in the stricter direction).\n\n",
		len(rows), same, differs)

	group := ""
	for _, r := range rows {
		if r.group != group {
			group = r.group
			fmt.Fprintf(&b, "\n== %s ==\n", group)
		}
		flag := " "
		if r.cel != r.celmatch {
			flag = "!"
		}
		fmt.Fprintf(&b, "%s CEL=%-11s SUBSET=%-11s [%s] %s\n", flag, r.cel, r.celmatch, r.claims, r.expr)
		if r.note != "" {
			fmt.Fprintf(&b, "      note: %s\n", r.note)
		}
		if r.detail != "" {
			fmt.Fprintf(&b, "      subset: %s\n", r.detail)
		}
	}
	got := b.String()

	if *update {
		if err := os.MkdirAll(filepath.Dir(tableFile), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(tableFile, []byte(got), 0o644); err != nil {
			t.Fatalf("writing %s: %v", tableFile, err)
		}
		t.Logf("wrote %s (%d cases, %d differ)", tableFile, len(rows), differs)
		return
	}
	want, err := os.ReadFile(tableFile)
	if err != nil {
		t.Fatalf("reading %s: %v (regenerate with -update)", tableFile, err)
	}
	if string(want) != got {
		t.Errorf("%s is out of date; regenerate with:\n"+
			"  go test ./pkg/celmatch/ -run TestConformance_TableIsCurrent -update\n"+
			"and read the diff: a deny that became an allow is a bypass.", tableFile)
	}
}

// TestConformance_CorpusCoversTheNamedRisks guards the corpus itself.
//
// A conformance suite decays by having cases removed, and the three behaviours
// below are the ones with no test before this file existed: equality against a
// claim whose JSON type is not what the operator assumes, `in` across mixed
// types, and nested selection through an absent intermediate. Asserting the
// corpus still exercises them keeps a later "tidy up the corpus" from quietly
// deleting the reason it was written.
func TestConformance_CorpusCoversTheNamedRisks(t *testing.T) {
	t.Parallel()
	corpus, _ := loadCorpus(t)

	counts := map[string]int{}
	for _, tc := range corpus.Cases {
		top := tc.Group
		if i := strings.IndexByte(top, '/'); i >= 0 {
			top = top[:i]
		}
		counts[top]++
	}
	// Floors, not exact counts: the corpus should be free to grow.
	for _, req := range []struct {
		group string
		min   int
	}{
		{"type-confusion", 30},
		{"missing-field", 20},
		{"absorption", 8},
		{"grammar", 10},
	} {
		if counts[req.group] < req.min {
			t.Errorf("corpus has %d %q cases, want at least %d — the corpus exists "+
				"because these are the untested behaviours on the authorization path",
				counts[req.group], req.group, req.min)
		}
	}

	// GitHub sends every one of its claims as a JSON string, repository_id
	// included. A corpus whose fixture made it a number would test the
	// evaluator against a token shape that does not exist, and would agree with
	// whatever the evaluator already did.
	gh, ok := corpus.Claimsets["gh_push"]
	if !ok {
		t.Fatal("corpus lost its realistic GitHub claim set")
	}
	for _, claim := range []string{"repository_id", "actor_id", "run_id", "run_number", "ref_protected"} {
		v, present := gh[claim]
		if !present {
			t.Errorf("gh_push has no %q claim", claim)
			continue
		}
		if _, isString := v.(string); !isString {
			t.Errorf("gh_push.%s is %T; a real GitHub token sends it as a JSON string, "+
				"and testing against the wrong shape is how the docs came to recommend "+
				"the one comparison that cannot work", claim, v)
		}
	}
}
