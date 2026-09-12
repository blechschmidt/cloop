package taskreplay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestVerdictFor is the table the whole feature turns on.
//
// Every row is an assertion about when this harness is allowed to say a commit
// reproduces. The two that matter most are the ones that must NOT say it:
// an unconfirmed base, and a project with no test command. Both are cases where
// the naive implementation returns a confident answer that is worth nothing.
func TestVerdictFor(t *testing.T) {
	pass := &TestOutcome{Ran: true, Passed: true, Framework: "go test"}
	fail := &TestOutcome{Ran: true, Passed: false, ExitCode: 1, Framework: "go test"}
	unrun := &TestOutcome{Ran: false, Framework: "go test"}

	confirmed := func(identical bool) *Comparison {
		return &Comparison{
			BaseConfirmed: true, Identical: identical,
			OriginalTree: "aaa", ReplayTree: map[bool]string{true: "aaa", false: "bbb"}[identical],
			FilesDiffering: []string{"main.go"}, OriginalCommits: 1,
		}
	}

	tests := []struct {
		name           string
		cmp            *Comparison
		original       *TestOutcome
		replay         *TestOutcome
		haveTests      bool
		skipTests      bool
		want           Verdict
		reasonContains string
	}{
		{
			name: "identical trees need no tests",
			cmp:  confirmed(true), haveTests: false,
			want: VerdictIdentical, reasonContains: "byte-for-byte",
		},
		{
			name: "identical trees still identical with tests available",
			cmp:  confirmed(true), haveTests: true, original: pass, replay: pass,
			want: VerdictIdentical,
		},
		{
			name: "different bytes, both suites green",
			cmp:  confirmed(false), haveTests: true, original: pass, replay: pass,
			want: VerdictEquivalent, reasonContains: "passes on both trees",
		},
		{
			name: "replay breaks what the original passed",
			cmp:  confirmed(false), haveTests: true, original: pass, replay: fail,
			want: VerdictDivergent, reasonContains: "fails",
		},
		{
			name: "replay fixes what the original broke",
			cmp:  confirmed(false), haveTests: true, original: fail, replay: pass,
			want: VerdictDivergent, reasonContains: "which the original fails",
		},
		{
			// Both failing is NOT equivalence: two suites can fail for
			// unrelated reasons, and certifying a broken change as faithfully
			// reproduced is the worst answer this harness could give.
			name: "both suites red is divergent, never equivalent",
			cmp:  confirmed(false), haveTests: true, original: fail, replay: fail,
			want: VerdictDivergent, reasonContains: "fails on both trees",
		},
		{
			name: "no test command means no equivalence claim",
			cmp:  confirmed(false), haveTests: false,
			want: VerdictInconclusive, reasonContains: "no detectable test command",
		},
		{
			name: "tests explicitly skipped",
			cmp:  confirmed(false), haveTests: false, skipTests: true,
			want: VerdictInconclusive, reasonContains: "tests were skipped",
		},
		{
			name: "a suite that could not execute decides nothing",
			cmp:  confirmed(false), haveTests: true, original: pass, replay: unrun,
			want: VerdictInconclusive, reasonContains: "could not be executed",
		},
		{
			name: "a missing outcome decides nothing",
			cmp:  confirmed(false), haveTests: true, original: nil, replay: pass,
			want: VerdictInconclusive, reasonContains: "did not run on both trees",
		},
		{
			// The trap this harness exists to avoid: an inferred base that is
			// wrong means the reproduction started from a tree that already
			// contained part of the change. Reaching the same tree from there
			// proves nothing, so it must not be reported as IDENTICAL.
			name: "unconfirmed base caps an identical result",
			cmp: &Comparison{
				BaseConfirmed: false, Identical: true,
				OriginalTree: "aaa", ReplayTree: "aaa", OriginalCommits: 3,
			},
			haveTests: true, original: pass, replay: pass,
			want: VerdictInconclusive, reasonContains: "did not start from the same tree",
		},
		{
			name: "unconfirmed base caps an equivalent result too",
			cmp: &Comparison{
				BaseConfirmed: false, Identical: false,
				OriginalTree: "aaa", ReplayTree: "bbb", OriginalCommits: 4,
			},
			haveTests: true, original: pass, replay: pass,
			want: VerdictInconclusive,
		},
		{
			name: "no comparison at all",
			cmp:  nil,
			want: VerdictInconclusive, reasonContains: "no comparison",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := verdictFor(tc.cmp, tc.original, tc.replay, tc.haveTests, tc.skipTests)
			if got != tc.want {
				t.Errorf("verdict = %q, want %q (reason: %s)", got, tc.want, reason)
			}
			if reason == "" {
				t.Error("reason is empty; it is the field an operator reads first and must never be blank")
			}
			if tc.reasonContains != "" && !strings.Contains(reason, tc.reasonContains) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.reasonContains)
			}
		})
	}
}

func TestTestOutcomeAgrees(t *testing.T) {
	pass := &TestOutcome{Ran: true, Passed: true}
	fail := &TestOutcome{Ran: true, Passed: false}
	unrun := &TestOutcome{Ran: false, Passed: true}

	cases := []struct {
		name string
		a, b *TestOutcome
		want bool
	}{
		{"both green", pass, pass, true},
		{"both red", fail, fail, false},
		{"one red", pass, fail, false},
		{"one never ran", pass, unrun, false},
		{"nil receiver", nil, pass, false},
		{"nil argument", pass, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Agrees(tc.b); got != tc.want {
				t.Errorf("Agrees = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerdictPredicates(t *testing.T) {
	for _, v := range AllVerdicts {
		if !v.Valid() {
			t.Errorf("%q is in AllVerdicts but Valid() says otherwise", v)
		}
	}
	if Verdict("made-up").Valid() {
		t.Error("an unknown verdict reported itself valid")
	}
	if !VerdictIdentical.Reproducible() || !VerdictEquivalent.Reproducible() {
		t.Error("identical and equivalent must both support the claim that a commit reproduces")
	}
	if VerdictDivergent.Reproducible() || VerdictInconclusive.Reproducible() {
		t.Error("divergent and inconclusive must never support a reproducibility claim")
	}
}

// TestReproduceRefusesWithoutRunner pins the "no host fallback" decision. A
// default runner would be the easiest possible way to silently undo the
// isolation guarantee this command's output depends on.
func TestReproduceRefusesWithoutRunner(t *testing.T) {
	_, err := Reproduce(context.Background(), t.TempDir(), 1, ReproduceOptions{})
	if !errors.Is(err, ErrNoRunner) {
		t.Fatalf("Reproduce without a runner: err = %v, want ErrNoRunner", err)
	}
}

// TestReproduceBranchIsAcceptableToWriteBack keeps the generated branch inside
// the naming rules the write-back machinery and the git proxy both enforce. A
// name they reject fails the run at the very end, after the model has been paid
// for.
func TestReproduceBranchIsAcceptableToWriteBack(t *testing.T) {
	at := time.Unix(1757700000, 0).UTC()
	branch := reproduceBranch(20221, at)

	if !strings.HasPrefix(branch, "cloop/") {
		t.Errorf("branch %q must start with cloop/ — ValidateWriteBackBranch requires it "+
			"and the git proxy only allows that prefix", branch)
	}
	if other := reproduceBranch(20221, at.Add(time.Second)); other == branch {
		t.Error("two reproductions a second apart produced the same branch name")
	}
	if !strings.Contains(branch, "20221") {
		t.Errorf("branch %q does not name the task it reproduces", branch)
	}
}

func TestTailOf(t *testing.T) {
	if got := tailOf("short", 100); got != "short" {
		t.Errorf("tailOf under the cap = %q, want unchanged", got)
	}
	got := tailOf("0123456789", 4)
	if !strings.HasSuffix(got, "6789") {
		t.Errorf("tailOf = %q, want it to keep the tail — that is where the error message is", got)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("tailOf = %q, want a truncation marker so a reader knows bytes are missing", got)
	}
}

func TestAtoiSafe(t *testing.T) {
	cases := map[string]int{"0": 0, "3": 3, " 12 ": 12, "": 0, "abc": 0, "1x": 0, "-4": 0}
	for in, want := range cases {
		if got := atoiSafe(in); got != want {
			t.Errorf("atoiSafe(%q) = %d, want %d", in, got, want)
		}
	}
}
