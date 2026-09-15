package pausereason

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeDropsReasonWhenNotPaused(t *testing.T) {
	r := New(CodeBudget, "daily budget spent")

	// The invariant that matters: a run that resumed must not keep claiming
	// it is waiting on something. Enforcing it at the persistence funnel is
	// what lets ~26 call sites stay ignorant of the field on the way out.
	for _, status := range []string{"running", "evolving", "complete", "failed", ""} {
		if got := Normalize(status, &r); got != nil {
			t.Errorf("Normalize(%q) = %+v, want nil: a non-paused run must carry no pause reason", status, got)
		}
	}
	if got := Normalize("paused", &r); got == nil || got.Code != CodeBudget {
		t.Errorf("Normalize(\"paused\") = %+v, want the budget reason preserved", got)
	}
}

func TestNormalizeDropsUnknownCode(t *testing.T) {
	// A row written by a newer cloop naming a code this binary has no label
	// for must degrade to a bare "paused", not render a raw identifier.
	r := Reason{Code: Code("teleported"), Detail: "from the future"}
	if got := Normalize("paused", &r); got != nil {
		t.Errorf("Normalize kept unknown code %q: %+v", r.Code, got)
	}
}

func TestNormalizeDoesNotAliasItsInput(t *testing.T) {
	at := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	r := NewUntil(CodeUsageCap, "5-hour cap reached", at)

	got := Normalize("paused", &r)
	if got == nil {
		t.Fatal("Normalize returned nil for a paused usage cap")
	}
	// Mutating the result must not reach back into the caller's value: the
	// orchestrator holds one Reason and persists it repeatedly.
	got.Detail = "mutated"
	if r.Detail != "5-hour cap reached" {
		t.Errorf("Normalize aliased its input: caller's Detail became %q", r.Detail)
	}
}

func TestAutoResumableOnlyForARolledOverUsageCap(t *testing.T) {
	past := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	now := past.Add(time.Minute)
	future := past.Add(2 * time.Hour)

	cases := []struct {
		name string
		r    *Reason
		want bool
	}{
		{"nil reason", nil, false},
		{"cap whose window reopened", ptr(NewUntil(CodeUsageCap, "5-hour cap reached", past)), true},
		{"cap at the exact reset instant", ptr(NewUntil(CodeUsageCap, "5-hour cap reached", now)), true},
		{"cap still inside its window", ptr(NewUntil(CodeUsageCap, "weekly cap reached", future)), false},
		{"cap with no known reset", ptr(New(CodeUsageCap, "cap reached")), false},

		// Every other code needs a human. Resuming these on a timer would
		// override the very decision that stopped the run — which is the
		// whole reason auto-resume is narrow rather than "resume anything
		// with a timestamp".
		{"declined approval", ptr(NewUntil(CodeApproval, "approval declined", past)), false},
		{"spent budget", ptr(NewUntil(CodeBudget, "budget spent", past)), false},
		{"operator stop", ptr(NewUntil(CodeOperator, "run stopped", past)), false},
		{"abort", ptr(NewUntil(CodeAbort, "credentials rejected", past)), false},
		{"plan-only", ptr(NewUntil(CodePlanOnly, "plan only", past)), false},
		{"idle", ptr(NewUntil(CodeIdle, "nothing to run", past)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.AutoResumable(now); got != tc.want {
				t.Errorf("AutoResumable(%v) = %v, want %v", now, got, tc.want)
			}
		})
	}
}

func TestSummaryRendersTheResumeClock(t *testing.T) {
	at := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	r := NewUntil(CodeUsageCap, "5-hour cap reached", at)

	if got, want := r.Summary(time.UTC), "5-hour cap reached, resumes 14:50"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}

	// No reset time: the phrase must not imply one.
	plain := New(CodeApproval, "approval declined for task #7")
	if got, want := plain.Summary(time.UTC), "approval declined for task #7"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}

	// No detail: fall back to the code's own noun rather than the raw code.
	bare := Reason{Code: CodeStale}
	if got, want := bare.Summary(time.UTC), "previous run ended unexpectedly"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
}

func TestReasonRoundTripsThroughJSON(t *testing.T) {
	at := time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)
	in := NewUntil(CodeUsageCap, "5-hour cap reached", at)

	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Reason
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", blob, err)
	}
	if out.Code != in.Code || out.Detail != in.Detail {
		t.Errorf("round trip changed the reason: %+v -> %+v", in, out)
	}
	if out.ResumesAt == nil || !out.ResumesAt.Equal(at) {
		t.Errorf("round trip lost resumes_at: got %v, want %v", out.ResumesAt, at)
	}
}

func TestEveryCodeHasALabel(t *testing.T) {
	// Known() is what the persistence layer filters on, so a code missing
	// from the label map is silently dropped on the way to disk.
	for _, c := range Codes() {
		if !Known(c) {
			t.Errorf("code %q is declared but Known() rejects it — it would never persist", c)
		}
		r := Reason{Code: c}
		if r.Label() == string(c) {
			t.Errorf("code %q has no prose label; operators would see the raw identifier", c)
		}
	}
}

func ptr(r Reason) *Reason { return &r }
