package pm

import (
	"strings"
	"testing"
)

func TestReviewGateValidate(t *testing.T) {
	ok := []ReviewGate{
		{},
		{Enabled: true},
		{Enabled: true, Provider: "anthropic", Model: "claude-opus-5-5", Effort: "high", Mode: "block"},
		{Provider: "ollama", Model: "llama3:70b", Mode: "advisory"},
		{Provider: "claudecode", Model: "claude-sonnet-5[1m]", MaxFixRounds: 5},
	}
	for _, g := range ok {
		if err := g.Validate(); err != nil {
			t.Errorf("%+v: %v", g, err)
		}
	}
	bad := []ReviewGate{
		{Provider: "mock"},
		{Provider: "bedrock"},
		{Model: "--dangerously-skip-permissions"},
		{Model: "a model"},
		{Model: strings.Repeat("m", 129)},
		{Effort: "extreme"},
		{Mode: "yolo"},
		{MaxFixRounds: -1},
		{MaxFixRounds: 6},
		{Instructions: strings.Repeat("x", MaxReviewInstructionsBytes+1)},
	}
	for _, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("%+v was accepted", g)
		}
	}
	var nilGate *ReviewGate
	if nilGate.Validate() != nil || nilGate.Active() {
		t.Error("a nil gate is not a valid, inactive one")
	}
}

func TestReviewGateNormalizeAndDefaults(t *testing.T) {
	g := &ReviewGate{Enabled: true, Provider: " Anthropic ", Mode: " FIX ", Effort: "High", Model: " claude-opus-5-5 "}
	g.Normalize()
	if g.Provider != "anthropic" || g.Mode != "fix" || g.Effort != "high" || g.Model != "claude-opus-5-5" {
		t.Errorf("normalized = %+v", g)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if g.EffectiveFixRounds() != DefaultReviewFixRounds {
		t.Errorf("default fix rounds = %d", g.EffectiveFixRounds())
	}
	if (&ReviewGate{Mode: ReviewModeBlock, MaxFixRounds: 4}).EffectiveFixRounds() != 0 {
		t.Error("block mode sends tasks back")
	}
	if (&ReviewGate{}).EffectiveMode() != ReviewModeFix {
		t.Error("the default mode is not fix")
	}
	c := g.Clone()
	c.Model = "other"
	if g.Model == "other" {
		t.Error("Clone shares storage")
	}
}

func TestTaskReviewRendering(t *testing.T) {
	r := &TaskReview{
		Verdict: ReviewChangesRequested, Mode: ReviewModeFix, Blocked: true, Model: "claude-opus-5-5",
		Rounds: 3, FixRounds: 2, Summary: "Two problems remain.",
		Findings: []ReviewFinding{{Severity: "blocker", File: "db.go", Line: 12, Title: "SQL injection"}, {Severity: "nit", Title: "typo"}},
	}
	h := r.Headline()
	for _, want := range []string{"changes requested", "claude-opus-5-5", "2 fix round(s)", "2 finding(s)", "not published"} {
		if !strings.Contains(h, want) {
			t.Errorf("headline %q lacks %q", h, want)
		}
	}
	d := r.Diagnosis()
	if !strings.Contains(d, "[blocker] db.go:12: SQL injection") || !strings.Contains(d, "Two problems remain.") {
		t.Errorf("diagnosis:\n%s", d)
	}
	if r.Approved() {
		t.Error("a blocked review reports approved")
	}
	adv := &TaskReview{Verdict: ReviewChangesRequested, Mode: ReviewModeAdvisory}
	if !adv.Approved() || !strings.Contains(adv.Headline(), "published anyway") {
		t.Errorf("advisory: %q", adv.Headline())
	}
	if !strings.Contains((&TaskReview{Verdict: ReviewUnavailable, Blocked: true, Error: "401"}).Headline(), "failing closed") {
		t.Error("an unavailable, blocking review does not say it failed closed")
	}
	var none *TaskReview
	if !none.Approved() || none.Headline() != "" || none.Clone() != nil {
		t.Error("a nil review is not a no-op")
	}
}

func TestTaskReviewBound(t *testing.T) {
	r := &TaskReview{Summary: strings.Repeat("é", 5000)}
	for i := 0; i < 40; i++ {
		r.Findings = append(r.Findings, ReviewFinding{Severity: "major", Title: strings.Repeat("t", 1000), Detail: strings.Repeat("d", 5000), Line: -3})
	}
	r.Published = []ReviewPublish{{Detail: strings.Repeat("p", 5000)}}
	r.Bound()
	if len(r.Summary) > 2100 || len(r.Findings) != MaxReviewFindings {
		t.Errorf("summary %d bytes, %d findings", len(r.Summary), len(r.Findings))
	}
	if !strings.HasSuffix(r.Summary, "…") || strings.ContainsRune(r.Summary, '�') {
		t.Error("summary was not cut on a rune boundary")
	}
	f := r.Findings[0]
	if len(f.Title) > 310 || len(f.Detail) > 610 || f.Line != 0 {
		t.Errorf("finding not bounded: title %d, detail %d, line %d", len(f.Title), len(f.Detail), f.Line)
	}
	if len(r.Published[0].Detail) > 410 {
		t.Errorf("publish detail %d bytes", len(r.Published[0].Detail))
	}
}
