package pm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

func TestParseRequirementsGateMode(t *testing.T) {
	for in, want := range map[string]string{
		"off": RequirementsGateOff, " Linked ": RequirementsGateLinked, "linked+must": RequirementsGateLinkedMust,
		"LINKED-MUST": RequirementsGateLinkedMust, "linked_must": RequirementsGateLinkedMust,
	} {
		got, err := ParseRequirementsGateMode(in)
		if err != nil || got != want {
			t.Errorf("ParseRequirementsGateMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "on", "must", "linked must", "linked+should"} {
		if _, err := ParseRequirementsGateMode(bad); err == nil || !strings.Contains(err.Error(), "linked+must") {
			t.Errorf("ParseRequirementsGateMode(%q) = %v, want an error naming the modes", bad, err)
		}
	}
}

func TestRequirementsGateModes(t *testing.T) {
	var nilGate *RequirementsGate
	cases := []struct {
		g              *RequirementsGate
		active, must   bool
		assess         bool
		mode, describe string
	}{
		{nilGate, false, false, false, "off", "off"},
		{&RequirementsGate{}, false, false, false, "off", "off"},
		{&RequirementsGate{Mode: "bogus", Assess: true}, false, false, false, "off", "off"},
		{&RequirementsGate{Mode: RequirementsGateOff, Assess: true}, false, false, false, "off", "off"},
		{&RequirementsGate{Mode: RequirementsGateLinked}, true, false, false, "linked", "its linked requirements pass"},
		{&RequirementsGate{Mode: RequirementsGateLinkedMust, Assess: true}, true, true, true, "linked+must",
			"its linked requirements and every approved must requirement pass (the model assesses untested ones)"},
	}
	for _, c := range cases {
		if c.g.Active() != c.active || c.g.IncludesMust() != c.must || c.g.AssessUntested() != c.assess ||
			c.g.EffectiveMode() != c.mode || c.g.Describe() != c.describe {
			t.Errorf("%+v: active %v must %v assess %v mode %q describe %q", c.g, c.g.Active(), c.g.IncludesMust(),
				c.g.AssessUntested(), c.g.EffectiveMode(), c.g.Describe())
		}
	}
	if err := (&RequirementsGate{Mode: "bogus"}).Validate(); err == nil {
		t.Error("an unknown mode validated")
	}
	if err := (&RequirementsGate{Mode: "linked"}).Validate(); err != nil {
		t.Error(err)
	}
	if c := (&RequirementsGate{Mode: "linked"}).Clone(); c == nil || c.Mode != "linked" {
		t.Errorf("clone = %+v", c)
	}
}

func verdict(id int, v string, blocking, regression bool, tests ...requirements.TestResult) RequirementVerdict {
	return RequirementVerdict{Result: requirements.Result{RequirementID: id, Verdict: v, Method: requirements.MethodTests, Tests: tests},
		Blocking: blocking, Regression: regression, Linked: true}
}

func TestTaskRequirementsCheckHeadline(t *testing.T) {
	c := &TaskRequirementsCheck{Outcome: RequirementsUnmet, Commit: strings.Repeat("a", 40), Dirty: true,
		Requirements: []RequirementVerdict{
			verdict(3, requirements.VerdictUnfulfilled, true, true),
			verdict(7, requirements.VerdictError, true, false),
			{Result: requirements.Result{RequirementID: 9, Verdict: requirements.VerdictUnverified, Method: requirements.MethodNone}},
			verdict(1, requirements.VerdictFulfilled, false, false),
		}}
	want := "Requirements unmet: R-3 unfulfilled (regression), R-7 error; R-9 unverified (no tests) at aaaaaaaaaaaa (with uncommitted changes)."
	if got := c.Headline(); got != want {
		t.Errorf("Headline() = %q\nwant %q", got, want)
	}
	if n := len(c.Blocking()); n != 2 {
		t.Errorf("blocking = %d", n)
	}
	if r := c.Regressions(); len(r) != 1 || r[0].RequirementID != 3 {
		t.Errorf("regressions = %+v", r)
	}
	if u := c.Unverified(); len(u) != 1 || u[0] != 9 {
		t.Errorf("unverified = %v", u)
	}
	met := &TaskRequirementsCheck{Outcome: RequirementsMet, Requirements: []RequirementVerdict{verdict(1, requirements.VerdictFulfilled, false, false)}}
	if got := met.Headline(); got != "Requirements met: R-1 fulfilled." {
		t.Errorf("met headline = %q", got)
	}
	var none *TaskRequirementsCheck
	if none.Met() || none.Unmet() || none.Headline() != "" || none.Clone() != nil {
		t.Error("a nil record is not empty")
	}
}

func TestTaskRequirementsCheckBound(t *testing.T) {
	long := strings.Repeat("é", MaxTaskRequirementOutputBytes)
	c := &TaskRequirementsCheck{Outcome: RequirementsUnmet, Commit: "not a commit", Consecutive: -3}
	for i := 0; i < MaxTaskRequirementsChecked+5; i++ {
		c.Requirements = append(c.Requirements, verdict(i+1, requirements.VerdictUnfulfilled, true, false,
			requirements.TestResult{Command: "true", Outcome: requirements.OutcomePass, Output: "passing output"},
			requirements.TestResult{Command: "false", Outcome: requirements.OutcomeFail, ExitCode: 1, Output: long}))
	}
	orig := c.Clone()
	c.Bound()
	if len(c.Requirements) != MaxTaskRequirementsChecked || c.Commit != "" || c.Consecutive != 0 {
		t.Fatalf("bound: %d requirements, commit %q, consecutive %d", len(c.Requirements), c.Commit, c.Consecutive)
	}
	pass, fail := c.Requirements[0].Tests[0], c.Requirements[0].Tests[1]
	if pass.Output != "" {
		t.Error("a passing test kept its output")
	}
	if len(fail.Output) > MaxTaskRequirementOutputBytes || !fail.Truncated || !strings.HasSuffix(long, fail.Output) {
		t.Errorf("failing output kept %d bytes, truncated %v", len(fail.Output), fail.Truncated)
	}
	if len(orig.Requirements) != MaxTaskRequirementsChecked+5 || orig.Requirements[0].Tests[0].Output == "" {
		t.Error("Clone shares its slices with the original")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back TaskRequirementsCheck
	if err := json.Unmarshal(raw, &back); err != nil || back.Requirements[0].RequirementID != 1 || !back.Requirements[0].Blocking {
		t.Errorf("round trip: %+v, %v", back.Requirements[0], err)
	}
	if !strings.Contains(string(raw), `"requirement_id":1`) {
		t.Errorf("the embedded result does not flatten into the verdict: %s", raw[:200])
	}
}
