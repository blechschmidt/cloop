package pm

import "testing"

func TestParseCommitRequirement(t *testing.T) {
	for in, want := range map[string]string{
		"": "committed", "committed": "committed", " Pushed ": "pushed", "off": "off", "OFF": "off",
	} {
		p, err := ParseCommitRequirement(in)
		if err != nil || p.Requirement() != want {
			t.Errorf("ParseCommitRequirement(%q) = %+v, %v; want %s", in, p, err, want)
		}
	}
	if _, err := ParseCommitRequirement("yes"); err == nil {
		t.Error("an unknown value was accepted")
	}
	var nilPolicy *CommitPolicy
	if nilPolicy.Active() || nilPolicy.RequiresPush() || nilPolicy.Clone() != nil || nilPolicy.Describe() != "off" {
		t.Error("a nil policy is not off")
	}
	p := &CommitPolicy{Pushed: true}
	if p.Active() || p.RequiresPush() || p.Requirement() != "off" {
		t.Error("a disabled policy with pushed remembered is not off")
	}
	p.Enabled = true
	if p.Describe() != "committed and pushed" || p.Clone() == p {
		t.Errorf("describe %q / clone shares", p.Describe())
	}
}
