package version

import (
	"errors"
	"testing"
)

func TestEdgeTargets(t *testing.T) {
	const full = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"
	if got := EdgeTarget(" A0F387020B4DF29E9F39EBE0369EC0DE0CA8C674 "); got != "edge:"+full {
		t.Errorf("EdgeTarget = %q", got)
	}
	for in, want := range map[string]string{"edge:" + full: full, "EDGE:a0f3870": "a0f3870"} {
		if got, err := ParseEdgeTarget(in); err != nil || got != want {
			t.Errorf("ParseEdgeTarget(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"v0.0.4", "edge:", "edge:a0f38", "edge:zzzzzzz", "edge:" + full + "0", "latest"} {
		if _, err := ParseEdgeTarget(bad); !errors.Is(err, ErrEdgeTarget) {
			t.Errorf("ParseEdgeTarget(%q) = %v, want ErrEdgeTarget", bad, err)
		}
	}
	if !IsEdgeTarget("edge:zzz") || IsEdgeTarget("v0.0.4") {
		t.Error("IsEdgeTarget")
	}
	if IsRelease("edge:" + full) {
		t.Error("an edge target passed for a release")
	}
}

func TestCommitOfAndSameCommit(t *testing.T) {
	if c, ok := CommitOf("dev+ga0f3870"); !ok || c != "a0f3870" {
		t.Errorf("CommitOf = %q, %t", c, ok)
	}
	for _, v := range []string{"v0.0.4", "dev", "dev+ga0f3870.dirty", "dev+ga0f38", ""} {
		if _, ok := CommitOf(v); ok {
			t.Errorf("CommitOf(%q) named a commit", v)
		}
	}
	if !SameCommit("dev+ga0f3870", "dev+ga0f38702") || SameCommit("dev+ga0f3870", "dev+gf25fd69") {
		t.Error("SameCommit")
	}
}

// TestClassifyMatchesOneCommitAbbreviatedTwice: a device upgraded to the hub's
// edge build reports seven digits, the hub's deploy may stamp eight, and that
// is no skew at all.
func TestClassifyMatchesOneCommitAbbreviatedTwice(t *testing.T) {
	if skew, _ := Classify("dev+ga0f38702", "dev+ga0f3870"); skew != SkewNone {
		t.Errorf("same commit, two abbreviations: %s", skew)
	}
	if skew, _ := Classify("dev+ga0f3870", "dev+gf25fd69"); skew != SkewUnversioned {
		t.Errorf("two commits: %s", skew)
	}
	if skew, _ := Classify("dev+ga0f3870", "dev+ga0f3870.dirty"); skew == SkewNone {
		t.Error("a dirty build of the hub's commit was called identical")
	}
}
