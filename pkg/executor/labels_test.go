package executor

import (
	"strings"
	"testing"
)

// TestValidateLabelsAcceptsWhatASelectorCanName (Task 20432): every label an
// operator can state is one a grant's label:k=v selector can match.
func TestValidateLabelsAcceptsWhatASelectorCanName(t *testing.T) {
	ok := []map[string]string{
		nil,
		{"region": "eu"},
		{"gpu": ""},
		{"topology.kubernetes.io/zone": "eu-west-1a", "tier": "a=b", "note": "two words"},
	}
	for _, labels := range ok {
		if err := ValidateLabels(labels); err != nil {
			t.Errorf("ValidateLabels(%v) = %v, want nil", labels, err)
		}
	}
	bad := []struct {
		labels map[string]string
		has    string
	}{
		{map[string]string{"": "x"}, "empty key"},
		{map[string]string{"a,b": "x"}, "selector cannot express"},
		{map[string]string{"a=b": "x"}, "selector cannot express"},
		{map[string]string{"a b": "x"}, "space"},
		{map[string]string{" a": "x"}, "surrounding space"},
		{map[string]string{"a": "x,y"}, "selector cannot express"},
		{map[string]string{"a": " x"}, "surrounding space"},
		{map[string]string{"a": "x\ty"}, "control character"},
		{map[string]string{strings.Repeat("k", MaxLabelKeyBytes+1): "x"}, "longer than"},
		{map[string]string{"a": strings.Repeat("v", MaxLabelValueBytes+1)}, "longer than"},
	}
	for _, tc := range bad {
		if err := ValidateLabels(tc.labels); err == nil || !strings.Contains(err.Error(), tc.has) {
			t.Errorf("ValidateLabels(%q) = %v, want an error mentioning %q", tc.labels, err, tc.has)
		}
	}
	many := map[string]string{}
	for i := 0; i <= MaxLabels; i++ {
		many[strings.Repeat("k", i+1)] = "v"
	}
	if err := ValidateLabels(many); err == nil {
		t.Error("more labels than MaxLabels were accepted")
	}
	if got := NormalizeLabels(map[string]string{" a ": " b "}); got["a"] != "b" || len(got) != 1 {
		t.Errorf("NormalizeLabels = %v", got)
	}
}
