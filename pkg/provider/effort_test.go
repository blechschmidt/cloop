package provider

import "testing"

func TestValidEffort(t *testing.T) {
	valid := append([]string{""}, EffortLevels...)
	for _, v := range valid {
		if !ValidEffort(v) {
			t.Errorf("ValidEffort(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"turbo", "LOW", "High", "maximum", " low", "low "} {
		if ValidEffort(v) {
			t.Errorf("ValidEffort(%q) = true, want false", v)
		}
	}
}
