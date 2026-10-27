package imagepolicy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestImageHarnessesTellsAbsentFromEmpty pins the distinction the whole check
// rests on: a label that is present and lists nothing is a statement, and an
// absent one is not.
func TestImageHarnessesTellsAbsentFromEmpty(t *testing.T) {
	for _, tc := range []struct {
		name     string
		labels   map[string]string
		carries  []string
		labelled bool
	}{
		{"no labels at all", nil, nil, false},
		{"other labels only", map[string]string{"org.opencontainers.image.title": "x"}, nil, false},
		{"the published image", map[string]string{HarnessesLabel: "claude,copilot,cloop,git"},
			[]string{"claude", "copilot", "cloop", "git"}, true},
		{"spaces and empty entries", map[string]string{HarnessesLabel: " claude , ,git,claude "},
			[]string{"claude", "git"}, true},
		{"present and empty", map[string]string{HarnessesLabel: ""}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carries, labelled := ImageHarnesses(tc.labels)
			if labelled != tc.labelled || !slices.Equal(carries, tc.carries) {
				t.Errorf("ImageHarnesses = %q, %v; want %q, %v", carries, labelled, tc.carries, tc.labelled)
			}
		})
	}
}

// TestCheckHarnessRefusesOnlyALabelThatSaysNo is the rule "unknown is not no":
// an unlabelled image, and a workload with no harness, pass; a label listing
// what the image carries without the harness is refused, naming both.
func TestCheckHarnessRefusesOnlyALabelThatSaysNo(t *testing.T) {
	claudeOnly := map[string]string{HarnessesLabel: "claude,cloop,git"}

	if err := CheckHarness("example.com/img:1", nil, "copilot", "remedy"); err != nil {
		t.Errorf("an unlabelled image was refused: %v", err)
	}
	if err := CheckHarness("example.com/img:1", claudeOnly, "", "remedy"); err != nil {
		t.Errorf("a workload naming no harness was refused: %v", err)
	}
	if err := CheckHarness("example.com/img:1", claudeOnly, "Claude", "remedy"); err != nil {
		t.Errorf("a harness the label lists, in another case, was refused: %v", err)
	}

	err := CheckHarness("example.com/img:1", claudeOnly, "copilot", "use the copilot image")
	if !errors.Is(err, ErrHarnessNotCarried) {
		t.Fatalf("CheckHarness = %v, want ErrHarnessNotCarried", err)
	}
	var missing *MissingHarnessError
	if !errors.As(err, &missing) || missing.Harness != "copilot" || !slices.Equal(missing.Carries, []string{"claude", "cloop", "git"}) {
		t.Fatalf("CheckHarness = %#v", err)
	}
	for _, want := range []string{"example.com/img:1", "copilot", "claude, cloop, git", HarnessesLabel, "use the copilot image"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}
	// Not a trust-policy verdict: an image that lacks a program is not an
	// image the hub distrusts, and the API must not say it is.
	if errors.Is(err, ErrDenied) {
		t.Errorf("a missing harness reads as an image-policy denial: %v", err)
	}

	empty := map[string]string{HarnessesLabel: " "}
	if err := CheckHarness("example.com/img:1", empty, "claude", ""); err == nil || !strings.Contains(err.Error(), "carries nothing") {
		t.Errorf("an image whose label lists nothing = %v, want a refusal saying it carries nothing", err)
	}
}
