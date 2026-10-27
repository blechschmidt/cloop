package executor

import "strings"

// HarnessImage is a sandbox image this repository publishes, and what it
// carries.
type HarnessImage struct {
	// Ref is the image, by the tag that moves with each release.
	Ref string
	// Carries lists the programs in it, as its org.cloop.harnesses label does
	// (imagepolicy.HarnessesLabel).
	Carries []string
}

// HarnessImages are the sandbox images .github/workflows/publish-images.yml
// publishes, the default first: a refusal that suggests an image names the
// first one carrying what is missing.
//
// Two because of the Copilot CLI's weight (Task 20450): it nearly doubles the
// image, and every claude project on every node would pull it. tests/docs
// holds each entry's Carries equal to the label its Dockerfile stage sets, and
// its Ref to an image the workflow publishes, so a suggestion here cannot send
// an operator to pull something that does not fix their problem.
var HarnessImages = []HarnessImage{
	{Ref: "ghcr.io/blechschmidt/cloop-harness:latest", Carries: []string{"claude", "cloop", "git"}},
	{Ref: "ghcr.io/blechschmidt/cloop-harness-copilot:latest", Carries: []string{"claude", "copilot", "cloop", "git"}},
}

// HarnessImageFor names the first published image that carries harness, or
// "" when none does.
func HarnessImageFor(harness string) string {
	harness = strings.TrimSpace(harness)
	if harness == "" {
		return ""
	}
	for _, img := range HarnessImages {
		for _, name := range img.Carries {
			if strings.EqualFold(name, harness) {
				return img.Ref
			}
		}
	}
	return ""
}

// HarnessImageRemedy is the sentence a refusal ends with when the image a
// workload would run in lacks its harness: run it in one that has it, naming a
// published one where there is one.
func HarnessImageRemedy(harness string) string {
	if ref := HarnessImageFor(harness); ref != "" {
		return "run it in an image that carries " + harness + ", such as " + ref +
			" — the executor's sandbox image, or image: in the project's .cloop/sandbox.yaml"
	}
	return "run it in an image that carries " + harness +
		" — the executor's sandbox image, or image: in the project's .cloop/sandbox.yaml"
}
