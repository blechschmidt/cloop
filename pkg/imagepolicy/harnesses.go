package imagepolicy

// harnesses.go reads what a sandbox image says it carries (Task 20450).
//
// A project's provider drives one agent CLI — claude for claudecode, copilot
// for copilot — and a container sandbox has exactly the programs its image
// put there. Nothing could see the mismatch before the workload started: a
// copilot project dispatched with an image that carries only claude was leased
// its credentials, started, and failed inside the sandbox with
//
//	exec: "copilot": executable file not found in $PATH
//
// So an image states what it carries, as a label — the published ones do:
//
//	org.cloop.harnesses=claude,copilot,cloop,git
//
// — and wherever a hub already holds an image's configuration (the container
// driver inspects every image it runs; the remote executor resolves a
// project's image at its registry under require_signature), it compares the
// list with the harness the project needs and refuses before the workload
// exists.
//
// An image without the label is not refused. Nearly every image in the world
// has none, the published images before this one included, and a label nobody
// wrote says nothing either way: unknown is not no. Only a label that lists
// what the image carries, without the harness, is a refusal.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// HarnessesLabel names the image label that lists the programs a sandbox
// image carries, comma-separated: the agent CLIs (claude, copilot) and the
// tools a run relies on (cloop, git), in the vocabulary
// executor.Spec.Harness and an agent's advertised harnesses use.
const HarnessesLabel = "org.cloop.harnesses"

// ErrHarnessNotCarried is the class of every *MissingHarnessError, for callers
// that match with errors.Is.
var ErrHarnessNotCarried = errors.New("imagepolicy: the image does not carry the harness the workload needs")

// ImageHarnesses reads HarnessesLabel from an image's labels: the programs it
// lists, trimmed and without empty entries, and whether the image carries the
// label at all.
//
// The second result is the one that matters. A label that is present and
// empty says the image carries nothing, which is a statement; a label that is
// absent says nothing.
func ImageHarnesses(labels map[string]string) (carries []string, labelled bool) {
	raw, ok := labels[HarnessesLabel]
	if !ok {
		return nil, false
	}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" && !slices.Contains(carries, name) {
			carries = append(carries, name)
		}
	}
	return carries, true
}

// CheckHarness refuses an image whose HarnessesLabel lists what it carries
// without want. It returns nil when want is empty — a workload with no harness
// to run asks nothing of the image — and when the image has no label.
//
// ref names the image in the refusal: what an operator configured or a
// project's sandbox.yaml wrote, not a digest it resolved to. remedy is the
// sentence telling them what to do instead, which only the caller can write:
// it knows which image to suggest and where this one was configured.
//
// Names are compared case-insensitively, as an agent's advertised harnesses
// are.
func CheckHarness(ref string, labels map[string]string, want, remedy string) error {
	want = strings.TrimSpace(want)
	if want == "" {
		return nil
	}
	carries, labelled := ImageHarnesses(labels)
	if !labelled {
		return nil
	}
	for _, name := range carries {
		if strings.EqualFold(name, want) {
			return nil
		}
	}
	return &MissingHarnessError{Ref: ref, Harness: want, Carries: carries, Remediation: remedy}
}

// MissingHarnessError is an image whose label lists what it carries, without
// the harness a workload needs.
//
// It is not a trust-policy verdict, and so not a *DenyError: the image may be
// perfectly trusted. What conflicts is the project's provider with the image
// the executor would run it in.
type MissingHarnessError struct {
	// Ref is the image, as it was configured.
	Ref string
	// Harness is the program the workload needs.
	Harness string
	// Carries is what the image's label lists.
	Carries []string
	// Remediation says what to do instead.
	Remediation string
}

// Error implements error.
func (e *MissingHarnessError) Error() string {
	carries := "nothing"
	if len(e.Carries) > 0 {
		carries = strings.Join(e.Carries, ", ")
	}
	msg := fmt.Sprintf("image %s carries %s (its %s label) and not %s, which this project's provider runs, "+
		"so the run would fail inside the sandbox as soon as it started", e.Ref, carries, HarnessesLabel, e.Harness)
	if e.Remediation != "" {
		msg += "; " + e.Remediation
	}
	return msg
}

// Is makes errors.Is(err, ErrHarnessNotCarried) true.
func (e *MissingHarnessError) Is(target error) bool { return target == ErrHarnessNotCarried }
