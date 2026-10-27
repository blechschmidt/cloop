package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// TestApplyRatchetsInstallsAllThree: `cloop ui`, every command's startup and
// `cloop hub doctor` install the section's fleet policies through this one
// method (Task 20387), so it must carry all three — and, being ratchets, none
// of them may loosen what is already in force.
func TestApplyRatchetsInstallsAllThree(t *testing.T) {
	prevHost := executor.SetAllowHostExecution(true)
	prevBuild := executor.SetMinAgentBuild("")
	executor.ResetResourceCeiling()
	t.Cleanup(func() {
		executor.SetAllowHostExecution(prevHost)
		executor.SetMinAgentBuild(prevBuild)
		executor.ResetResourceCeiling()
	})

	strict := false
	e := ExecutorsConfig{AllowHostProcess: &strict, MinAgentBuild: "v2.0.0"}
	e.Limits.MaxPIDs = 256
	e.ApplyRatchets()

	if executor.HostExecutionAllowed() {
		t.Error("host execution is still allowed")
	}
	if got := executor.MinAgentBuild(); got != "v2.0.0" {
		t.Errorf("min agent build = %q, want v2.0.0", got)
	}
	if got := executor.FleetResourceCeiling(); got.PIDs != 256 {
		t.Errorf("fleet ceiling = %+v, want 256 PIDs", got)
	}

	allow := true
	ExecutorsConfig{AllowHostProcess: &allow}.ApplyRatchets()
	if executor.HostExecutionAllowed() {
		t.Error("a later, looser section loosened the host policy")
	}
}

// TestApplyRatchetsInstallsTheIsolationEvidencePolicy: the fourth fleet policy
// rides the same method (Task 20439), and a later "warn" cannot relax it.
func TestApplyRatchetsInstallsTheIsolationEvidencePolicy(t *testing.T) {
	prev := executor.SetIsolationEvidenceRequired(false)
	t.Cleanup(func() { executor.SetIsolationEvidenceRequired(prev) })

	ExecutorsConfig{IsolationEvidence: executor.IsolationEvidencePolicyRequired}.ApplyRatchets()
	if !executor.IsolationEvidenceRequired() {
		t.Fatal("isolation_evidence: required was not installed")
	}
	ExecutorsConfig{IsolationEvidence: executor.IsolationEvidencePolicyWarn}.ApplyRatchets()
	if !executor.IsolationEvidenceRequired() {
		t.Fatal("a later warn relaxed the policy")
	}
	if err := ValidateExecutors(ExecutorsConfig{IsolationEvidence: "strict"}); err == nil {
		t.Error("an unknown policy validated")
	}
	if err := ValidateExecutors(ExecutorsConfig{IsolationEvidence: "required"}); err != nil {
		t.Errorf("required: %v", err)
	}
	if w := ExecutorWarnings(ExecutorsConfig{IsolationEvidence: "strict"}); len(w) == 0 ||
		!strings.Contains(strings.Join(w, " "), "isolation_evidence") {
		t.Errorf("no warning for an unknown policy: %v", w)
	}
}

// TestApplyRatchetsInstallsTheImageProvenancePolicy: executors.image_provenance
// rides the same method (Task 20453), and a later "warn" cannot relax it.
func TestApplyRatchetsInstallsTheImageProvenancePolicy(t *testing.T) {
	prev := executor.SetImageProvenanceRequired(false)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })

	ExecutorsConfig{ImageProvenance: executor.ImageProvenancePolicyWarn}.ApplyRatchets()
	if executor.ImageProvenanceRequired() {
		t.Fatal("warn installed required")
	}
	ExecutorsConfig{ImageProvenance: executor.ImageProvenancePolicyRequired}.ApplyRatchets()
	if !executor.ImageProvenanceRequired() {
		t.Fatal("image_provenance: required was not installed")
	}
	ExecutorsConfig{ImageProvenance: executor.ImageProvenancePolicyWarn}.ApplyRatchets()
	if !executor.ImageProvenanceRequired() {
		t.Fatal("a later warn relaxed the policy")
	}
	if err := ValidateExecutors(ExecutorsConfig{ImageProvenance: "strict"}); err == nil ||
		!strings.Contains(err.Error(), "image_provenance") {
		t.Errorf("an unknown policy validated: %v", err)
	}
	if err := ValidateExecutors(ExecutorsConfig{ImageProvenance: "required"}); err != nil {
		t.Errorf("required: %v", err)
	}
	if w := ExecutorWarnings(ExecutorsConfig{ImageProvenance: "strict"}); len(w) == 0 ||
		!strings.Contains(strings.Join(w, " "), "image_provenance") {
		t.Errorf("no warning for an unknown policy: %v", w)
	}
}

// TestGovernOperatorImagesReachesThePolicy: the YAML key reaches the policy the
// drivers enforce, and changes no verdict on a project's image.
func TestGovernOperatorImagesReachesThePolicy(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("sandbox:\n  image_policy:\n    allowed_registries: [ghcr.io]\n"+
		"    govern_operator_images: true\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	p := cfg.Sandbox.ImagePolicy.Policy()
	if !p.GovernOperatorImages || !p.GovernsOperatorImage("ghcr.io/acme/base:1") {
		t.Fatalf("govern_operator_images did not reach the policy: %+v", p)
	}
	if p.GovernsOperatorImage("ghcr.io/blechschmidt/cloop-harness:latest") {
		t.Error("cloop's own image is governed by the project rules; it has its own pin")
	}
	ungoverned := p
	ungoverned.GovernOperatorImages = false
	if p.Fingerprint() != ungoverned.Fingerprint() {
		t.Error("govern_operator_images changed the fingerprint of a verdict it does not affect")
	}
}
