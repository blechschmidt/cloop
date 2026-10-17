package config

import (
	"strings"
	"testing"

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
