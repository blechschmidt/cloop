package config

import (
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
