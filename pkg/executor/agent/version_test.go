package agent

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/version"
)

// TestAgentVersionIsNotTheFrozenConstant is the regression test for the defect
// at the root of this task.
//
// AgentVersion was `const AgentVersion = "1"` with a comment explaining that it
// made "version skew across a fleet visible from the Executors panel". It was
// never once incremented, so every device in every fleet reported the same
// value regardless of what it was running — the field meant to diagnose skew was
// itself why skew could not be diagnosed.
//
// The assertion is against the literal rather than for a specific value, because
// the correct value depends on how the binary was built. Under `go test` there is
// no linker stamp, so the honest answer is the dev build's — which is still
// strictly more information than "1".
func TestAgentVersionIsNotTheFrozenConstant(t *testing.T) {
	if AgentVersion == version.LegacyAgentVersion {
		t.Fatalf("AgentVersion is still the hardcoded %q placeholder; "+
			"it must come from the build version in pkg/version",
			version.LegacyAgentVersion)
	}
	if AgentVersion == "" {
		t.Fatal("AgentVersion is empty; a hello frame with no version is " +
			"indistinguishable from a pre-reporting agent")
	}
}

// TestAgentVersionTracksTheBuildVersion pins the source of truth. A copy that
// merely happened to differ from "1" would drift the moment a release was cut.
func TestAgentVersionTracksTheBuildVersion(t *testing.T) {
	if got, want := AgentVersion, version.String(); got != want {
		t.Errorf("AgentVersion = %q, want %q (pkg/version.String())", got, want)
	}
}
