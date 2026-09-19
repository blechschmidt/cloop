package executor

// Tests for the per-executor sandbox settings (Task 20307).
//
// The properties worth pinning are the ones a reasonable refactor would break
// while leaving the happy path working:
//
//   - the engine and the runtime name are allowlisted/shape-checked, because
//     both become part of a command an executor runs;
//   - SandboxModeDefault is not a containment claim, so nothing derived from it
//     may report isolation;
//   - a runtime recorded against host mode confers nothing, because a runtime
//     name is not a boundary on its own.

import (
	"strings"
	"testing"
)

func TestSandboxSettings_Validate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      SandboxSettings
		wantErr string // substring; empty means it must be accepted
	}{
		{"empty is unset and valid", SandboxSettings{}, ""},
		{"host", SandboxSettings{Mode: SandboxModeHost}, ""},
		{"container with everything", SandboxSettings{
			Mode: SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "ghcr.io/x/y:v1",
		}, ""},
		{"unknown mode", SandboxSettings{Mode: SandboxMode("vm")}, "sandbox mode"},

		// The engine ends up as the program an executor executes, so anything
		// outside the allowlist is refused rather than passed through.
		{"unknown engine", SandboxSettings{
			Mode: SandboxModeContainer, Engine: "kubectl",
		}, "container engine"},
		{"engine as a path", SandboxSettings{
			Mode: SandboxModeContainer, Engine: "/usr/bin/docker",
		}, "container engine"},

		// A runtime name is resolved by the engine against a root-owned table.
		// A path would turn "name a runtime" into "name a binary run as root".
		{"runtime as a path", SandboxSettings{
			Mode: SandboxModeContainer, Runtime: "/tmp/evil",
		}, "not a path"},
		{"runtime with a backslash", SandboxSettings{
			Mode: SandboxModeContainer, Runtime: `a\b`,
		}, "not a path"},
		{"runtime starting with a dash", SandboxSettings{
			Mode: SandboxModeContainer, Runtime: "--privileged",
		}, "may not start with a dash"},
		{"runtime with a space", SandboxSettings{
			Mode: SandboxModeContainer, Runtime: "kata qemu",
		}, "may use letters"},

		// An image reference reaches an argv too.
		{"image starting with a dash", SandboxSettings{
			Mode: SandboxModeContainer, Image: "-v/etc:/etc",
		}, "may not start with a dash"},
		{"image with whitespace", SandboxSettings{
			Mode: SandboxModeContainer, Image: "img --privileged",
		}, "whitespace"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.in.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate(%+v) = %v, want accepted", tc.in, err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate(%+v) accepted a value it must refuse", tc.in)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate(%+v) = %q, want it to mention %q", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestSandboxSettings_ValidateRejectsBadEngineEvenUnderHostMode pins the
// ordering inside Validate. An admin who typed a bad engine and left the mode on
// host must be told about the engine, not have it silently dropped by Normalize
// — otherwise the same typo returns the moment they switch the mode.
func TestSandboxSettings_ValidateRejectsBadEngineEvenUnderHostMode(t *testing.T) {
	t.Parallel()
	err := SandboxSettings{Mode: SandboxModeHost, Engine: "nope"}.Validate()
	if err == nil {
		t.Fatal("a bad engine under host mode must still be reported, not silently discarded")
	}
}

func TestSandboxSettings_NormalizeDropsFieldsHostModeCannotUse(t *testing.T) {
	t.Parallel()

	got := SandboxSettings{
		Mode: SandboxModeHost, Engine: "podman", Runtime: "kata", Image: "img",
	}.Normalize()

	if got.Mode != SandboxModeHost {
		t.Errorf("mode = %q, want host", got.Mode)
	}
	// Dropped rather than retained: a value kept here would be resurrected by a
	// later switch back to container without anyone re-confirming it.
	if got.Engine != "" || got.Runtime != "" || got.Image != "" {
		t.Errorf("host mode kept container fields: %+v", got)
	}
}

func TestSandboxSettings_NormalizeTrims(t *testing.T) {
	t.Parallel()
	got := SandboxSettings{
		Mode: SandboxMode("  container "), Engine: " podman ", Runtime: " kata ", Image: " img ",
	}.Normalize()
	want := SandboxSettings{Mode: SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "img"}
	if got != want {
		t.Errorf("Normalize = %+v, want %+v", got, want)
	}
}

// TestSandboxSettings_IsolationClaimsRequireContainerMode is the security
// property of this type. A runtime name is not a boundary; the mode is.
func TestSandboxSettings_IsolationClaimsRequireContainerMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                    string
		in                      SandboxSettings
		wantVirt, wantKernelIso bool
	}{
		{"kata in container mode is a VM",
			SandboxSettings{Mode: SandboxModeContainer, Runtime: "kata"}, true, true},
		{"runsc in container mode is a userspace kernel, not a VM",
			SandboxSettings{Mode: SandboxModeContainer, Runtime: "runsc"}, false, true},
		{"runc in container mode is neither",
			SandboxSettings{Mode: SandboxModeContainer, Runtime: "runc"}, false, false},

		// The cases that matter. A runtime recorded against host execution
		// confines nothing, and neither does one recorded against an unset mode.
		{"kata under host mode confines nothing",
			SandboxSettings{Mode: SandboxModeHost, Runtime: "kata"}, false, false},
		{"kata under an unset mode confines nothing",
			SandboxSettings{Runtime: "kata"}, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.IsVirtualized(); got != tc.wantVirt {
				t.Errorf("IsVirtualized() = %v, want %v", got, tc.wantVirt)
			}
			if got := tc.in.IsKernelIsolated(); got != tc.wantKernelIso {
				t.Errorf("IsKernelIsolated() = %v, want %v", got, tc.wantKernelIso)
			}
		})
	}
}

// TestSandboxModeDefaultIsNotAContainmentClaim guards the conservative
// direction. "Nobody has said" must never answer yes to "is this contained".
func TestSandboxModeDefaultIsNotAContainmentClaim(t *testing.T) {
	t.Parallel()
	if SandboxModeDefault.Isolates() {
		t.Error("the unset mode must not report isolation: it means the executor does " +
			"whatever it did before, which for a remote agent is host execution")
	}
	if !SandboxModeContainer.Isolates() {
		t.Error("container mode must report isolation")
	}
	if SandboxModeHost.Isolates() {
		t.Error("host mode must not report isolation")
	}
}

func TestSandboxSettings_IsZero(t *testing.T) {
	t.Parallel()
	if !(SandboxSettings{}).IsZero() {
		t.Error("the zero value must report IsZero")
	}
	if (SandboxSettings{Mode: SandboxModeHost}).IsZero() {
		t.Error("an explicit host mode is a decision, not nothing")
	}
}

func TestValidateRuntimeName_EmptyIsTheEngineDefault(t *testing.T) {
	t.Parallel()
	if err := ValidateRuntimeName(""); err != nil {
		t.Errorf("empty must mean the engine's own default, got %v", err)
	}
	if err := ValidateRuntimeName("   "); err != nil {
		t.Errorf("blank must mean the engine's own default, got %v", err)
	}
	long := make([]byte, MaxRuntimeNameLen+1)
	for i := range long {
		long[i] = 'k'
	}
	if err := ValidateRuntimeName(string(long)); err == nil {
		t.Error("a name past the bound must be refused")
	}
}

func TestSandboxSettings_Describe(t *testing.T) {
	t.Parallel()
	// "default" rather than "" — the audit trail records this string, and an
	// empty from/to field would read as a missing value rather than as a mode.
	if got := (SandboxSettings{}).Describe(); got != "default" {
		t.Errorf("Describe() = %q, want %q", got, "default")
	}
	got := SandboxSettings{
		Mode: SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "img",
	}.Describe()
	for _, want := range []string{"container", "engine=podman", "runtime=kata", "image=img"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, want it to mention %q", got, want)
		}
	}
}
