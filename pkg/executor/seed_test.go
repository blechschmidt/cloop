package executor

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func gzipHeader(n int) []byte {
	return append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0}, n)...)
}

func TestValidateProjectSeed(t *testing.T) {
	cases := []struct {
		name string
		seed []byte
		want string // substring; "" means it must be accepted
	}{
		{"empty is fine", nil, ""},
		{"a plausible seed", gzipHeader(64), ""},
		{"not compressed", []byte(`{"goal":"x"}`), "not gzip-compressed"},
		{"one byte", []byte{0x1f}, "not gzip-compressed"},
		{"over the ceiling", gzipHeader(MaxProjectSeedBytes), "ceiling"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProjectSeed(tc.seed)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateProjectSeed = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ValidateProjectSeed accepted an invalid seed")
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("error should wrap ErrInvalidSpec; got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestSpecRefusesASeedOnABindWorkspace: a bind workspace's .cloop/ *is* the
// control plane's own, so writing a seed over it would replace live project
// state with a snapshot of itself — the same class of mistake as cloning over
// a bind mount.
func TestSpecRefusesASeedOnABindWorkspace(t *testing.T) {
	spec := Spec{
		WorkDir:     "/projects/demo",
		Argv:        []string{"cloop", "run"},
		ProjectSeed: gzipHeader(32),
		Workspace:   Workspace{Kind: WorkspaceBind},
	}
	err := spec.Validate()
	if err == nil {
		t.Fatal("a seed on a bind workspace must be refused")
	}
	if !strings.Contains(err.Error(), "bind workspace") {
		t.Errorf("error = %q, want it to name the bind workspace", err)
	}

	// The same seed on a git workspace is the whole point of the feature.
	spec.Workspace = Workspace{
		Kind: WorkspaceGit,
		Repo: "https://example.com/acme/tool.git",
		Ref:  "main",
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("a seed on a git workspace must be accepted: %v", err)
	}
}

// TestSeedImpliesAPlacementRequirement: the hub attaches a seed only to an
// executor that advertises it, so this requirement is the backstop for a
// future caller that forgets — a dropped seed is a run that exits blaming the
// project.
func TestSeedImpliesAPlacementRequirement(t *testing.T) {
	spec := Spec{
		WorkDir:   "/projects/demo",
		Argv:      []string{"cloop", "run"},
		Workspace: Workspace{Kind: WorkspaceGit, Repo: "https://example.com/a.git", Ref: "main"},
	}
	if spec.SandboxRequirements().RequireProjectSeed {
		t.Error("a spec with no seed must not require seeding")
	}

	spec.ProjectSeed = gzipHeader(32)
	req := spec.SandboxRequirements()
	if !req.RequireProjectSeed {
		t.Fatal("a spec carrying a seed must require an executor that can place it")
	}

	caps := Capabilities{
		Isolation:                     IsolationRemote,
		SupportsWorkspaceProvisioning: true,
		NetworkEgress:                 true,
		SupportsProjectSeed:           false,
	}
	_, err := Select([]Candidate{{Executor: &capExecutor{id: "edge-1", caps: caps}}}, req)
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("Select = %v, want a *PlacementError", err)
	}
	if !strings.Contains(err.Error(), "no cloop project found") {
		t.Errorf("the refusal should name the symptom it prevents; got %q", err)
	}

	caps.SupportsProjectSeed = true
	if _, err := Select([]Candidate{{Executor: &capExecutor{id: "edge-1", caps: caps}}}, req); err != nil {
		t.Errorf("a seed-capable executor must be accepted: %v", err)
	}
}
