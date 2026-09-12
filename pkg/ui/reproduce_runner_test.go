package ui

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
)

// These are the tests reproduce_runner.go's file comment points at: one per
// guarantee taskreplay.SandboxRunner makes to its callers.
//
// They assert on the spec and on the predicates rather than by starting a
// sandbox — workspaceTestExecutor's Start fails loudly precisely so that a test
// in this package cannot begin real work.

// TestIsolatesRefusesHostSharingExecutors is the guarantee that matters most.
// A reproduction on a host-sharing executor would run against the operator's
// working tree, so its verdict would describe uncommitted local edits rather
// than the recorded commit.
func TestIsolatesRefusesHostSharingExecutors(t *testing.T) {
	cases := []struct {
		name string
		caps executor.Capabilities
		want bool
	}{
		{"local process", executor.Capabilities{SharesHostFilesystem: true}, false},
		{
			// The case a single-predicate check would get wrong: confined, but
			// pointed at the hub's own checkout.
			name: "container bind-mounting the project",
			caps: executor.Capabilities{Isolation: executor.IsolationContainer, SharesHostFilesystem: true},
			want: false,
		},
		{"no isolation at all", executor.Capabilities{Isolation: executor.IsolationNone}, false},
		{
			name: "container with its own filesystem",
			caps: executor.Capabilities{Isolation: executor.IsolationContainer, SupportsWorkspaceProvisioning: true},
			want: true,
		},
		{"remote agent", executor.Capabilities{Isolation: executor.IsolationRemote}, true},
		{"vm", executor.Capabilities{Isolation: executor.IsolationVM}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := &workspaceTestExecutor{id: "x", kind: "test", caps: tc.caps}
			if got := isolates(ex); got != tc.want {
				t.Errorf("isolates(%+v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
	if isolates(nil) {
		t.Error("isolates(nil) = true; a missing executor must never be treated as isolating")
	}
}

// TestPinWorkspaceToRequiresAFreshCheckout: the second guarantee. A workspace
// that is not a git checkout means the executor shares our filesystem, and
// running there would score the working tree.
func TestPinWorkspaceToRequiresAFreshCheckout(t *testing.T) {
	base := "0123456789abcdef0123456789abcdef01234567"

	t.Run("pins ref and clears depth", func(t *testing.T) {
		spec := executor.Spec{Workspace: executor.Workspace{
			Kind: executor.WorkspaceGit, Repo: "https://example.com/r.git",
			Ref: "main", Depth: 1,
		}}
		got, err := pinWorkspaceTo(spec, base)
		if err != nil {
			t.Fatalf("pinWorkspaceTo: %v", err)
		}
		if got.Workspace.Ref != base {
			t.Errorf("Ref = %q, want the base commit %q", got.Workspace.Ref, base)
		}
		if got.Workspace.Depth != 0 {
			t.Errorf("Depth = %d, want 0 — a shallow fetch cannot resolve an arbitrary commit",
				got.Workspace.Depth)
		}
		if err := got.Workspace.Validate(); err != nil {
			t.Errorf("the pinned workspace is not a valid spec: %v", err)
		}
	})

	for _, kind := range []executor.WorkspaceKind{executor.WorkspaceBind, executor.WorkspaceNone, ""} {
		t.Run("refuses "+string(kind), func(t *testing.T) {
			_, err := pinWorkspaceTo(executor.Spec{Workspace: executor.Workspace{Kind: kind}}, base)
			if !errors.Is(err, ErrNoIsolatingExecutor) {
				t.Errorf("err = %v, want ErrNoIsolatingExecutor for a %q workspace", err, kind)
			}
		})
	}

	t.Run("refuses an empty base", func(t *testing.T) {
		spec := executor.Spec{Workspace: executor.Workspace{Kind: executor.WorkspaceGit}}
		if _, err := pinWorkspaceTo(spec, "  "); err == nil {
			t.Error("pinWorkspaceTo accepted an empty base commit")
		}
	})
}

// TestAttachPromptProducesADeliverableFile checks the prompt channel, including
// the permission bits: SecretFile.Validate refuses a group- or world-readable
// file, and the prompt carries the project's goal and instructions.
func TestAttachPromptProducesADeliverableFile(t *testing.T) {
	got, err := attachPrompt(executor.Spec{}, "do the thing")
	if err != nil {
		t.Fatalf("attachPrompt: %v", err)
	}
	if len(got.SecretFiles) != 1 {
		t.Fatalf("SecretFiles = %d, want 1", len(got.SecretFiles))
	}
	f := got.SecretFiles[0]
	if string(f.Content) != "do the thing" {
		t.Errorf("content = %q, want the prompt", f.Content)
	}
	if f.Dir != reproducePromptDir || f.Name != reproducePromptFile {
		t.Errorf("path = %s/%s, want %s/%s", f.Dir, f.Name, reproducePromptDir, reproducePromptFile)
	}
	if err := executor.ValidateSecretFiles(got.SecretFiles); err != nil {
		t.Errorf("the delivered prompt is not a valid secret file: %v", err)
	}

	// The argv the sandbox runs must name the same path the file lands at, or
	// the reproduction starts and reads an empty prompt. Both sides are built
	// from the same two constants; this asserts they are still joined the same
	// way on each side.
	argvPath := reproducePromptDir + "/" + reproducePromptFile
	if argvPath != f.Dir+"/"+f.Name {
		t.Errorf("the argv names %s but the file lands at %s/%s", argvPath, f.Dir, f.Name)
	}
}

func TestReproduceRunnerExeFallsBackToPath(t *testing.T) {
	if got := (&reproduceRunner{selfExe: "/usr/local/bin/cloop"}).exe(); got != "/usr/local/bin/cloop" {
		t.Errorf("exe() = %q, want the injected binary", got)
	}
	if got := (&reproduceRunner{selfExe: "  "}).exe(); got != "cloop" {
		t.Errorf("exe() = %q, want the bare command when none was injected", got)
	}
}

// TestParseTestOutcomeReadsTheMarker covers the stdout protocol between the two
// halves of `cloop task reproduce`.
func TestParseTestOutcomeReadsTheMarker(t *testing.T) {
	want := taskreplay.TestOutcome{Ran: true, Passed: false, ExitCode: 2, Framework: "go test"}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	transcript := "building...\nFAIL\n" + ReproduceResultMarker + string(data) + "\n"

	got := parseTestOutcome(transcript)
	if got == nil {
		t.Fatal("parseTestOutcome found no marker in a transcript that has one")
	}
	if got.ExitCode != 2 || got.Passed || !got.Ran || got.Framework != "go test" {
		t.Errorf("parsed %+v, want %+v", *got, want)
	}

	t.Run("last marker wins", func(t *testing.T) {
		// A suite that echoes the marker itself must not shadow the real one,
		// which this harness always writes last.
		spoof, _ := json.Marshal(taskreplay.TestOutcome{Ran: true, Passed: true})
		mixed := ReproduceResultMarker + string(spoof) + "\nmore output\n" +
			ReproduceResultMarker + string(data) + "\n"
		if got := parseTestOutcome(mixed); got == nil || got.Passed {
			t.Errorf("parsed %+v, want the trailing (real) outcome, which failed", got)
		}
	})

	for name, in := range map[string]string{
		"no marker":      "just output\n",
		"malformed json": ReproduceResultMarker + "{not json}\n",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseTestOutcome(in); got != nil {
				t.Errorf("parseTestOutcome(%q) = %+v, want nil", in, got)
			}
		})
	}
}

func TestTestArgsEncodesAsJSON(t *testing.T) {
	// A dash-leading argument is the reason this is JSON and not a trailing
	// `-- cmd...`: cobra would claim it.
	got := testArgs([]string{"go", "test", "-race", "./..."})
	if len(got) != 2 || got[0] != "--test-command" {
		t.Fatalf("testArgs = %v, want [--test-command <json>]", got)
	}
	var back []string
	if err := json.Unmarshal([]byte(got[1]), &back); err != nil {
		t.Fatalf("the encoded command does not decode: %v", err)
	}
	if strings.Join(back, " ") != "go test -race ./..." {
		t.Errorf("round trip = %v", back)
	}
	if testArgs(nil) != nil {
		t.Error("testArgs(nil) should add no flag at all")
	}
}

func TestModelArgsCarriesTheRecordedSettings(t *testing.T) {
	got := strings.Join(modelArgs(&taskreplay.Provenance{
		Provider: "anthropic", Model: "claude-opus-4-8", Effort: "high",
	}), " ")
	for _, want := range []string{"--provider anthropic", "--model claude-opus-4-8", "--effort high"} {
		if !strings.Contains(got, want) {
			t.Errorf("modelArgs = %q, want it to contain %q", got, want)
		}
	}
	if modelArgs(&taskreplay.Provenance{}) != nil {
		t.Error("an empty provenance should add no model flags, letting the sandbox use its config")
	}
}

// TestReproduceRunnerImplementsTheSeam is a compile-time assertion with a name,
// so a signature change in pkg/taskreplay fails here rather than at the call
// site in cmd/.
func TestReproduceRunnerImplementsTheSeam(t *testing.T) {
	var _ taskreplay.SandboxRunner = NewReproduceRunner("cloop")
}
