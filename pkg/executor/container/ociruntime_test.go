package container

// ociruntime_test.go covers the second runtime axis: the value that reaches
// `--runtime`, and the isolation claim that follows from it.
//
// Like argv_test.go this over-specifies deliberately. The name in this field
// is resolved by docker's daemon (as root) or by podman against
// containers.conf, so what may appear here is a security question, and the
// rendered flag is the only place the answer is observable.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestValidateOCIRuntime(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string // substring; "" means the value must be accepted
	}{
		// Accepted: the names Kata and the stock runtimes are registered under.
		{"empty means CLI default", "", ""},
		{"whitespace is empty", "   ", ""},
		{"kata", "kata", ""},
		{"kata-qemu", "kata-qemu", ""},
		{"kata-runtime", "kata-runtime", ""},
		{"containerd shim spelling", "io.containerd.kata.v2", ""},
		{"crun", "crun", ""},
		{"underscores", "my_runtime", ""},
		{"digits", "kata2", ""},

		// A path is the case this validator exists for. docker resolves a
		// runtime name against daemon.json and podman against containers.conf,
		// both root-owned; a path would instead name a binary those daemons
		// execute, turning "config" into "arbitrary code as root".
		{"absolute path", "/usr/bin/kata-runtime", "not a path"},
		{"relative path", "./kata", "not a path"},
		{"parent traversal", "../../bin/sh", "not a path"},
		{"windows separator", `C:\kata.exe`, "not a path"},

		// A leading dash would be parsed as another flag rather than as the
		// value of --runtime, which is an argv-injection primitive.
		{"leading dash", "-privileged", "may not start with a dash"},
		{"double dash", "--volume=/:/host", "may not start with a dash"},

		// Shell and whitespace metacharacters. Nothing here is passed through
		// a shell, but a name is an identifier and these are not in it.
		{"space", "kata qemu", "may use letters"},
		{"semicolon", "kata;id", "may use letters"},
		// Rejected by the path check rather than the charset one — it contains
		// a slash — but rejected either way, which is what matters.
		{"command with a path", "kata;rm -rf /", "not a path"},
		{"newline", "kata\nrunc", "may use letters"},
		{"dollar", "kata$(id)", "may use letters"},
		{"null byte", "kata\x00", "may use letters"},
		{"backtick", "kata`id`", "may use letters"},

		{"too long", strings.Repeat("k", maxOCIRuntimeNameLen+1), "too long"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOCIRuntime(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateOCIRuntime(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateOCIRuntime(%q) = nil, want an error containing %q", tc.in, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ValidateOCIRuntime(%q) = %q, want it to mention %q", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestValidateOCIRuntimeBoundaryLength pins the boundary itself, so an
// off-by-one in the length check cannot pass by rejecting one character early.
func TestValidateOCIRuntimeBoundaryLength(t *testing.T) {
	atLimit := strings.Repeat("k", maxOCIRuntimeNameLen)
	if err := ValidateOCIRuntime(atLimit); err != nil {
		t.Errorf("a name of exactly %d characters must be accepted, got %v", maxOCIRuntimeNameLen, err)
	}
}

// TestIsVirtualizedOCIRuntimeDelegates checks that this package's spelling and
// the shared matcher cannot drift apart. The exhaustive table lives in
// pkg/executor/virtualization_test.go; duplicating it here would create the
// second definition the delegation exists to prevent.
func TestIsVirtualizedOCIRuntimeDelegates(t *testing.T) {
	for _, name := range []string{"", "kata", "kata-qemu", "runc", "runsc", "KATA", "notkata"} {
		if got, want := IsVirtualizedOCIRuntime(name), executor.IsVirtualizedRuntime(name); got != want {
			t.Errorf("IsVirtualizedOCIRuntime(%q) = %v but executor.IsVirtualizedRuntime = %v — "+
				"the two spellings of one question must agree", name, got, want)
		}
	}
}

// --- argv rendering ------------------------------------------------------

// TestBuildRunArgs_OCIRuntimeAbsentByDefault is the compatibility guarantee:
// a deployment that does not configure an OCI runtime must produce exactly the
// command line it produced before the field existed.
func TestBuildRunArgs_OCIRuntimeAbsentByDefault(t *testing.T) {
	got := mustBuild(t, baseRequest())
	for i, a := range got.Args {
		if a == "--runtime" {
			t.Fatalf("--runtime appears at index %d of %v with no OCIRuntime configured", i, got.Args)
		}
	}
}

// TestBuildRunArgs_OCIRuntimeRendered checks the flag reaches argv as a
// separate argument (not --runtime=name, which podman accepts but which makes
// the value harder to assert on) and that it precedes the `--` separator.
func TestBuildRunArgs_OCIRuntimeRendered(t *testing.T) {
	req := baseRequest()
	req.OCIRuntime = "kata-qemu"
	got := mustBuild(t, req)

	idx := -1
	for i, a := range got.Args {
		if a == "--runtime" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("--runtime missing from %v", got.Args)
	}
	if idx+1 >= len(got.Args) || got.Args[idx+1] != "kata-qemu" {
		t.Fatalf("--runtime is not followed by the configured name in %v", got.Args)
	}

	sep := -1
	for i, a := range got.Args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("no `--` separator in %v", got.Args)
	}
	if idx > sep {
		t.Errorf("--runtime at %d comes after the `--` separator at %d, so it would be "+
			"passed to the workload instead of the runtime", idx, sep)
	}
}

// TestBuildRunArgs_OCIRuntimeKeepsConfinementFlags guards against the change
// being made by *replacing* isolation flags rather than adding to them. Kata
// does not make --cap-drop or --read-only redundant: defence in depth is the
// whole point, and a VM whose guest still drops capabilities is strictly
// better than one that does not.
func TestBuildRunArgs_OCIRuntimeKeepsConfinementFlags(t *testing.T) {
	req := baseRequest()
	req.OCIRuntime = "kata"
	joined := strings.Join(mustBuild(t, req).Args, " ")

	for _, must := range []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--network=none",
		"--pull=never",
	} {
		if !strings.Contains(joined, must) {
			t.Errorf("%s is missing under a kata runtime; the VM boundary adds to the "+
				"container one, it does not replace it\nargv: %s", must, joined)
		}
	}
}

// TestBuildRunArgs_OCIRuntimeValidatedAtRender is the belt-and-braces check.
// Options.Normalize already validates, but buildRunArgs is the security
// boundary this package documents, and it must not render a value it was
// handed directly by a caller that skipped normalisation.
func TestBuildRunArgs_OCIRuntimeValidatedAtRender(t *testing.T) {
	for _, bad := range []string{"/usr/bin/kata", "-privileged", "kata;id"} {
		req := baseRequest()
		req.OCIRuntime = bad
		if _, err := buildRunArgs(req); err == nil {
			t.Errorf("buildRunArgs accepted OCIRuntime %q — the argv builder must re-check "+
				"what it renders, not trust the caller", bad)
		}
	}
}

// --- options and capabilities --------------------------------------------

func TestOptionsNormalizeOCIRuntime(t *testing.T) {
	t.Run("trims whitespace", func(t *testing.T) {
		got, err := Options{OCIRuntime: "  kata-qemu  "}.Normalize()
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if got.OCIRuntime != "kata-qemu" {
			t.Errorf("OCIRuntime = %q, want the trimmed name", got.OCIRuntime)
		}
	})

	t.Run("rejects a path", func(t *testing.T) {
		if _, err := (Options{OCIRuntime: "/usr/bin/kata-runtime"}).Normalize(); err == nil {
			t.Error("Normalize accepted a path as an OCI runtime")
		}
	})

	t.Run("empty stays empty", func(t *testing.T) {
		got, err := Options{}.Normalize()
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if got.OCIRuntime != "" {
			t.Errorf("OCIRuntime = %q, want empty — the zero value must remain 'CLI default'", got.OCIRuntime)
		}
	})
}

// TestCapabilitiesIsolationFollowsOCIRuntime is the claim the placement layer
// acts on: a Kata executor must describe itself as a VM, and a runc one must
// not.
func TestCapabilitiesIsolationFollowsOCIRuntime(t *testing.T) {
	cases := []struct {
		ociRuntime  string
		isolation   executor.Isolation
		virtualized bool
	}{
		{"", executor.IsolationContainer, false},
		{"runc", executor.IsolationContainer, false},
		{"crun", executor.IsolationContainer, false},
		{"runsc", executor.IsolationContainer, false},
		{"kata", executor.IsolationVM, true},
		{"kata-qemu", executor.IsolationVM, true},
		{"io.containerd.kata.v2", executor.IsolationVM, true},
	}

	for _, tc := range cases {
		t.Run("runtime="+tc.ociRuntime, func(t *testing.T) {
			// Constructed directly rather than through New, which would need a
			// container runtime binary on the machine running the tests.
			e := &Executor{id: "c", opts: Options{OCIRuntime: tc.ociRuntime, Network: NetworkNone}}

			caps := e.Capabilities()
			if caps.Isolation != tc.isolation {
				t.Errorf("Isolation = %q, want %q", caps.Isolation, tc.isolation)
			}
			if caps.Virtualized != tc.virtualized {
				t.Errorf("Virtualized = %v, want %v", caps.Virtualized, tc.virtualized)
			}
			if e.Virtualized() != tc.virtualized {
				t.Errorf("Virtualized() = %v, want %v", e.Virtualized(), tc.virtualized)
			}
			if e.OCIRuntime() != tc.ociRuntime {
				t.Errorf("OCIRuntime() = %q, want %q", e.OCIRuntime(), tc.ociRuntime)
			}
		})
	}
}
