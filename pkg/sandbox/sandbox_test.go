package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestParse_Accepts(t *testing.T) {
	const src = `
image: ghcr.io/example/py:3.12
setup:
  - pip install -r requirements.txt
  - apt-get update && apt-get install -y ripgrep
env:
  - ANTHROPIC_API_KEY
  - GITHUB_TOKEN
resources:
  cpu: 2
  memory: 4g
  pids: 512
capabilities:
  git: true
  network: ci-egress
mounts:
  - source: .cache/pip
    target: /home/agent/.cache/pip
  - source: vendor
    target: /opt/vendor
    read_only: true
`
	spec, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if spec.Image != "ghcr.io/example/py:3.12" {
		t.Errorf("Image = %q", spec.Image)
	}
	if len(spec.Setup) != 2 {
		t.Errorf("Setup = %v", spec.Setup)
	}
	if len(spec.Env) != 2 || spec.Env[0] != "ANTHROPIC_API_KEY" {
		t.Errorf("Env = %v", spec.Env)
	}
	if spec.Resources.CPU != 2 || spec.Resources.Memory != "4g" || spec.Resources.PIDs != 512 {
		t.Errorf("Resources = %+v", spec.Resources)
	}
	if !spec.Capabilities.Git || spec.Capabilities.Network != "ci-egress" {
		t.Errorf("Capabilities = %+v", spec.Capabilities)
	}
	if len(spec.Mounts) != 2 || !spec.Mounts[1].ReadOnly {
		t.Errorf("Mounts = %+v", spec.Mounts)
	}
}

// TestParse_ClosedSchema: an unknown key is a typo or a probe, and both are
// better as an error than as a field that silently did nothing.
func TestParse_ClosedSchema(t *testing.T) {
	for _, src := range []string{
		"resource:\n  cpu: 2\n",          // singular typo
		"image: a\nprivileged: true\n",   // a field we do not have
		"capabilities:\n  root: true\n",  // nested unknown
		"resources:\n  memory_mb: 512\n", // plausible-but-wrong spelling
	} {
		if _, _, err := Parse([]byte(src)); err == nil {
			t.Errorf("Parse(%q) = nil, want an error for the unknown field", src)
		}
	}
}

func TestParse_EmptyIsValid(t *testing.T) {
	for _, src := range []string{"", "\n", "# only a comment\n"} {
		spec, _, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if !spec.IsZero() {
			t.Errorf("Parse(%q) is not zero: %+v", src, spec)
		}
	}
}

func TestParse_RejectsSecondDocument(t *testing.T) {
	_, _, err := Parse([]byte("image: a\n---\nimage: b\n"))
	if err == nil {
		t.Fatal("a second document must be an error, not silently ignored")
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]struct{ src, want string }{
		"env value smuggled":  {"env:\n  - \"TOKEN=hunter2\"\n", "not [A-Za-z_]"},
		"env leading digit":   {"env:\n  - 1PATH\n", "not [A-Za-z_]"},
		"env empty":           {"env:\n  - \"\"\n", "is empty"},
		"setup multiline":     {"setup:\n  - \"a\\nb\"\n", "multiple lines"},
		"setup blank":         {"setup:\n  - \"   \"\n", "blank"},
		"negative cpu":        {"resources:\n  cpu: -1\n", "must be >= 0"},
		"unparsable memory":   {"resources:\n  memory: lots\n", "resources.memory"},
		"tiny memory":         {"resources:\n  memory: 8m\n", "below the minimum"},
		"unlimited pids":      {"resources:\n  pids: -1\n", "cannot waive"},
		"absolute mount src":  {"mounts:\n  - source: /etc\n    target: /x\n", "is absolute"},
		"dotdot mount src":    {"mounts:\n  - source: ../../etc\n    target: /x\n", `".." element`},
		"relative mount tgt":  {"mounts:\n  - source: a\n    target: x\n", "is relative"},
		"root mount tgt":      {"mounts:\n  - source: a\n    target: /\n", "shadow the sandbox root"},
		"colon in mount":      {"mounts:\n  - source: \"a:ro\"\n    target: /x\n", "colon"},
		"duplicate target":    {"mounts:\n  - source: a\n    target: /x\n  - source: b\n    target: /x\n", "claimed twice"},
		"grant name spaces":   {"capabilities:\n  network: \"a b\"\n", "grant name"},
		"image with metachar": {"image: \"a;rm -rf /\"\n", "image"},
		"image leading dash":  {"image: \"-v\"\n", "image"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("Parse(%q) = nil, want an error", tc.src)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("error %q does not wrap ErrInvalidSpec — it would render as a 500", err)
			}
		})
	}
}

// TestParse_ClampsRatherThanRejects: an out-of-range number is a wish, not an
// attack. Honour it at the ceiling and say so.
func TestParse_ClampsRatherThanRejects(t *testing.T) {
	spec, warnings, err := Parse([]byte("resources:\n  cpu: 999999\n  memory: 900000g\n  pids: 999999999\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Resources.CPU != config.ContainerCPUsUpper {
		t.Errorf("CPU = %v, want the clamp %v", spec.Resources.CPU, config.ContainerCPUsUpper)
	}
	if spec.Resources.PIDs != config.ContainerPIDsUpper {
		t.Errorf("PIDs = %d, want the clamp %d", spec.Resources.PIDs, config.ContainerPIDsUpper)
	}
	mb, err := config.ParseMemoryMB(spec.Resources.Memory)
	if err != nil || mb != config.ContainerMemoryMBUpper {
		t.Errorf("Memory = %q (%d MB, err %v), want the clamp %d MB",
			spec.Resources.Memory, mb, err, config.ContainerMemoryMBUpper)
	}
	if len(warnings) != 3 {
		t.Errorf("want a warning per clamp, got %d: %v", len(warnings), warnings)
	}
}

func TestParse_DeduplicatesEnv(t *testing.T) {
	spec, _, err := Parse([]byte("env:\n  - A\n  - A\n  - B\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(spec.Env) != 2 {
		t.Errorf("Env = %v, want the duplicate collapsed", spec.Env)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := Load(dir); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load on a project with no spec = %v, want ErrNotFound", err)
	}

	writeSpec(t, dir, "image: alpine:3.20\n")
	spec, _, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if spec.Image != "alpine:3.20" {
		t.Errorf("Image = %q", spec.Image)
	}
}

// TestLoad_BoundsFileSize: the file is repo-supplied, so an unbounded read is
// a memory-exhaustion primitive reachable by opening a pull request.
func TestLoad_BoundsFileSize(t *testing.T) {
	dir := t.TempDir()
	writeSpec(t, dir, "# "+strings.Repeat("x", maxFileBytes+1)+"\n")
	if _, _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("Load on an oversized spec = %v, want a size error", err)
	}
}

// TestHash_StableAcrossFormatting is what makes the hash usable as a build
// cache key: two files that mean the same thing must not build two images.
func TestHash_StableAcrossFormatting(t *testing.T) {
	a, _, err := Parse([]byte("image: x:1\nenv:\n  - B\n  - A\nresources:\n  cpu: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Parse([]byte("resources:\n  cpu: 1.0\nenv: [A, B]\nimage: \"x:1\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("hashes differ for equivalent specs:\n%s\n%s", a.Hash(), b.Hash())
	}
}

func TestHash_ChangesWithContent(t *testing.T) {
	a, _, _ := Parse([]byte("image: x:1\n"))
	b, _, _ := Parse([]byte("image: x:2\n"))
	if a.Hash() == b.Hash() {
		t.Fatal("different images hash the same")
	}
}

// TestSetupHash_IgnoresRunTimeFields: a change to env or resources applies per
// run and must not invalidate an already-built image.
func TestSetupHash_IgnoresRunTimeFields(t *testing.T) {
	a, _, _ := Parse([]byte("image: x:1\nsetup: [\"echo hi\"]\nenv: [A]\n"))
	b, _, _ := Parse([]byte("image: x:1\nsetup: [\"echo hi\"]\nenv: [B]\nresources:\n  cpu: 4\n"))
	if a.SetupHash() != b.SetupHash() {
		t.Fatal("setup hash changed for an edit that does not affect the image")
	}
	if a.Hash() == b.Hash() {
		t.Fatal("spec hash must still distinguish them")
	}
	c, _, _ := Parse([]byte("image: x:1\nsetup: [\"echo bye\"]\n"))
	if a.SetupHash() == c.SetupHash() {
		t.Fatal("setup hash did not change when the commands did")
	}
}

// --- requirements -------------------------------------------------------

func TestRequirements(t *testing.T) {
	cases := map[string]struct {
		src    string
		verify func(*testing.T, executor.Requirements)
	}{
		"image demands an override-capable node": {
			"image: x:1\n",
			func(t *testing.T, r executor.Requirements) {
				if !r.RequireImageOverride {
					t.Error("RequireImageOverride not set")
				}
			},
		},
		"setup demands a builder": {
			"setup: [\"echo hi\"]\n",
			func(t *testing.T, r executor.Requirements) {
				if !r.RequireSandboxBuild {
					t.Error("RequireSandboxBuild not set")
				}
			},
		},
		"resources demand enforcement": {
			"resources:\n  cpu: 1\n",
			func(t *testing.T, r executor.Requirements) {
				if !r.RequireResourceLimits {
					t.Error("RequireResourceLimits not set — the limit would be silently ignored")
				}
			},
		},
		"network capability demands egress": {
			"capabilities:\n  network: g\n",
			func(t *testing.T, r executor.Requirements) {
				if !r.RequireNetworkEgress {
					t.Error("RequireNetworkEgress not set")
				}
			},
		},
		"git capability demands the harness": {
			"capabilities:\n  git: true\n",
			func(t *testing.T, r executor.Requirements) {
				if len(r.Harnesses) != 1 || r.Harnesses[0] != "git" {
					t.Errorf("Harnesses = %v", r.Harnesses)
				}
			},
		},
		"no network capability demands nothing": {
			"image: x:1\n",
			func(t *testing.T, r executor.Requirements) {
				if r.RequireNetworkEgress {
					t.Error("a spec that asks for no network must not require egress")
				}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec, _, err := Parse([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			tc.verify(t, (&Resolved{Spec: spec, Hash: spec.Hash()}).Requirements())
		})
	}
}

// --- apply --------------------------------------------------------------

// allowAll is a GrantChecker that says yes, for tests exercising the path
// after the grant check.
type allowAll struct{}

func (allowAll) HasEgressGrant(string, string) bool { return true }

// TestApplyTo_NarrowsNetworkWithoutAGrant is the core one-directional
// guarantee: a spec may take the network away and can never add one.
func TestApplyTo_NarrowsNetworkWithoutAGrant(t *testing.T) {
	res := mustResolve(t, "image: x:1\n")
	var spec executor.Spec
	if err := res.ApplyTo(&spec, "/p", allowAll{}); err != nil {
		t.Fatal(err)
	}
	if !spec.DisableNetwork {
		t.Fatal("a spec with no capabilities.network must disable the network")
	}
}

func TestApplyTo_GrantHeldLeavesNetworkAlone(t *testing.T) {
	res := mustResolve(t, "capabilities:\n  network: ci\n")
	var spec executor.Spec
	if err := res.ApplyTo(&spec, "/p", allowAll{}); err != nil {
		t.Fatal(err)
	}
	if spec.DisableNetwork {
		t.Fatal("a held grant must leave the executor's own network in place")
	}
}

// TestApplyTo_GrantNotHeld: the failure must be typed and carry a remediation,
// because the person who wrote the YAML cannot issue themselves a grant.
func TestApplyTo_GrantNotHeld(t *testing.T) {
	res := mustResolve(t, "capabilities:\n  network: ci\n")
	for name, grants := range map[string]GrantChecker{
		"nil checker":  nil,
		"denies":       denyAll{},
		"wrong tenant": denyAll{},
	} {
		t.Run(name, func(t *testing.T) {
			var spec executor.Spec
			err := res.ApplyTo(&spec, "/p", grants)
			var denied *GrantDeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("ApplyTo = %v, want *GrantDeniedError", err)
			}
			if denied.GrantID != "ci" || denied.Remediation() == "" {
				t.Fatalf("unhelpful error: %+v", denied)
			}
		})
	}
}

type denyAll struct{}

func (denyAll) HasEgressGrant(string, string) bool { return false }

func TestApplyTo_Resources(t *testing.T) {
	res := mustResolve(t, "resources:\n  cpu: 1.5\n  memory: 2g\n  pids: 256\n")
	var spec executor.Spec
	if err := res.ApplyTo(&spec, "/p", allowAll{}); err != nil {
		t.Fatal(err)
	}
	if spec.ResourceLimits.CPUMillis != 1500 {
		t.Errorf("CPUMillis = %d, want 1500", spec.ResourceLimits.CPUMillis)
	}
	if spec.ResourceLimits.MemoryMB != 2048 {
		t.Errorf("MemoryMB = %d, want 2048", spec.ResourceLimits.MemoryMB)
	}
	if spec.ResourceLimits.PIDs != 256 {
		t.Errorf("PIDs = %d, want 256", spec.ResourceLimits.PIDs)
	}
	if spec.SandboxHash == "" {
		t.Error("SandboxHash not stamped onto the spec")
	}
}

// TestApplyTo_ProducesAValidSpec closes the loop: whatever the parser accepts
// must survive executor.Spec.Validate, or the refusal happens at the driver
// with a worse message.
func TestApplyTo_ProducesAValidSpec(t *testing.T) {
	res := mustResolve(t, `
image: alpine:3.20
setup: ["echo hi"]
resources:
  cpu: 1
  memory: 512m
mounts:
  - source: .cache
    target: /cache
`)
	spec := executor.Spec{WorkDir: "/p", Argv: []string{"cloop", "run"}}
	if err := res.ApplyTo(&spec, "/p", allowAll{}); err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("a spec the parser accepted failed executor validation: %v", err)
	}
}

// --- env filtering ------------------------------------------------------

func TestFilterEnv(t *testing.T) {
	env := []string{"A=1", "B=2", "C=3", "malformed"}

	t.Run("allowlist narrows", func(t *testing.T) {
		got := mustResolve(t, "env: [A, C]\n").FilterEnv(env)
		if strings.Join(got, ",") != "A=1,C=3" {
			t.Fatalf("FilterEnv = %v", got)
		}
	})

	// An absent env: key is "no opinion", not "forward nothing". Reading it as
	// the latter would strip the API key from every project that adds a
	// sandbox.yaml purely to pin an image.
	t.Run("absent key passes everything through", func(t *testing.T) {
		got := mustResolve(t, "image: x:1\n").FilterEnv(env)
		if len(got) != len(env) {
			t.Fatalf("FilterEnv = %v, want the input untouched", got)
		}
	})

	// The spec expresses a wish, not an entitlement: a name the project holds
	// no value for forwards nothing rather than conjuring one.
	t.Run("cannot introduce a variable", func(t *testing.T) {
		got := mustResolve(t, "env: [SECRET_THE_PROJECT_LACKS]\n").FilterEnv(env)
		if len(got) != 0 {
			t.Fatalf("FilterEnv = %v, want empty", got)
		}
	})

	t.Run("no spec is a no-op", func(t *testing.T) {
		if got := (&Resolved{}).FilterEnv(env); len(got) != len(env) {
			t.Fatalf("FilterEnv = %v", got)
		}
	})
}

// --- resolve ------------------------------------------------------------

func TestResolve_MissingIsNotAnError(t *testing.T) {
	res, err := Resolve(t.TempDir())
	if err != nil {
		t.Fatalf("Resolve on a project with no spec: %v", err)
	}
	if res.Present() {
		t.Fatal("Present() is true for a project with no spec")
	}
	// The no-spec path must apply nothing and require nothing.
	spec := executor.Spec{Image: "operator-choice"}
	if err := res.ApplyTo(&spec, "/p", nil); err != nil {
		t.Fatal(err)
	}
	if spec.Image != "operator-choice" || spec.DisableNetwork {
		t.Fatalf("a project with no spec had its run modified: %+v", spec)
	}
	if req := res.Requirements(); reflect.DeepEqual(req, executor.Requirements{}) == false {
		t.Fatalf("a project with no spec produced placement requirements: %+v", req)
	}
}

// TestResolve_InvalidDoesNotDegradeToDefaults: silently ignoring a broken spec
// would run the task in an environment nobody described, and the failure would
// look like the project's own bug.
func TestResolve_InvalidDoesNotDegradeToDefaults(t *testing.T) {
	dir := t.TempDir()
	writeSpec(t, dir, "resources:\n  cpu: -5\n")
	res, err := Resolve(dir)
	if err == nil {
		t.Fatal("Resolve on an invalid spec = nil, want an error")
	}
	if res.Present() {
		t.Fatal("an invalid spec must not be reported as present")
	}
}

// TestResolve_EmptySpecIsNotPresent: a file with only comments asks for
// nothing, and must not force placement constraints on the project.
func TestResolve_EmptySpecIsNotPresent(t *testing.T) {
	dir := t.TempDir()
	writeSpec(t, dir, "# nothing yet\n")
	res, err := Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Present() {
		t.Fatal("an empty spec must not be Present")
	}
}

func mustResolve(t *testing.T, src string) *Resolved {
	t.Helper()
	spec, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return &Resolved{Spec: spec, Hash: spec.Hash(), Warnings: warnings, Source: FileName}
}

func writeSpec(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, ".cloop", "sandbox.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
