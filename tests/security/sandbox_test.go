package security

// Guarantee 8: a repo-committed .cloop/sandbox.yaml can make a run more
// confined and can never make it less.
//
// This is the newest untrusted input in cloop and the one with the least
// friction in front of it. A grant is issued by an operator; a config change is
// made on the hub. A sandbox spec arrives by `git pull` — anyone who can open a
// pull request can propose one, and on a multi-tenant hub the person who merges
// it is not the person whose infrastructure executes it. The file describes the
// *environment* a workload runs in, which is precisely the set of knobs an
// attacker would want.
//
// So the property is one-directional and stated as such: for every spec the
// parser accepts, the resulting run must be at most as permissive as the same
// run without a spec. The tests below drive the real parser and the real argv
// builder, not reimplementations, and need no container runtime.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/sandbox"
)

// applySandboxSpec parses src and folds it into a Spec, as the control plane
// does. grantsHeld decides whether the project holds every egress grant the
// spec names.
func applySandboxSpec(t *testing.T, src string, workDir string, grantsHeld bool) (executor.Spec, error) {
	t.Helper()
	parsed, _, err := sandbox.Parse([]byte(src))
	if err != nil {
		return executor.Spec{}, err
	}
	res := &sandbox.Resolved{Spec: parsed, Hash: parsed.Hash(), Source: sandbox.FileName}
	spec := executor.Spec{WorkDir: workDir, Argv: []string{"/usr/local/bin/cloop", "run"}}
	return spec, res.ApplyTo(&spec, workDir, grantChecker(grantsHeld))
}

type grantChecker bool

func (g grantChecker) HasEgressGrant(string, string) bool { return bool(g) }

// TestSandboxSpecCannotWidenTheNetwork: there is no field that adds egress.
// Omitting capabilities.network removes it; naming a grant asserts one the
// project already holds and leaves the operator's network exactly as it was.
func TestSandboxSpecCannotWidenTheNetwork(t *testing.T) {
	dir := t.TempDir()

	t.Run("no grant named removes the network", func(t *testing.T) {
		// The executor has a network. The spec must still end up with none.
		spec, err := applySandboxSpec(t, "image: alpine:3.20\n", dir, true)
		if err != nil {
			t.Fatal(err)
		}
		if !spec.DisableNetwork {
			t.Fatal("a spec naming no egress grant left the network on")
		}
		argv := mustAuditArgv(t, container.Options{
			Network:       container.NetworkBridge,
			AllowRootUser: true,
		}, dir, spec)
		if !argvHasFlagValue(argv, "--network", container.NetworkNone) {
			t.Fatalf("argv does not confine the network: %v", argv)
		}
	})

	t.Run("a held grant cannot exceed the executor", func(t *testing.T) {
		// Even with the grant, a --network=none executor stays confined.
		// Requirements.RequireNetworkEgress refuses this at placement; here the
		// point is that the driver would not widen it even if it were reached.
		spec, err := applySandboxSpec(t, "capabilities:\n  network: ci\n", dir, true)
		if err != nil {
			t.Fatal(err)
		}
		argv := mustAuditArgv(t, container.Options{
			Network:       container.NetworkNone,
			AllowRootUser: true,
		}, dir, spec)
		if !argvHasFlagValue(argv, "--network", container.NetworkNone) {
			t.Fatalf("a sandbox spec widened a confined executor: %v", argv)
		}
	})

	t.Run("an unheld grant refuses the run", func(t *testing.T) {
		_, err := applySandboxSpec(t, "capabilities:\n  network: ci\n", dir, false)
		var denied *sandbox.GrantDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("ApplyTo = %v, want *GrantDeniedError — a spec must not grant itself egress", err)
		}
	})
}

// TestSandboxSpecCannotEscapeTheWorkspace: mount sources are workspace-relative
// and nothing else. A spec that could name a host path would turn "merge this
// PR" into "read the control plane's /etc/shadow".
func TestSandboxSpecCannotEscapeTheWorkspace(t *testing.T) {
	escapes := map[string]string{
		"parent traversal":     "mounts:\n  - source: ../../etc\n    target: /host\n",
		"absolute source":      "mounts:\n  - source: /etc/shadow\n    target: /host\n",
		"mid-path traversal":   "mounts:\n  - source: a/../../etc\n    target: /host\n",
		"option injection":     "mounts:\n  - source: \"x:/etc:ro\"\n    target: /host\n",
		"target option inject": "mounts:\n  - source: x\n    target: \"/host:/etc\"\n",
		"root target":          "mounts:\n  - source: x\n    target: /\n",
		"newline in source":    "mounts:\n  - source: \"a\\nb\"\n    target: /host\n",
		"backslash source":     "mounts:\n  - source: 'a\\..\\..\\etc'\n    target: /host\n",
	}
	for name, src := range escapes {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sandbox.Parse([]byte(src)); err == nil {
				t.Fatalf("the parser accepted %q — the host filesystem would be "+
					"bind-mounted into a sandbox on a pull request's say-so", src)
			}
		})
	}

	// And the containment survives a symlink, which no syntactic check catches:
	// "cache" contains no "..", but resolving it lands outside the project.
	dir := mustEvalSymlinks(t, t.TempDir())
	outside := mustEvalSymlinks(t, t.TempDir())
	if err := os.Symlink(outside, dir+"/cache"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	spec, err := applySandboxSpec(t, "mounts:\n  - source: cache\n    target: /cache\n", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := container.AuditRunArgv(container.Options{AllowRootUser: true},
		container.AuditRuntime{Name: "docker"}, dir, spec); err == nil {
		t.Fatal("a symlink out of the workspace was accepted as a mount source")
	}
}

// TestSandboxSpecCannotSmuggleSecretValues: `env` is an allowlist of names. A
// value in the file would be a credential committed to a repo *and* a way to
// override one the hub injected.
func TestSandboxSpecCannotSmuggleSecretValues(t *testing.T) {
	for name, src := range map[string]string{
		"assignment":  "env:\n  - \"AWS_SECRET_ACCESS_KEY=AKIA...\"\n",
		"equals only": "env:\n  - \"=\"\n",
		"empty":       "env:\n  - \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sandbox.Parse([]byte(src)); err == nil {
				t.Fatalf("the parser accepted %q as an env entry", src)
			}
		})
	}

	// The allowlist can only ever remove. A name the project holds no value
	// for forwards nothing rather than conjuring one.
	parsed, _, err := sandbox.Parse([]byte("env:\n  - KEPT\n  - NEVER_GRANTED\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := &sandbox.Resolved{Spec: parsed, Hash: parsed.Hash()}
	got := res.FilterEnv([]string{"KEPT=1", "DROPPED=2"})
	if strings.Join(got, ",") != "KEPT=1" {
		t.Fatalf("FilterEnv = %v, want only the granted-and-allowlisted entry", got)
	}
}

// TestSandboxSpecCannotReachTheExtraArgsDenylist: the sandbox-escaping flags
// guarded in container.ValidateExtraArgs must have no path from a repo file.
//
// The check is on the *rendered argv* rather than on the schema, because the
// schema is what changes: a future field that happens to render into a flag
// would be reviewed as a feature and not as a sandbox escape.
func TestSandboxSpecCannotReachTheExtraArgsDenylist(t *testing.T) {
	dir := t.TempDir()
	// Every field the schema has, at once, with values chosen to be as
	// provocative as the validators allow.
	src := "image: alpine:3.20\n" +
		"setup:\n  - \"echo hi\"\n" +
		"env:\n  - PATH\n" +
		"resources:\n  cpu: 1\n  memory: 512m\n  pids: 16\n" +
		"capabilities:\n  git: true\n  network: ci\n" +
		"mounts:\n  - source: sub\n    target: /mnt/sub\n"

	spec, err := applySandboxSpec(t, src, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH must have a value or the driver refuses to silently drop it.
	spec.Env = []string{"PATH=/usr/bin"}

	argv := mustAuditArgv(t, container.Options{AllowRootUser: true}, dir, spec)
	joined := strings.Join(argv, " ")
	for _, f := range forbiddenFlagSubstrings {
		if strings.Contains(joined, f.frag) {
			t.Fatalf("a sandbox spec produced %s — %s\nargv: %s", f.frag, f.why, joined)
		}
	}

	// The confinement flags the driver always sets must survive a spec that
	// touched every other knob.
	for _, required := range []string{"--cap-drop", "--security-opt"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("a sandbox spec removed %s from the argv: %s", required, joined)
		}
	}
}

// TestSandboxSpecCannotWaiveTheProcessCap: `pids: -1` is the runtimes' spelling
// of "unlimited", and a fork bomb budget is not a decision a repo-committed
// file gets to make. The executor's own config still can.
func TestSandboxSpecCannotWaiveTheProcessCap(t *testing.T) {
	if _, _, err := sandbox.Parse([]byte("resources:\n  pids: -1\n")); err == nil {
		t.Fatal("the parser accepted pids: -1")
	}
	spec, err := applySandboxSpec(t, "resources:\n  pids: 32\n", t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if spec.ResourceLimits.PIDs != 32 {
		t.Fatalf("PIDs = %d, want 32", spec.ResourceLimits.PIDs)
	}
}

// TestSandboxSpecIsRefusedUnderStrictMode: the no-host-execution policy is
// checked on this path too. A project carrying a spec must not reach the host
// driver by a route that skips Registry.Resolve.
func TestSandboxSpecIsRefusedUnderStrictMode(t *testing.T) {
	restore := executor.SetAllowHostExecution(false)
	defer executor.SetAllowHostExecution(restore)

	parsed, _, err := sandbox.Parse([]byte("image: alpine:3.20\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := &sandbox.Resolved{Spec: parsed, Hash: parsed.Hash()}

	err = executor.CheckSandboxSupport(hostShapedExecutor{}, res.Requirements(), "/srv/app")
	var denied *executor.HostExecutionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("CheckSandboxSupport = %v, want *HostExecutionDeniedError", err)
	}
	if denied.Remediation() == "" {
		t.Fatal("the refusal carries no remediation")
	}
}

// TestSandboxBuildInheritsTheRunsNetwork: `setup:` runs repo-authored commands.
// If the build had unconditional egress it would be a way for a pull request to
// reach the Internet from a deployment whose configuration forbids it.
func TestSandboxBuildInheritsTheRunsNetwork(t *testing.T) {
	network, err := container.AuditBuildNetwork(
		container.Options{Network: container.NetworkBridge},
		executor.Spec{DisableNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if network != container.NetworkNone {
		t.Fatalf("a setup: build ran with network %q while its run had none", network)
	}

	network, err = container.AuditBuildNetwork(
		container.Options{Network: container.NetworkNone},
		executor.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if network != container.NetworkNone {
		t.Fatalf("a setup: build ran with network %q on a confined executor", network)
	}
}

// --- helpers ------------------------------------------------------------

func mustAuditArgv(t *testing.T, opts container.Options, workDir string, spec executor.Spec) []string {
	t.Helper()
	argv, err := container.AuditRunArgv(opts, container.AuditRuntime{Name: "docker"}, workDir, spec)
	if err != nil {
		t.Fatalf("AuditRunArgv: %v", err)
	}
	return argv
}

func argvHasFlagValue(argv []string, flag, value string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && argv[i+1] == value {
			return true
		}
		if a == flag+"="+value {
			return true
		}
	}
	return false
}

func mustEvalSymlinks(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return dir
	}
	return resolved
}

// hostShapedExecutor stands in for the localprocess driver: no isolation and
// none of the sandbox capabilities.
type hostShapedExecutor struct{ executor.Executor }

func (hostShapedExecutor) ID() string   { return "host" }
func (hostShapedExecutor) Kind() string { return executor.KindLocalProcess }
func (hostShapedExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationNone, NetworkEgress: true}
}
