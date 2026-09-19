package container

// The smoke test behind `cloop executor test` is the only check that proves a
// sandbox can actually run something — every preflight finding before it is
// inference from the host. So it has to work on the hosts operators really
// have, and a hub installed as a system service runs as root.
//
// TestIntegration_SmokeTest cannot cover this: it sets AllowRootUser so the
// suite can use a root-owned t.TempDir(), which waives the very policy that
// makes the case interesting. This file runs the same call with the policy on.

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestIntegration_SmokeTestUnderRootControlPlane is the regression.
//
// SmokeTest makes its own throwaway workdir when given none, and a rootful run
// takes the sandbox UID from that directory's owner. Created by a root control
// plane it is root-owned, so the UID came out 0, the driver refused it, and the
// refusal talked about chowning "the project directory" — which the operator
// never named and which does not exist for this call. That made the command
// unusable on precisely the deployment it is most needed on.
func TestIntegration_SmokeTestUnderRootControlPlane(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("this test is about what a root control plane does; not root")
	}
	// The control plane's binary is dynamically linked against glibc, so the
	// smoke test needs a glibc image rather than the musl-based default.
	ex := newTestExecutor(t, glibcTestImage, func(o *Options) {
		// The point of the test: keep the non-root policy that production
		// enforces, rather than waiving it as the sibling integration test
		// does.
		o.AllowRootUser = false
	})

	result, err := ex.SmokeTest(context.Background(), "")
	if err != nil {
		if strings.Contains(err.Error(), "uid 0") {
			t.Fatalf("the smoke test refused its own workdir as root-owned: %v", err)
		}
		t.Fatalf("SmokeTest: %v (output: %s)", err, result.Output)
	}
	if result.ExitCode != 0 {
		t.Fatalf("smoke test exit code = %d, want 0 (output: %s)", result.ExitCode, result.Output)
	}
	if result.Output == "" {
		t.Error("the smoke test produced no output at all")
	}
}

// TestSmokeTestWorkdirIsNotRootOwned checks the mechanism directly, without a
// container runtime, so the reason the test above passes is pinned down rather
// than inferred from a green run.
func TestSmokeTestWorkdirIsNotRootOwned(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership handover only applies when the control plane is root")
	}
	dir := t.TempDir()
	// Reproduce what SmokeTest does to a directory it owns.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, smokeTestUID, smokeTestGID); err != nil {
		t.Fatalf("chown to the unprivileged smoke-test owner: %v", err)
	}

	ex := &Executor{}
	user := ex.sandboxUser(dir)
	if user == "" {
		t.Fatal("sandboxUser returned no user for a directory it can stat")
	}
	if strings.HasPrefix(user, "0:") {
		t.Fatalf("sandbox user = %q, which the driver refuses", user)
	}
	if err := validateNonRootUser(user); err != nil {
		t.Fatalf("the smoke-test workdir owner must satisfy the non-root policy: %v", err)
	}
}
