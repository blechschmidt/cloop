package cmd

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Task 20370: `cloop require-committed` sets "done means committed" without
// starting a run, and `cloop status` shows it.
func TestRequireCommittedCommandAndStatus(t *testing.T) {
	dir := t.TempDir()
	if _, err := state.Init(dir, "goal", 0); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	run := func(args ...string) string {
		t.Helper()
		out, err := captureStdout(t, func() error { return requireCommittedCmd.RunE(requireCommittedCmd, args) })
		if err != nil {
			t.Fatalf("require-committed %v: %v", args, err)
		}
		return out
	}
	status := func() string {
		t.Helper()
		out, err := captureStdout(t, func() error { return statusCmd.RunE(statusCmd, nil) })
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		return out
	}
	policy := func() *pm.CommitPolicy {
		t.Helper()
		s, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s.CommitPolicy
	}

	if out := run(); !strings.Contains(out, "Done means committed: off") {
		t.Errorf("a new project shows:\n%s", out)
	}
	if strings.Contains(status(), "Done:") {
		t.Error("status shows the setting before anyone set it")
	}

	if out := run("pushed"); !strings.Contains(out, "on, and pushed") {
		t.Errorf("after pushed:\n%s", out)
	}
	if p := policy(); !p.RequiresPush() {
		t.Fatalf("stored policy = %+v", p)
	}
	if out := status(); !strings.Contains(out, "Done:     only once committed and pushed") {
		t.Errorf("status does not show it:\n%s", out)
	}

	run("off")
	if p := policy(); p.Active() || !p.Pushed {
		t.Errorf("off = %+v, want off with pushed remembered", p)
	}
	if out := status(); !strings.Contains(out, "on the agent's word") {
		t.Errorf("status after off:\n%s", out)
	}

	if _, err := captureStdout(t, func() error { return requireCommittedCmd.RunE(requireCommittedCmd, []string{"always"}) }); err == nil {
		t.Error("an unknown value was accepted")
	}
}
