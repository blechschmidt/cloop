package e2e_test

// `cloop run --pm` and `cloop init --pm` on the real binary (Task 20491).
//
// --pm once switched on planning. It was removed in May 2026, when planning
// became how every run works, but the dashboard's New Project dialog,
// `cloop watch --auto-run`, `cloop serve`'s /run/start, voice commands, the
// example recipe and over a hundred help lines kept passing it or telling
// people to, and each of them stopped at "unknown flag: --pm". The flag is
// accepted again, does nothing, and says so once.

import (
	"strings"
	"testing"
)

func TestRemovedPMFlagIsAcceptedAgain(t *testing.T) {
	dir := newWorkDir(t)
	const notice = "Flag --pm has been deprecated"

	out := mustRun(t, dir, "init", "--provider", "mock", "--skip-clarify", "--pm", "Write a greeting")
	assertNotContains(t, out, "unknown flag")
	if n := countOccurrences(out, notice); n != 1 {
		t.Errorf("cloop init --pm should say once that --pm is deprecated, said it %d times:\n%s", n, out)
	}

	mustRun(t, dir, "task", "add", "Write the greeting", "--no-ai", "--auto")

	// The mock provider answers TASK_DONE, so the run finishes its one task.
	out = mustRun(t, dir, "run", "--pm")
	assertNotContains(t, out, "unknown flag")
	if n := countOccurrences(out, notice); n != 1 {
		t.Errorf("cloop run --pm should say once that --pm is deprecated, said it %d times:\n%s", n, out)
	}
	assertContains(t, out, "Task 1 complete")

	// Accepted, not advertised: the flag list in help does not offer it.
	for _, cmd := range []string{"run", "init"} {
		for _, line := range strings.Split(mustRun(t, dir, cmd, "--help"), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "--pm") {
				t.Errorf("cloop %s --help lists the deprecated flag: %q", cmd, line)
			}
		}
	}
}
