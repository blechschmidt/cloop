package ciscripts_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowJob returns the text of one job of a workflow: from its two-space
// key to the next one.
func workflowJob(t *testing.T, workflow, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", workflow))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	keys := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\s*$`).FindAllStringIndex(wf, -1)
	for i, k := range keys {
		if strings.TrimSpace(wf[k[0]:k[1]]) == name+":" {
			end := len(wf)
			if i+1 < len(keys) {
				end = keys[i+1][0]
			}
			return wf[k[0]:end]
		}
	}
	t.Fatalf("%s has no %s job", workflow, name)
	return ""
}

// rehearsalTests are the scenarios a run of the upgrade rehearsal must have
// passed by name: tests/upgrade skips without the network, and a skip is a
// pass to go test.
var rehearsalTests = []string{"TestRollingUpgradeFromTheLatestRelease", "TestRollbackToTheReleaseAfterMainMigrated"}

// TestCIRehearsesTheRollingUpgradeOnEveryPush (Task 20452): CI runs the
// upgrade rehearsal against a build stamped with its place on main, with the
// release verified by cosign, fails a skip, and keeps the suite within its
// wall-time budget.
func TestCIRehearsesTheRollingUpgradeOnEveryPush(t *testing.T) {
	job := workflowJob(t, "ci.yml", "upgrade-rehearsal")
	for _, want := range []string{
		"fetch-depth: 0",
		"sigstore/cosign-installer@",
		"CLOOP_UPGRADE_E2E: \"1\"",
		"CLOOP_UPGRADE_MAIN_BIN:",
		"-X $pkg.Sequence=",
		"go test ./tests/upgrade/",
		"scripts/test-budget.py --timeout",
		"timeout-minutes:",
		"bash scripts/ci-step.sh --why",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("the upgrade-rehearsal job does not contain %q", want)
		}
	}
	for _, name := range rehearsalTests {
		if !strings.Contains(job, name) {
			t.Errorf("the upgrade-rehearsal job does not require %s to have passed by name", name)
		}
	}
}

// TestNoReleaseIsPublishedWhileTheRehearsalIsRed (Task 20452): the release
// workflow rehearses the upgrade from the release before against the binary it
// is about to publish, and does so before anything is signed or uploaded.
func TestNoReleaseIsPublishedWhileTheRehearsalIsRed(t *testing.T) {
	job := workflowJob(t, "release.yml", "release")
	rehearse := strings.Index(job, "go test ./tests/upgrade/")
	if rehearse < 0 {
		t.Fatal("release.yml does not run the upgrade rehearsal")
	}
	for _, later := range []string{"cosign sign-blob", "gh release create", "gh release upload"} {
		if i := strings.Index(job, later); i >= 0 && i < rehearse {
			t.Errorf("release.yml runs %q before the upgrade rehearsal", later)
		}
	}
	step := job[max(0, rehearse-2000):]
	for _, want := range append([]string{"CLOOP_UPGRADE_MAIN_BIN: /tmp/verify/cloop"}, rehearsalTests...) {
		if !strings.Contains(step, want) {
			t.Errorf("release.yml's rehearsal step does not contain %q", want)
		}
	}
}
