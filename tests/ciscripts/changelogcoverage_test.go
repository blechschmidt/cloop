package ciscripts_test

// changelogcoverage_test.go runs scripts/changelog-coverage.py (Task 20431),
// CI's check that no feature or fix reaches main without the CHANGELOG.md entry
// the release — and the security-fix age gate — reads, against histories it
// builds itself: tags, merges, and changelogs edited before and after a release.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// history is a git repository the test writes commits and tags into.
type history struct {
	t   *testing.T
	dir string
	n   int
}

func newHistory(t *testing.T) *history {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	h := &history{t: t, dir: t.TempDir()}
	h.git("init", "-q", "-b", "main")
	return h
}

func (h *history) git(args ...string) string {
	h.t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=ci", "-c", "user.email=ci@example.com",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
	cmd.Dir = h.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit commits a change under subject and returns its sha. A non-empty
// changelog becomes CHANGELOG.md in the same commit.
func (h *history) commit(subject, changelog string) string {
	h.t.Helper()
	h.n++
	// A file of its own, so that branches never conflict when merged.
	if err := os.WriteFile(filepath.Join(h.dir, fmt.Sprintf("work-%d.txt", h.n)), []byte(subject), 0o644); err != nil {
		h.t.Fatal(err)
	}
	if changelog != "" {
		if err := os.WriteFile(filepath.Join(h.dir, "CHANGELOG.md"), []byte(changelog), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	h.git("add", "-A")
	h.git("commit", "-q", "-m", subject)
	return h.git("rev-parse", "HEAD")
}

// check runs the script against the repository.
func (h *history) check(args ...string) (string, int) {
	h.t.Helper()
	out, errOut, code := run(h.t, python(h.t), append([]string{"-B", "scripts/changelog-coverage.py",
		"--repo", h.dir}, args...)...)
	return out + errOut, code
}

func wantOutput(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("the output does not say %q:\n%s", w, out)
		}
	}
}

// released is a changelog the v0.0.5 tag carries: its section names Task 1.
const released = "# Changelog\n\n## [Unreleased]\n\n## [0.0.5] - 2026-10-12\n\n### Security\n\n" +
	"- **An old fix.** Released already (Task 1).\n"

// withUnreleased puts entry under [Unreleased].
func withUnreleased(changelog, entry string) string {
	return strings.Replace(changelog, "## [Unreleased]\n", "## [Unreleased]\n\n"+entry, 1)
}

// releasedHistory is a repository at the v0.0.5 tag.
func releasedHistory(t *testing.T) *history {
	t.Helper()
	h := newHistory(t)
	h.commit("feat(hub): the first feature (Task 1)", released)
	h.git("tag", "-a", "v0.0.5", "-m", "v0.0.5")
	return h
}

// TestChangelogCoverageFailsForATaskWithNoEntry: a fix after the release that
// names a task no changelog line names fails the check, naming the commit and
// the task; docs, test, ci, release and refactor commits are exempt; and once
// the entry is written, it passes.
func TestChangelogCoverageFailsForATaskWithNoEntry(t *testing.T) {
	h := releasedHistory(t)
	fix := h.commit("fix(secrets): bind grants to their host (Task 2)", "")
	for _, exempt := range []string{"docs(secrets): say so (Task 3)", "test(secrets): pin it (Task 4)",
		"ci: gate it (Task 5)", "release: cut it (Task 6)", "refactor(secrets): tidy it (Task 7)"} {
		h.commit(exempt, "")
	}

	out, code := h.check()
	if code != 1 {
		t.Fatalf("exit %d, want 1 for a fix with no entry:\n%s", code, out)
	}
	wantOutput(t, out,
		"6 commit(s) since v0.0.5 (6 on the first-parent line), 1 of them feat, fix or perf, naming 1 task(s):",
		"MISSING  Task 2  ("+fix[:8]+")",
		"::error file=CHANGELOG.md,title=No changelog entry::"+fix[:8]+
			` "fix(secrets): bind grants to their host (Task 2)" names Task 2, which no line added to CHANGELOG.md `+
			"since v0.0.5 mentions.",
		"Add an entry under ## [Unreleased] in CHANGELOG.md")
	for _, task := range []string{"Task 3", "Task 4", "Task 5", "Task 6", "Task 7"} {
		if strings.Contains(out, task) {
			t.Errorf("an exempt commit's %s was checked:\n%s", task, out)
		}
	}

	// What the check reads is what is committed: an entry still in the
	// working tree does not count, and it says so.
	entry := withUnreleased(released,
		"### Security\n\n- **Grants are bound to their host.** A token went\n  wherever an origin pointed (Task 2).\n")
	if err := os.WriteFile(filepath.Join(h.dir, "CHANGELOG.md"), []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = h.check()
	if code != 1 || !strings.Contains(out, "note: CHANGELOG.md has changes HEAD does not hold") {
		t.Fatalf("an uncommitted entry: exit %d, want 1 with a note\n%s", code, out)
	}

	h.commit("docs: the changelog entry", entry)
	out, code = h.check()
	if code != 0 {
		t.Fatalf("exit %d, want 0 once the entry is written:\n%s", code, out)
	}
	wantOutput(t, out, "ok       Task 2  CHANGELOG.md:8  ("+fix[:8]+")",
		"Every task a feat, fix or perf commit since v0.0.5 names has an entry in CHANGELOG.md.")
}

// TestChangelogCoverageCountsOnlyLinesAddedToAnUnreleasedSection: the
// released section already naming the task does not count, and neither does a
// line added to it after the release; a line in the section of the release
// being cut does.
func TestChangelogCoverageCountsOnlyLinesAddedToAnUnreleasedSection(t *testing.T) {
	h := releasedHistory(t)
	h.commit("fix(hub): the first feature, fixed (Task 1)", "")
	if out, code := h.check(); code != 1 || !strings.Contains(out, "MISSING  Task 1") {
		t.Fatalf("an entry from before the tag counted: exit %d\n%s", code, out)
	}

	inReleased := strings.Replace(released, "(Task 1).\n", "(Task 1).\n- **Fixed again.** (Task 1).\n", 1)
	h.commit("docs: note it in the released section", inReleased)
	if out, code := h.check(); code != 1 || !strings.Contains(out, "MISSING  Task 1") {
		t.Fatalf("a line added to the released 0.0.5 section counted: exit %d\n%s", code, out)
	}

	cut := strings.Replace(inReleased, "## [Unreleased]\n", "## [Unreleased]\n\n## [0.0.6] - 2026-10-16\n\n"+
		"### Fixed\n\n- **The first feature works.** (Task 1).\n", 1)
	h.commit("release: v0.0.6", cut)
	if out, code := h.check(); code != 0 || !strings.Contains(out, "ok       Task 1  CHANGELOG.md:9") {
		t.Fatalf("an entry in the 0.0.6 section, the release being cut, did not count: exit %d\n%s", code, out)
	}

	// Once 0.0.6 is tagged, its section is released too.
	h.git("tag", "v0.0.6")
	h.commit("fix(hub): and again (Task 1)", "")
	if out, code := h.check(); code != 1 || !strings.Contains(out, "since v0.0.6") || !strings.Contains(out, "MISSING  Task 1") {
		t.Fatalf("after v0.0.6 its own section counted: exit %d\n%s", code, out)
	}
}

// TestChangelogCoverageReadsTaskLists: a subject naming two tasks needs both,
// and a changelog list of tasks may wrap onto the next line.
func TestChangelogCoverageReadsTaskLists(t *testing.T) {
	h := releasedHistory(t)
	h.commit("feat(ui): two things at once (Tasks 10, 11)", "")
	h.commit("perf(ui): faster (Task 12)", "")
	h.commit("fix(ui): and more (Task 13)", "")
	h.commit("docs: the entries", withUnreleased(released,
		"### Added\n\n- **Things.** They arrived (Tasks 10,\n  12 and 14).\n"))

	out, code := h.check()
	if code != 1 {
		t.Fatalf("exit %d, want 1 for Tasks 11 and 13:\n%s", code, out)
	}
	wantOutput(t, out, "ok       Task 10  CHANGELOG.md:7", "ok       Task 12  CHANGELOG.md:8",
		"MISSING  Task 11", "MISSING  Task 13", "naming 4 task(s)")
}

// TestChangelogCoverageChecksWhatAMergeBringsIn: a fix on a merged branch is
// not on main's first-parent line, and is checked all the same — as it is for
// a pull request, which CI checks out as a merge.
func TestChangelogCoverageChecksWhatAMergeBringsIn(t *testing.T) {
	h := releasedHistory(t)
	h.git("checkout", "-q", "-b", "topic")
	fix := h.commit("fix(topic): a fix on a branch (Task 20)", "")
	h.git("checkout", "-q", "main")
	h.commit("docs: meanwhile on main", "")
	h.git("merge", "-q", "--no-ff", "topic", "-m", "Merge branch 'topic'")

	out, code := h.check()
	if code != 1 {
		t.Fatalf("exit %d, want 1 for the merged fix:\n%s", code, out)
	}
	wantOutput(t, out, "3 commit(s) since v0.0.5 (2 on the first-parent line)", "MISSING  Task 20  ("+fix[:8]+")")
}

// TestChangelogCoverageNeedsAnEntryFromAFixThatNamesNoTask: a feat, fix or
// perf commit naming no task must add a changelog line itself, whatever its
// subject's form.
func TestChangelogCoverageNeedsAnEntryFromAFixThatNamesNoTask(t *testing.T) {
	h := releasedHistory(t)
	bare := h.commit("fix: a typo in an error message", "")
	h.commit("feat(api)!: a breaking change", withUnreleased(released, "### Changed\n\n- **The API changed.**\n"))

	out, code := h.check()
	if code != 1 {
		t.Fatalf("exit %d, want 1 for the bare fix:\n%s", code, out)
	}
	wantOutput(t, out, "MISSING  no task  "+bare[:8]+" fix: a typo in an error message",
		"::error file=CHANGELOG.md,title=No changelog entry::"+bare[:8]+
			` "fix: a typo in an error message" is a feat, fix or perf commit that names no task and adds no line to CHANGELOG.md.`)
	if strings.Contains(out, "a breaking change") {
		t.Errorf("the commit that wrote its own entry was reported:\n%s", out)
	}
}

// TestChangelogCoveragePicksTheLatestReleaseTag: the highest release tag the
// checked commit contains — not a prerelease, a tag of another shape, or a
// release on a branch that was never merged.
func TestChangelogCoveragePicksTheLatestReleaseTag(t *testing.T) {
	h := newHistory(t)
	h.commit("feat: one (Task 1)", released)
	h.git("tag", "v0.0.4")
	h.commit("feat: two (Task 2)", "")
	h.git("tag", "v0.0.5-rc.1")
	h.commit("feat: three (Task 3)", withUnreleased(released, "- (Tasks 2, 3)\n"))
	h.git("tag", "-a", "v0.0.5", "-m", "v0.0.5")
	h.commit("ci: four", "")
	h.git("tag", "edge")
	h.git("tag", "t20328-presnap")
	h.git("checkout", "-q", "-b", "elsewhere")
	h.commit("feat: elsewhere (Task 9)", "")
	h.git("tag", "v0.0.9")
	h.git("checkout", "-q", "main")
	h.commit("fix: five (Task 5)", "")

	out, code := h.check()
	if code != 1 || !strings.Contains(out, "2 commit(s) since v0.0.5 ") || !strings.Contains(out, "MISSING  Task 5") {
		t.Fatalf("exit %d, want 1 checking the two commits since v0.0.5:\n%s", code, out)
	}
	if out, code := h.check("--since", "v0.0.4"); code != 1 || !strings.Contains(out, "since v0.0.4") {
		t.Errorf("--since v0.0.4: exit %d\n%s", code, out)
	}
	if out, code := h.check("--since", "edge"); code != 2 || !strings.Contains(out, "edge is not a release tag") {
		t.Errorf("--since edge: exit %d, want 2\n%s", code, out)
	}
}

// TestChangelogCoverageRefusesWhatItCannotCheck: a shallow clone has neither
// the commits nor the tag, and a history with no release has nothing to list
// the commits since.
func TestChangelogCoverageRefusesWhatItCannotCheck(t *testing.T) {
	h := releasedHistory(t)
	h.commit("fix: one (Task 2)", "")
	shallow := filepath.Join(t.TempDir(), "shallow")
	h.git("clone", "-q", "--depth", "1", "file://"+h.dir, shallow)
	out, errOut, code := run(t, python(t), "-B", "scripts/changelog-coverage.py", "--repo", shallow)
	if code != 2 || !strings.Contains(errOut, "shallow clone") {
		t.Errorf("a shallow clone: exit %d, want 2 naming it\n%s%s", code, out, errOut)
	}

	untagged := newHistory(t)
	untagged.commit("fix: one (Task 2)", released)
	if out, code := untagged.check(); code != 2 || !strings.Contains(out, "contains no release tag") {
		t.Errorf("no release tag: exit %d, want 2 saying so\n%s", code, out)
	}
}

// TestCIRunsTheChangelogCoverageCheck: CI runs the script on every push and
// pull request, on the whole history.
func TestCIRunsTheChangelogCoverageCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	// Each job runs from its two-space key to the next one.
	keys := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\s*$`).FindAllStringIndex(wf, -1)
	var job string
	for i, k := range keys {
		if strings.TrimSpace(wf[k[0]:k[1]]) == "changelog:" {
			end := len(wf)
			if i+1 < len(keys) {
				end = keys[i+1][0]
			}
			job = wf[k[0]:end]
		}
	}
	if job == "" {
		t.Fatal("ci.yml has no changelog job")
	}
	for _, want := range []string{"fetch-depth: 0", "python3 scripts/changelog-coverage.py"} {
		if !strings.Contains(job, want) {
			t.Errorf("the changelog job does not contain %q:\n%s", want, job)
		}
	}
	on := wf[:strings.Index(wf, "\njobs:")]
	for _, event := range []string{"push:", "pull_request:"} {
		if !strings.Contains(on, event) {
			t.Errorf("ci.yml no longer runs on %s", event)
		}
	}
}
