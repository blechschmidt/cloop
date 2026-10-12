package ciscripts_test

// securityage_test.go runs scripts/unreleased-security-age.py (Task 20421), the
// Released installer workflow's "ship something" check for security fixes no
// release carries, against a repository whose commits it dates itself.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// datedRepo is a git repository whose commits carry the dates the test gives.
type datedRepo struct {
	t   *testing.T
	dir string
	now time.Time
}

func newDatedRepo(t *testing.T) *datedRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	r := &datedRepo{t: t, dir: t.TempDir(), now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
	r.git(0, "init", "-q", "-b", "main")
	return r
}

// git runs git in the repository, committing daysAgo days before now.
func (r *datedRepo) git(daysAgo int, args ...string) string {
	r.t.Helper()
	when := r.now.Add(-time.Duration(daysAgo) * 24 * time.Hour).Format(time.RFC3339)
	cmd := exec.Command("git", append([]string{"-c", "user.name=ci", "-c", "user.email=ci@example.com",
		"-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// commit writes CHANGELOG.md and commits it daysAgo days before now.
func (r *datedRepo) commit(daysAgo int, changelog string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, "CHANGELOG.md"), []byte(changelog), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git(daysAgo, "add", "CHANGELOG.md")
	r.git(daysAgo, "commit", "-q", "-m", fmt.Sprintf("changelog, %d days ago", daysAgo))
}

// check runs the script against the repository's changelog.
func (r *datedRepo) check(dir string) (string, int) {
	r.t.Helper()
	out, errOut, code := run(r.t, python(r.t), "scripts/unreleased-security-age.py",
		"--changelog", filepath.Join(dir, "CHANGELOG.md"), "--max-days", "14",
		"--now", fmt.Sprint(r.now.Unix()))
	return out + errOut, code
}

const ageHeader = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- **A feature.** It does things.\n\n"

// TestSecurityAgeFailsOnlyForAnOverdueFix: an [Unreleased] Security entry
// first written twenty days ago fails the check — even after its first line
// was edited yesterday, since its age is its oldest line's — and names itself;
// one written three days ago does not; and once a release carries them,
// nothing waits.
func TestSecurityAgeFailsOnlyForAnOverdueFix(t *testing.T) {
	r := newDatedRepo(t)
	old := "- **The hub binds loopback.** A hub without sign-in\n  answered the network.\n"
	r.commit(20, ageHeader+"### Security\n\n"+old+"\n## [0.0.4] - 2026-09-27\n\n- Older things.\n")
	recent := "- **Origins are checked.** A page could\n  drive the hub.\n"
	r.commit(3, ageHeader+"### Security\n\n"+old+"\n"+recent+"\n## [0.0.4] - 2026-09-27\n\n- Older things.\n")
	edited := strings.Replace(old, "binds loopback.", "binds loopback only.", 1)
	r.commit(1, ageHeader+"### Security\n\n"+edited+"\n"+recent+"\n## [0.0.4] - 2026-09-27\n\n- Older things.\n")

	out, code := r.check(r.dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1 for a fix twenty days without a release:\n%s", code, out)
	}
	for _, want := range []string{
		`::error file=`, `title=Ship something::The [Unreleased] Security entry "The hub binds loopback only."`,
		"has waited 20 days for a release", "Ship something: 1 security fix(es)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `entry "Origins are checked."`) {
		t.Errorf("a three-day-old entry was called overdue:\n%s", out)
	}

	released := "# Changelog\n\n## [Unreleased]\n\n## [0.0.5] - 2026-10-12\n\n### Security\n\n" + edited + "\n" +
		recent + "\n## [0.0.4] - 2026-09-27\n\n- Older things.\n"
	r.commit(0, released)
	if out, code := r.check(r.dir); code != 0 || !strings.Contains(out, "nothing is waiting for a release") {
		t.Errorf("after the release: exit %d\n%s", code, out)
	}
}

// TestSecurityAgeRefusesAShallowClone: a shallow clone dates every older line
// by its boundary commit, which would make an overdue fix look new.
func TestSecurityAgeRefusesAShallowClone(t *testing.T) {
	r := newDatedRepo(t)
	r.commit(30, ageHeader+"### Security\n\n- **An old fix.** Still waiting.\n")
	r.commit(1, ageHeader+"### Security\n\n- **An old fix.** Still waiting.\n\n### Fixed\n\n- A bug.\n")
	shallow := filepath.Join(t.TempDir(), "shallow")
	r.git(0, "clone", "-q", "--depth", "1", "file://"+r.dir, shallow)
	out, code := r.check(shallow)
	if code != 2 || !strings.Contains(out, "shallow clone") {
		t.Errorf("a shallow clone: exit %d, want 2 naming the clone\n%s", code, out)
	}
}

// TestReleasedInstallerRunsTheSecurityAgeCheck: the scheduled workflow runs the
// script on the whole history.
func TestReleasedInstallerRunsTheSecurityAgeCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "released-installer.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	job := wf[strings.Index(wf, "security-fixes-released:"):]
	for _, want := range []string{"fetch-depth: 0", "python3 scripts/unreleased-security-age.py --max-days 14"} {
		if !strings.Contains(job, want) {
			t.Errorf("the security-fixes-released job does not contain %q", want)
		}
	}
	if !strings.Contains(wf, "cron:") {
		t.Error("the Released installer workflow no longer runs on a clock")
	}
}
