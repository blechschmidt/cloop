package ciscripts_test

// releasenotes_test.go runs scripts/release-notes.py (Task 20421), which turns
// a release's CHANGELOG.md section into the GitHub release body. GitHub refuses
// a body over 125,000 characters at the end of the release job, after the
// artifacts are built and the tag is pushed, so the script cuts a longer
// section at a whole entry and links the rest.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const notesFixture = `# Changelog

## [Unreleased]

- Not yet.

## [0.0.5] - 2026-10-12

Intro.

### Security

- **First fix.** One.
- **Second fix.** Two,
  wrapped.

### Fixed

- **A bug.** Three.

## [0.0.4] - 2026-09-27

- Older.
`

func releaseNotes(t *testing.T, changelog string, args ...string) (string, string, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o644); err != nil {
		t.Fatal(err)
	}
	return run(t, python(t), append([]string{"scripts/release-notes.py", "--changelog", path}, args...)...)
}

// TestReleaseNotesPrintTheVersionsSection: exactly the lines between the
// version's heading and the next one, with or without a leading v; nothing,
// and success, for a version the changelog does not have.
func TestReleaseNotesPrintTheVersionsSection(t *testing.T) {
	want := "Intro.\n\n### Security\n\n- **First fix.** One.\n- **Second fix.** Two,\n  wrapped.\n\n### Fixed\n\n" +
		"- **A bug.** Three.\n"
	for _, v := range []string{"0.0.5", "v0.0.5"} {
		out, errOut, code := releaseNotes(t, notesFixture, v)
		if code != 0 || out != want {
			t.Errorf("%s: exit %d\n%q\nwant\n%q\n%s", v, code, out, want, errOut)
		}
	}
	if out, _, code := releaseNotes(t, notesFixture, "0.0.9"); code != 0 || out != "" {
		t.Errorf("a missing section: exit %d, %q", code, out)
	}
}

// TestReleaseNotesCutAtAWholeEntry: a section over the limit is cut before the
// entry that would cross it, never inside one, and ends with the link.
func TestReleaseNotesCutAtAWholeEntry(t *testing.T) {
	long := strings.Repeat("x", 60)
	changelog := "## [1.0.0] - 2026-10-12\n\n### Security\n\n"
	for i := 0; i < 40; i++ {
		changelog += "- **Entry " + string(rune('A'+i%26)) + ".** " + long + "\n  " + long + "\n"
	}
	out, errOut, code := releaseNotes(t, changelog, "1.0.0", "--limit", "1500", "--link", "https://example.test/CHANGELOG.md")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if n := len([]rune(out)); n > 1500 {
		t.Errorf("cut to %d characters, over the 1500 limit", n)
	}
	if !strings.HasSuffix(out, "the rest is in [CHANGELOG.md](https://example.test/CHANGELOG.md).\n") {
		t.Errorf("the cut body does not link the rest:\n%s", out)
	}
	body := strings.TrimSuffix(out, out[strings.LastIndex(out, "\n\n…and more."):])
	if !strings.HasSuffix(body, long) {
		t.Errorf("the body was cut inside an entry:\n%s", body)
	}
	if !strings.Contains(errOut, "over 1500") {
		t.Errorf("the cut was not reported: %q", errOut)
	}
}

// TestNewestReleaseNotesFitUncut: the newest release in this repository's
// CHANGELOG.md is published whole. A section that would be cut is a release
// whose notes nobody reads in full; condense it before tagging.
func TestNewestReleaseNotesFitUncut(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(raw)
	if m == nil {
		t.Skip("CHANGELOG.md names no release")
	}
	out, errOut, code := run(t, python(t), "scripts/release-notes.py", string(m[1]))
	if code != 0 || out == "" {
		t.Fatalf("release-notes.py %s: exit %d\n%s", m[1], code, errOut)
	}
	if strings.Contains(errOut, "published cut") {
		t.Errorf("the %s section would be cut for GitHub: %s", m[1], strings.TrimSpace(errOut))
	}
}
