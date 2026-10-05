package version

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestParseSequence(t *testing.T) {
	for in, want := range map[string]int{"1": 1, "4150": 4150, " 42 ": 42, "1073741824": MaxSequence} {
		if got, ok := ParseSequence(in); !ok || got != want {
			t.Errorf("ParseSequence(%q) = %d, %t; want %d", in, got, ok, want)
		}
	}
	// Anything a broken build script could stamp reads as "carries none",
	// never as a position — a huge one would make a device refuse every
	// later build as older.
	for _, in := range []string{"", "0", "-3", "+3", "4.5", "0x10", "1073741825", "99999999999", "four"} {
		if got, ok := ParseSequence(in); ok {
			t.Errorf("ParseSequence(%q) = %d, want none", in, got)
		}
	}
}

func TestBuildCommitPrefersTheStamp(t *testing.T) {
	const stamped = "4453c68e1c2b3a4d5e6f708192a3b4c5d6e7f809"
	const vcs = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"
	clean := func() (map[string]string, bool) {
		return map[string]string{"vcs.revision": vcs, "vcs.modified": "false"}, true
	}
	dirty := func() (map[string]string, bool) {
		return map[string]string{"vcs.revision": vcs, "vcs.modified": "true"}, true
	}
	none := func() (map[string]string, bool) { return nil, false }
	for _, c := range []struct {
		name, stamp string
		build       func() (map[string]string, bool)
		want        string
	}{
		{"the stamp", stamped, clean, stamped},
		{"the stamp, upper case", strings.ToUpper(stamped), none, stamped},
		{"a clean checkout's revision", "", clean, vcs},
		{"a dirty checkout is no commit's build", "", dirty, ""},
		{"a malformed stamp falls back", "4453c68", clean, vcs},
		{"nothing known", "", none, ""},
	} {
		if got := buildCommit(c.stamp, c.build); got != c.want {
			t.Errorf("%s: buildCommit = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSequenceLabel(t *testing.T) {
	if got := SequenceLabel(4150); got != "sequence 4150 on main" {
		t.Errorf("SequenceLabel(4150) = %q", got)
	}
	if got := SequenceLabel(0); got != "no sequence" {
		t.Errorf("SequenceLabel(0) = %q", got)
	}
}

// TestPublishedReleaseSequencesMatchTheirTags holds the table's sequences to
// the tags (Task 20380): a release whose build script stamps the sequence must
// list `git rev-list --count --first-parent <tag>`, and one whose script does
// not must list none — its binaries carry none, and a device running a
// sequenced build refuses them. Skipped where git or the tags are missing, like
// TestPublishedReleaseProtocolsMatchTheirTags.
func TestPublishedReleaseSequencesMatchTheirTags(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root := moduleRoot(t)
	if out, err := exec.Command(git, "-C", root, "rev-parse", "--verify", "--quiet", "v0.0.4").CombinedOutput(); err != nil {
		t.Skipf("the release tags are not in this checkout (%v: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, _ := exec.Command(git, "-C", root, "rev-parse", "--is-shallow-repository").Output(); strings.TrimSpace(string(out)) != "false" {
		t.Skip("a shallow checkout cannot count a tag's first-parent history")
	}
	for _, r := range PublishedReleases() {
		script, err := exec.Command(git, "-C", root, "show", r.Tag+":scripts/build-release.sh").Output()
		if err != nil {
			t.Errorf("%s: cannot read scripts/build-release.sh at the tag: %v", r.Tag, err)
			continue
		}
		stamps := strings.Contains(string(script), "pkg/version.Sequence=")
		if !stamps {
			if r.Sequence != 0 {
				t.Errorf("%s's build script stamps no sequence, but the table lists %d", r.Tag, r.Sequence)
			}
			continue
		}
		out, err := exec.Command(git, "-C", root, "rev-list", "--count", "--first-parent", r.Tag).Output()
		if err != nil {
			t.Errorf("%s: %v", r.Tag, err)
			continue
		}
		want, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		if r.Sequence != want {
			t.Errorf("%s is sequence %d on main, but the table lists %d", r.Tag, want, r.Sequence)
		}
	}
	if seq, known := ReleaseSequence("v0.0.4"); !known || seq != 0 {
		t.Errorf("ReleaseSequence(v0.0.4) = %d, %t; v0.0.4 is listed and carries none", seq, known)
	}
	if _, known := ReleaseSequence("v9.9.9"); known {
		t.Error("a release this build has never heard of is known")
	}
}
