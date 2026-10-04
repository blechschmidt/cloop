package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestPublishedReleasesAreOrdered holds the table to the shape ReleaseProtocol
// relies on: oldest first, no tag listed twice or out of order, and protocols
// that never go down. A bound computed from an unordered table would be a
// wrong answer to "would this release move the device backwards".
func TestPublishedReleasesAreOrdered(t *testing.T) {
	rels := PublishedReleases()
	if len(rels) == 0 {
		t.Fatal("no published releases listed; every protocol bound would be unknown")
	}
	for i, r := range rels {
		if !IsRelease(r.Tag) {
			t.Errorf("entry %d: %q is not a release tag", i, r.Tag)
		}
		if r.Protocol <= 0 {
			t.Errorf("entry %d (%s): protocol %d; every published binary speaks some protocol",
				i, r.Tag, r.Protocol)
		}
		if i == 0 {
			continue
		}
		prev := rels[i-1]
		cmp, ok := Compare(prev.Tag, r.Tag)
		if !ok || cmp >= 0 {
			t.Errorf("entry %d (%s) does not follow entry %d (%s); the table must be oldest "+
				"first and strictly ordered", i, r.Tag, i-1, prev.Tag)
		}
		if r.Protocol < prev.Protocol {
			t.Errorf("%s speaks v%d, older than the earlier %s's v%d; protocol never decreases "+
				"from one release to the next, and ReleaseProtocol assumes it does not",
				r.Tag, r.Protocol, prev.Tag, prev.Protocol)
		}
	}
	newest, ok := NewestPublishedRelease()
	if !ok || newest != rels[len(rels)-1] {
		t.Errorf("NewestPublishedRelease() = %+v, %v; want the table's last entry %+v",
			newest, ok, rels[len(rels)-1])
	}
}

// TestPublishedReleasesIsACopy: a caller sorting or trimming what it was given
// must not rewrite this build's knowledge of the release history.
func TestPublishedReleasesIsACopy(t *testing.T) {
	got := PublishedReleases()
	got[0].Protocol = 999
	if PublishedReleases()[0].Protocol == 999 {
		t.Fatal("PublishedReleases returned the table itself")
	}
}

func TestIsRelease(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"v0.0.4", true},
		{"v1.2.3", true},
		{"v10.20.30", true},
		{"v1.2.3-rc1", true},
		{"v1.2.3-rc.1", true},
		{" v0.0.1 ", true},
		// What an unreleased build reports, and what the old Upgrade dialog
		// prefilled on such a hub.
		{"dev", false},
		{"dev+g8b418e2", false},
		{"dev+g8b418e2.dirty", false},
		// Build metadata names a build near a release, not the release.
		{"v1.2.3+g4f7b5bc", false},
		{LegacyAgentVersion, false},
		{"", false},
		{"latest", false},
		// A device resolves the tag verbatim; there is no "1.2.3" tag.
		{"1.2.3", false},
		{"v1.2", false},
		{"v1.2.3.4", false},
		{"v01.2.3", false},
		{"v1.2.3-", false},
		{"v1.2.x", false},
	} {
		if got := IsRelease(tc.in); got != tc.want {
			t.Errorf("IsRelease(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestReleaseProtocolBounds pins the bounds for the four positions a tag can
// have relative to the table, using the real entries: v0.0.1 speaks v6 and
// v0.0.4 speaks v13.
func TestReleaseProtocolBounds(t *testing.T) {
	for _, tc := range []struct {
		tag    string
		lo, hi int
	}{
		// Listed: exact.
		{"v0.0.1", 6, 6},
		{"v0.0.4", 13, 13},
		// Between two listed releases. v0.0.2 and v0.0.3 are real tags that
		// were never published; their true protocols (v7, v13) lie inside.
		{"v0.0.2", 6, 13},
		{"v0.0.3", 6, 13},
		{"v0.0.4-rc1", 6, 13},
		// Before everything listed: nothing below, the oldest above.
		{"v0.0.0", 0, 6},
		// After everything listed: newer than this build, no upper bound.
		{"v0.0.5", 13, 0},
		{"v1.0.0", 13, 0},
		// Not a release at all.
		{"dev", 0, 0},
		{"dev+g8b418e2", 0, 0},
		{"latest", 0, 0},
		{"", 0, 0},
	} {
		lo, hi := ReleaseProtocol(tc.tag)
		if lo != tc.lo || hi != tc.hi {
			t.Errorf("ReleaseProtocol(%q) = (%d, %d), want (%d, %d)", tc.tag, lo, hi, tc.lo, tc.hi)
		}
	}
}

// TestPublishedReleaseProtocolsMatchTheirTags checks the table against the
// source it summarises: each entry's protocol must be the ProtocolVersion line
// of pkg/executor/remote/proto.go at that tag. A wrong number here is the
// whole defect this table exists to prevent — a hub judging "this release will
// not move the device backwards" from a figure nobody checked.
//
// It needs git and the tags, which a shallow CI checkout may lack, so it skips
// rather than fails when `git rev-parse v0.0.4` does not succeed.
func TestPublishedReleaseProtocolsMatchTheirTags(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root := moduleRoot(t)
	if out, err := exec.Command(git, "-C", root, "rev-parse", "--verify", "--quiet", "v0.0.4").CombinedOutput(); err != nil {
		t.Skipf("the release tags are not in this checkout (%v: %s)", err, strings.TrimSpace(string(out)))
	}
	line := regexp.MustCompile(`(?m)^\s*ProtocolVersion\s*=\s*([0-9]+)\s*$`)
	for _, r := range PublishedReleases() {
		out, err := exec.Command(git, "-C", root, "show", r.Tag+":pkg/executor/remote/proto.go").Output()
		if err != nil {
			t.Errorf("%s: cannot read pkg/executor/remote/proto.go at the tag: %v", r.Tag, err)
			continue
		}
		m := line.FindSubmatch(out)
		if m == nil {
			t.Errorf("%s: no `ProtocolVersion = N` line in pkg/executor/remote/proto.go", r.Tag)
			continue
		}
		got, _ := strconv.Atoi(string(m[1]))
		if got != r.Protocol {
			t.Errorf("%s speaks protocol v%d at its tag, but the table says v%d", r.Tag, got, r.Protocol)
		}
	}
}

// moduleRoot finds the directory holding go.mod, walking up from the package
// directory `go test` runs in.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}
