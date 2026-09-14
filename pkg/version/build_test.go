package version

import (
	"testing"
	"time"
)

// vcs builds a settings map the way debug.ReadBuildInfo would report it.
func vcs(kv map[string]string) func() (map[string]string, bool) {
	return func() (map[string]string, bool) { return kv, true }
}

func noVCS() (map[string]string, bool) { return nil, false }

func noExec() (time.Time, bool) { return time.Time{}, false }

func execAt(t time.Time) func() (time.Time, bool) {
	return func() (time.Time, bool) { return t, true }
}

// TestBuildInfo_Identified is the distinction the dashboard is built on: a
// build that can name its own source versus one that reports the generic
// fallback and is indistinguishable from every other unstamped build.
//
// The third case is not hypothetical. The reference hub builds from a
// `git archive` export, which carries no VCS data, with no -ldflags — so it
// reports bare "dev" and Identified must be false for it.
func TestBuildInfo_Identified(t *testing.T) {
	commit := map[string]string{"vcs.revision": "1a2b3c4d5e6f7890", "vcs.modified": "false"}

	for _, tc := range []struct {
		name       string
		stamped    string
		readVCS    func() (map[string]string, bool)
		wantVer    string
		identified bool
	}{
		{"release stamp", "v1.2.3", noVCS, "v1.2.3", true},
		{"dev build in a checkout", DevVersion, vcs(commit), "dev+g1a2b3c4", true},
		{"archive export, no stamp", DevVersion, noVCS, DevVersion, false},
		{"empty stamp falls back", "", noVCS, DevVersion, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildInfo(tc.stamped, tc.readVCS, noExec)
			if got.Version != tc.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tc.wantVer)
			}
			if got.Identified != tc.identified {
				t.Errorf("Identified = %v, want %v (version %q)",
					got.Identified, tc.identified, got.Version)
			}
		})
	}
}

// TestBuildInfo_RevisionIsFull pins that BuildInfo carries the whole hash even
// though String() embeds only seven characters. A dashboard that shows a build
// should be able to link to the commit.
func TestBuildInfo_RevisionIsFull(t *testing.T) {
	const full = "1a2b3c4d5e6f78901234567890abcdefabcdef12"
	got := buildInfo(DevVersion, vcs(map[string]string{
		"vcs.revision": full,
		"vcs.modified": "true",
	}), noExec)

	if got.Revision != full {
		t.Errorf("Revision = %q, want the full hash %q", got.Revision, full)
	}
	if !got.Modified {
		t.Error("Modified = false, want true for a dirty checkout")
	}
	if got.Version != "dev+g1a2b3c4.dirty" {
		t.Errorf("Version = %q, want the 7-char enriched form", got.Version)
	}
}

// TestBuildInfo_TimestampPrefersVCS asserts the ordering: a real commit
// timestamp wins, and the executable's mtime is only a fallback. Getting this
// backwards would report the install time of a release binary as its build
// date, which is wrong by however long the artifact sat in a registry.
func TestBuildInfo_TimestampPrefersVCS(t *testing.T) {
	committed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	written := time.Date(2026, 9, 14, 4, 43, 0, 0, time.UTC)

	got := buildInfo(DevVersion, vcs(map[string]string{
		"vcs.revision": "1a2b3c4d",
		"vcs.time":     committed.Format(time.RFC3339),
	}), execAt(written))

	if !got.BuiltAt.Equal(committed) {
		t.Errorf("BuiltAt = %v, want the commit time %v", got.BuiltAt, committed)
	}
	if got.BuiltAtSource != SourceCommit {
		t.Errorf("BuiltAtSource = %q, want %q", got.BuiltAtSource, SourceCommit)
	}
}

// TestBuildInfo_TimestampFallsBackToBinary covers the deployment this feature
// exists for. With no VCS data there is no commit time, and the executable's
// mtime is the only evidence of how recent the running build is — so it must be
// reported, and it must be labelled as what it really is.
func TestBuildInfo_TimestampFallsBackToBinary(t *testing.T) {
	written := time.Date(2026, 9, 14, 4, 43, 0, 0, time.UTC)

	got := buildInfo(DevVersion, noVCS, execAt(written))

	if !got.BuiltAt.Equal(written) {
		t.Errorf("BuiltAt = %v, want the binary mtime %v", got.BuiltAt, written)
	}
	if got.BuiltAtSource != SourceBinary {
		t.Errorf("BuiltAtSource = %q, want %q — an mtime must not be presented "+
			"as a commit date", got.BuiltAtSource, SourceBinary)
	}
}

// TestBuildInfo_UnreadableTimestampsAreZero: a VCS timestamp Go did not record,
// or recorded unparseably, must leave BuiltAt zero rather than defaulting to
// the epoch and rendering as "built 56 years ago".
func TestBuildInfo_UnreadableTimestampsAreZero(t *testing.T) {
	got := buildInfo(DevVersion, vcs(map[string]string{
		"vcs.revision": "1a2b3c4d",
		"vcs.time":     "not a timestamp",
	}), noExec)

	if !got.BuiltAt.IsZero() {
		t.Errorf("BuiltAt = %v, want the zero time when nothing is readable", got.BuiltAt)
	}
	if got.BuiltAtSource != "" {
		t.Errorf("BuiltAtSource = %q, want empty alongside a zero timestamp", got.BuiltAtSource)
	}
}

// TestBuild_IsMemoized guards the sync.Once wiring: Build must be safe and
// cheap to call from a request handler.
func TestBuild_IsMemoized(t *testing.T) {
	first := Build()
	if got := Build(); got != first {
		t.Errorf("Build() returned %+v then %+v — it must be stable", first, got)
	}
	// The running test binary is built by `go test`, which stamps no version,
	// so the only guarantee worth asserting is that it reports *something*.
	if first.Version == "" {
		t.Error("Build().Version is empty; it must always name a version")
	}
}
