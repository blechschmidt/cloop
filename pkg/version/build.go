package version

// Build provenance: everything the running binary can say about where it came
// from, for the operators and dashboards that have to answer "is this actually
// the build I deployed?".
//
// String() alone cannot answer that question, because it has a blind spot that
// this deployment lands in exactly. Go stamps vcs.* into a binary only when the
// build runs inside a VCS checkout, and -ldflags only stamps what the build
// script passes. A build that has neither — `git archive main | tar -x` into a
// scratch directory, then `go build`, which is how the reference hub at :8888 is
// produced — reports the bare constant "dev" and is indistinguishable from every
// other unstamped build ever made. An operator looking at that dashboard could
// not tell a binary built minutes ago from one that had been running for weeks
// because the deploy silently skipped.
//
// So this file adds two things String() does not have:
//
//   - Identified, which says plainly whether the build can name its own source
//     rather than leaving a "dev" on screen that reads like an answer.
//   - BuiltAt, which falls back to the executable's own modification time when
//     no VCS or linker stamp is present. That timestamp is always available and
//     it moves on every deploy, so it answers "how recent is this?" even for a
//     build that cannot say *what* it is. It is labelled with its provenance
//     rather than presented as a build date, because an mtime is when the file
//     was written, not when the code was compiled — an honest approximation
//     beats a precise-looking fiction.

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Timestamp provenance. Reported alongside BuiltAt so a caller can label it
// truthfully instead of calling every timestamp a build date.
const (
	// SourceCommit: BuiltAt came from vcs.time, which is when the revision was
	// committed — the build itself happened at some later, unrecorded moment.
	SourceCommit = "commit"
	// SourceBinary: BuiltAt is the executable's mtime, i.e. when this file was
	// written or installed. The fallback for builds carrying no VCS data.
	SourceBinary = "binary"
)

// BuildInfo is the running binary's self-description.
type BuildInfo struct {
	// Version is String(): the stamped release, the VCS-enriched dev string,
	// or bare DevVersion when the build carries neither.
	Version string
	// Revision is the full commit hash, empty when the build carries no VCS
	// data. Full rather than the 7 characters String() embeds, because a
	// dashboard showing a build can also link to it.
	Revision string
	// Modified reports that the checkout had uncommitted changes. Only
	// meaningful when Revision is set.
	Modified bool
	// BuiltAt is when this build came into being, as best as can be
	// determined; zero only if even the executable could not be stat'd.
	BuiltAt time.Time
	// BuiltAtSource is SourceCommit or SourceBinary, empty when BuiltAt is
	// zero. See the constants for what each actually measures.
	BuiltAtSource string
	// Identified reports whether the build can name the source it was made
	// from. False means every copy of this binary reports the same "dev" and
	// cannot be told apart — the case worth surfacing to an operator rather
	// than hiding behind a version string that looks like it means something.
	Identified bool
}

// Build returns this binary's provenance, computed once.
func Build() BuildInfo {
	builtOnce.Do(func() { builtValue = buildInfo(Version, readBuildInfo, executableModTime) })
	return builtValue
}

var (
	builtOnce  sync.Once
	builtValue BuildInfo
)

// executableModTime is indirected for the same reason readBuildInfo is: tests
// need to drive the fallback path without arranging a real binary on disk.
var executableModTime = func() (time.Time, bool) {
	path, err := os.Executable()
	if err != nil {
		return time.Time{}, false
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// buildInfo is Build's logic, separated from the sync.Once so it is testable.
func buildInfo(
	stamped string,
	readVCS func() (map[string]string, bool),
	execTime func() (time.Time, bool),
) BuildInfo {
	out := BuildInfo{Version: resolve(stamped, readVCS)}
	// A build is identified when it says anything other than the bare
	// fallback — either the linker stamped a release version, or resolve
	// enriched "dev" with a revision from the toolchain's VCS data.
	out.Identified = out.Version != DevVersion

	if settings, ok := readVCS(); ok {
		out.Revision = strings.TrimSpace(settings["vcs.revision"])
		out.Modified = settings["vcs.modified"] == "true"
		if ts := strings.TrimSpace(settings["vcs.time"]); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				out.BuiltAt, out.BuiltAtSource = t.UTC(), SourceCommit
			}
		}
	}

	// No VCS timestamp: fall back to when the binary itself was written. This
	// is the path every archive-built and cross-compiled release takes, and
	// the only signal such a build has that distinguishes "deployed this
	// morning" from "the deploy has been failing for a week".
	if out.BuiltAt.IsZero() {
		if t, ok := execTime(); ok {
			out.BuiltAt, out.BuiltAtSource = t.UTC(), SourceBinary
		}
	}
	return out
}
