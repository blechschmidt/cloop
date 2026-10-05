package version

// sequence.go is a build's place in main's history (Task 20380): the number a
// device's root helper uses to refuse being moved backwards.
//
// A version string cannot order two builds of main. Every edge build is
// "dev+g<sha>", and Compare answers "not comparable" for any two of them — so
// before this, the installer's downgrade guard compared protocols only, and
// root would install any older signed edge build at the same protocol that an
// unprivileged agent (or a compromised hub) asked for: one from before a fix to
// the agent, or to the helper itself. The signed manifest's built_at could not
// stand in either: it is when a build ran, and a re-run of an old commit is
// "newer" than every build since.
//
// The sequence is the commit's first-parent position on main —
//
//	git rev-list --count --first-parent <commit>
//
// on a full-depth checkout — which only ever grows along main. The build
// scripts stamp it, with the full commit it was counted for:
//
//	-ldflags "-X github.com/blechschmidt/cloop/pkg/version.Sequence=<n>
//	          -X github.com/blechschmidt/cloop/pkg/version.Commit=<40 hex digits>"
//
// scripts/build-release.sh does it for every build it makes, so a release is
// stamped with its tagged commit's position and orders against edge builds in
// both directions; scripts/build-edge.sh checks that the binary reports what it
// was counted as and writes the same pair into the signed manifest.
//
// The two variables follow Version's rule: plain strings initialised to a
// constant, or the linker's -X silently does nothing.

import (
	"strconv"
	"strings"
)

// Sequence is the build's first-parent position on main, stamped at build
// time. Empty for a build that was not stamped — a developer's `go build`, and
// every build made before Task 20380.
//
// Keep the initialiser a constant string. See the package comment.
var Sequence = ""

// Commit is the full commit the sequence was counted for, stamped with it.
//
// Keep the initialiser a constant string. See the package comment.
var Commit = ""

// MaxSequence bounds a sequence this package believes. A stamp beyond it is
// not a position on any real history but a broken build script, and reading
// it as one would make a device refuse every later build as older.
const MaxSequence = 1 << 30

// ParseSequence reads a sequence: a positive decimal integer no larger than
// MaxSequence. Ok is false for anything else, including "" and "0".
func ParseSequence(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 10 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > MaxSequence {
		return 0, false
	}
	return n, true
}

// BuildSequence returns this build's sequence, and false when it carries none
// (or a malformed stamp, which is treated as none).
func BuildSequence() (int, bool) { return ParseSequence(Sequence) }

// BuildCommit returns the full commit this build says it was made from: the
// commit stamped beside the sequence, else the revision the toolchain
// recorded for a clean checkout. Empty when neither is known — and for a
// build of a checkout with uncommitted changes, which is no commit's build.
func BuildCommit() string {
	return buildCommit(Commit, readBuildInfo)
}

// buildCommit is BuildCommit's logic, separated so it is testable.
func buildCommit(stamped string, build func() (map[string]string, bool)) string {
	if c := strings.ToLower(strings.TrimSpace(stamped)); IsCommit(c, 40) {
		return c
	}
	settings, ok := build()
	if !ok || settings["vcs.modified"] == "true" {
		return ""
	}
	if rev := strings.ToLower(strings.TrimSpace(settings["vcs.revision"])); IsCommit(rev, 40) {
		return rev
	}
	return ""
}

// SequenceLabel renders a sequence for an operator: "sequence 4231 on main",
// or "no sequence" for zero.
func SequenceLabel(n int) string {
	if n <= 0 {
		return "no sequence"
	}
	return "sequence " + strconv.Itoa(n) + " on main"
}
