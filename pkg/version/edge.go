package version

// edge.go names builds of the edge channel (Task 20376): "edge:<commit>", the
// upgrade target a device resolves to a signed build of a commit on main, and
// the commit a dev build's version carries.
//
// Here rather than in pkg/upgrade, which fetches and verifies those builds,
// because the hub's planner and refusals need to recognise a target and
// compare commits without linking a downloader — and this package is the one
// every layer may import.

import (
	"errors"
	"fmt"
	"strings"
)

// EdgeTargetPrefix starts an upgrade target that names an edge build.
const EdgeTargetPrefix = "edge:"

// ErrEdgeTarget reports a malformed edge target.
var ErrEdgeTarget = errors.New("version: not an edge target")

// EdgeTarget formats the target naming commit's edge build.
func EdgeTarget(commit string) string {
	return EdgeTargetPrefix + strings.ToLower(strings.TrimSpace(commit))
}

// IsEdgeTarget reports whether s names an edge build at all, well-formed or
// not — so "edge:zzz" is refused as a malformed edge target rather than as
// "not a release".
func IsEdgeTarget(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), EdgeTargetPrefix)
}

// ParseEdgeTarget returns the commit an "edge:<commit>" target names,
// lowercased: 7 to 40 hex digits.
func ParseEdgeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !IsEdgeTarget(s) {
		return "", fmt.Errorf("%w: %q", ErrEdgeTarget, s)
	}
	commit := strings.ToLower(s[len(EdgeTargetPrefix):])
	if !IsCommit(commit, 7) {
		return "", fmt.Errorf("%w: %q does not name a commit (want edge:<7 to 40 hex digits>)", ErrEdgeTarget, s)
	}
	return commit, nil
}

// IsCommit reports whether s is between min and 40 lowercase hex digits.
func IsCommit(s string, min int) bool {
	if len(s) < min || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

// CommitOf returns the commit prefix a dev build's version names —
// "dev+g8b418e2" → "8b418e2" — and false for anything else: a release, bare
// "dev", or a dirty tree, which no CI build matches.
func CommitOf(v string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(v), DevVersion+"+g")
	if !ok || !IsCommit(rest, 7) {
		return "", false
	}
	return rest, true
}

// SameCommit reports whether two versions or commits name the same commit:
// one is a prefix of the other, the shorter at least seven digits. It
// tolerates the abbreviation length differing between the deploy, which
// stamps `git log --format=%h`, and CI, which stamps seven digits.
func SameCommit(a, b string) bool {
	if c, ok := CommitOf(a); ok {
		a = c
	}
	if c, ok := CommitOf(b); ok {
		b = c
	}
	a, b = strings.ToLower(a), strings.ToLower(b)
	if !IsCommit(a, 7) || !IsCommit(b, 7) {
		return false
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}
