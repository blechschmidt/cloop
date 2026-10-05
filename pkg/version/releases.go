package version

// releases.go is what this build knows about cloop's *published* releases:
// which tags a device can actually install, and the newest executor protocol
// each of those binaries speaks (Task 20371).
//
// A hub needs this to answer one question before it asks a device to upgrade:
// would installing that release move the device forward? The Executors panel's
// Upgrade button and the fleet auto-update policy can only make a device
// install a published, signed release — the hub never supplies bytes, by design
// (see pkg/executor/remote/upgradeproto.go) — and a hub running an unreleased
// build speaks a newer protocol than any release does. Asking a device on such
// a build to install "latest" moved it backwards: its own preflight could not
// order "dev+g47e68a9" against "v0.0.4", so it installed v0.0.4 and dropped
// from protocol v14 to v13, losing everything the hub needed v14 for.
//
// Version strings cannot answer the question — a dev build has no position in
// the release order — but protocol numbers can, and every release's number is
// fixed the moment it is tagged. So the table below records it.

import (
	"regexp"
	"strings"
)

// Release is one published cloop release.
type Release struct {
	// Tag is the release's git tag, e.g. "v0.0.4".
	Tag string
	// Protocol is the newest executor-agent protocol version the release's
	// binaries speak: remote.ProtocolVersion at that tag.
	Protocol int
	// Sequence is the tagged commit's first-parent position on main, which
	// the release's binaries are stamped with (Task 20380): what a device
	// orders an install by. Zero for every release made before builds were
	// stamped — their binaries carry none, and a device whose build carries
	// one refuses them as older.
	Sequence int
}

// publishedReleases lists every cloop release that was published with
// binaries, oldest first, with the protocol each one speaks.
//
// To maintain it, add the release's entry in the commit being tagged: the
// release's own binary then knows it is a release and what it speaks, and every
// later build inherits the entry. The protocol is the `ProtocolVersion = N` line
// of pkg/executor/remote/proto.go at that commit; TestPublishedReleaseProtocols
// MatchTheirTags checks every entry against its tag wherever git and the tags
// are available. The sequence is `git rev-list --count --first-parent HEAD` at
// that commit — what scripts/build-release.sh stamps — and is checked against
// the tag the same way (TestPublishedReleaseSequencesMatchTheirTags); a release
// whose build script did not stamp one has none. A tag whose release was never published with binaries stays
// out — v0.0.2 (protocol v7) and v0.0.3 (v13) are tags no device can install —
// and if a tagged release then fails to publish, remove its entry again.
//
// Oldest first, strictly ordered, and with protocols that never decrease:
// ReleaseProtocol's bounds for a tag that is not listed rest on that, and
// TestPublishedReleasesAreOrdered holds the table to it.
var publishedReleases = []Release{
	{Tag: "v0.0.1", Protocol: 6},
	{Tag: "v0.0.4", Protocol: 13},
}

// ReleaseSequence returns the sequence the release tag's binaries carry, and
// whether the tag is in the published table at all. A listed release with a
// zero sequence is known to carry none; an unlisted one — a release newer than
// this build, say — is unknown, and only the device can judge it.
func ReleaseSequence(tag string) (seq int, known bool) {
	tag = strings.TrimSpace(tag)
	for _, r := range publishedReleases {
		if r.Tag == tag {
			return r.Sequence, true
		}
	}
	return 0, false
}

// PublishedReleases returns the published releases this build knows of, oldest
// first. The slice is a copy.
func PublishedReleases() []Release {
	return append([]Release(nil), publishedReleases...)
}

// NewestPublishedRelease returns the newest published release this build knows
// of, and false when it knows of none.
//
// "Knows of" is the honest qualifier: a release published after this build was
// made is not in its table. Callers say so in what they render.
func NewestPublishedRelease() (Release, bool) {
	if len(publishedReleases) == 0 {
		return Release{}, false
	}
	return publishedReleases[len(publishedReleases)-1], true
}

// releaseTag is a vMAJOR.MINOR.PATCH tag with an optional prerelease suffix and
// no build metadata: the shape every cloop release tag has, and the only shape
// a device can resolve to a published release.
var releaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// IsRelease reports whether v names a release: a vMAJOR.MINOR.PATCH tag,
// optionally with a -prerelease suffix, and no +build metadata.
//
// False for everything else, and in particular for what an unreleased build
// reports — "dev", "dev+g8b418e2", "dev+g8b418e2.dirty" — for the legacy "1"
// placeholder and for "". Build metadata disqualifies a string because it is
// what a dev build carries, and a release tag never does: "v1.2.3+g4f7b5bc"
// names a build *near* v1.2.3, which a device cannot download.
func IsRelease(v string) bool {
	return releaseTag.MatchString(strings.TrimSpace(v))
}

// ReleaseProtocol bounds the executor protocol the release tag speaks, from
// the published-release table, assuming a later release never speaks an older
// protocol than an earlier one.
//
// A tag in the table is exact (lo == hi). Any other release tag lies between
// two entries: lo is the protocol of the newest listed release ordered before
// it, 0 when there is none, and hi the protocol of the oldest listed release
// ordered after it, 0 when there is none — which means no upper bound is known,
// as for a release newer than this build. A string that is not a release tag
// yields (0, 0).
func ReleaseProtocol(tag string) (lo, hi int) {
	return ReleaseProtocolIn(publishedReleases, tag)
}

// ReleaseProtocolIn is ReleaseProtocol over rels, which must be shaped like
// the published table: oldest first, strictly ordered, protocols never
// decreasing. It lets a caller that pins the table — a test whose sentences
// must not change when a release is added — bound tags the same way.
func ReleaseProtocolIn(rels []Release, tag string) (lo, hi int) {
	tag = strings.TrimSpace(tag)
	if !IsRelease(tag) {
		return 0, 0
	}
	for _, r := range rels {
		cmp, ok := Compare(r.Tag, tag)
		if !ok {
			continue
		}
		switch {
		case cmp == 0:
			return r.Protocol, r.Protocol
		case cmp < 0:
			// Ascending table: the last one seen before tag is the newest.
			lo = r.Protocol
		case hi == 0:
			// The first one seen after tag is the oldest.
			hi = r.Protocol
		}
	}
	return lo, hi
}
