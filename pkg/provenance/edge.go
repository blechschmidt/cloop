package provenance

// edge.go is the second trust root: the edge channel (Task 20376).
//
// A release is cut from a tag and signed by release.yml running on that tag,
// and DefaultIdentityRegexp accepts nothing else. That is right for releases
// and it left a hub that deploys main nightly with no signed artifact to hand
// its devices: every protocol bump stranded the fleet until someone built a
// static binary by hand, copied it over and installed it with
// --insecure-skip-verify — the one flag this package exists to make rare.
//
// The edge channel signs the hub's own builds instead. After CI passes on a
// commit on main, .github/workflows/edge.yml cross-builds that commit, signs
// every archive and a manifest naming the commit, and publishes them as assets
// of a single "edge" prerelease. Fulcio names the signer
//
//	https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main
//
// and EdgeIdentityRegexp accepts exactly that string. It is a separate pin,
// not a widening of DefaultIdentityRegexp, and the separation is the point:
//
//   - A release target is still verified against the tag-only release
//     identity. An edge signature does not make anything a release, so a
//     device on the stable channel cannot be moved onto an edge build by
//     anyone, and `cloop upgrade` never installs one.
//   - An edge target is verified against the edge identity only. A release
//     signature does not satisfy it, nor does edge.yml running on any other
//     branch, nor any other workflow on main — CI, which runs on every pull
//     request's merge ref, least of all.
//   - Which identity applies is decided by the device from the kind of target
//     it resolved, never by anything the hub sends. The upgrade frame names a
//     version and nothing else (pkg/executor/remote/upgradeproto.go).
//
// What the edge pin vouches for is weaker than a release, and the docs say so:
// "a commit on main that passed CI", not "a version someone decided to ship".
// Anyone who can push to main can already change what edge.yml builds, so the
// identity cannot protect against them — it protects against everyone who
// cannot.

import (
	"fmt"
	"os"
	"strings"
)

// EdgeWorkflowPath is the workflow file the edge identity names, relative to
// the repository root.
const EdgeWorkflowPath = ".github/workflows/edge.yml"

// EdgeIdentityRegexp matches the SAN Fulcio issues to this repository's edge
// workflow running on main.
//
// Anchored at both ends and with every dot escaped, for the reasons
// DefaultIdentityRegexp gives. Unlike that one it has no wildcard at all: the
// ref is the literal refs/heads/main, so edge.yml run from another branch, a
// tag or a pull request's merge ref does not match.
const EdgeIdentityRegexp = `^https://github\.com/blechschmidt/cloop/\.github/workflows/edge\.yml@refs/heads/main$`

// EdgeIdentityEnv overrides the edge identity, for an enterprise that builds
// cloop from a fork and publishes its own edge channel. It is deliberately a
// separate variable from IdentityEnv: repointing the release pin must not
// repoint this one, or the release identity would start vouching for edge
// builds, and the reverse.
const EdgeIdentityEnv = "CLOOP_PROVENANCE_EDGE_IDENTITY"

// Channel names a stream of signed builds a device can install from, and with
// it the signing identity a build must carry.
type Channel string

const (
	// ChannelStable is published releases, signed by release.yml on a tag.
	// Every device follows it; it is what an absent setting means.
	ChannelStable Channel = "stable"
	// ChannelEdge is the hub's own builds: commits on main that passed CI,
	// signed by edge.yml on main. A device follows it only when an operator
	// on that device opted in.
	ChannelEdge Channel = "edge"
)

// ParseChannel reads a channel name. Empty means ChannelStable.
func ParseChannel(s string) (Channel, error) {
	switch Channel(strings.ToLower(strings.TrimSpace(s))) {
	case "", ChannelStable:
		return ChannelStable, nil
	case ChannelEdge:
		return ChannelEdge, nil
	}
	return "", fmt.Errorf("provenance: unknown update channel %q (want stable or edge)", s)
}

// EdgeIdentity returns the edge identity regexp in force: EdgeIdentityEnv when
// set, else EdgeIdentityRegexp.
func EdgeIdentity() string {
	if s := strings.TrimSpace(os.Getenv(EdgeIdentityEnv)); s != "" {
		return s
	}
	return EdgeIdentityRegexp
}

// ForChannel returns a copy of v that requires the signing identity of channel
// c. The binary and issuer carry over; the identity does not.
//
// For ChannelStable the copy is v as configured — the release identity, or
// whatever Identity/IdentityEnv repoint it to. For ChannelEdge the identity is
// EdgeIdentity() whatever v.Identity says: a verifier configured for releases
// must not lend its pin to an edge build, and that holds for an explicit
// Identity as much as for the environment.
func (v *Verifier) ForChannel(c Channel) *Verifier {
	out := &Verifier{}
	if v != nil {
		*out = *v
	}
	if c == ChannelEdge {
		out.Identity = EdgeIdentity()
	}
	return out
}
