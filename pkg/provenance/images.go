package provenance

// images.go is the third trust root: cloop's own container images (Task
// 20453).
//
// Release archives are signed by release.yml on a tag and edge builds by
// edge.yml on main. The images were signed by nothing. publish-images.yml
// pushed ghcr.io/blechschmidt/cloop, cloop-harness and cloop-harness-copilot,
// and the image every sandbox runs by default is the mutable tag
// ghcr.io/blechschmidt/cloop-harness:latest — so whoever could push to those
// packages (a leaked publishing token, a compromised workflow) decided what
// code ran beside every lease's credentials on every hub using the default.
//
// The publishing workflow now signs every digest it pushes, keyless, and Fulcio
// names the signer
//
//	https://github.com/blechschmidt/cloop/.github/workflows/publish-images.yml@refs/heads/main
//	https://github.com/blechschmidt/cloop/.github/workflows/publish-images.yml@refs/tags/v0.0.8
//
// ImagesIdentityRegexp accepts exactly those two shapes: the refs that publish
// (pushes to main publish :edge, release tags publish the version tags and
// :latest), and nothing else. It is a separate pin from both of the others, for
// the reason edge.go gives for its own: an image signature makes nothing a
// release, a release signature vouches for no image, and repointing one pin for
// a fork must never move another. Which pin applies is decided by what is being
// verified — an image is only ever checked against this one — never by anything
// a registry or a device says.
//
// What it vouches for is what the edge pin vouches for, one level coarser: an
// image built by this repository's publishing workflow from main or from a
// release tag. Anyone who can push to main can change what that workflow
// builds, so the pin cannot protect against them. It protects against everyone
// who can push to the registry and not to the repository.

import (
	"os"
	"strings"
)

// ImagesWorkflowPath is the workflow file the images identity names, relative
// to the repository root.
const ImagesWorkflowPath = ".github/workflows/publish-images.yml"

// ImagesIdentityRegexp matches the SAN Fulcio issues to this repository's image
// publishing workflow running on main or on a release tag.
//
// Anchored at both ends, every dot escaped, and the tag `[^/]+` as in
// DefaultIdentityRegexp, so the workflow run from another branch, a pull
// request's merge ref, a tag with a slash in it, or any other workflow in this
// repository does not match.
const ImagesIdentityRegexp = `^https://github\.com/blechschmidt/cloop/\.github/workflows/publish-images\.yml@refs/(heads/main|tags/v[^/]+)$`

// Environment overrides for an enterprise that rebuilds cloop's images and
// signs them with its own workflow. Both are separate from the release and edge
// variables: repointing the release pin at another issuer must not leave every
// image checked against a GitHub identity under that issuer — which would refuse
// them all as wrongly signed — and repointing this one must not let an image
// signature vouch for a binary.
const (
	ImagesIssuerEnv   = "CLOOP_PROVENANCE_IMAGES_ISSUER"
	ImagesIdentityEnv = "CLOOP_PROVENANCE_IMAGES_IDENTITY"
)

// ImagesIssuer returns the OIDC issuer an image signature must come from:
// ImagesIssuerEnv when set, else DefaultIssuer.
func ImagesIssuer() string {
	if s := strings.TrimSpace(os.Getenv(ImagesIssuerEnv)); s != "" {
		return s
	}
	return DefaultIssuer
}

// ImagesIdentity returns the identity regexp an image signature must carry:
// ImagesIdentityEnv when set, else ImagesIdentityRegexp.
func ImagesIdentity() string {
	if s := strings.TrimSpace(os.Getenv(ImagesIdentityEnv)); s != "" {
		return s
	}
	return ImagesIdentityRegexp
}
