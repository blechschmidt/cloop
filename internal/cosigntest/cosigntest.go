// Package cosigntest stands in for cosign in tests that need its verdict to
// depend on *who* signed, not merely on whether verification was asked for.
//
// The stand-ins elsewhere exit 0 or 1 unconditionally, which proves what cloop
// asks cosign and nothing about whether the answer would differ between a
// release signature and an edge one (Task 20376). This one reads the signer's
// identity — the certificate SAN Fulcio would have issued — out of a stand-in
// bundle, and matches it against the --certificate-identity-regexp and
// --certificate-oidc-issuer it was given, the way cosign does. A test can then
// sign an artifact "as" release.yml on a tag or edge.yml on main and assert
// which verifications accept it.
//
// It checks only identity and issuer, plus that the bundle names the very
// bytes being verified (a SHA-256 the bundle carries), so a bundle copied
// beside another artifact is refused as cosign would refuse it. It proves
// nothing about real signatures; TestRealCosignRejectsATamperedBlob in
// pkg/provenance does that with the real tool.
//
// The regexp is evaluated with grep -E. Every identity cloop pins is plain
// POSIX ERE — anchors, escaped dots, a bracket expression — so ERE and Go's
// RE2, which cosign uses, agree on them; TestFakeCosignAgreesWithGoRegexp in
// pkg/provenance holds the matrix to that.
package cosigntest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Issuer is GitHub's OIDC issuer, the one every signer here claims.
const Issuer = "https://token.actions.githubusercontent.com"

// SANs a stand-in bundle can claim, for the matrix tests.
const (
	// Release is release.yml on a tag: the stable channel's signer.
	Release = "https://github.com/blechschmidt/cloop/.github/workflows/release.yml@refs/tags/v9.9.9"
	// Edge is edge.yml on main: the edge channel's signer.
	Edge = "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main"
	// EdgeOtherBranch is edge.yml run from a branch that is not main.
	EdgeOtherBranch = "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/feature"
	// EdgeOnTag is edge.yml run on a tag.
	EdgeOnTag = "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/tags/v9.9.9"
	// CIOnMain is another workflow on main.
	CIOnMain = "https://github.com/blechschmidt/cloop/.github/workflows/ci.yml@refs/heads/main"
	// ReleaseOnMain is the release workflow run from main rather than a tag.
	ReleaseOnMain = "https://github.com/blechschmidt/cloop/.github/workflows/release.yml@refs/heads/main"
	// ForkEdge is a fork's edge workflow on its main.
	ForkEdge = "https://github.com/attacker/cloop/.github/workflows/edge.yml@refs/heads/main"
)

// bundle is the stand-in bundle's shape.
type bundle struct {
	SAN    string `json:"san"`
	Issuer string `json:"issuer"`
	SHA256 string `json:"sha256"`
}

// Bundle returns a stand-in bundle claiming that san signed blob.
func Bundle(san string, blob []byte) []byte {
	sum := sha256.Sum256(blob)
	b, _ := json.Marshal(bundle{SAN: san, Issuer: Issuer, SHA256: hex.EncodeToString(sum[:])})
	return b
}

// script is the stand-in. It parses the verify-blob argv cloop builds, reads
// the bundle's three fields with sed (the JSON above is one line with no
// escapes in any field), and refuses with cosign's own wording on a mismatch.
const script = `#!/bin/sh
bundle= issuer= identity= blob=
while [ $# -gt 0 ]; do
  case "$1" in
    verify-blob) shift ;;
    --bundle) bundle=$2; shift 2 ;;
    --certificate-oidc-issuer) issuer=$2; shift 2 ;;
    --certificate-identity-regexp) identity=$2; shift 2 ;;
    --*) shift 2 ;;
    *) blob=$1; shift ;;
  esac
done
if [ -n "${COSIGNTEST_LOG:-}" ]; then printf '%s %s\n' "$identity" "$blob" >> "$COSIGNTEST_LOG"; fi
field() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' "$bundle"; }
san=$(field san); iss=$(field issuer); want=$(field sha256)
got=$(sha256sum "$blob" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  echo "Error: error verifying bundle: invalid signature when validating ASN.1 encoded signature" >&2; exit 1
fi
if [ "$iss" != "$issuer" ]; then
  echo "Error: none of the expected identities matched what was in the certificate, got issuer [$iss]" >&2; exit 1
fi
if ! printf '%s\n' "$san" | grep -Eq -- "$identity"; then
  echo "Error: none of the expected identities matched what was in the certificate, got subjects [$san]" >&2; exit 1
fi
echo "Verified OK" >&2
`

// Install writes the stand-in into a fresh directory and returns its path.
// Pass it as provenance.Verifier.Binary, or put its directory on PATH.
func Install(t testing.TB) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("cosigntest: writing the stand-in cosign: %v", err)
	}
	return bin
}
