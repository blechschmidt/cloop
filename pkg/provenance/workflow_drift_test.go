package provenance

// workflow_drift_test.go keeps the two halves of the trust root from drifting.
//
// The pin is written down twice and has to be: the release workflow passes it
// to `cosign verify-blob` in YAML, and every consumer passes the same string in
// Go. Neither can import the other.
//
// The failure mode that costs the most is not a mismatch that breaks a build.
// It is a *silent* one — the workflow signs with an identity the Go constant
// does not accept, every check in the release pipeline passes because it is
// verifying against its own copy, and the release is published. Then every
// installer and every `cloop upgrade` on every device refuses it, for a release
// that cannot be amended because the signature is what is wrong with it.
//
// The release workflow does re-verify its own signatures before publishing, but
// that is too late to be the only gate: it fails at tag time, after artifacts
// are built, rather than on the commit that introduced the drift. This runs on
// every commit.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// releaseWorkflow reads .github/workflows/release.yml from the repository root.
func releaseWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// TestReleaseWorkflowPinsTheSameIdentity. The workflow builds the identity with
// ${GITHUB_REPOSITORY} interpolated, so the comparison substitutes the real
// value the way the runner would.
func TestReleaseWorkflowPinsTheSameIdentity(t *testing.T) {
	wf := releaseWorkflow(t)

	// identity="…" as the workflow assigns it.
	re := regexp.MustCompile(`identity="([^"]+)"`)
	m := re.FindStringSubmatch(wf)
	if m == nil {
		t.Fatal("release.yml no longer assigns identity=\"…\"; if the verification " +
			"step was renamed or removed, this gate is now vacuous and must be updated")
	}
	got := strings.ReplaceAll(m[1], "${GITHUB_REPOSITORY}", "blechschmidt/cloop")

	if got != DefaultIdentityRegexp {
		t.Errorf("the release workflow and pkg/provenance pin different identities.\n"+
			"  release.yml:      %s\n"+
			"  DefaultIdentityRegexp: %s\n"+
			"A release signed under the first would be refused by every installer and "+
			"every `cloop upgrade` that checks against the second.", got, DefaultIdentityRegexp)
	}
}

// TestReleaseWorkflowPinsTheSameIssuer does the same for the issuer, which is
// the flag whose omission is hardest to notice: the identity regexp would still
// match, so verification would still "work" while accepting a certificate from
// any issuer Fulcio federates with.
func TestReleaseWorkflowPinsTheSameIssuer(t *testing.T) {
	wf := releaseWorkflow(t)

	re := regexp.MustCompile(`issuer="([^"]+)"`)
	m := re.FindStringSubmatch(wf)
	if m == nil {
		t.Fatal("release.yml no longer assigns issuer=\"…\"")
	}
	if m[1] != DefaultIssuer {
		t.Errorf("the release workflow pins issuer %q, pkg/provenance pins %q",
			m[1], DefaultIssuer)
	}
}

// TestReleaseWorkflowSignsAndPublishesBundles guards the mechanical half: a
// signature that is produced but never uploaded leaves every consumer failing
// closed on a missing bundle, which presents as "the release is broken" rather
// than as the one-line omission it is.
func TestReleaseWorkflowSignsAndPublishesBundles(t *testing.T) {
	wf := releaseWorkflow(t)

	for _, want := range []struct{ snippet, why string }{
		{"id-token: write",
			"keyless signing needs an OIDC token; without this permission cosign cannot reach Fulcio"},
		{"sigstore/cosign-installer",
			"cosign has to be installed in the runner before it can sign"},
		{"cosign sign-blob",
			"nothing signs the artifacts"},
		{"--bundle",
			"signing without --bundle emits no verification material to publish"},
		{"dist/release/*.sigstore.json",
			"the bundles are not uploaded as release assets, so no consumer can fetch one"},
	} {
		if !strings.Contains(wf, want.snippet) {
			t.Errorf("release.yml no longer contains %q: %s", want.snippet, want.why)
		}
	}

	// The bundles must also be covered by the asset-reachability check at the
	// end of the workflow — that step is the only thing that notices an asset
	// GitHub did not actually serve.
	if !strings.Contains(wf, "checksums.txt.sigstore.json") {
		t.Error("the published-asset check does not cover the signature bundles, so a " +
			"bundle that failed to upload would be found by a device rather than by CI")
	}
}

// TestBundleSuffixMatchesWhatTheWorkflowWrites ties the name consumers derive
// to the name the workflow produces. They meet only at a URL, where a mismatch
// is a 404 that reads as "this release is not signed".
func TestBundleSuffixMatchesWhatTheWorkflowWrites(t *testing.T) {
	wf := releaseWorkflow(t)
	if !strings.Contains(wf, `"$f.sigstore.json"`) {
		t.Errorf("release.yml does not write bundles as <artifact>%s, which is what "+
			"BundleNameFor derives", BundleSuffix)
	}
	if got := BundleNameFor("cloop_linux_amd64.tar.gz"); got != "cloop_linux_amd64.tar.gz.sigstore.json" {
		t.Errorf("BundleNameFor produced %q", got)
	}
}
