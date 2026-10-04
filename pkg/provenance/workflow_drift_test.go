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

// edgeWorkflow reads .github/workflows/edge.yml (Task 20376).
func edgeWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", filepath.FromSlash(EdgeWorkflowPath))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// TestEdgeWorkflowPinsTheSameIdentity is the edge channel's drift gate: the
// identity edge.yml verifies its own signatures against, before publishing, is
// the one every device verifies them against. The first assignment in the file
// is the one the verification step uses.
func TestEdgeWorkflowPinsTheSameIdentity(t *testing.T) {
	wf := edgeWorkflow(t)
	m := regexp.MustCompile(`identity="([^"]+)"`).FindStringSubmatch(wf)
	if m == nil {
		t.Fatal("edge.yml no longer assigns identity=\"…\"; the self-verification step was renamed or removed")
	}
	if got := strings.ReplaceAll(m[1], "${GITHUB_REPOSITORY}", "blechschmidt/cloop"); got != EdgeIdentityRegexp {
		t.Errorf("edge.yml and pkg/provenance pin different identities.\n"+
			"  edge.yml:           %s\n"+
			"  EdgeIdentityRegexp: %s\n"+
			"Every edge build would be refused by every device.", got, EdgeIdentityRegexp)
	}
	m = regexp.MustCompile(`issuer="([^"]+)"`).FindStringSubmatch(wf)
	if m == nil || m[1] != DefaultIssuer {
		t.Errorf("edge.yml does not pin the issuer %s: %v", DefaultIssuer, m)
	}
	// The workflow names itself in the pin; a renamed file would sign under a
	// SAN nothing accepts.
	if !strings.Contains(EdgeIdentityRegexp, regexp.QuoteMeta(filepath.Base(EdgeWorkflowPath))) {
		t.Errorf("EdgeIdentityRegexp does not name %s", EdgeWorkflowPath)
	}
}

// TestEdgeWorkflowOnlyEverSignsMain checks the properties of edge.yml that
// make its signature mean "a commit on main that passed CI" and keep the
// prerelease out of the way of everything that resolves "latest".
func TestEdgeWorkflowOnlyEverSignsMain(t *testing.T) {
	wf := edgeWorkflow(t)
	for _, want := range []struct{ snippet, why string }{
		{"workflow_run:", "the workflow must run after CI, not on its own trigger"},
		{"workflows: [CI]", "it must follow the CI workflow"},
		{"github.event.workflow_run.conclusion == 'success'", "a failed CI run must not be published"},
		{"github.event.workflow_run.event == 'push'", "pull requests — including a fork's branch named main — must never be built here"},
		{"github.event.workflow_run.head_branch == 'main'", "only main is the edge channel"},
		{"github.event.workflow_run.head_repository.full_name == github.repository", "a fork's code must never be signed"},
		{"git merge-base --is-ancestor", "the commit is checked to be on main before it is built"},
		{"id-token: write", "keyless signing needs the OIDC token"},
		{"cosign sign-blob", "nothing signs the artifacts"},
		{`--bundle "$f.sigstore.json"`, "devices look for <asset>.sigstore.json"},
		{"--prerelease --latest=false", "the edge release must never be latest, or the installer would install main"},
		{"releases/latest", "the workflow checks that latest is still a release"},
		{"scripts/edge-prune.py", "builds beyond the newest commits are pruned"},
		{"scripts/build-edge.sh", "the asset names come from the script the Go drift test reads"},
		{"run-name: Edge build of ${{ github.event.workflow_run.head_sha }}",
			"the hub finds the run that built its commit by this title (upgrade.workflowRuns)"},
	} {
		if !strings.Contains(wf, want.snippet) {
			t.Errorf("edge.yml no longer contains %q: %s", want.snippet, want.why)
		}
	}
	// No tag is ever moved: nothing edits the release's tag or pushes one.
	for _, banned := range []string{"git push", "git tag", "gh release edit", "--latest=true", "--latest\n", "--target \"$COMMIT\" --draft"} {
		if strings.Contains(wf, banned) {
			t.Errorf("edge.yml contains %q; the edge tag is created once and never moved, and the release is never latest", banned)
		}
	}
	if strings.Count(wf, "--target") != 1 {
		t.Errorf("edge.yml sets a release target %d times; only the create that makes the tag may", strings.Count(wf, "--target"))
	}
}
