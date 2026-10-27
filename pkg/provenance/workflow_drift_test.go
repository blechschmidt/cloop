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

	"gopkg.in/yaml.v3"
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
		{"group: edge-${{ github.event.workflow_run.head_sha }}",
			"publishes are serialised per commit at the job, so a skipped run cannot cancel a pending build"},
		{"fetch-depth: 0",
			"the build is stamped with its first-parent count on main, which a shallow clone gets wrong (Task 20380)"},
		{"git rev-list --first-parent origin/main",
			"the commit must be on main's first-parent history for its count to be a position on main"},
		{"for f in *.tar.gz *_manifest.v2.json *_manifest.json; do",
			"both manifests — schema 2 with the sequence, and schema 1 for devices that read nothing else — are signed and verified"},
		{`"cloop_${COMMIT}_manifest.v2.json.sigstore.json"`, "the schema-2 manifest's bundle is checked to be served"},
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
	// A workflow-level group would let a failed CI run's skipped build cancel a
	// real one waiting in it (GitHub keeps one pending run per group).
	if strings.Contains(wf, "\nconcurrency:") {
		t.Error("edge.yml has a workflow-level concurrency group; it must be per commit, on the job")
	}
	if strings.Count(wf, "--target") != 1 {
		t.Errorf("edge.yml sets a release target %d times; only the create that makes the tag may", strings.Count(wf, "--target"))
	}
}

// TestEdgeManifestNamesTheBuildsPlaceOnMain is the manifest's half of Task
// 20380's drift gate. Every edge build is stamped with its commit's
// first-parent position on main, and the signed manifest names the same
// number (schema 2): a device's installer refuses a build whose sequence is
// lower than the installed binary's, and requires the binary's stamp to match
// the manifest. If build-edge.sh stopped writing the field, or stopped
// checking the binary against it, every device would refuse every new edge
// build as "naming no sequence" — or accept a binary its manifest does not
// describe. pkg/upgrade's TestEdgeScriptWritesTheManifestSchemaThisBuildReads
// holds the schema number to upgrade.EdgeManifestSchema.
func TestEdgeManifestNamesTheBuildsPlaceOnMain(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "build-edge.sh")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	script := string(b)
	for _, want := range []struct{ snippet, why string }{
		{`"schema": 2`, "the manifest is schema 2, the first to name a sequence"},
		{`"sequence": sequence`, "the manifest names the build's place on main"},
		{"git -C \"$REPO_ROOT\" rev-list --count --first-parent \"$commit\"",
			"the sequence is the commit's first-parent count, the number build-release.sh stamps"},
		{"rev-parse --is-shallow-repository", "a shallow checkout's count is wrong, so it is refused"},
		{`reported.get("sequence") != sequence`, "the binary must report the sequence the manifest names"},
		{`reported.get("commit") != commit`, "the binary must report the commit the manifest names"},
	} {
		if !strings.Contains(script, want.snippet) {
			t.Errorf("build-edge.sh no longer contains %q: %s", want.snippet, want.why)
		}
	}
	// A release is stamped with its tagged commit's place too, and its
	// workflow checks the binary says so.
	wf := releaseWorkflow(t)
	for _, want := range []string{
		"fetch-depth: 0",
		"want_sequence=$(git rev-list --count --first-parent HEAD)",
		`got.get("sequence") != sequence`,
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml no longer contains %q; a release's sequence would go unchecked", want)
		}
	}
}

// imagesWorkflow reads .github/workflows/publish-images.yml (Task 20453).
func imagesWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", filepath.FromSlash(ImagesWorkflowPath))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v — ImagesWorkflowPath names a workflow that does not exist, so every image "+
			"would be signed under an identity the pin does not name", path, err)
	}
	return string(b)
}

// TestImagesWorkflowPinsTheSameIdentity is the images pin's drift gate: the
// identity publish-images.yml verifies its own signatures against, before any
// hub is asked to run the image, is the one every hub verifies them against.
func TestImagesWorkflowPinsTheSameIdentity(t *testing.T) {
	wf := imagesWorkflow(t)
	m := regexp.MustCompile(`identity="([^"]+)"`).FindStringSubmatch(wf)
	if m == nil {
		t.Fatal("publish-images.yml no longer assigns identity=\"…\"; the self-verification step was renamed or removed")
	}
	if got := strings.ReplaceAll(m[1], "${GITHUB_REPOSITORY}", "blechschmidt/cloop"); got != ImagesIdentityRegexp {
		t.Errorf("publish-images.yml and pkg/provenance pin different identities.\n"+
			"  publish-images.yml:   %s\n"+
			"  ImagesIdentityRegexp: %s\n"+
			"Every image would be refused as wrongly signed by every hub.", got, ImagesIdentityRegexp)
	}
	m = regexp.MustCompile(`issuer="([^"]+)"`).FindStringSubmatch(wf)
	if m == nil || m[1] != DefaultIssuer {
		t.Errorf("publish-images.yml does not pin the issuer %s: %v", DefaultIssuer, m)
	}
	// The workflow names itself in the pin; a renamed file would sign under a
	// SAN nothing accepts.
	if !strings.Contains(ImagesIdentityRegexp, regexp.QuoteMeta(filepath.Base(ImagesWorkflowPath))) {
		t.Errorf("ImagesIdentityRegexp does not name %s", ImagesWorkflowPath)
	}
}

// TestImagesWorkflowPublishesOnlyFromThePinnedRefs holds the workflow's
// triggers to the pin: it runs on pushes to main and to release tags, the two
// ref shapes ImagesIdentityRegexp accepts, and on nothing else that could sign.
// A trigger added without the pin following would publish images every hub
// refuses as wrongly signed; a pin widened without the triggers would accept a
// signature the workflow was never meant to make.
func TestImagesWorkflowPublishesOnlyFromThePinnedRefs(t *testing.T) {
	var doc struct {
		On   map[string]yaml.Node `yaml:"on"`
		Jobs map[string]struct {
			If string `yaml:"if"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(imagesWorkflow(t)), &doc); err != nil {
		t.Fatalf("publish-images.yml does not parse: %v", err)
	}
	if len(doc.On) == 0 {
		t.Fatal("publish-images.yml has no triggers that parse; this gate would pass vacuously")
	}
	for trigger := range doc.On {
		switch trigger {
		case "push", "workflow_dispatch":
		default:
			t.Errorf("publish-images.yml runs on %q, which ImagesIdentityRegexp does not account for — "+
				"a pull request, a schedule or a workflow_run would sign from refs the pin was not written for", trigger)
		}
	}
	var push struct {
		Tags     []string `yaml:"tags"`
		Branches []string `yaml:"branches"`
	}
	node := doc.On["push"]
	if err := node.Decode(&push); err != nil {
		t.Fatalf("publish-images.yml's push trigger does not parse: %v", err)
	}
	if strings.Join(push.Tags, ",") != "v*" || strings.Join(push.Branches, ",") != "main" {
		t.Errorf("publish-images.yml publishes on tags %v and branches %v; ImagesIdentityRegexp accepts "+
			"refs/tags/v… and refs/heads/main — change both together", push.Tags, push.Branches)
	}
	// workflow_dispatch can start the workflow on any branch, so the job is
	// limited to the refs the pin accepts.
	const wantIf = "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
	if got := doc.Jobs["publish"].If; got != wantIf {
		t.Errorf("the publish job's if is %q, want %q: a dispatch from another branch would push images "+
			"signed under an identity every hub refuses", got, wantIf)
	}

	// And the pin itself, against the SANs Fulcio would issue.
	pin := regexp.MustCompile(ImagesIdentityRegexp)
	san := func(ref string) string {
		return "https://github.com/blechschmidt/cloop/.github/workflows/publish-images.yml@" + ref
	}
	for _, ref := range []string{"refs/heads/main", "refs/tags/v0.0.8", "refs/tags/v1.2.3-rc.1"} {
		if !pin.MatchString(san(ref)) {
			t.Errorf("ImagesIdentityRegexp refuses %s, a ref the workflow publishes from", san(ref))
		}
	}
	for _, s := range []string{
		san("refs/heads/feature"),
		san("refs/pull/7/merge"),
		san("refs/tags/v1/../../heads/main"),
		san("refs/tags/x1.0.0"),
		san("refs/heads/main") + "x",
		"https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main",
		"https://github.com/blechschmidt/cloop/.github/workflows/release.yml@refs/tags/v0.0.8",
		"https://github.com/blechschmidt/cloop/.github/workflows/publish-imagesxyml@refs/heads/main",
		"https://github.com/attacker/cloop/.github/workflows/publish-images.yml@refs/heads/main",
	} {
		if pin.MatchString(s) {
			t.Errorf("ImagesIdentityRegexp accepts %s", s)
		}
	}
}

// TestImagesWorkflowSignsEveryDigestItPushes guards the mechanical half: the
// permission keyless signing needs, the signing of the index and of every
// platform manifest, the self-check against the pin, and the negative — a
// digest nobody signed, and the release and edge pins, refused — including
// through the published hub's own `cloop hub verify-image` and its bundled
// cosign.
func TestImagesWorkflowSignsEveryDigestItPushes(t *testing.T) {
	wf := imagesWorkflow(t)
	for _, want := range []struct{ snippet, why string }{
		{"id-token: write", "keyless signing needs an OIDC token; without this permission cosign cannot reach Fulcio"},
		{"sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
			"cosign has to be installed in the runner before it can sign, by an installer pinned by commit"},
		{`cosign sign --yes "$REF@$d"`, "nothing signs the digests"},
		{`select(.platform.os != "unknown")`, "each platform manifest is signed, not only the index"},
		{`digests="$INDEX `, "the index a tag names is signed"},
		{"cosign verify --certificate-oidc-issuer", "the signatures are verified before any hub runs the image"},
		{"no signatures found", "a digest nobody signed must be refused for having no signature"},
		{`grep -q "no matching"`, "another identity's pin must refuse the signatures for their signer"},
		{`/\.github/workflows/edge\.yml@refs/heads/main$`, "the edge pin is shown not to vouch for an image"},
		{`/\.github/workflows/release\.yml@refs/tags/v[^/]+$`, "the release pin is shown not to vouch for an image"},
		{"hub verify-image --json", "the published hub's own check is run against what was signed"},
		{"--entrypoint /usr/local/bin/cosign", "the hub image's bundled cosign is shown to run"},
		{ImagesIdentityEnv, "the hub's override is shown to turn a pass into a mismatch"},
	} {
		if !strings.Contains(wf, want.snippet) {
			t.Errorf("publish-images.yml no longer contains %q: %s", want.snippet, want.why)
		}
	}
}

// TestImagesWorkflowInstallsTheCosignTheHubBundles: what signs in CI is what
// verifies in the published hub image, and the Dockerfile pins that binary by
// its checksum for both architectures it is built for.
func TestImagesWorkflowInstallsTheCosignTheHubBundles(t *testing.T) {
	m := regexp.MustCompile(`cosign-release:\s*'(v[0-9.]+)'`).FindStringSubmatch(imagesWorkflow(t))
	if m == nil {
		t.Fatal("publish-images.yml no longer pins cosign-release")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	d := regexp.MustCompile(`(?m)^ARG COSIGN_VERSION=(v[0-9.]+)$`).FindStringSubmatch(dockerfile)
	if d == nil {
		t.Fatal("the Dockerfile no longer pins ARG COSIGN_VERSION; the hub image would carry no cosign, or an unpinned one")
	}
	if m[1] != d[1] {
		t.Errorf("publish-images.yml signs with cosign %s, the hub image bundles %s", m[1], d[1])
	}
	for _, arch := range []string{"AMD64", "ARM64"} {
		if !regexp.MustCompile(`(?m)^ARG COSIGN_SHA256_` + arch + `=[0-9a-f]{64}$`).MatchString(dockerfile) {
			t.Errorf("the Dockerfile does not pin the %s cosign binary by its SHA-256", strings.ToLower(arch))
		}
	}
	for _, want := range []string{`sha256sum -c -`, "COPY --from=cosign /out/cosign /usr/local/bin/cosign"} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("the Dockerfile no longer contains %q: the bundled cosign is not checked, or not shipped", want)
		}
	}
}
