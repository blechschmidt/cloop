package install

import (
	"bufio"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Every other gate on release naming compares this repository against itself.
//
// scripts/build-release.sh --list, pkg/upgrade.assetNameFor and the shell in
// bootstrap.go are checked against each other by release_assets_test.go and
// bootstrap_release_test.go, and the container tests drive the real installer
// against a mirror this repository builds. After Task 20240 all four agreed —
// and `curl … | sh` still 404'd on every device, for weeks, because the
// published release predated the fix and nothing ever re-examined it.
//
// That is the shape of the defect: not a disagreement between two files, but a
// disagreement between the code and an artifact that was correct when it was
// cut and went stale while sitting still. No repo-internal check can see it,
// because nothing in the repository is wrong. The post-publish step in
// release.yml asks GitHub the right question, but only during a release — so
// it cannot notice that a release cut *before* that step existed is broken, and
// it stays silent for however long the current release remains current.
//
// So this asks GitHub directly, and it asks about the artifacts rather than
// about names in a script: what does /releases/latest/download actually serve,
// and would the installer's own lookups succeed against it.
//
// Opt-in, because it needs the network and because it asserts a property of the
// deployment rather than of the working tree — a contributor's pull request
// must not go red over a release they did not cut and cannot fix:
//
//	CLOOP_PUBLISHED_RELEASE=1 go test ./pkg/executor/install/ -run Published -v
//
// It is wired into a scheduled CI job rather than the pull-request path, since
// "the published installer still works" is a question that goes stale with time
// rather than with commits.

// publishedReleaseEnv gates the tests in this file.
const publishedReleaseEnv = "CLOOP_PUBLISHED_RELEASE"

// releasesBaseURL is the same base the generated installer defaults to (see
// CLOOP_RELEASES in bootstrap.go) and the same one release.yml checks after
// publishing. Spelled out rather than derived, so that a change to the shell
// default fails here instead of silently moving what this file verifies.
const releasesBaseURL = "https://github.com/blechschmidt/cloop/releases/latest/download"

// requirePublishedRelease skips unless the suite was asked for.
func requirePublishedRelease(t *testing.T) {
	t.Helper()
	if os.Getenv(publishedReleaseEnv) != "1" {
		t.Skipf("set %s=1 to check the published release", publishedReleaseEnv)
	}
}

// httpStatus returns the status code for a GET of url.
//
// GET rather than HEAD: GitHub serves release assets as a redirect to object
// storage, and a HEAD that the storage layer answers differently would make
// this test disagree with the installer, which only ever issues GETs. The
// bodies are discarded without being read, so the cost is the redirect
// handshake rather than the download.
func httpStatus(t *testing.T, url string) int {
	t.Helper()

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building a request for %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// fetchPublishedChecksums returns the body of the release's checksums.txt.
//
// This file is the release's own manifest of what it published, and it is
// fetchable without a token — which matters, because it lets this test state
// what GitHub is serving without depending on an authenticated API call that
// CI would have to be granted and a developer would have to configure.
func fetchPublishedChecksums(t *testing.T) string {
	t.Helper()

	client := &http.Client{Timeout: 60 * time.Second}
	url := releasesBaseURL + "/checksums.txt"
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned HTTP %d. The installer downloads this file to "+
			"verify every archive it fetches; without it no install can complete.",
			url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return string(body)
}

// publishedArchiveNames parses the archive names out of a checksums.txt body,
// in the GNU format the release script writes and the installer's awk reads:
// "<hex>  <filename>".
func publishedArchiveNames(t *testing.T, body string) []string {
	t.Helper()

	var names []string
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.HasSuffix(fields[1], ".tar.gz") {
			names = append(names, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("parsing checksums.txt: %v", err)
	}
	if len(names) == 0 {
		t.Fatalf("the published checksums.txt lists no .tar.gz archives:\n%s", body)
	}
	return names
}

// TestPublishedReleaseArtifactsCarryNoVersion is the assertion this task
// exists for, made against the release rather than against the script.
//
// release_assets_test.go already forbids a version in the names the build
// script *would* publish. That test passed throughout, because the script was
// fixed; the release was not re-cut, so every device kept fetching a name no
// longer published under. The two assertions look alike and catch disjoint
// failures: one guards the code, this one guards the artifact.
func TestPublishedReleaseArtifactsCarryNoVersion(t *testing.T) {
	requirePublishedRelease(t)

	// Any run of digits separated by dots, with or without a leading "v" —
	// 1.2.3, v0.0.1, 2.0. Same rule as release_assets_test.go, deliberately,
	// so the two cannot disagree about what "carries a version" means.
	versionish := regexp.MustCompile(`v?\d+\.\d+`)

	for _, name := range publishedArchiveNames(t, fetchPublishedChecksums(t)) {
		stem := strings.TrimSuffix(name, ".tar.gz")
		if m := versionish.FindString(stem); m != "" {
			t.Errorf("the published release carries %q, whose name embeds a version (%q).\n"+
				"The bootstrap installer fetches %s/cloop_<os>_<arch>.tar.gz, which "+
				"resolves only against a fixed name — so this release cannot be "+
				"installed by `curl … | sh` on any device. Re-cut the release from a "+
				"commit that includes the versionless naming in scripts/build-release.sh.",
				name, m, releasesBaseURL)
		}
	}
}

// TestPublishedReleaseServesEveryInstallerAsset walks the exact set of URLs the
// installer and the upgrader fetch, and requires each to resolve.
//
// The expected names come from scripts/build-release.sh --list rather than from
// a literal list here, so adding a platform to the release matrix extends this
// check automatically instead of leaving the new platform's users to discover
// the gap themselves.
func TestPublishedReleaseServesEveryInstallerAsset(t *testing.T) {
	requirePublishedRelease(t)

	for name := range publishedArtifacts(t) {
		// The archive itself.
		if code := httpStatus(t, releasesBaseURL+"/"+name); code != http.StatusOK {
			t.Errorf("%s/%s is HTTP %d.\nThe generated install.sh downloads this exact "+
				"URL; every device on this platform fails with \"download failed\".",
				releasesBaseURL, name, code)
		}
		// The signature bundle beside it. The installer fails closed when this
		// 404s, so an unpublished bundle breaks an install exactly as an
		// unpublished archive does — and is easier to forget, since nothing
		// about a successful build depends on it.
		bundle := name + ".sigstore.json"
		if code := httpStatus(t, releasesBaseURL+"/"+bundle); code != http.StatusOK {
			t.Errorf("%s/%s is HTTP %d.\nverify_signature() downloads this and dies when "+
				"it is missing, so installs fail unless every operator passes "+
				"--insecure-skip-verify.", releasesBaseURL, bundle, code)
		}
	}

	// checksums.txt and its own signature: verify_archive() fetches both, and
	// treats either being absent as fatal.
	for _, name := range []string{"checksums.txt", "checksums.txt.sigstore.json"} {
		if code := httpStatus(t, releasesBaseURL+"/"+name); code != http.StatusOK {
			t.Errorf("%s/%s is HTTP %d; verify_archive() cannot complete without it.",
				releasesBaseURL, name, code)
		}
	}
}

// TestPublishedChecksumsListEveryInstallerAsset closes the gap a reachability
// check alone would leave open.
//
// The installer looks each archive up in checksums.txt by exact name
// (awk '$2 == n'), and treats an absent entry as fatal. A release can therefore
// serve checksums.txt with HTTP 200 and still fail every install, because the
// names inside it are the old ones — which is precisely what v0.0.1 did: the
// archives 404'd *and* the manifest listed cloop_0.0.1_linux_amd64.tar.gz, so
// even a device that somehow obtained the archive would have been told it was
// "not listed in checksums.txt".
func TestPublishedChecksumsListEveryInstallerAsset(t *testing.T) {
	requirePublishedRelease(t)

	listed := map[string]bool{}
	for _, name := range publishedArchiveNames(t, fetchPublishedChecksums(t)) {
		listed[name] = true
	}

	// Sorted so the failure message reads the same way on every run.
	listedNames := slices.Sorted(maps.Keys(listed))

	for name := range publishedArtifacts(t) {
		if !listed[name] {
			t.Errorf("%q is not listed in the published checksums.txt (it lists %s).\n"+
				"verify_archive() dies with \"%s is not listed in checksums.txt\", so the "+
				"install fails even when the archive itself downloads.",
				name, strings.Join(listedNames, ", "), name)
		}
	}
}

// TestPublishedReleaseInstallsOnACleanDevice is the whole circuit: the real
// script, rendered as the hub serves it, fetching the real release, on an image
// with no cloop and no cosign.
//
// The tests above would each have caught this task's defect on their own. This
// one is the answer to "but does it actually work", which is a different
// question from "is every URL 200" — an archive can resolve and still contain
// the wrong layout, a binary for the wrong architecture, or nothing runnable.
//
// It runs with CLOOP_INSECURE_SKIP_VERIFY=1, and it is worth being explicit
// that this is a narrowing: a real device verifies the signature, and that path
// is covered against the mirror by the four signature tests in
// bootstrap_container_test.go. Reproducing it here would mean installing cosign
// into the container from a third-party release URL, making a check of *our*
// release depend on the availability of someone else's — while testing
// behaviour already pinned elsewhere. What is unique to this test is the
// artifact under it, so that is what it isolates.
func TestPublishedReleaseInstallsOnACleanDevice(t *testing.T) {
	requirePublishedRelease(t)
	docker := requirePublishedContainer(t)

	// No CLOOP_RELEASES override: the script falls back to its built-in
	// default, which is the URL a real device uses.
	harness := `set -eu
. /in/installer.sh
command -v cloop >/dev/null 2>&1 && { echo "FAIL: the image already has cloop"; exit 1; }
CLOOP_INSECURE_SKIP_VERIFY=1
bin=$(find_or_fetch_cloop)
[ "$bin" = "/usr/local/bin/cloop" ] || { printf 'FAIL: returned [%s]\n' "$bin"; exit 1; }
[ -x "$bin" ] || { echo "FAIL: $bin is not executable"; exit 1; }
"$bin" version
`
	out, err := runPublishedHarness(t, docker, installerBody(t), harness)
	if err != nil {
		t.Fatalf("the published release does not install on a clean device: %v\n%s\n\n"+
			"This is what an operator sees when they run the command the Executors "+
			"panel gives them.", err, out)
	}
	if !strings.Contains(out, "cloop ") {
		t.Errorf("the installed binary did not report a version, so the archive's "+
			"layout is not what the installer expects:\n%s", out)
	}
	if strings.Contains(out, "cloop dev") {
		t.Errorf("the published binary reports \"dev\", so the release was built "+
			"without the version ldflag; `cloop upgrade --check` will never offer "+
			"an update to it:\n%s", out)
	}
}

// requirePublishedContainer gates the container test on a usable docker,
// keyed to this file's own env var so the published checks can be run without
// also opting into the mirror suite (which cross-builds cloop and takes
// minutes).
func requirePublishedContainer(t *testing.T) string {
	t.Helper()

	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("docker not found: %v", err)
	}
	if out, err := exec.Command(docker, "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker is installed but not usable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return docker
}

// runPublishedHarness runs harness in a throwaway alpine container with the
// generated installer available to source, and deliberately no mirror: with
// CLOOP_RELEASES unset the script falls back to its built-in default and
// reaches the real release over the network, exactly as a device does.
func runPublishedHarness(t *testing.T, docker, script, harness string) (string, error) {
	t.Helper()

	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "installer.sh"), []byte(script), 0o644); err != nil {
		t.Fatalf("writing installer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(in, "harness.sh"), []byte(harness), 0o644); err != nil {
		t.Fatalf("writing harness: %v", err)
	}

	cmd := exec.Command(docker, "run", "--rm",
		"-v", in+":/in:ro",
		"alpine:3", "sh", "/in/harness.sh")

	// A container that never exits would otherwise hang the package's whole
	// test binary until -timeout fires, hiding which test was at fault.
	timer := time.AfterFunc(5*time.Minute, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()

	out, err := cmd.CombinedOutput()
	return string(out), err
}
