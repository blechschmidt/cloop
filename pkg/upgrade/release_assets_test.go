package upgrade

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The release script and the upgrader agree on asset names by construction in
// exactly one direction: this file. `cloop upgrade` looks for a single
// filename computed from its own GOOS/GOARCH and fails the upgrade if the
// release does not carry it, so a rename on either side is not a build error
// or a test failure anywhere else — it is a silent break that surfaces only
// when a user runs `cloop upgrade` against a published release, which is the
// last place anyone wants to discover it.
//
// The script is invoked in --list mode rather than parsed, so these assertions
// are about what it actually emits.

const releaseScript = "../../scripts/build-release.sh"

// listReleaseArtifacts runs the release script's --list mode and returns the
// artifact names it says it would publish.
//
// It takes no version, because the names do not depend on one — that is the
// invariant TestReleaseArtifactsCarryNoVersion exists to defend.
func listReleaseArtifacts(t *testing.T) []string {
	t.Helper()

	path, err := filepath.Abs(releaseScript)
	if err != nil {
		t.Fatalf("resolving %s: %v", releaseScript, err)
	}

	out, err := exec.Command("bash", path, "--list").Output()
	if err != nil {
		t.Fatalf("running %s --list: %v", releaseScript, err)
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s --list printed no artifacts", releaseScript)
	}
	return names
}

// TestReleaseArtifactsMatchAssetNaming checks that every artifact the release
// script publishes is one the upgrader would recognise — i.e. that each name
// round-trips through assetNameFor for the platform encoded in it.
func TestReleaseArtifactsMatchAssetNaming(t *testing.T) {
	for _, name := range listReleaseArtifacts(t) {
		// cloop_linux_amd64.tar.gz -> ["cloop", "linux", "amd64"]
		trimmed := strings.TrimSuffix(name, ".tar.gz")
		if trimmed == name {
			t.Errorf("artifact %q does not end in .tar.gz; the upgrader only "+
				"unpacks gzipped tarballs", name)
			continue
		}

		parts := strings.Split(trimmed, "_")
		if len(parts) != 3 {
			t.Errorf("artifact %q does not have the cloop_<os>_<arch> shape "+
				"the upgrader parses", name)
			continue
		}

		goos, goarch := parts[1], parts[2]
		if want := assetNameFor(goos, goarch); want != name {
			t.Errorf("release script publishes %q for %s/%s, but the upgrader "+
				"looks for %q", name, goos, goarch, want)
		}
	}
}

// TestReleaseCoversRunningPlatform is the assertion that would have caught a
// platform being dropped from the script's matrix: if the platform this test
// runs on is not published, `cloop upgrade` on that platform can only ever
// report "no release asset found".
func TestReleaseCoversRunningPlatform(t *testing.T) {
	want := assetNameFor(runtime.GOOS, runtime.GOARCH)
	for _, name := range listReleaseArtifacts(t) {
		if name == want {
			return
		}
	}
	t.Errorf("the release script publishes no asset for %s/%s (expected %q); "+
		"`cloop upgrade` cannot work on this platform",
		runtime.GOOS, runtime.GOARCH, want)
}

// TestReleaseArtifactsCarryNoVersion is the regression test for Task 20240.
//
// A versioned asset name is not merely ugly: it makes
// /releases/latest/download/<name> — the only stable download URL GitHub
// offers, and the one the bootstrap installer hardcodes — resolve to an asset
// no release has ever published. The break is invisible to every other check
// here, because a versioned name is perfectly self-consistent; it round-trips,
// it covers every platform, and it 404s for every user.
//
// Version numbers are the obvious thing to reach for when naming a build
// artifact, so this asserts their absence explicitly rather than leaving it
// implied by the shape assertion above.
func TestReleaseArtifactsCarryNoVersion(t *testing.T) {
	// Any run of digits separated by dots, with or without a leading "v":
	// 1.2.3, v0.0.1, 2.0, and so on.
	versionish := regexp.MustCompile(`v?\d+\.\d+`)

	for _, name := range listReleaseArtifacts(t) {
		stem := strings.TrimSuffix(name, ".tar.gz")
		if m := versionish.FindString(stem); m != "" {
			t.Errorf("artifact %q embeds a version (%q). The installer fetches "+
				"releases/latest/download/%s, which can only resolve if the name "+
				"is the same for every release — see scripts/build-release.sh",
				name, m, assetNameFor(runtime.GOOS, runtime.GOARCH))
		}
	}
}

// TestUpgradeFallsBackToVersionedAsset covers the other half of the rename:
// a binary built after Task 20240 still has to be able to upgrade from the
// releases published before it, which carry versioned assets.
func TestUpgradeFallsBackToVersionedAsset(t *testing.T) {
	legacy := legacyAssetNameFor("v0.0.1", runtime.GOOS, runtime.GOARCH)
	if strings.Contains(legacy, "_v0.0.1_") {
		t.Errorf("legacyAssetNameFor kept the tag's leading %q: %s", "v", legacy)
	}
	if !strings.Contains(legacy, "_0.0.1_") {
		t.Errorf("legacyAssetNameFor(%q) = %q, want the bare version in it",
			"v0.0.1", legacy)
	}

	// The fallback must be reachable from a release that carries only the old
	// name — which is exactly what github.com/blechschmidt/cloop v0.0.1 is.
	assets := []Asset{{Name: legacy}}
	if got := findAsset(assets, assetNameFor(runtime.GOOS, runtime.GOARCH)); got != nil {
		t.Fatal("the unversioned name matched a release that has no unversioned asset")
	}
	if got := findAsset(assets, legacy); got == nil {
		t.Errorf("a v0.0.1-era release is unreachable: no asset matched %q", legacy)
	}
}
