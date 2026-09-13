package upgrade

import (
	"os/exec"
	"path/filepath"
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

// listReleaseArtifacts runs the release script's --list mode for version and
// returns the artifact names it says it would publish.
func listReleaseArtifacts(t *testing.T, version string) []string {
	t.Helper()

	path, err := filepath.Abs(releaseScript)
	if err != nil {
		t.Fatalf("resolving %s: %v", releaseScript, err)
	}

	out, err := exec.Command("bash", path, "--list", version).Output()
	if err != nil {
		t.Fatalf("running %s --list %s: %v", releaseScript, version, err)
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
	const version = "v1.2.3"

	for _, name := range listReleaseArtifacts(t, version) {
		// cloop_1.2.3_linux_amd64.tar.gz -> ["cloop", "1.2.3", "linux", "amd64"]
		trimmed := strings.TrimSuffix(name, ".tar.gz")
		if trimmed == name {
			t.Errorf("artifact %q does not end in .tar.gz; the upgrader only "+
				"unpacks gzipped tarballs", name)
			continue
		}

		parts := strings.Split(trimmed, "_")
		if len(parts) != 4 {
			t.Errorf("artifact %q does not have the cloop_<version>_<os>_<arch> "+
				"shape the upgrader parses", name)
			continue
		}

		goos, goarch := parts[2], parts[3]
		if want := assetNameFor(version, goos, goarch); want != name {
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
	const version = "v1.2.3"

	want := assetNameFor(version, runtime.GOOS, runtime.GOARCH)
	for _, name := range listReleaseArtifacts(t, version) {
		if name == want {
			return
		}
	}
	t.Errorf("the release script publishes no asset for %s/%s (expected %q); "+
		"`cloop upgrade` cannot work on this platform",
		runtime.GOOS, runtime.GOARCH, want)
}

// TestReleaseVersionPrefixStripped pins the one transformation that is easy to
// get backwards. The git tag carries a leading "v" and the asset does not; an
// asset named cloop_v0.0.1_... is findable by nothing.
func TestReleaseVersionPrefixStripped(t *testing.T) {
	for _, name := range listReleaseArtifacts(t, "v0.0.1") {
		if strings.Contains(name, "_v0.0.1_") {
			t.Errorf("artifact %q kept the tag's leading \"v\"; the upgrader "+
				"strips it and would look for cloop_0.0.1_...", name)
		}
		if !strings.Contains(name, "_0.0.1_") {
			t.Errorf("artifact %q does not carry the bare version 0.0.1", name)
		}
	}
}
