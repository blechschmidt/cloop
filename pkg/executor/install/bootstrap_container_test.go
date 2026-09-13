package install

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The bootstrap installer is a shell script that runs as root on a machine
// nobody is watching, and every other test in this package reads it rather
// than runs it. That gap is where Task 20240 lived: two defects on the same
// path, each of which any execution at all would have caught.
//
//   - The URL named an artifact the release pipeline had never published, so
//     the download 404'd on every device.
//   - say() wrote progress to stdout, which is find_or_fetch_cloop's return
//     channel, so the binary path came back with a progress line glued to the
//     front of it and the installer exited 127.
//
// The second was invisible until the first was fixed. Reading the script finds
// neither; running it finds both immediately.
//
// So this runs it — against a real release archive built by this test, served
// over HTTP, fetched by the real script in a container with no cloop on it.
// It is opt-in because it needs a container runtime and a cross-build:
//
//	CLOOP_INSTALL_E2E=1 go test ./pkg/executor/install/ -run Container -v
//
// The full lifecycle beyond the download — system user, 0600 credential,
// unit file, enable and start — is covered by install_test.go against a fake
// root, and was additionally verified by hand in a privileged systemd
// container when this test was written. What is covered *here* is precisely
// the part those cannot reach: the script actually fetching a real artifact.

// installE2EEnv gates the container tests.
const installE2EEnv = "CLOOP_INSTALL_E2E"

// requireContainerE2E skips unless the suite was asked for and can run.
func requireContainerE2E(t *testing.T) string {
	t.Helper()

	if os.Getenv(installE2EEnv) != "1" {
		t.Skipf("set %s=1 to run the installer container tests", installE2EEnv)
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("docker not found: %v", err)
	}
	if out, err := exec.Command(docker, "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker is installed but not usable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return docker
}

// buildReleaseArchive cross-builds cloop for the container's platform and
// packages it exactly as scripts/build-release.sh does — same asset name, same
// "./"-prefixed members, same GNU-format checksums.txt beside it.
//
// The archive is built here rather than downloaded so the test asserts against
// the naming this repository *currently* produces, which is the thing that
// drifted. It returns the directory to serve and the asset name.
func buildReleaseArchive(t *testing.T) (dir, asset, version string) {
	t.Helper()

	dir = t.TempDir()
	stage := t.TempDir()
	version = "v0.0.0-e2e"

	// The container runs the host's architecture, so the asset has to match it.
	goarch := runtime.GOARCH
	asset = assetNameForTest("linux", goarch)

	build := exec.Command("go", "build", "-trimpath",
		"-ldflags", "-s -w -X github.com/blechschmidt/cloop/pkg/version.Version="+version,
		"-o", filepath.Join(stage, "cloop"), "../../..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cross-building cloop for linux/%s: %v\n%s", goarch, err, out)
	}

	archive := filepath.Join(dir, asset)
	if out, err := exec.Command("tar", "-czf", archive, "-C", stage, ".").CombinedOutput(); err != nil {
		t.Fatalf("packaging %s: %v\n%s", asset, err, out)
	}

	sum, err := exec.Command("sha256sum", archive).Output()
	if err != nil {
		t.Skipf("sha256sum unavailable, cannot build a checksums.txt: %v", err)
	}
	line := fmt.Sprintf("%s  %s\n", strings.Fields(string(sum))[0], asset)
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(line), 0o600); err != nil {
		t.Fatalf("writing checksums.txt: %v", err)
	}
	return dir, asset, version
}

// assetNameForTest mirrors the one naming rule under test. It is spelled out
// rather than imported from pkg/upgrade (which would be an import cycle in
// spirit if not in fact) because TestBootstrapDownloadsAPublishedArtifact
// already pins both against scripts/build-release.sh.
func assetNameForTest(goos, goarch string) string {
	return fmt.Sprintf("cloop_%s_%s.tar.gz", goos, goarch)
}

// serveDir serves dir on all interfaces so a container can reach it, and
// returns the port. The listener is closed when the test ends.
func serveDir(t *testing.T, dir string) int {
	t.Helper()

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listening for the release server: %v", err)
	}
	srv := &http.Server{Handler: http.FileServer(http.Dir(dir))}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().(*net.TCPAddr).Port
}

// runInstallerHarness runs script in a throwaway container with harness as the
// program, and returns the combined output.
//
// alpine is used with no packages added: its busybox provides wget, sha256sum,
// tar, awk and install, so the script's own fallbacks are exercised on a
// genuinely minimal device rather than on a fat image that hides them.
func runInstallerHarness(t *testing.T, docker, script, harness string, port int) (string, error) {
	t.Helper()

	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "installer.sh"), []byte(script), 0o644); err != nil {
		t.Fatalf("writing installer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(in, "harness.sh"), []byte(harness), 0o644); err != nil {
		t.Fatalf("writing harness: %v", err)
	}

	cmd := exec.Command(docker, "run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", in+":/in:ro",
		"-e", fmt.Sprintf("CLOOP_RELEASES=http://host.docker.internal:%d", port),
		"alpine:3", "sh", "/in/harness.sh")

	done := make(chan struct{})
	timer := time.AfterFunc(5*time.Minute, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		close(done)
	})
	out, err := cmd.CombinedOutput()
	timer.Stop()

	return string(out), err
}

// installerBody is the script with its trailing `main "$@"` removed, so a
// harness can source it and call one function.
func installerBody(t *testing.T) string {
	t.Helper()

	script := BootstrapScript(BootstrapParams{
		Server: "wss://hub.example.test/api/executors/connect",
		Pin:    "sha256:2jmj7l5rSw0yVb-vlWAYkK-YBwk=",
	})
	const invocation = "\nmain \"$@\"\n"
	if !strings.HasSuffix(script, invocation) {
		t.Fatalf("the bootstrap script no longer ends in %q", strings.TrimSpace(invocation))
	}
	return strings.TrimSuffix(script, invocation)
}

// TestContainerInstallerFetchesAndInstalls is the end-to-end assertion: on a
// machine with no cloop, the real script downloads the real artifact, verifies
// it, installs it, and returns a path that runs.
func TestContainerInstallerFetchesAndInstalls(t *testing.T) {
	docker := requireContainerE2E(t)
	dir, asset, version := buildReleaseArchive(t)
	port := serveDir(t, dir)

	// The harness calls find_or_fetch_cloop exactly as main() does — through a
	// command substitution. That shape is the test: if any diagnostic reaches
	// stdout, $bin is not a path and the comparison below fails, which is
	// precisely how the 127 exit reached production.
	harness := `set -eu
. /in/installer.sh
command -v cloop >/dev/null 2>&1 && { echo "FAIL: the image already has cloop"; exit 1; }
bin=$(find_or_fetch_cloop)
[ "$bin" = "/usr/local/bin/cloop" ] || { printf 'FAIL: find_or_fetch_cloop returned [%s], not a bare path\n' "$bin"; exit 1; }
[ -x "$bin" ] || { echo "FAIL: $bin is not executable"; exit 1; }
"$bin" version
`
	out, err := runInstallerHarness(t, docker, installerBody(t), harness, port)
	if err != nil {
		t.Fatalf("the installer failed to fetch %s: %v\n%s", asset, err, out)
	}
	if !strings.Contains(out, "cloop "+version) {
		t.Errorf("the installed binary does not report the version it was built "+
			"with (%s); the release ldflag or the archive layout changed.\n%s",
			version, out)
	}
	if !strings.Contains(out, "verified "+asset) {
		t.Errorf("the installer did not verify %s against checksums.txt.\n%s", asset, out)
	}
}

// TestContainerInstallerRefusesATamperedArchive covers the case the checksum
// exists for. The archive is installed 0755 on a device that is about to be
// handed credentials, so a download whose bytes do not match the release must
// not reach the filesystem.
func TestContainerInstallerRefusesATamperedArchive(t *testing.T) {
	docker := requireContainerE2E(t)
	dir, asset, _ := buildReleaseArchive(t)

	// Keep checksums.txt honest and corrupt the artifact, which is what a
	// compromised mirror or a truncated transfer looks like from the device.
	if err := os.WriteFile(filepath.Join(dir, asset), []byte("not a tarball"), 0o600); err != nil {
		t.Fatalf("tampering with %s: %v", asset, err)
	}
	port := serveDir(t, dir)

	// die() runs inside the command substitution, so its `exit 1` ends that
	// subshell and surfaces as a failed assignment here — not as the script
	// exiting. The harness has to turn that into its own exit status, and must
	// also check the filesystem: "refused" is only meaningful if nothing was
	// installed on the way to refusing.
	harness := `set -eu
. /in/installer.sh
if bin=$(find_or_fetch_cloop); then
  printf 'FAIL: installed [%s] from a tampered archive\n' "$bin"
  exit 1
fi
if [ -e /usr/local/bin/cloop ]; then
  echo "FAIL: refused, but left a binary behind at /usr/local/bin/cloop"
  exit 1
fi
echo REFUSED
`
	out, err := runInstallerHarness(t, docker, installerBody(t), harness, port)
	if err != nil || !strings.Contains(out, "REFUSED") {
		t.Fatalf("the installer accepted a tampered archive (err=%v):\n%s", err, out)
	}
	if !strings.Contains(out, "checksum mismatch") {
		t.Errorf("the installer refused the tampered archive, but not because of "+
			"the checksum — so the refusal may be incidental:\n%s", out)
	}
}

// TestContainerInstallerReportsAMissingArtifact pins the failure mode that
// Task 20240 actually shipped: an asset name nothing publishes. Should the
// naming drift again, a device must say so in one line rather than proceed.
func TestContainerInstallerReportsAMissingArtifact(t *testing.T) {
	docker := requireContainerE2E(t)

	// An empty directory is a release that publishes nothing under the name
	// the installer asks for — indistinguishable, from the device, from the
	// versioned-asset release that prompted this task.
	port := serveDir(t, t.TempDir())

	harness := `set -eu
. /in/installer.sh
if bin=$(find_or_fetch_cloop); then
  printf 'FAIL: returned [%s] with nothing published\n' "$bin"
  exit 1
fi
if [ -e /usr/local/bin/cloop ]; then
  echo "FAIL: nothing was published, yet a binary appeared"
  exit 1
fi
echo REFUSED
`
	out, err := runInstallerHarness(t, docker, installerBody(t), harness, port)
	if err != nil || !strings.Contains(out, "REFUSED") {
		t.Fatalf("the installer claimed success against an empty release (err=%v):\n%s", err, out)
	}
	if !strings.Contains(out, "download failed") {
		t.Errorf("a missing artifact should fail with \"download failed: <url>\", "+
			"naming the URL an operator has to go look at:\n%s", out)
	}
}
