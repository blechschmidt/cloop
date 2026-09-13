package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The bootstrap installer downloads a release artifact by name. Nothing in
// this repository used to check that the name it builds is one the release
// pipeline actually publishes, and for v0.0.1 it was not: CI published
// cloop_0.0.1_linux_amd64.tar.gz while the script fetched
// cloop_linux_amd64.tar.gz, so GET /install.sh worked, printed a friendly
// "downloading …", and 404'd on every device (Task 20240).
//
// That gap was structural rather than careless. Three things compute this
// name — scripts/build-release.sh, pkg/upgrade.assetNameFor, and the shell in
// bootstrap.go — and a drift gate existed for the first two only. The third
// is the one users hit first and the only one with no compiler, no type, and
// no test between it and production.
//
// So: rather than re-derive the URL in Go and assert against the derivation
// (which would only prove this file agrees with itself), these tests run the
// generated shell and read the URL it really builds, for every platform it
// claims to support, then check each against the release script's own --list
// output. Both sides are the real artifacts.

const buildReleaseScript = "../../../scripts/build-release.sh"

// publishedArtifacts returns the artifact names scripts/build-release.sh says
// it would publish.
func publishedArtifacts(t *testing.T) map[string]bool {
	t.Helper()

	path, err := filepath.Abs(buildReleaseScript)
	if err != nil {
		t.Fatalf("resolving %s: %v", buildReleaseScript, err)
	}
	out, err := exec.Command("bash", path, "--list").Output()
	if err != nil {
		t.Fatalf("running %s --list: %v", buildReleaseScript, err)
	}

	names := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names[line] = true
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s --list printed no artifacts", buildReleaseScript)
	}
	return names
}

// downloadURLFor runs the generated installer's own fetch path with `uname`
// stubbed to the given platform, and returns the URL it tried to download.
//
// It works by sourcing the script with its final `main "$@"` removed — so
// nothing executes on load — then shadowing `uname` and `curl` with shell
// functions and calling fetch_cloop directly. Shell functions take precedence
// over PATH, so this needs no fake binaries and no root: `curl` returns
// failure, and the script's own error path prints the URL it was given.
func downloadURLFor(t *testing.T, script, unameS, unameM string) (url string, ok bool) {
	t.Helper()

	// Stripping the invocation is also an assertion. The trailing `main "$@"`
	// is what makes a truncated `curl | sh` run nothing at all instead of half
	// an installer as root; if it ever stops being the last line, this test
	// should say so rather than silently testing a different script.
	const invocation = "\nmain \"$@\"\n"
	if !strings.HasSuffix(script, invocation) {
		t.Fatalf("the bootstrap script does not end in %q; it must define "+
			"everything first and invoke main on the last line, so that a "+
			"truncated download executes nothing", strings.TrimSpace(invocation))
	}
	body := strings.TrimSuffix(script, invocation)

	dir := t.TempDir()
	libPath := filepath.Join(dir, "installer.sh")
	if err := os.WriteFile(libPath, []byte(body), 0o600); err != nil {
		t.Fatalf("writing installer body: %v", err)
	}

	harness := `set -eu
. "$1"
uname() {
  case "${1:-}" in
    -s) printf '%s\n' "$FAKE_UNAME_S" ;;
    -m) printf '%s\n' "$FAKE_UNAME_M" ;;
  esac
}
# Fail the download so the script reports the URL rather than fetching 13MB.
# wget is shadowed too, so a machine without curl takes the same path.
curl() { return 1; }
wget() { return 1; }
fetch_cloop
`
	harnessPath := filepath.Join(dir, "harness.sh")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("writing harness: %v", err)
	}

	cmd := exec.Command("sh", harnessPath, libPath)
	cmd.Env = append(os.Environ(),
		"FAKE_UNAME_S="+unameS,
		"FAKE_UNAME_M="+unameM,
	)
	// Both streams: the URL is announced on stdout by say() and repeated on
	// stderr by die(). Reading the combined output keeps this independent of
	// which one the script chooses.
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fetch_cloop succeeded with curl and wget stubbed to fail; "+
			"output:\n%s", out)
	}

	for _, field := range strings.Fields(string(out)) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			return strings.TrimSuffix(field, ":"), true
		}
	}
	return "", false
}

// TestBootstrapDownloadsAPublishedArtifact is the regression test for Task
// 20240: every platform the installer can run on must resolve to an artifact
// the release pipeline publishes.
func TestBootstrapDownloadsAPublishedArtifact(t *testing.T) {
	script := BootstrapScript(BootstrapParams{
		Server: "wss://hub.example.com/api/executors/connect",
		Pin:    "sha256/AAAA",
	})
	published := publishedArtifacts(t)

	// Every `uname -m` the script's case statement accepts, on every `uname -s`
	// a release targets. A row here that the script does not recognise fails
	// loudly below, so this table cannot silently drift out of coverage
	// either.
	platforms := []struct{ unameS, unameM string }{
		{"Linux", "x86_64"},
		{"Linux", "amd64"},
		{"Linux", "aarch64"},
		{"Linux", "arm64"},
		{"Linux", "armv7l"},
		{"Linux", "armv7"},
		{"Linux", "armhf"},
		{"Darwin", "x86_64"},
		{"Darwin", "arm64"},
	}

	for _, p := range platforms {
		t.Run(p.unameS+"/"+p.unameM, func(t *testing.T) {
			url, ok := downloadURLFor(t, script, p.unameS, p.unameM)
			if !ok {
				t.Fatalf("the installer built no download URL for "+
					"uname -s=%q uname -m=%q; it refuses a platform it claims "+
					"to support", p.unameS, p.unameM)
			}

			asset := url[strings.LastIndex(url, "/")+1:]
			if !published[asset] {
				t.Errorf("the installer fetches %s, but scripts/build-release.sh "+
					"publishes no such artifact.\n  url:       %s\n  published: %v\n"+
					"Every device on this platform would get an HTTP 404.",
					asset, url, keysOf(published))
			}
		})
	}
}

// TestBootstrapUsesTheStableLatestURL pins the other half of the contract. An
// unversioned artifact name only helps if it is fetched from the endpoint that
// tracks the newest release; pointing this at a specific tag would freeze every
// future device on today's binary, which is a slower and quieter failure than
// the 404 it replaced.
func TestBootstrapUsesTheStableLatestURL(t *testing.T) {
	script := BootstrapScript(BootstrapParams{Server: "wss://h/x", Pin: "p"})

	url, ok := downloadURLFor(t, script, "Linux", "x86_64")
	if !ok {
		t.Fatal("the installer built no download URL for linux/x86_64")
	}

	const want = "https://github.com/blechschmidt/cloop/releases/latest/download/"
	if !strings.HasPrefix(url, want) {
		t.Errorf("installer downloads from %q, want the %q prefix — only the "+
			"/latest/download/ endpoint resolves for every future release",
			url, want)
	}
}

// TestBootstrapRejectsUnknownArchitecture checks the negative case: an
// unsupported machine must be told so, not handed a URL that will 404.
func TestBootstrapRejectsUnknownArchitecture(t *testing.T) {
	script := BootstrapScript(BootstrapParams{Server: "wss://h/x", Pin: "p"})

	if url, ok := downloadURLFor(t, script, "Linux", "riscv64"); ok {
		t.Errorf("the installer built %q for an architecture no release "+
			"targets; it should refuse with an actionable message instead", url)
	}
}

// TestBootstrapProgressGoesToStderr is the regression test for the second
// defect Task 20240 turned up, which the 404 had been hiding.
//
// find_or_fetch_cloop returns the binary path to its caller through a command
// substitution:
//
//	bin=$(find_or_fetch_cloop)
//	"$bin" executor agent install …
//
// so stdout inside it is a return channel, not a console. say() wrote there,
// and on the one path where it had anything to say — the download — the
// progress line was captured into $bin along with the path, leaving the
// installer to execute "==> downloading http://…/usr/local/bin/cloop" as a
// single word and exit 127.
//
// The invariant is therefore not "say happens to be quiet" but "no diagnostic
// reaches stdout", which is what this asserts, for each of the three helpers.
func TestBootstrapProgressGoesToStderr(t *testing.T) {
	script := BootstrapScript(BootstrapParams{Server: "wss://h/x", Pin: "p"})
	body := strings.TrimSuffix(script, "\nmain \"$@\"\n")

	dir := t.TempDir()
	libPath := filepath.Join(dir, "installer.sh")
	if err := os.WriteFile(libPath, []byte(body), 0o600); err != nil {
		t.Fatalf("writing installer body: %v", err)
	}

	// die() exits, so it runs in a subshell; its stdout is captured all the
	// same. Each helper is given a distinctive argument so a leak names itself.
	harness := `set -eu
. "$1"
leaked=""
out=$(say "SAY-MARKER")            ; [ -z "$out" ] || leaked="$leaked say"
out=$(warn "WARN-MARKER")          ; [ -z "$out" ] || leaked="$leaked warn"
out=$( (die "DIE-MARKER") || true ) ; [ -z "$out" ] || leaked="$leaked die"
[ -z "$leaked" ] || { printf 'leaked to stdout:%s\n' "$leaked"; exit 1; }
`
	harnessPath := filepath.Join(dir, "harness.sh")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("writing harness: %v", err)
	}

	out, err := exec.Command("sh", harnessPath, libPath).CombinedOutput()
	if err != nil {
		t.Errorf("a diagnostic helper writes to stdout: %s\n"+
			"stdout inside find_or_fetch_cloop is the binary path it returns; "+
			"anything else written there is concatenated into that path and "+
			"executed. Send it to stderr (>&2).", strings.TrimSpace(string(out)))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
