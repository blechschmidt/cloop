package install

// bootstrap_channel_test.go runs the rendered /install.sh (Task 20421): it never
// hands the agent installer a cloop that speaks an older executor protocol than
// the hub that rendered it, and --channel edge installs exactly the hub's own
// build, signed by the edge workflow, and puts the device on the edge channel —
// only when the operator asked for it.
//
// The script runs under sh on this machine, sourced with its final `main "$@"`
// removed, with the network, cosign and the install destination replaced by
// shell functions and stubs: curl copies from a mirror directory, cosign is the
// stand-in bootstrap_container_test.go uses, and /usr/local/bin is redirected
// into the test's own directory. So the real fetch, verification and protocol
// logic runs, in CI, without root and without touching the machine.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/upgrade"
)

const (
	channelHubCommit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"
	channelHubProto  = 21
	// edgeSigningIdentity is the SAN Fulcio issues to the edge workflow on
	// main, which the edge pin accepts and the release pin refuses.
	edgeSigningIdentity = "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main"
)

// stubVersion is what a stub cloop reports for `version --json`, shaped like
// cmd's versionReport and indented as its encoder indents it. A negative
// protocol makes the stub reject --json, as a cloop too old to have it does.
type stubVersion struct {
	Version     string `json:"version"`
	Go          string `json:"go"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Protocol    int    `json:"protocol"`
	MinProtocol int    `json:"min_protocol"`
	Commit      string `json:"commit,omitempty"`
	Sequence    int    `json:"sequence,omitempty"`
	Schema      int    `json:"schema"`
}

// stubCloop is a cloop stand-in: `version --json` prints v, and `executor
// agent install` records its arguments in $CLOOP_STUB_ARGS.
func stubCloop(t *testing.T, v stubVersion) string {
	t.Helper()
	report, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	jsonBranch := "  printf '%s\\n' '" + string(report) + "'\n  exit 0\n"
	if v.Protocol < 0 {
		jsonBranch = "  echo 'Error: unknown flag: --json' >&2\n  exit 1\n"
	}
	return "#!/bin/sh\n" +
		"if [ \"${1:-}\" = version ] && [ \"${2:-}\" = --json ]; then\n" + jsonBranch + "fi\n" +
		"if [ \"${1:-}\" = executor ]; then\n  cat >/dev/null\n  printf '%s\\n' \"$*\" >> \"$CLOOP_STUB_ARGS\"\n  exit 0\nfi\n" +
		"echo \"cloop " + v.Version + "\"\n"
}

func edgeBuildReport(protocol int, commit string) stubVersion {
	return stubVersion{Version: "dev+g" + commit[:7], Go: "go1.26.9", OS: "linux", Arch: "amd64",
		Protocol: protocol, MinProtocol: 1, Commit: commit, Sequence: 4300, Schema: 63}
}

func releaseReport(tag string, protocol int) stubVersion {
	return stubVersion{Version: tag, Go: "go1.26.9", OS: "linux", Arch: "amd64", Protocol: protocol,
		MinProtocol: 1, Schema: 63}
}

// tarCloop packages a cloop as the release script does: one ./cloop member.
func tarCloop(t *testing.T, script string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./cloop", Mode: 0o755, Size: int64(len(script)),
		Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// stableMirror publishes a release the way release.yml does: the archive,
// checksums.txt, and a bundle beside each, signed by identity.
func stableMirror(t *testing.T, mirror, script, identity string) {
	t.Helper()
	dir := filepath.Join(mirror, "stable")
	archive := tarCloop(t, script)
	writeFile(t, filepath.Join(dir, "cloop_linux_amd64.tar.gz"), archive, 0o644)
	writeChecksums(t, dir, "cloop_linux_amd64.tar.gz")
	signStub(t, dir, "cloop_linux_amd64.tar.gz", identity)
	signStub(t, dir, "checksums.txt", identity)
}

// edgeManifestOpts bends one edge publication for a negative case.
type edgeManifestOpts struct {
	manifestCommit string // the commit the manifest claims, default the build's
	wrongHash      bool   // list a hash that is not the archive's
	identity       string // who signed, default the edge workflow
}

// edgeMirror publishes commit's edge build the way edge.yml does: the
// commit-named archive and the schema-2 manifest, each with its bundle.
func edgeMirror(t *testing.T, mirror, commit, script string, o edgeManifestOpts) {
	t.Helper()
	dir := filepath.Join(mirror, "edge")
	name := upgrade.EdgeArchiveName(commit, "linux", "amd64")
	archive := tarCloop(t, script)
	writeFile(t, filepath.Join(dir, name), archive, 0o644)
	hash := sha256Hex(archive)
	if o.wrongHash {
		hash = sha256Hex([]byte("another build"))
	}
	if o.manifestCommit == "" {
		o.manifestCommit = commit
	}
	if o.identity == "" {
		o.identity = edgeSigningIdentity
	}
	// Indented and sorted exactly as scripts/build-edge.sh writes it.
	manifest, err := json.MarshalIndent(map[string]any{
		"schema": 2, "commit": o.manifestCommit, "version": "dev+g" + commit[:7], "protocol": channelHubProto,
		"sequence": 4300, "archives": map[string]string{name: hash}, "built_at": "2026-10-12T00:00:00Z", "run": "",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestName := upgrade.EdgeManifestV2Name(commit)
	writeFile(t, filepath.Join(dir, manifestName), append(manifest, '\n'), 0o644)
	signStub(t, dir, name, o.identity)
	signStub(t, dir, manifestName, o.identity)
}

// channelScript renders install.sh for a hub at channelHubProto; edge says
// whether CI published the hub's build.
func channelScript(edge bool) BootstrapParams {
	p := BootstrapParams{
		Server:      "wss://hub.example.test/api/executors/connect",
		Pin:         "sha256:2jmj7l5rSw0yVb-vlWAYkK-YBwk=",
		HubVersion:  "dev+g" + channelHubCommit[:7],
		HubProtocol: channelHubProto,
	}
	if edge {
		p.EdgeCommit = channelHubCommit
	} else {
		p.EdgeUnavailable = "CI has not published commit a0f3870 yet: CI is still running on it."
	}
	return p
}

// fetchHarness runs fetch_cloop on channel against mirror, with /usr/local/bin
// redirected into work/bin. It returns the output and whether it succeeded.
func runFetch(t *testing.T, p BootstrapParams, mirror, channel string) (out string, work string, ok bool) {
	t.Helper()
	work = t.TempDir()
	harness := `set -eu
. "$1"
uname() { case "${1:-}" in -s) echo Linux ;; -m) echo x86_64 ;; esac; }
curl() {
  src="$MIRROR/${2#http://mirror.test/}"
  [ -f "$src" ] || return 22
  command cp "$src" "$4"
}
wget() { return 1; }
mktemp() {
  case "${1:-}" in
    -d) command mktemp -d "$WORK/tmp.XXXXXX" ;;
    /usr/local/bin/*) command mktemp "$WORK/bin/${1#/usr/local/bin/}" ;;
    *) command mktemp "$@" ;;
  esac
}
install() {
  dest=$4
  case "$dest" in /usr/local/bin/*) dest=$WORK/bin/${dest#/usr/local/bin/} ;; esac
  command install -m "$2" "$3" "$dest"
}
mv() {
  dest=$3
  case "$dest" in /usr/local/bin/*) dest=$WORK/bin/${dest#/usr/local/bin/} ;; esac
  command mv -f "$2" "$dest"
}
CLOOP_RELEASES=http://mirror.test/stable
CLOOP_EDGE_RELEASES=http://mirror.test/edge
CLOOP_CHANNEL=$TEST_CHANNEL
if bin=$(fetch_cloop); then
  echo "INSTALLED=$bin"
else
  echo REFUSED
fi
`
	out, err := runHarness(t, work, p, harness, []string{"MIRROR=" + mirror, "TEST_CHANNEL=" + channel})
	if err != nil {
		t.Fatalf("the harness itself failed: %v\n%s", err, out)
	}
	return out, work, strings.Contains(out, "INSTALLED=/usr/local/bin/cloop")
}

// runHarness sources the rendered script into harness under sh, with the stub
// cosign first on PATH and work/bin and work/path created.
func runHarness(t *testing.T, work string, p BootstrapParams, harness string, env []string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	for _, tool := range []string{"sha256sum", "tar", "install", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed: %v", tool, err)
		}
	}
	script := BootstrapScript(p)
	const invocation = "\nmain \"$@\"\n"
	if !strings.HasSuffix(script, invocation) {
		t.Fatalf("the bootstrap script does not end in %q", strings.TrimSpace(invocation))
	}
	writeFile(t, filepath.Join(work, "installer.sh"), []byte(strings.TrimSuffix(script, invocation)), 0o600)
	writeFile(t, filepath.Join(work, "harness.sh"), []byte(harness), 0o600)
	writeFile(t, filepath.Join(work, "path", "cosign"), []byte(stubCosign), 0o755)
	if err := os.MkdirAll(filepath.Join(work, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, filepath.Join(work, "harness.sh"), filepath.Join(work, "installer.sh"))
	cmd.Env = append(os.Environ(), "WORK="+work, "PATH="+filepath.Join(work, "path")+":"+os.Getenv("PATH"),
		"CLOOP_STUB_ARGS="+filepath.Join(work, "args.log"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// installedNothing reports what fetch_cloop left in the redirected
// /usr/local/bin: after a refusal, nothing — not the binary, not its stage.
func installedNothing(t *testing.T, work string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(work, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("a refused install left %s in /usr/local/bin", e.Name())
	}
}

// TestBootstrapStableInstallsAReleaseThatKeepsUp: the latest release, verified
// against the release identity and checksums.txt, is installed when it speaks
// the hub's protocol — or a newer one.
func TestBootstrapStableInstallsAReleaseThatKeepsUp(t *testing.T) {
	for _, proto := range []int{channelHubProto, channelHubProto + 1} {
		t.Run(fmt.Sprintf("v%d", proto), func(t *testing.T) {
			mirror := t.TempDir()
			stableMirror(t, mirror, stubCloop(t, releaseReport("v0.0.5", proto)), genuineSigningIdentity)
			out, work, ok := runFetch(t, channelScript(true), mirror, "stable")
			if !ok {
				t.Fatalf("the latest release was not installed:\n%s", out)
			}
			for _, want := range []string{
				"verified the signature on cloop_linux_amd64.tar.gz",
				"verified the signature on checksums.txt",
				"verified cloop_linux_amd64.tar.gz",
				fmt.Sprintf("the latest release (v0.0.5) speaks executor protocol v%d; this hub speaks v21", proto),
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the output does not say %q:\n%s", want, out)
				}
			}
			if _, err := os.Stat(filepath.Join(work, "bin", "cloop")); err != nil {
				t.Errorf("no cloop in /usr/local/bin: %v", err)
			}
		})
	}
}

// TestBootstrapRefusesAReleaseBehindTheHub is the defect this task closes: a
// hub at protocol v21 handed devices v0.0.4, which speaks v13. The release is
// refused before it takes the name cloop, and the refusal names both protocols
// and the way forward — --channel edge when the hub's build is published, a
// build of the hub's source otherwise.
func TestBootstrapRefusesAReleaseBehindTheHub(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edge   bool
		remedy []string
	}{
		{"the hub's build is published", true, []string{
			"re-run this installer with --channel edge to install that build (commit " + channelHubCommit + ")",
		}},
		{"the hub's build is not published", false, []string{
			"No signed build of this hub's protocol can be downloaded: CI has not published commit a0f3870 yet",
			"CLOOP_BIN=/path/to/cloop",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mirror := t.TempDir()
			stableMirror(t, mirror, stubCloop(t, releaseReport("v0.0.4", 13)), genuineSigningIdentity)
			out, work, ok := runFetch(t, channelScript(tc.edge), mirror, "stable")
			if ok || !strings.Contains(out, "REFUSED") {
				t.Fatalf("a release speaking v13 was installed for a hub at v21:\n%s", out)
			}
			want := append([]string{
				"the latest release (v0.0.4) speaks executor protocol v13, older than this hub's v21 (dev+ga0f3870)",
				"Refusing to install it.",
			}, tc.remedy...)
			for _, w := range want {
				if !strings.Contains(out, w) {
					t.Errorf("the refusal does not say %q:\n%s", w, out)
				}
			}
			installedNothing(t, work)
		})
	}
}

// TestBootstrapEdgeInstallsTheHubsOwnBuild: --channel edge fetches the
// commit-named archive the hub named, verifies it and its manifest against the
// edge workflow's identity, checks the manifest lists its bytes and the binary
// reports the commit, and installs it.
func TestBootstrapEdgeInstallsTheHubsOwnBuild(t *testing.T) {
	mirror := t.TempDir()
	edgeMirror(t, mirror, channelHubCommit, stubCloop(t, edgeBuildReport(channelHubProto, channelHubCommit)),
		edgeManifestOpts{})
	out, work, ok := runFetch(t, channelScript(true), mirror, "edge")
	if !ok {
		t.Fatalf("the hub's edge build was not installed:\n%s", out)
	}
	archive := upgrade.EdgeArchiveName(channelHubCommit, "linux", "amd64")
	for _, want := range []string{
		"downloading http://mirror.test/edge/" + archive,
		"verified the signature on " + archive,
		"verified the signature on " + upgrade.EdgeManifestV2Name(channelHubCommit),
		"verified " + archive + " against the edge manifest",
		"the edge build reports commit " + channelHubCommit,
		"speaks executor protocol v21",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "bin", "cloop")); err != nil {
		t.Errorf("no cloop in /usr/local/bin: %v", err)
	}
}

// TestBootstrapEdgeRefusesAnythingButTheHubsBuild: each way an edge download
// can fail to be the hub's own signed build is refused, and nothing is
// installed.
func TestBootstrapEdgeRefusesAnythingButTheHubsBuild(t *testing.T) {
	other := "1111111020b4df29e9f39ebe0369ec0de0ca8c67"
	for _, tc := range []struct {
		name   string
		report stubVersion
		opts   edgeManifestOpts
		says   string
	}{
		{"signed by the release workflow", edgeBuildReport(21, channelHubCommit),
			edgeManifestOpts{identity: genuineSigningIdentity}, "SIGNATURE VERIFICATION FAILED"},
		{"a manifest for another commit", edgeBuildReport(21, channelHubCommit),
			edgeManifestOpts{manifestCommit: other}, "the edge manifest does not describe commit " + channelHubCommit},
		{"bytes the manifest does not list", edgeBuildReport(21, channelHubCommit),
			edgeManifestOpts{wrongHash: true}, "checksum mismatch"},
		{"a binary of another commit", edgeBuildReport(21, other), edgeManifestOpts{},
			"the edge build reports commit " + other + ", not " + channelHubCommit},
		{"a build behind the hub", edgeBuildReport(20, channelHubCommit), edgeManifestOpts{},
			"speaks executor protocol v20, older than this hub's v21"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mirror := t.TempDir()
			edgeMirror(t, mirror, channelHubCommit, stubCloop(t, tc.report), tc.opts)
			out, work, ok := runFetch(t, channelScript(true), mirror, "edge")
			if ok || !strings.Contains(out, "REFUSED") {
				t.Fatalf("installed:\n%s", out)
			}
			if !strings.Contains(out, tc.says) {
				t.Errorf("the refusal does not say %q:\n%s", tc.says, out)
			}
			installedNothing(t, work)
		})
	}
}

// TestBootstrapStableRefusesAnEdgeBuildAsARelease: the two pins are separate.
// An edge build published under a release's name is not a release.
func TestBootstrapStableRefusesAnEdgeBuildAsARelease(t *testing.T) {
	mirror := t.TempDir()
	stableMirror(t, mirror, stubCloop(t, edgeBuildReport(21, channelHubCommit)), edgeSigningIdentity)
	out, work, ok := runFetch(t, channelScript(true), mirror, "stable")
	if ok || !strings.Contains(out, "SIGNATURE VERIFICATION FAILED") {
		t.Fatalf("an edge-signed archive passed as a release:\n%s", out)
	}
	installedNothing(t, work)
}

// TestBootstrapHoldsABinaryAlreadyHereToTheHub: a cloop already on the device,
// or CLOOP_BIN, is used rather than replaced — and refused when it speaks an
// older protocol than the hub, including one too old to say which it speaks.
func TestBootstrapHoldsABinaryAlreadyHereToTheHub(t *testing.T) {
	for _, tc := range []struct {
		name     string
		report   stubVersion
		accepted bool
		says     []string
	}{
		{"level with the hub", releaseReport("v0.0.5", 21), true, []string{"speaks executor protocol v21"}},
		{"ahead of the hub", releaseReport("v0.0.6", 22), true, []string{"speaks executor protocol v22"}},
		{"behind the hub", releaseReport("v0.0.4", 13), false, []string{
			"CLOOP_BIN (", "(v0.0.4) speaks executor protocol v13, older than this hub's v21",
			"Remove or rename it so this script downloads a cloop instead",
			"re-run this installer with --channel edge",
		}},
		{"too old to say", stubVersion{Version: "v0.0.1", Protocol: -1}, false, []string{
			"does not report its executor protocol (a cloop too old to say)",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			stub := filepath.Join(work, "stub", "cloop")
			writeFile(t, stub, []byte(stubCloop(t, tc.report)), 0o755)
			harness := `set -eu
. "$1"
if bin=$(find_or_fetch_cloop); then echo "USING=$bin"; else echo REFUSED; fi
`
			out, err := runHarness(t, work, channelScript(true), harness, []string{"CLOOP_BIN=" + stub})
			if err != nil {
				t.Fatalf("harness: %v\n%s", err, out)
			}
			if got := strings.Contains(out, "USING="+stub); got != tc.accepted {
				t.Fatalf("accepted = %t, want %t:\n%s", got, tc.accepted, out)
			}
			for _, w := range tc.says {
				if !strings.Contains(out, w) {
					t.Errorf("the output does not say %q:\n%s", w, out)
				}
			}
		})
	}
}

// TestBootstrapChannelIsTheOperatorsChoice: main passes --channel edge to the
// agent installer exactly when the operator wrote it, and refuses it on a hub
// with no edge build to install, saying why.
func TestBootstrapChannelIsTheOperatorsChoice(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edge     bool
		args     string
		ok       bool
		channel  bool
		saysWhat string
	}{
		{"no flag installs on the stable channel", true, "", true, false, "done."},
		{"--channel edge puts the device on the edge channel", true, "--channel edge", true, true,
			"this device follows the edge channel"},
		{"--channel=edge too", true, "--channel=edge", true, true, "this device follows the edge channel"},
		{"--channel stable is the default", true, "--channel stable", true, false, "done."},
		{"--channel edge with no edge build is refused", false, "--channel edge", false, false,
			"--channel edge installs this hub's own build from the edge channel, and there is none to install: " +
				"CI has not published commit a0f3870 yet"},
		{"an unknown channel is refused", true, "--channel nightly", false, false, "unknown channel: nightly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			stub := filepath.Join(work, "stub", "cloop")
			writeFile(t, stub, []byte(stubCloop(t, edgeBuildReport(21, channelHubCommit))), 0o755)
			harness := `set -eu
. "$1"
id() { echo 0; }
find_or_fetch_cloop() { echo "$STUB"; }
if (main $TEST_ARGS); then echo MAIN-OK; else echo MAIN-REFUSED; fi
`
			out, err := runHarness(t, work, channelScript(tc.edge), harness, []string{
				"STUB=" + stub, "TEST_ARGS=" + tc.args, "CLOOP_ENROLL_BUNDLE=cloopenroll1.test"})
			if err != nil {
				t.Fatalf("harness: %v\n%s", err, out)
			}
			if got := strings.Contains(out, "MAIN-OK"); got != tc.ok {
				t.Fatalf("main succeeded = %t, want %t:\n%s", got, tc.ok, out)
			}
			if !strings.Contains(out, tc.saysWhat) {
				t.Errorf("the output does not say %q:\n%s", tc.saysWhat, out)
			}
			args, _ := os.ReadFile(filepath.Join(work, "args.log"))
			if !tc.ok {
				if len(args) != 0 {
					t.Errorf("the agent installer ran after a refusal: %s", args)
				}
				return
			}
			if !strings.Contains(string(args), "executor agent install --output systemd") {
				t.Fatalf("the agent installer was not run as expected: %q", args)
			}
			if got := strings.Contains(string(args), "--channel edge"); got != tc.channel {
				t.Errorf("--channel edge passed = %t, want %t: %s", got, tc.channel, args)
			}
		})
	}
}

// TestBootstrapEdgeURLMatchesUpgrade: the script downloads edge builds from
// where pkg/upgrade says they are published.
func TestBootstrapEdgeURLMatchesUpgrade(t *testing.T) {
	if want := strings.TrimSuffix(upgrade.EdgeAssetURL(""), "/"); edgeReleasesURL != want {
		t.Errorf("install.sh downloads edge builds from %s, pkg/upgrade from %s", edgeReleasesURL, want)
	}
}

// TestBootstrapScriptCarriesTheHubsBuild: the hub's protocol and edge build
// are rendered as plain assignments the device's environment cannot change,
// and anything that is not a full commit is not rendered as one.
func TestBootstrapScriptCarriesTheHubsBuild(t *testing.T) {
	body := BootstrapScript(channelScript(true))
	for _, want := range []string{
		"\nCLOOP_HUB_PROTOCOL=21\n",
		"\nCLOOP_HUB_VERSION=dev+ga0f3870\n",
		"\nCLOOP_EDGE_COMMIT=" + channelHubCommit + "\n",
		"\nCLOOP_CHANNEL=stable\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the script does not carry %q", strings.TrimSpace(want))
		}
	}
	p := channelScript(true)
	p.EdgeCommit = "a0f3870; rm -rf /"
	if body := BootstrapScript(p); !strings.Contains(body, "\nCLOOP_EDGE_COMMIT=''\n") {
		t.Error("a value that is not a full commit was rendered as the edge commit")
	}
}
