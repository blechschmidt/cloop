package agent

// Device-side tests for automatic harness installation (Task 20336).
//
// # Why every test here rebuilds PATH from scratch
//
// The machine that runs this suite is a cloop development host, and a cloop
// development host has claude installed — at /usr/bin/claude, at
// /usr/local/bin/claude and at ~/.local/bin/claude, all three. A test that
// inherited the ambient PATH would take the already-present branch on the very
// first line and pass without exercising anything, and it would go on passing
// if the install path were deleted outright.
//
// So each test builds a PATH containing exactly the tools the installer needs
// and nothing else. `installerSandbox` is that setup, and the assertion it
// makes first — that claude is *not* resolvable — is load-bearing rather than
// defensive: without it these tests are theatre.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// installerSandbox points PATH at a directory holding only the binaries a
// vendor install script needs, and returns that directory.
//
// It also gives the test its own HOME. TestMain already moves HOME off the real
// one for the whole package, but that is a single directory shared by every
// test in the binary — so an install performed by one test stays in
// ~/.local/bin and is found by the next one through EnsureHarnessPath, which
// made a test that asserts "the script installed nothing" pass for the wrong
// reason and then fail for the wrong reason. Per-test is the only hermetic
// answer when the thing under test writes to the home directory.
func installerSandbox(t *testing.T) string {
	t.Helper()

	t.Setenv("HOME", t.TempDir())

	bin := t.TempDir()
	for _, tool := range []string{"bash", "mkdir", "chmod"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("this environment has no %s, which a vendor install script needs", tool)
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatalf("link %s into the sandbox: %v", tool, err)
		}
	}

	// t.Setenv restores the real PATH on cleanup, which matters because
	// EnsureHarnessPath mutates the process environment and this binary's
	// other tests run in the same process.
	t.Setenv("PATH", bin)

	if p, err := exec.LookPath("claude"); err == nil {
		t.Fatalf("the sandbox PATH still resolves claude at %s; these tests would pass "+
			"without testing anything", p)
	}
	return bin
}

// fakeInstaller makes installScriptFetcher serve a script of the test's
// choosing, restoring the real one afterwards.
func fakeInstaller(t *testing.T, script string) {
	t.Helper()
	prev := installScriptFetcher
	installScriptFetcher = func(context.Context, string, string) (string, error) { return script, nil }
	t.Cleanup(func() { installScriptFetcher = prev })
}

// installsClaudeScript writes a stand-in claude to the location Anthropic's
// real installer uses, so the post-install probe is exercised against the same
// directory layout production will produce.
//
// printf and the redirect are bash builtins rather than coreutils, because the
// sandbox PATH deliberately holds only what a real installer needs — and
// discovering that `cat` was missing is the point of building it that way.
const installsClaudeScript = `#!/bin/bash
set -e
mkdir -p "$HOME/.local/bin"
printf '%s\n' '#!/bin/sh' 'echo "9.9.9 (Claude Code)"' > "$HOME/.local/bin/claude"
chmod +x "$HOME/.local/bin/claude"
`

// TestInstallPutsTheHarnessSomewhereThePayloadCanFindIt is the whole feature in
// one assertion, and the assertion is deliberately not "the file exists".
//
// A test that checked only for ~/.local/bin/claude would have passed against
// the first draft of this code, which installed the harness correctly and left
// it invisible: that directory is not on a service manager's PATH, so
// exec.LookPath kept failing and the dispatch kept being refused — with a
// successful install now in front of the refusal to make it baffling. What has
// to be true is that the binary is *resolvable by name*, because that is how
// `cloop run` inside the payload will look for it.
func TestInstallPutsTheHarnessSomewhereThePayloadCanFindIt(t *testing.T) {
	installerSandbox(t)
	fakeInstaller(t, installsClaudeScript)

	a := &Agent{}
	out := a.installHarness(context.Background(), remote.InstallHarnessPayload{Harness: "claude"})

	if !out.Installed {
		t.Fatalf("Installed = false, Reason = %q", out.Reason)
	}
	if out.AlreadyPresent {
		t.Error("AlreadyPresent = true for a harness the script had to install")
	}
	resolved, err := exec.LookPath("claude")
	if err != nil {
		t.Fatalf("claude is installed but still not resolvable by name: %v", err)
	}
	if out.Path != resolved {
		t.Errorf("reported Path %q, but the name resolves to %q", out.Path, resolved)
	}
	if !strings.Contains(out.Version, "9.9.9") {
		t.Errorf("Version = %q, want the version the installed binary prints", out.Version)
	}
	// The reported path is what an operator debugging PATH reads, so it has to
	// be the real location rather than a bare name.
	if !filepath.IsAbs(out.Path) {
		t.Errorf("Path = %q, want an absolute path", out.Path)
	}
}

// TestAnAlreadyInstalledHarnessIsASuccess covers two dispatches racing for one
// device. The second asked "can you run claude now", and the answer is yes —
// reporting a failure because there was no work to do would refuse a dispatch
// that should proceed.
func TestAnAlreadyInstalledHarnessIsASuccess(t *testing.T) {
	bin := installerSandbox(t)
	writeStubBinary(t, filepath.Join(bin, "claude"), "1.2.3 (Claude Code)")

	// Any attempt to fetch is a bug: the harness is already here.
	prev := installScriptFetcher
	installScriptFetcher = func(context.Context, string, string) (string, error) {
		t.Error("fetched an installer for a harness that was already present")
		return "", errors.New("should not be called")
	}
	t.Cleanup(func() { installScriptFetcher = prev })

	a := &Agent{}
	out := a.installHarness(context.Background(), remote.InstallHarnessPayload{Harness: "claude"})

	if !out.Installed || !out.AlreadyPresent {
		t.Fatalf("Installed = %v, AlreadyPresent = %v; want both true (Reason %q)",
			out.Installed, out.AlreadyPresent, out.Reason)
	}
}

// TestAnUnknownHarnessIsRefusedByName is the security boundary stated as
// behaviour.
//
// The hub names a harness; this device turns names into URLs from a table
// compiled into it. A name with no entry has no installer, and the refusal
// lists what the device does know so the operator can see the difference
// between "not supported" and "misspelled".
func TestAnUnknownHarnessIsRefusedByName(t *testing.T) {
	installerSandbox(t)

	prev := installScriptFetcher
	installScriptFetcher = func(context.Context, string, string) (string, error) {
		t.Error("fetched an installer for a harness with no table entry")
		return "", errors.New("should not be called")
	}
	t.Cleanup(func() { installScriptFetcher = prev })

	a := &Agent{}
	out := a.installHarness(context.Background(),
		remote.InstallHarnessPayload{Harness: "definitely-not-a-harness"})

	if out.Installed {
		t.Fatal("Installed = true for a harness with no official installer")
	}
	for _, want := range []string{"definitely-not-a-harness", "claude"} {
		if !strings.Contains(out.Reason, want) {
			t.Errorf("Reason should mention %q; got %q", want, out.Reason)
		}
	}
}

// TestOnlyClaudeIsInstallable pins the table's contents, because its
// membership is an assertion someone has to make deliberately.
//
// cloop is absent on purpose: it already has the upgrade frame, which verifies
// Sigstore provenance against a pinned identity, and routing it through a shell
// script would be a downgrade dressed up as a convenience.
func TestOnlyClaudeIsInstallable(t *testing.T) {
	if len(officialHarnessInstallers) != 1 {
		t.Fatalf("installer table = %v; adding an entry means asserting that a URL is that "+
			"vendor's official installer, which needs a human who checked",
			knownInstallerNames())
	}
	spec, ok := officialHarnessInstallers["claude"]
	if !ok {
		t.Fatal("the claude entry is missing")
	}
	// The exact URL Anthropic documents at code.claude.com/docs/en/setup. A
	// change here is a change to what every device in every fleet downloads
	// and executes, so it should never pass unnoticed.
	if spec.ScriptURL != "https://claude.ai/install.sh" {
		t.Errorf("claude installer URL = %q, want the documented official installer",
			spec.ScriptURL)
	}
	if spec.OriginSuffix != ".claude.ai" {
		t.Errorf("claude OriginSuffix = %q; the published URL redirects to "+
			"downloads.claude.ai, so the vendor's domain has to be declared or the real "+
			"installer is refused on every device", spec.OriginSuffix)
	}
}

// TestEveryInstallerIsHTTPS is the invariant fetchInstallScript's no-downgrade
// rule relies on.
//
// That rule refuses a redirect from https to http. It is only equivalent to
// "the script always arrives over TLS" because every entry starts out https, so
// an http entry added here would silently turn the check off for that harness.
func TestEveryInstallerIsHTTPS(t *testing.T) {
	for name, spec := range officialHarnessInstallers {
		if !strings.HasPrefix(spec.ScriptURL, "https://") {
			t.Errorf("%s installer URL %q is not HTTPS; the response is piped into a shell",
				name, spec.ScriptURL)
		}
		if spec.OriginSuffix != "" && !strings.HasPrefix(spec.OriginSuffix, ".") {
			t.Errorf("%s OriginSuffix %q must start with a dot, or it is matched as a bare "+
				"substring and admits a lookalike domain", name, spec.OriginSuffix)
		}
	}
}

// TestAFailingScriptReportsWhatItSaid keeps the operator's only clue.
//
// A vendor script that dies says why on its last line — no downloader, no
// network, unsupported libc. Swallowing that and reporting "install failed"
// would leave an operator with a device to SSH into and nothing to look for.
func TestAFailingScriptReportsWhatItSaid(t *testing.T) {
	installerSandbox(t)
	fakeInstaller(t, "#!/bin/bash\necho 'curl: (6) Could not resolve host' >&2\nexit 6\n")

	a := &Agent{}
	out := a.installHarness(context.Background(), remote.InstallHarnessPayload{Harness: "claude"})

	if out.Installed {
		t.Fatal("Installed = true after the installer exited non-zero")
	}
	if !strings.Contains(out.Reason, "Could not resolve host") {
		t.Errorf("Reason should carry the script's own output; got %q", out.Reason)
	}
}

// TestAScriptThatSucceedsWithoutInstallingIsNotASuccess is the case that would
// otherwise produce the original bug with extra steps.
//
// If the probe were skipped and exit 0 taken as proof, the device would
// advertise a harness it does not have, the hub would place work on it, and the
// run would die with "executable file not found in $PATH" — the exact failure
// this whole line of work exists to remove.
func TestAScriptThatSucceedsWithoutInstallingIsNotASuccess(t *testing.T) {
	installerSandbox(t)
	fakeInstaller(t, "#!/bin/bash\necho 'all done'\nexit 0\n")

	a := &Agent{}
	out := a.installHarness(context.Background(), remote.InstallHarnessPayload{Harness: "claude"})

	if out.Installed {
		t.Fatal("Installed = true for a script that exited 0 and installed nothing")
	}
	if !strings.Contains(out.Reason, "still not on") {
		t.Errorf("Reason should say the binary is still not resolvable; got %q", out.Reason)
	}
}

// TestTheInstallerRunsWithoutTheAgentsOwnEnvironment keeps the agent's
// enrollment credential away from a vendor script.
//
// The agent's environment carries whatever its service unit set, and the
// enrollment token is in that class of value. A script fetched from the
// internet has no business reading it, so the child gets a constructed
// environment instead of an inherited one.
func TestTheInstallerRunsWithoutTheAgentsOwnEnvironment(t *testing.T) {
	installerSandbox(t)
	t.Setenv("CLOOP_AGENT_SECRET", "super-secret-enrollment-token")

	// The script writes its own view of the variable where the test can read it.
	leak := filepath.Join(t.TempDir(), "leak")
	fakeInstaller(t, fmt.Sprintf(
		"#!/bin/bash\nprintf '%%s' \"${CLOOP_AGENT_SECRET-}\" > %q\nexit 1\n", leak))

	a := &Agent{}
	_ = a.installHarness(context.Background(), remote.InstallHarnessPayload{Harness: "claude"})

	got, err := os.ReadFile(leak)
	if err != nil {
		t.Fatalf("the script did not run: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("the installer saw CLOOP_AGENT_SECRET=%q; it must not inherit the agent's "+
			"environment", got)
	}
}

// TestFetchRefusesARedirectOffTheVendorsOrigin is the check that makes "the hub
// cannot choose the bytes" true in practice.
//
// Pinning only the requested URL would be no protection at all: an attacker who
// can answer for the vendor's host, or poison a CDN in front of it, answers
// with a redirect — and a client that followed it would hand the result to a
// shell. The final URL is what gets checked.
func TestFetchRefusesARedirectOffTheVendorsOrigin(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!/bin/bash\necho pwned\n"))
	}))
	defer evil.Close()

	// Addressed as "localhost" while the vendor server is "127.0.0.1". Both
	// resolve to loopback, so the redirect is genuinely followed and the
	// refusal is the origin check firing rather than a connection failure
	// standing in for it — and the two are different *hostnames*, which is what
	// the check compares. Reusing httptest's own URL for both would compare
	// 127.0.0.1 against 127.0.0.1 and pass while testing nothing, which is
	// exactly what the first version of this test did.
	evilURL := strings.Replace(evil.URL, "127.0.0.1", "localhost", 1)

	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evilURL, http.StatusFound)
	}))
	defer vendor.Close()

	_, err := fetchInstallScript(context.Background(), vendor.URL, "")
	if err == nil {
		t.Fatal("a redirect to another origin was followed and the script accepted")
	}
	if !strings.Contains(err.Error(), "redirected") {
		t.Errorf("error should name the redirect; got %v", err)
	}
}

// TestFetchFollowsARedirectInsideTheVendorsDomain is the case that only showed
// up against the live URL, and would otherwise have shipped a feature that
// never once worked.
//
// https://claude.ai/install.sh is a redirector: it answers 302 to
// https://downloads.claude.ai/claude-code-releases/bootstrap.sh. The obvious
// check — pin the host that was asked for — passes every test written with a
// single-host fake server and refuses the real installer on every device in
// every fleet. So the rule is the vendor's *domain*, and this is the assertion
// that keeps it that way.
func TestFetchFollowsARedirectInsideTheVendorsDomain(t *testing.T) {
	const body = "#!/bin/bash\necho installed\n"

	// httptest serves on 127.0.0.1, so the hostnames are supplied directly to
	// withinOrigin below; here the concern is only that a cross-host redirect
	// is followed at all when the suffix permits it.
	if !withinOrigin("downloads.claude.ai", "claude.ai", ".claude.ai") {
		t.Fatal("a redirect from claude.ai to downloads.claude.ai must be allowed; " +
			"this is what the real installer does")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/install.sh" {
			http.Redirect(w, r, "/releases/bootstrap.sh", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := fetchInstallScript(context.Background(), srv.URL+"/install.sh", "")
	if err != nil {
		t.Fatalf("a same-host redirect was refused: %v", err)
	}
	if got != body {
		t.Errorf("fetched %q, want the redirected body", got)
	}
}

// TestWithinOrigin covers the suffix rule directly, including the substring
// mistake that is the classic way this check is written wrong.
func TestWithinOrigin(t *testing.T) {
	for _, tc := range []struct {
		host, requested, suffix string
		want                    bool
	}{
		{"claude.ai", "claude.ai", ".claude.ai", true},
		{"downloads.claude.ai", "claude.ai", ".claude.ai", true},
		{"a.b.claude.ai", "claude.ai", ".claude.ai", true},
		{"CLAUDE.AI", "claude.ai", ".claude.ai", true},
		// The one that matters: a domain that merely *ends with* the vendor's
		// name is a different registration and a different owner.
		{"evilclaude.ai", "claude.ai", ".claude.ai", false},
		{"claude.ai.evil.example", "claude.ai", ".claude.ai", false},
		{"evil.example", "claude.ai", ".claude.ai", false},
		// No suffix declared falls back to the strict exact-host rule.
		{"downloads.claude.ai", "claude.ai", "", false},
		{"claude.ai", "claude.ai", "", true},
	} {
		got := withinOrigin(tc.host, tc.requested, tc.suffix)
		if got != tc.want {
			t.Errorf("withinOrigin(%q, %q, %q) = %v, want %v",
				tc.host, tc.requested, tc.suffix, got, tc.want)
		}
	}
}

// TestFetchRefusesAnOversizedBody bounds what a malfunctioning or hostile
// endpoint can make the device buffer.
func TestFetchRefusesAnOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("A", 64<<10)
		for written := 0; written <= maxInstallScriptBytes; written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if _, err := fetchInstallScript(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("an oversized body was accepted as an install script")
	}
}

// TestFetchRefusesAnEmptyOrFailedResponse covers the two answers that are not
// a script. An empty body would otherwise be written out and run as a no-op
// script that exits 0 — which the probe would then have to catch, one layer
// later than it should.
func TestFetchRefusesAnEmptyOrFailedResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{"empty", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }},
		{"not found", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.h)
			defer srv.Close()
			if _, err := fetchInstallScript(context.Background(), srv.URL, ""); err == nil {
				t.Fatalf("a %s response was accepted as an install script", tc.name)
			}
		})
	}
}

// writeStubBinary creates an executable that prints a version, standing in for
// an already-installed harness.
func writeStubBinary(t *testing.T, path, version string) {
	t.Helper()
	body := "#!/bin/sh\necho \"" + version + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil { //nolint:gosec — a test stub that must be executable
		t.Fatalf("write stub %s: %v", path, err)
	}
}
