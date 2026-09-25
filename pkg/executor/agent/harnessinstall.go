package agent

// Agent side of the harness-install frame: a device fetching the harness a
// project needs, from that harness's own official installer (Task 20336).
//
// # What the hub is and is not allowed to say
//
// The frame carries a harness *name*. This file owns the table that turns that
// name into a URL, and the table is a compile-time constant. A hub that has
// been taken over can therefore ask a device to install Claude Code from
// Anthropic and can ask for nothing else, because there is nothing else to ask
// for — an unknown name has no entry and is refused by name in the reply.
//
// The script is fetched here rather than by shelling out to `curl … | bash`,
// which is what the published instructions say and what a first draft writes.
// Four things are gained by not doing that, and each of them is a failure this
// code would otherwise have:
//
//   - The scheme and host are checked against the table entry after redirects
//     are resolved, so a DNS or CDN compromise that would redirect the download
//     elsewhere is refused instead of piped into a shell.
//   - The body is bounded. `curl | bash` streams into an interpreter that
//     begins executing before the response is complete, so a truncated or
//     hostile response runs its prefix; a file that is read fully and then run
//     cannot.
//   - curl need not be installed. It usually is, but "usually" on an edge
//     device is how a fleet acquires two classes of machine.
//   - The script's output is captured, so a failure can be reported to the hub
//     and rendered beside the device instead of scrolling past on a machine
//     nobody is logged into.
//
// # Running as the agent's user, never elevated
//
// The installer is invoked as whoever the agent is, with no privilege
// escalation anywhere in this file. That matches what the installer expects —
// Anthropic's documented install needs no root and writes only under the home
// directory — and it bounds this primitive: the worst an install can do is what
// the agent could already do. An agent running as root will install into root's
// home, which is consistent, because root's home is also where the payload it
// starts will look. See harnesspath.go for why "where it looks" needed work.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// harnessInstaller is one published installer: where it lives and what it
// leaves behind.
type harnessInstaller struct {
	// ScriptURL is the vendor's official install script. A constant in this
	// table and never a value from the wire — that is the security model of
	// the whole feature (see installproto.go).
	ScriptURL string
	// OriginSuffix bounds where that URL may redirect to: the vendor's own
	// domain and its subdomains, written with a leading dot.
	//
	// It exists because the published entry point is a redirector, and only
	// testing this against the live URL revealed it — https://claude.ai/
	// install.sh answers 302 to https://downloads.claude.ai/
	// claude-code-releases/bootstrap.sh. A check pinned to the *requested*
	// host, which is the obvious thing to write, would therefore have refused
	// the real installer on every device while passing every unit test that
	// used a fake one.
	//
	// So the rule is "inside the vendor's domain" rather than "the exact host
	// asked for". That still refuses the attack the check is for — an answer
	// for the vendor's host, or a poisoned CDN, redirecting to an origin the
	// vendor does not control — while surviving the vendor moving assets
	// between their own hosts, which they evidently do.
	OriginSuffix string
	// MirrorURLs are other official locations of the same script, tried in
	// order when ScriptURL does not serve it. Constants like ScriptURL, and
	// each must itself lie inside OriginSuffix, which TestEveryInstallerIsHTTPS
	// holds.
	//
	// They exist because a vendor's documented entry point and the place its
	// bytes live are often different hosts behind different edges, and the
	// entry point is the one more likely to turn a machine away. Found on a
	// real edge device (Task 20337): an Alibaba Cloud VM in Jakarta got HTTP
	// 403 from https://claude.ai/install.sh on every attempt — the claude.ai
	// website puts a Cloudflare bot challenge in front of datacenter address
	// ranges — while downloads.claude.ai, which that URL redirects to and which
	// the script itself downloads the binary from, answered 200. An executor is
	// very often exactly such a machine, so an installer that only knew the
	// entry point failed on the devices that need it most.
	//
	// A mirror is tried only when a source is *unavailable*. A source that was
	// refused on a safety rule stops the install; see errInstallSourceRefused.
	MirrorURLs []string
	// Binary is the command the install is expected to put on PATH, which is
	// what the post-install probe looks for. Named separately from the table
	// key because they are only incidentally equal today.
	Binary string
	// VersionArgs prints the installed version, used to report what landed.
	VersionArgs []string
}

// officialHarnessInstallers is the complete set of harnesses a device will
// install on the control plane's request.
//
// Only Claude Code is here, and the omissions are deliberate rather than
// pending. `cloop` itself is excluded because it already has a purpose-built
// path with a stronger guarantee — the upgrade frame, which verifies Sigstore
// provenance against a pinned identity — and routing it through a shell script
// instead would be a downgrade. codex and gemini are excluded because this
// table is an assertion that a URL is the vendor's official installer, and that
// assertion has to be made one harness at a time by someone who checked.
var officialHarnessInstallers = map[string]harnessInstaller{
	// Documented at https://code.claude.com/docs/en/setup as
	// `curl -fsSL https://claude.ai/install.sh | bash`.
	//
	// It installs to ~/.local/bin/claude with the versions it manages under
	// ~/.local/share/claude, needs no root, and requires bash and a downloader
	// on the device. The first of those is why harnesspath.go exists.
	"claude": {
		ScriptURL: "https://claude.ai/install.sh",
		// Observed to redirect to downloads.claude.ai; see OriginSuffix.
		OriginSuffix: ".claude.ai",
		// Where ScriptURL redirects to, fetched directly. It is the same
		// script served by the host the script downloads the binary from, so
		// a device that can use the install at all can reach it; see
		// MirrorURLs for the device that could not reach ScriptURL.
		MirrorURLs:  []string{"https://downloads.claude.ai/claude-code-releases/bootstrap.sh"},
		Binary:      "claude",
		VersionArgs: []string{"--version"},
	},
}

// sources lists where the installer may be fetched from, in the order to try
// them: the documented entry point first, then its mirrors.
func (h harnessInstaller) sources() []string {
	return append([]string{h.ScriptURL}, h.MirrorURLs...)
}

const (
	// maxInstallScriptBytes bounds the script body. Real install scripts are a
	// few tens of kilobytes; this is generous enough never to reject one and
	// small enough that a hostile or malfunctioning endpoint cannot make the
	// device buffer a response until it dies.
	maxInstallScriptBytes = 2 << 20 // 2 MiB

	// installScriptFetchTimeout bounds retrieving the script itself.
	installScriptFetchTimeout = 60 * time.Second

	// installRunTimeout bounds the script's own execution. Generous because
	// the script downloads a platform binary of its own over a link that may
	// be an edge device's uplink, and a timeout that fires mid-download would
	// leave a half-installed harness for the next probe to misread.
	installRunTimeout = 15 * time.Minute

	// installOutputExcerpt bounds how much of a failed script's output is
	// reported back. Enough to carry the error line a shell script ends on,
	// bounded because this string is rendered in the UI beside a device.
	installOutputExcerpt = 2000
)

// ErrNoOfficialInstaller reports that a harness has no entry in the table
// above, and so cannot be installed on request.
var ErrNoOfficialInstaller = errors.New("agent: no official installer for this harness")

// errInstallSourceRefused marks a fetch that a safety rule stopped — a
// downgrade to plaintext, a redirect off the vendor's domain, a body larger
// than any installer — as opposed to a source that simply did not serve the
// script.
//
// The distinction decides whether the next source is tried. Unavailability is
// a property of one host and says nothing about the others, so falling through
// to a mirror is the right answer to it. A safety refusal is evidence that
// something between the device and the vendor is interfering, and routing
// around it would turn a refusal into a retry an attacker gets to keep
// playing; it ends the install and is reported as it is.
var errInstallSourceRefused = errors.New("refused")

// installScriptFetcher retrieves an install script. Indirected through a
// variable so tests can serve their own script without reaching the network;
// production always uses fetchInstallScript.
var installScriptFetcher = fetchInstallScript

// handleInstallHarness serves a TypeInstallHarness frame.
//
// Synchronous, unlike handleUpgrade. Installing a harness does not restart the
// agent, so the session that carried the request is still alive to carry the
// answer — and the hub is holding a dispatch open waiting for exactly that. The
// hub's own context bounds the wait; see RequestHarnessInstall.
func (a *Agent) handleInstallHarness(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeInstallHarness(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}

	out := a.installHarness(ctx, payload)
	a.reply(ctx, sess, remote.TypeHarnessInstalled, frame.ID, "", out)
}

// installHarness performs the install and describes the result.
//
// It never returns an error: every failure is a HarnessInstalledPayload with
// Installed false and a Reason an operator can act on. The caller's job is to
// put that on the wire, and a Go error beside it would only give it two ways to
// say the same thing.
func (a *Agent) installHarness(
	ctx context.Context, p remote.InstallHarnessPayload,
) remote.HarnessInstalledPayload {
	out := remote.HarnessInstalledPayload{Harness: p.Harness}

	spec, ok := officialHarnessInstallers[p.Harness]
	if !ok {
		out.Reason = fmt.Sprintf(
			"%q has no official installer known to this agent (it knows: %s), so there is "+
				"nothing it can be asked to run; install it on the device by hand",
			p.Harness, strings.Join(knownInstallerNames(), ", "))
		return out
	}

	// Already present is a success, not a no-op to report as failure. Two
	// dispatches for the same device can race here, and the second one asking
	// "can you run claude now" deserves "yes" rather than an error about work
	// it did not need to do.
	if path, err := exec.LookPath(spec.Binary); err == nil {
		out.Installed = true
		out.AlreadyPresent = true
		out.Path = path
		out.Version = a.harnessVersion(ctx, path, spec.VersionArgs)
		return out
	}

	// bash specifically, not sh: the published script is bash and the devices
	// most likely to need this are the ones where /bin/sh is dash or BusyBox
	// ash. Checked up front so the refusal names the package to install
	// instead of surfacing as a syntax error from the middle of a vendor
	// script.
	bash, err := exec.LookPath("bash")
	if err != nil {
		out.Reason = fmt.Sprintf(
			"the %s installer is a bash script and this device has no bash on PATH; install "+
				"bash (on Alpine: `apk add bash curl`) and retry", p.Harness)
		return out
	}

	// A home directory the installer can write to. Checked here because the
	// script resolves ~ itself: with HOME unset — which is how some service
	// managers start a unit — it would install into /.local/bin, succeed, and
	// leave a binary in a directory nothing will ever look in.
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		out.Reason = "this agent has no HOME set, and the installer writes into the home " +
			"directory; set HOME in the agent's service unit and retry"
		return out
	}

	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		reason = "requested by the control plane"
	}
	a.logf("harness install: fetching the official %s installer from %s (%s)",
		p.Harness, spec.ScriptURL, reason)

	script, err := a.fetchFirstAvailable(ctx, spec)
	if err != nil {
		out.Reason = fmt.Sprintf("fetching the official %s installer: %v", p.Harness, err)
		return out
	}

	if err := a.runInstallScript(ctx, bash, script, home); err != nil {
		out.Reason = fmt.Sprintf("the official %s installer failed: %v", p.Harness, err)
		return out
	}

	// The installer writes into ~/.local/bin, which is not on a service
	// manager's PATH — so the probe below would fail on a perfectly successful
	// install without this. See harnesspath.go.
	if added := EnsureHarnessPath(); len(added) > 0 {
		a.logf("harness install: added %s to this agent's PATH", strings.Join(added, ", "))
	}

	path, err := exec.LookPath(spec.Binary)
	if err != nil {
		out.Reason = fmt.Sprintf(
			"the official %s installer reported success but %q is still not on this agent's "+
				"PATH (searched %s); the install may have landed somewhere this agent cannot "+
				"see, so check it on the device with `%s --version`",
			p.Harness, spec.Binary, os.Getenv("PATH"), spec.Binary)
		return out
	}

	out.Installed = true
	out.Path = path
	out.Version = a.harnessVersion(ctx, path, spec.VersionArgs)
	a.logf("harness install: installed %s at %s (%s)", p.Harness, path, displayOrUnknown(out.Version))
	return out
}

// fetchFirstAvailable fetches the installer from the first of spec's sources
// that serves it.
//
// On failure the error names every source tried and what each answered, in
// order — the only way an operator can tell "this device cannot reach the
// vendor at all" from "the entry point turned it away and the mirror was fine
// until yesterday".
func (a *Agent) fetchFirstAvailable(ctx context.Context, spec harnessInstaller) (string, error) {
	sources := spec.sources()
	attempts := make([]string, 0, len(sources))
	for i, src := range sources {
		if i > 0 {
			a.logf("harness install: %s; trying %s", attempts[len(attempts)-1], src)
		}
		script, err := installScriptFetcher(ctx, src, spec.OriginSuffix)
		if err == nil {
			return script, nil
		}
		attempts = append(attempts, fmt.Sprintf("%s: %v", src, err))
		if errors.Is(err, errInstallSourceRefused) || ctx.Err() != nil {
			// A safety refusal is final (see errInstallSourceRefused), and a
			// cancelled dispatch has nobody left to install for.
			break
		}
	}
	return "", errors.New(strings.Join(attempts, "; "))
}

// runInstallScript writes the script to a private file and runs it.
//
// A file rather than a pipe into bash's stdin, because a script read from a
// pipe cannot be re-read — and these installers commonly re-exec themselves or
// seek. The directory is 0700 and removed however this ends: a world-readable
// script in /tmp that root is about to execute is a local privilege escalation
// waiting for a second process to notice the window.
func (a *Agent) runInstallScript(ctx context.Context, bash, script, home string) error {
	dir, err := os.MkdirTemp("", "cloop-harness-install-")
	if err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("securing the staging directory: %w", err)
	}

	path := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return fmt.Errorf("writing the installer: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, installRunTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, bash, path)
	cmd.Dir = dir
	// An explicit environment rather than the agent's own. The agent's holds
	// its enrollment credential and whatever else the service unit set, and a
	// vendor script has no business reading either. HOME and PATH are what an
	// installer needs; PATH is the agent's so the script can find the
	// downloader and coreutils it shells out to.
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("it did not finish within %s; %s", installRunTimeout,
				excerpt(string(output)))
		}
		return fmt.Errorf("%w; %s", err, excerpt(string(output)))
	}
	return nil
}

// fetchInstallScript retrieves the script over HTTPS, refusing anything that
// leaves the vendor domain the table named.
//
// The final URL is checked, not the requested one. A redirect is the whole
// point of the check: an attacker who can answer for the vendor's host, or
// poison a CDN in front of it, redirects to their own origin — and a client
// that validated only what it asked for would follow along and hand the result
// to a shell.
func fetchInstallScript(ctx context.Context, rawURL, originSuffix string) (string, error) {
	want, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("the installer URL is unparseable: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, installScriptFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if final := resp.Request.URL; final != nil {
		// Stated as "must not downgrade" rather than "must be HTTPS", and the
		// two are the same rule here: every entry in the installer table is
		// HTTPS, which TestEveryInstallerIsHTTPS holds, so a redirect that does
		// not downgrade cannot be plaintext in production. Expressed relative
		// to the request because that is what makes the redirect rules
		// exercisable against a local test server — and a check that can only
		// be tested in production is a check nobody tests.
		if want.Scheme == "https" && final.Scheme != "https" {
			return "", fmt.Errorf(
				"%w: it redirected from https to %s; refusing to run a script fetched over a "+
					"connection that could have been rewritten in transit",
				errInstallSourceRefused, final.Scheme)
		}
		if !withinOrigin(final.Hostname(), want.Hostname(), originSuffix) {
			return "", fmt.Errorf(
				"%w: it redirected from %s to %s, which is outside %s; refusing to run a "+
					"script from an origin the vendor does not control",
				errInstallSourceRefused, want.Hostname(), final.Hostname(), originSuffix)
		}
	}
	if resp.StatusCode != http.StatusOK {
		if isBotChallenge(resp) {
			// Said outright because the bare status reads as "forbidden" — a
			// permissions problem to go looking for — when what happened is
			// that the site's edge screened this network and wanted a browser.
			return "", fmt.Errorf("the server answered HTTP %d with a Cloudflare bot challenge "+
				"(the site is screening this device's network, as it commonly does for "+
				"datacenter address ranges)", resp.StatusCode)
		}
		return "", fmt.Errorf("the server answered HTTP %d", resp.StatusCode)
	}

	// One byte over the cap so a script that is exactly at it is distinguished
	// from one that was truncated by the reader.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInstallScriptBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxInstallScriptBytes {
		return "", fmt.Errorf("%w: the script is larger than %d bytes, which no real installer is",
			errInstallSourceRefused, maxInstallScriptBytes)
	}
	if len(body) == 0 {
		return "", errors.New("the server returned an empty script")
	}
	return string(body), nil
}

// isBotChallenge reports whether a refusal came from a Cloudflare bot check
// rather than from the application behind it. Cloudflare marks a challenge it
// served with `cf-mitigated: challenge`, which is documented for exactly this:
// telling a challenge apart from an origin's own 403.
func isBotChallenge(resp *http.Response) bool {
	return strings.EqualFold(strings.TrimSpace(resp.Header.Get("Cf-Mitigated")), "challenge")
}

// withinOrigin reports whether a redirect landed somewhere the vendor controls:
// the host originally asked for, or the declared domain and its subdomains.
//
// Comparison is case-insensitive, which DNS is. The suffix must be written with
// a leading dot and is matched as one, so a suffix of ".claude.ai" admits
// downloads.claude.ai and refuses evilclaude.ai — the substring match that
// would not is the classic way this check is written wrong.
//
// An empty suffix falls back to an exact host match. That is the strict
// reading, and it is the right default for a table entry whose author has not
// said where the vendor may redirect.
func withinOrigin(host, requested, suffix string) bool {
	if strings.EqualFold(host, requested) {
		return true
	}
	suffix = strings.TrimSpace(suffix)
	if suffix == "" || !strings.HasPrefix(suffix, ".") {
		return false
	}
	host = strings.ToLower(host)
	suffix = strings.ToLower(suffix)
	// The bare domain as well as its subdomains: ".claude.ai" admits
	// "claude.ai" itself, which is the host the entry names in the first place.
	return host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix)
}

// harnessVersion asks the freshly installed binary what it is, for the report.
//
// Best effort: a harness that cannot be version-probed is still installed, and
// failing the install over a cosmetic field would be absurd. The short timeout
// is because this is a `--version` call — anything slower than a second is a
// binary that is doing something other than printing its version.
func (a *Agent) harnessVersion(ctx context.Context, path string, args []string) string {
	if len(args) == 0 {
		return ""
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(probeCtx, path, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(firstLine(string(out)))
}

// knownInstallerNames lists the table's keys for a refusal message, sorted so
// the text is stable across runs and across Go's map iteration order.
func knownInstallerNames() []string {
	names := make([]string, 0, len(officialHarnessInstallers))
	for name := range officialHarnessInstallers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// excerpt renders a failed script's output for a one-line reason, keeping the
// tail rather than the head: a shell script's useful output is the error it
// died on, and that is the last thing it printed.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "it produced no output"
	}
	if len(s) > installOutputExcerpt {
		s = "…" + s[len(s)-installOutputExcerpt:]
	}
	return "it said: " + s
}

func displayOrUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "version unknown"
	}
	return s
}
