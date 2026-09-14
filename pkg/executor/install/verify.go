package install

// verify.go asks a staged cloop binary what it is, before an upgrade replaces a
// working agent with it (Task 20252).
//
// The previous flow hashed the new binary only to compare it with the old one
// and decide whether anything needed doing. A SHA-256 answers "are these the
// same bytes" and nothing else — a truncated download, a binary for the wrong
// architecture, and a text file all hash perfectly well, and all three were
// renamed over a running agent's binary and the service restarted. On a device
// an operator cannot reach again quickly, that turns a routine rollout into a
// site visit.
//
// The only honest check is to run the thing. A binary that cannot exec on this
// machine fails immediately and unambiguously (ENOEXEC), a truncated one fails
// the same way, and one that runs can be asked what it is. Everything else —
// inspecting ELF headers, trusting a filename, comparing sizes — is inference
// about a question the kernel will answer for free.
//
// Two properties shape the implementation:
//
//   - The probe must be cheap, bounded, and side-effect free. It runs with a
//     timeout, in a directory with no project in it, and against a subcommand
//     that deliberately skips cloop's root pre-run (see cmd/version.go). A
//     verification step that can hang is a verification step that turns into a
//     flag somebody passes to skip it.
//   - The fallback is as important as the check. `version --json` is new, so a
//     binary that predates it exits non-zero on the flag — which is information,
//     not failure. The probe falls back to the plain text form, which every
//     cloop has printed since there was a version command, and records that the
//     protocol numbers are unknown rather than inventing them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/version"
)

// ProbeTimeout bounds one execution of a candidate binary.
//
// Generous relative to what `cloop version` costs (milliseconds) because the
// failure it guards against is a binary that never returns at all, not a slow
// one. A device under memory pressure can take seconds to fault in a 40 MB
// executable, and killing a good binary for being slow would be the same class
// of mistake as installing a bad one.
const ProbeTimeout = 20 * time.Second

// ErrBinaryUnusable means the staged file is not a cloop binary this machine can
// run: it failed to execute, exited non-zero, timed out, or produced output that
// does not identify it.
//
// Deliberately *not* overridable by --force. --force means "replace even though
// the bytes are identical"; it has never meant "install something I have been
// shown is broken", and widening it to mean that would delete the only check
// standing between a truncated download and an offline device. There is no flag
// for this, because there is no case for it: a binary that will not run on this
// machine will not run after being renamed into place either.
var ErrBinaryUnusable = errors.New("install: the staged binary failed verification")

// ErrDowngrade means the staged binary is older than what is installed, or
// speaks a protocol the control plane no longer accepts.
//
// This one *is* overridable with --force, because a deliberate rollback is a
// real operation — an operator backing out a bad release needs it, and refusing
// outright would send them to `cp` and `systemctl`, bypassing every other check
// in this file.
var ErrDowngrade = errors.New("install: refusing to install an older build")

// BinaryIdentity is what a candidate binary said about itself.
type BinaryIdentity struct {
	// Version is the build version it reported, e.g. "v0.1.0" or
	// "dev+g4f7b5bc". Never empty for a successful probe.
	Version string
	// Protocol and MinProtocol are the executor-agent protocol versions it
	// speaks. Zero means it did not report them — a build older than the
	// machine-readable version report. Zero is "unknown", never "none": a
	// caller must not read it as "speaks no protocol".
	Protocol, MinProtocol int
	// OS and Arch are the platform it was built for, empty when unreported.
	OS, Arch string
	// Structured records that the machine-readable form was available, which
	// is what makes the protocol fields meaningful.
	Structured bool
}

// String renders an identity for an operator-facing message.
func (id BinaryIdentity) String() string {
	var b strings.Builder
	b.WriteString(id.Version)
	if id.OS != "" && id.Arch != "" {
		fmt.Fprintf(&b, " (%s/%s)", id.OS, id.Arch)
	}
	if id.Structured {
		fmt.Fprintf(&b, ", protocol v%d", id.Protocol)
	}
	return b.String()
}

// identify runs path and reads back what it claims to be.
//
// It tries the machine-readable form first and falls back to the text form, so
// a current binary yields protocol numbers and an older one still yields a
// version. Both failing is a verification failure, and the returned error names
// which of the several distinguishable causes it was — "exec format error" and
// "no such file" send an operator to completely different places.
func (in *Installer) identify(path string) (BinaryIdentity, error) {
	jsonOut, jsonErr := in.probe(path, "version", "--json")
	if errors.Is(jsonErr, errStagedProbe) {
		// Not a verification failure: this installer targets another machine.
		// Returned unwrapped so the caller can tell "skipped" from "failed";
		// folding it into ErrBinaryUnusable would report a check that was
		// never run as one the binary flunked.
		return BinaryIdentity{}, errStagedProbe
	}
	if jsonErr == nil {
		if id, ok := parseVersionJSON(jsonOut); ok {
			return id, nil
		}
	}

	textOut, textErr := in.probe(path, "version")
	if textErr == nil {
		if id, ok := parseVersionText(textOut); ok {
			return id, nil
		}
		return BinaryIdentity{}, fmt.Errorf(
			"%w: %s ran but did not identify itself as cloop.\n"+
				"It printed: %s\n"+
				"This is not the cloop binary — check what was copied to this device",
			ErrBinaryUnusable, path, firstLine(textOut))
	}

	// Both forms failed. The text run is the one to report: --json is expected
	// to fail on an older build, so its error is rarely the real cause.
	return BinaryIdentity{}, fmt.Errorf("%w: %s could not be run.\n%s\n"+
		"A binary that will not execute here will not execute after being installed. "+
		"Re-copy it to the device and check the transfer completed",
		ErrBinaryUnusable, path, describeProbeFailure(path, textOut, textErr))
}

// probe executes one candidate binary and returns its stdout.
//
// Stdout only: a cobra command that warns on stderr would otherwise corrupt the
// JSON, and the stderr that matters — a failing run's — is carried on the
// ExitError for describeProbeFailure to read.
func (in *Installer) probe(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
	defer cancel()

	if in.Exec != nil {
		return in.Exec(ctx, path, args...)
	}
	// A staged installer describes a device that is not this machine, so its
	// binary may legitimately be for another architecture and running it here
	// would be wrong even if it happened to work. Same rule as Installer.run.
	// Verification is skipped in that mode and Upgrade says so rather than
	// reporting a check it did not perform.
	if in.staged() {
		return nil, errStagedProbe
	}

	cmd := exec.CommandContext(ctx, path, args...)
	// A scratch directory, created empty and removed afterwards. cloop's root
	// pre-run reads the project config of whatever directory it starts in and
	// reconciles executors from it; `version` opts out of that (see
	// cmd/version.go), but an *older* binary predates the opt-out — and the
	// binaries this probe runs are older ones by definition. Running it
	// somewhere disposable means whatever an old build decides to create is
	// created somewhere nobody will find it later.
	dir, dirErr := os.MkdirTemp("", "cloop-verify-")
	if dirErr == nil {
		cmd.Dir = dir
		defer os.RemoveAll(dir)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if ctx.Err() != nil {
		return stdout.Bytes(), fmt.Errorf("timed out after %s", ProbeTimeout)
	}
	return stdout.Bytes(), err
}

// errStagedProbe marks the one case where verification is skipped rather than
// failed. Upgrade turns it into a reported fact, never into a refusal.
var errStagedProbe = errors.New("install: staged installer does not execute the candidate binary")

// parseVersionJSON reads the machine-readable report.
func parseVersionJSON(out []byte) (BinaryIdentity, bool) {
	var rep struct {
		Version     string `json:"version"`
		OS          string `json:"os"`
		Arch        string `json:"arch"`
		Protocol    int    `json:"protocol"`
		MinProtocol int    `json:"min_protocol"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &rep); err != nil {
		return BinaryIdentity{}, false
	}
	v := strings.TrimSpace(rep.Version)
	if v == "" {
		return BinaryIdentity{}, false
	}
	return BinaryIdentity{
		Version:     v,
		Protocol:    rep.Protocol,
		MinProtocol: rep.MinProtocol,
		OS:          strings.TrimSpace(rep.OS),
		Arch:        strings.TrimSpace(rep.Arch),
		Structured:  true,
	}, true
}

// parseVersionText reads the human form, whose first line has been
// "cloop <version>" since the command existed.
//
// The "cloop " prefix is the whole identity check for an older binary: anything
// else on this path — a shell script, a different tool, half a download that
// happens to exec — does not print it.
func parseVersionText(out []byte) (BinaryIdentity, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "cloop ")
		if !ok {
			continue
		}
		v := strings.TrimSpace(rest)
		if v == "" {
			return BinaryIdentity{}, false
		}
		return BinaryIdentity{Version: v}, true
	}
	return BinaryIdentity{}, false
}

// describeProbeFailure turns an exec failure into a sentence naming the likely
// cause, because the raw errors are opaque exactly when it matters most.
//
// "exec format error" is what a wrong-architecture binary and a truncated
// download both produce, and it is the failure this whole file exists to catch;
// an operator who sees it printed verbatim has to know that ENOEXEC means
// "wrong machine" to get anywhere.
func describeProbeFailure(path string, out []byte, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "exec format error"):
		return fmt.Sprintf("  %s is not a runnable binary on this device (%s/%s).\n"+
			"  Either it was built for another architecture, or the copy is truncated or corrupt.",
			path, runtime.GOOS, runtime.GOARCH)
	case errors.Is(err, exec.ErrNotFound), strings.Contains(msg, "no such file"):
		return fmt.Sprintf("  %s does not exist.", path)
	case strings.Contains(msg, "permission denied"):
		return fmt.Sprintf("  %s is not executable. chmod +x it, or re-copy it.", path)
	case strings.Contains(msg, "timed out"):
		return fmt.Sprintf("  %s did not return within %s. A cloop binary prints its version "+
			"immediately; one that hangs is not one to install.", path, ProbeTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		detail := firstLine(exitErr.Stderr)
		if detail == "" {
			detail = firstLine(out)
		}
		if detail != "" {
			return fmt.Sprintf("  %s exited %d: %s", path, exitErr.ExitCode(), detail)
		}
		return fmt.Sprintf("  %s exited %d with no output.", path, exitErr.ExitCode())
	}
	return "  " + msg
}

// checkUpgradeSafety decides whether staged may replace installed.
//
// installed may be a zero identity: the currently-installed binary is probed
// best-effort, because an agent whose binary is already broken is precisely the
// one that most needs replacing, and refusing to upgrade because the *old*
// binary would not run is the wrong way round.
func checkUpgradeSafety(staged, installed BinaryIdentity, minProtocol int) error {
	// The control plane's floor. Only checked when the binary reported it:
	// zero means "did not say", and treating silence as v0 would refuse every
	// build older than machine-readable version reporting on a protocol
	// technicality rather than on the version comparison below, which is the
	// check that actually understands the question.
	if staged.Structured && staged.Protocol > 0 && staged.Protocol < minProtocol {
		return fmt.Errorf("%w: the staged binary (%s) speaks executor protocol v%d, but this "+
			"control plane requires v%d or newer.\n"+
			"Installing it would take this device out of the fleet: the hub would refuse its "+
			"hello frame and the agent would reconnect forever.\n"+
			"Pass --force if you are deliberately rolling back and will downgrade the hub too",
			ErrDowngrade, staged.Version, staged.Protocol, minProtocol)
	}

	if installed.Version == "" {
		return nil
	}
	cmp, ok := version.Compare(staged.Version, installed.Version)
	if !ok {
		// One side is an unreleased build, so they cannot be ordered. Not a
		// refusal: a developer testing a fix on a device is a legitimate and
		// common thing to do, and the binary has already been shown to run.
		return nil
	}
	if cmp < 0 {
		return fmt.Errorf("%w: %s is older than the installed %s.\n"+
			"An upgrade that silently moves a device backwards is how a fleet ends up running "+
			"builds nobody chose.\n"+
			"Pass --force to install it anyway (a deliberate rollback), or copy the intended "+
			"binary to this device",
			ErrDowngrade, staged.Version, installed.Version)
	}
	return nil
}

// firstLine returns the first non-empty line of output, bounded, for embedding
// in an error message.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const max = 200
		if len(line) > max {
			return line[:max] + "…"
		}
		return line
	}
	return ""
}
