package remote

// The harness-install frame: asking a device to fetch the harness a project
// needs, from that harness's own official installer (Task 20336).
//
// # Why this exists beside checkHarness rather than instead of it
//
// Task 20332 taught the hub to refuse a dispatch whose harness the device does
// not have, replacing a five-minute failure deep inside a run with an immediate
// message. That was the right fix for a *wrong* placement. It is the wrong fix
// for the ordinary case that produced it: an operator enrolls a fresh edge
// device, binds a claudecode project to it, and is told to go and install
// something by hand on a machine the whole point of the fleet was to stop
// hand-administering.
//
// So the refusal stays — it is still what a device that cannot be fixed gets —
// and this frame is the attempt that now happens first.
//
// # The security shape, which is the upgrade frame's argument reused
//
// This is the protocol's second remote code execution primitive: it ends with
// the device running a shell script as whatever user the agent is. Everything
// in upgradeproto.go's file comment applies here unchanged, and the payload is
// constrained the same way:
//
//  1. There is no script URL, and there must never be one. The frame names a
//     *harness* — a key into a table of official installers compiled into the
//     agent — and the device turns that key into a URL itself. A hub that has
//     been taken over can ask a device to install Claude Code from Anthropic;
//     it cannot ask it to install anything else from anywhere else.
//
//  2. There is no script body, no argv, no environment and no interpreter
//     override, for the same reason. Each would let the frame say what runs
//     rather than merely which published installer to run.
//
// TestInstallHarnessPayloadHasNoRemoteCodeExecutionFields enforces both by
// reflection, so a later field that quietly widens this fails the build.
//
// # Unlike upgrade, the acknowledgement is a real outcome
//
// The upgrade frame can only ever answer "accepted", because a successful
// upgrade restarts the agent and destroys the session the answer would travel
// on. Installing a harness restarts nothing: the agent is still running, still
// connected, and can say whether the binary is now there. So this frame answers
// with the finished result — installed or not, where it landed, what version it
// is — and the hub can act on it within the same dispatch that triggered it.
// That difference is the reason Start can install-then-continue rather than
// install-then-give-up-until-next-time.

import (
	"fmt"
	"strings"
)

const (
	// TypeInstallHarness (control plane → agent) asks the device to install a
	// named harness from that harness's official installer. Added in v12.
	TypeInstallHarness FrameType = "install_harness"
	// TypeHarnessInstalled (agent → control plane) reports the outcome. Unlike
	// TypeUpgrading this is a completion, not an intent; see the file comment.
	TypeHarnessInstalled FrameType = "harness_installed"
)

// MinHarnessInstallVersion is the first protocol version whose agents
// understand the install frame.
//
// A device below it is not broken and must not be treated as such: it simply
// keeps the pre-20336 behaviour of refusing a harness it does not have, with
// the message that names the manual remedies. The hub therefore checks this
// gate and *skips* the attempt rather than failing on it — the opposite of
// MinUpgradeVersion, where being too old is itself the thing the operator asked
// about and so has to be reported.
const MinHarnessInstallVersion = 12

// SupportsHarnessInstall reports whether an agent speaking this protocol
// version can be asked to install a harness.
func SupportsHarnessInstall(version int) bool { return version >= MinHarnessInstallVersion }

// InstallHarnessPayload is the body of TypeInstallHarness.
//
// Read the file comment before adding a field. This frame may name which
// published installer to run and nothing whatsoever about how to run it.
type InstallHarnessPayload struct {
	// Harness is the key into the agent's table of official installers, e.g.
	// "claude". Not a URL, not a command — see the file comment.
	Harness string `json:"harness"`

	// Reason is free text for the device's log, distinguishing an install
	// triggered by a dispatch from one an operator asked for directly. It is
	// diagnostic only and never affects what is installed.
	Reason string `json:"reason,omitempty"`
}

// HarnessInstalledPayload is the body of TypeHarnessInstalled: whether the
// harness is now present, and what the device ended up with.
type HarnessInstalledPayload struct {
	// Installed reports that the harness is now runnable on this device. It is
	// true both for a fresh install and for AlreadyPresent, because the
	// question the hub asked was "can you run this now", not "did you do work".
	Installed bool `json:"installed"`

	// AlreadyPresent distinguishes "it was already here" from "I fetched it",
	// so the hub can tell a race against a concurrent dispatch from an install
	// it actually caused, and log accordingly.
	AlreadyPresent bool `json:"already_present,omitempty"`

	// Harness echoes what was installed, so a log line or an audit row is
	// self-describing rather than needing the request beside it.
	Harness string `json:"harness,omitempty"`

	// Path is where the binary landed and Version what it reports. Both are
	// diagnostic, and Path earns its place: the official installer puts Claude
	// Code in ~/.local/bin, which is not on a service manager's default PATH,
	// and an operator debugging "installed but still not found" needs to see
	// the directory the agent had to add.
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`

	// Reason explains a failure. Always set when Installed is false: the
	// refusals here have entirely different fixes — no installer for this
	// harness, no bash on the device, no network, the script exited non-zero —
	// and a bare "install failed" would make them indistinguishable in the one
	// place an operator reads them.
	Reason string `json:"reason,omitempty"`
}

// DecodeInstallHarness decodes an install frame.
//
// The harness name is rejected unless it is a bare token. A registry lookup
// already constrains it — an unknown key has no installer and the device
// refuses — so this is defence in depth rather than the control. It is here
// because the failure it prevents is silent: a name carrying a path separator
// or a shell metacharacter is a sign that something upstream is composing this
// field from user input, and the moment to fail is before a later change gives
// that field somewhere dangerous to land.
func DecodeInstallHarness(f Frame) (InstallHarnessPayload, error) {
	var p InstallHarnessPayload
	if err := decodePayload(f, &p); err != nil {
		return p, err
	}
	p.Harness = strings.TrimSpace(p.Harness)
	if p.Harness == "" {
		return p, fmt.Errorf("%w: install frame has no harness", ErrProtocol)
	}
	if !isBareToken(p.Harness) {
		return p, fmt.Errorf(
			"%w: install frame names harness %q, which is not a bare name; the field is a key "+
				"into the agent's table of official installers, never a path or a command",
			ErrProtocol, p.Harness)
	}
	return p, nil
}

// DecodeHarnessInstalled decodes an install outcome.
func DecodeHarnessInstalled(f Frame) (HarnessInstalledPayload, error) {
	var p HarnessInstalledPayload
	err := decodePayload(f, &p)
	return p, err
}

// isBareToken reports whether s is a plain identifier: ASCII letters, digits,
// hyphen and underscore, and nothing else. An allowlist rather than a
// denylist, because the point is to admit the handful of names that are real
// harnesses rather than to guess at every character that could be abused.
func isBareToken(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return false
		}
	}
	return s != ""
}
