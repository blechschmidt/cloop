// Package version is the single place that knows which cloop build this is.
//
// It exists because the answer had to be readable from two places that cannot
// see each other. The CLI knew its own version — cmd.Version, patched by
// ldflags at release time — but pkg/executor/agent sits below the CLI in the
// import graph and cannot import it, so the agent reported a frozen constant
// ("1", never once incremented) to the control plane instead. The fix is not a
// second constant; it is moving the answer below both of them.
//
// Two constraints shape this file:
//
//   - Version must stay a plain string var initialised to a *constant*
//     expression. The Go linker's -X flag is documented to work only on such a
//     variable; `var Version = something()` compiles fine and then silently
//     ignores the stamp, which would reintroduce the exact bug this package
//     exists to fix — a build that cannot say what it is.
//   - Nothing here imports anything but the standard library, so every layer
//     of cloop can ask.
package version

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// DevVersion is the value an unstamped build reports. Exported because both
// the comparison logic here and the release tooling's tests need to name it
// rather than repeat the literal.
const DevVersion = "dev"

// LegacyAgentVersion is what agents built before build-version reporting sent
// in their hello frame: a hardcoded "1" that never changed.
//
// It is recognised explicitly because it is actively misleading rather than
// merely absent. Parsed as a version it is major 1, which compares as *newer*
// than the hub's v0.0.x — so an agent running a year-old build would be
// reported as ahead of the control plane. Naming the sentinel turns the fleet's
// most misleading input into its clearest message.
const LegacyAgentVersion = "1"

// Version is the build version, stamped at release time with
//
//	-ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=v1.2.3"
//
// Keep the initialiser a constant string. See the package comment.
var Version = DevVersion

// String returns the build version, enriching an unstamped build with whatever
// the toolchain recorded about the checkout it came from.
//
// A developer running `go build` gets "dev" from the linker, and a fleet of
// devices all reporting "dev" is no more diagnosable than a fleet all
// reporting "1". Go stamps VCS data into the binary by default, so a dev build
// can still identify itself as "dev+g4f7b5bc" — or "dev+g4f7b5bc.dirty" for an
// uncommitted tree, which is exactly the build an operator most needs to spot
// on a device.
func String() string {
	resolved.Do(func() { resolvedValue = resolve(Version, readBuildInfo) })
	return resolvedValue
}

var (
	resolved      sync.Once
	resolvedValue string
)

// readBuildInfo is indirected so tests can supply VCS settings without needing
// a real instrumented build.
var readBuildInfo = func() (map[string]string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(info.Settings))
	for _, s := range info.Settings {
		out[s.Key] = s.Value
	}
	return out, true
}

// resolve is String's logic, separated from the sync.Once so it is testable.
func resolve(stamped string, build func() (map[string]string, bool)) string {
	v := strings.TrimSpace(stamped)
	if v == "" {
		v = DevVersion
	}
	// A stamped release says what it is; VCS data would only add noise.
	if v != DevVersion {
		return v
	}
	settings, ok := build()
	if !ok {
		return v
	}
	rev := strings.TrimSpace(settings["vcs.revision"])
	if rev == "" {
		return v
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	out := v + "+g" + rev
	if settings["vcs.modified"] == "true" {
		out += ".dirty"
	}
	return out
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// parsed is a version broken into comparable parts.
type parsed struct {
	major, minor, patch int
	// pre is the prerelease tag ("rc1"), empty for a final release. It is
	// carried but only used to break exact numeric ties, because ordering
	// prerelease identifiers properly is more precision than fleet skew
	// reporting needs.
	pre string
}

// parse reads a vMAJOR.MINOR.PATCH string. Ok is false for anything it cannot
// read with confidence — "dev", "dev+g4f7b5bc", "1", "" — because a guess here
// becomes a wrong skew warning on an operator's screen.
func parse(s string) (parsed, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return parsed{}, false
	}
	v = strings.TrimPrefix(v, "v")
	// Build metadata never affects ordering; strip it before anything else.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	fields := strings.Split(v, ".")
	// Require all three components. A bare "1" is the legacy agent sentinel,
	// not version 1.0.0, and accepting it would rank a stale device above the
	// hub — see LegacyAgentVersion.
	if len(fields) != 3 {
		return parsed{}, false
	}
	out := parsed{pre: pre}
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return parsed{}, false
		}
		switch i {
		case 0:
			out.major = n
		case 1:
			out.minor = n
		case 2:
			out.patch = n
		}
	}
	return out, true
}

// Compare orders two versions: -1 if a precedes b, +1 if it follows, 0 if they
// are equal or not comparable. Ok reports whether both parsed.
//
// Callers must check ok rather than treating 0 as "same build": "dev" versus
// "v1.2.3" is not a tie, it is a question this function cannot answer, and a
// caller that conflated the two would report a half-upgraded fleet as uniform.
func Compare(a, b string) (result int, ok bool) {
	pa, okA := parse(a)
	pb, okB := parse(b)
	if !okA || !okB {
		return 0, false
	}
	for _, d := range [...]int{pa.major - pb.major, pa.minor - pb.minor, pa.patch - pb.patch} {
		if d != 0 {
			return sign(d), true
		}
	}
	switch {
	// A prerelease precedes the release it leads to; equal tags tie.
	case pa.pre == pb.pre:
		return 0, true
	case pa.pre != "" && pb.pre == "":
		return -1, true
	case pa.pre == "" && pb.pre != "":
		return 1, true
	default:
		return sign(strings.Compare(pa.pre, pb.pre)), true
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Skew
// ---------------------------------------------------------------------------

// Skew classifies one agent's build against the control plane's.
type Skew string

const (
	// SkewUnknown: the agent reported no version at all. Either it predates
	// the hello field or something stripped it.
	SkewUnknown Skew = "unknown"
	// SkewLegacy: the agent reported LegacyAgentVersion, so it is running a
	// build from before agents knew their own version.
	SkewLegacy Skew = "legacy"
	// SkewNone: same build as the hub.
	SkewNone Skew = "none"
	// SkewUnversioned: one side is an unstamped dev build, so the two cannot
	// be ordered. Reported rather than hidden: a dev binary on a fleet device
	// is itself worth an operator's attention.
	SkewUnversioned Skew = "unversioned"
	// SkewPatch: trails the hub by a patch release only.
	SkewPatch Skew = "patch"
	// SkewBehind: trails the hub by a minor or major release. This is the
	// "materially trails" case — the one where protocol capabilities and
	// wire-visible behaviour plausibly differ.
	SkewBehind Skew = "behind"
	// SkewAhead: newer than the hub. Not merely cosmetic — an agent can speak
	// frames this control plane does not implement, and the usual cause is a
	// half-finished hub upgrade.
	SkewAhead Skew = "ahead"
)

// Material reports whether this skew deserves an operator's attention now.
//
// Patch drift across a large fleet is normal and flagging it would train
// operators to ignore the banner, which would cost them the case that matters.
func (s Skew) Material() bool {
	switch s {
	case SkewLegacy, SkewBehind, SkewAhead, SkewUnversioned:
		return true
	default:
		return false
	}
}

// Classify compares an agent's reported build against the hub's and returns
// both the classification and the sentence to show an operator.
//
// The note names the remediation because the classification alone sends
// somebody to a search box. It deliberately does *not* name a flag that does
// not exist: the previous message pointed at
// `cloop executor agent install --upgrade`, and an operator who tried it got
// an unknown-flag error from the one command they had been told would help.
func Classify(hub, agent string) (Skew, string) {
	hub = strings.TrimSpace(hub)
	agent = strings.TrimSpace(agent)

	switch {
	case agent == "":
		return SkewUnknown, "This device has not reported a build version. " +
			"It predates build-version reporting; upgrade it to make its version visible."
	case agent == LegacyAgentVersion:
		return SkewLegacy, "This device reports the placeholder build version that agents sent " +
			"before they knew their own. Its real version is unknown — upgrade it to find out."
	}

	if hub != "" && agent == hub {
		return SkewNone, ""
	}

	cmp, ok := Compare(agent, hub)
	if !ok {
		switch {
		case agent == DevVersion || strings.HasPrefix(agent, DevVersion+"+"):
			return SkewUnversioned, fmt.Sprintf(
				"This device runs an unreleased build (%s), so it cannot be compared with the hub (%s).",
				agent, displayVersion(hub))
		case hub == DevVersion || strings.HasPrefix(hub, DevVersion+"+"):
			return SkewUnversioned, fmt.Sprintf(
				"The hub runs an unreleased build (%s), so this device (%s) cannot be compared with it.",
				displayVersion(hub), agent)
		default:
			return SkewUnversioned, fmt.Sprintf(
				"This device reports %q, which is not a version this hub (%s) can compare against.",
				agent, displayVersion(hub))
		}
	}

	switch {
	case cmp > 0:
		return SkewAhead, fmt.Sprintf(
			"This device runs %s, newer than the hub's %s. Upgrade the hub: an agent ahead of its "+
				"control plane can speak frames the hub does not implement.", agent, hub)
	case cmp == 0:
		return SkewNone, ""
	}

	// Behind. Distinguish patch drift from a material gap.
	pa, _ := parse(agent)
	ph, _ := parse(hub)
	if pa.major == ph.major && pa.minor == ph.minor {
		return SkewPatch, fmt.Sprintf("This device runs %s; the hub runs %s.", agent, hub)
	}
	return SkewBehind, fmt.Sprintf(
		"This device runs %s, which materially trails the hub's %s.", agent, hub)
}

// displayVersion renders a version for a message, naming an empty one rather
// than leaving a gap in the sentence.
func displayVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}
