package executor

// protocolneed.go writes every sentence the hub says when a device's agent
// speaks too old a protocol for what is being asked of it, and the remedy that
// goes with it (Task 20371).
//
// The refusals used to be written where they were raised — a dozen call sites
// in pkg/executor/remote and pkg/ui — and they all ended the same way: "upgrade
// the agent with `cloop executor agent install --upgrade`". That advice is often
// untrue, and the reason is where it becomes untrue:
//
//   - The Executors panel's Upgrade button and the fleet auto-update policy can
//     only make a device install a published, signed release. That is the
//     security model of the upgrade frame (pkg/executor/remote/upgradeproto.go):
//     the hub names a version and never supplies bytes.
//   - A hub that is itself a release can hand its devices that release, and the
//     advice works. A hub running an unreleased build speaks a newer protocol
//     than any published release, so no release can satisfy what it needs — and
//     pressing Upgrade on a device already ahead of the newest release moves it
//     backwards. That is the reference deployment: its hub is a dev build at
//     protocol v16, its device "sgx" a dev build at v14, and the newest
//     published release, v0.0.4, speaks v13.
//   - `install --upgrade` installs whatever binary runs it. A binary built from
//     source carries no signed provenance, so the command refuses it without
//     --insecure-skip-verify; and a release signs its archive, not the binary
//     inside, so a release binary copied to a device by hand needs it too.
//
// So the remedy is chosen here, once, from the hub's own build (HubBuild), and
// every refusal names both numbers: the protocol the device speaks and the one
// the hub needs. TestProtocolRefusalsGoThroughTheHelper (protocolneed_gate_test.go)
// fails the build when a "needs vN" sentence is written anywhere else.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// HubBuild reports the control plane's own build: version.String(), unless a
// test pins it.
//
// The remedy for a trailing device depends on it — a hub that is a release can
// hand its devices that release, one that is not cannot — and pkg/ui compares
// devices against the same value, so pinning it in a test moves both.
var HubBuild = version.String

// MinRemoteUpgradeVersion is the first protocol version whose agents accept the
// upgrade frame: remote.MinUpgradeVersion, mirrored here because this package
// sits below pkg/executor/remote and writes the advice that depends on it.
// TestMinRemoteUpgradeVersionMatchesTheWire in pkg/executor/remote keeps the two
// equal.
const MinRemoteUpgradeVersion = 11

// staticBuildCommand builds cloop the way a device needs it: one binary with no
// libc of the build machine's baked in.
const staticBuildCommand = "CGO_ENABLED=0 go build -o cloop ."

// knownReleases is the table of published releases the advice is written
// from: pkg/version's, unless a test pins it — the sentences these functions
// write are pinned word for word, and must not change when a release is added.
var knownReleases = version.PublishedReleases

func newestKnownRelease() (version.Release, bool) {
	rels := knownReleases()
	if len(rels) == 0 {
		return version.Release{}, false
	}
	return rels[len(rels)-1], true
}

func knownReleaseProtocol(tag string) (lo, hi int) {
	return version.ReleaseProtocolIn(knownReleases(), tag)
}

// NeedsProtocol composes a refusal for a device whose agent speaks too old a
// protocol:
//
//	"<subject> speaks protocol v<have>, and the hub needs v<need> <purpose>."
//
// followed by AgentUpgradePath(have, need) and, when instead is not empty, the
// alternative remedy it states ("Or remove the grant from this project.").
// purpose completes "the hub needs vN ___", e.g. "for firewall rules stored in
// the hub" or "to revoke <bindings> mid-run".
//
// A have of zero or less means the device's protocol is not known — an offline
// device, or a driver that does not report one — and the sentence says only that
// it is older than what is needed, which is what the caller established.
func NeedsProtocol(subject string, have, need int, purpose, instead string) string {
	return joinSentences(ProtocolShortfall(subject, have, need, purpose), AgentUpgradePath(have, need), instead)
}

// ProtocolShortfall is NeedsProtocol's first sentence alone, for a caller that
// carries the remedy in a field of its own (a preflight finding's Fix).
func ProtocolShortfall(subject string, have, need int, purpose string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "The device's agent"
	}
	speaks := fmt.Sprintf("speaks protocol v%d", have)
	if have <= 0 {
		speaks = "speaks an older protocol"
	}
	s := fmt.Sprintf("%s %s, and the hub needs v%d", subject, speaks, need)
	if p := strings.TrimSpace(purpose); p != "" {
		s += " " + p
	}
	return s + "."
}

// AgentUpgradePath is the remedy for a device whose agent speaks protocol have
// when the hub needs need, chosen by the hub's own build.
//
// A hub that is a release names its own release, installed by the Executors
// panel's Upgrade button — or by hand, once, when the device predates remote
// upgrade (v11). A hub that is not says so, says that no published release may
// carry what it needs, and gives the path that works: build cloop from the hub's
// source and install it on the device with --insecure-skip-verify. Where the
// newest published release does satisfy need, and the device can be upgraded
// remotely, the Upgrade button is offered as well.
//
// Either number may be zero for "not known"; the sentence then leaves out what
// depends on it.
func AgentUpgradePath(have, need int) string {
	h := hubFacts()
	if h.release {
		manual := releaseSteps("the " + h.version + " release binary")
		switch {
		case have > 0 && have < MinRemoteUpgradeVersion && need == MinRemoteUpgradeVersion:
			return "Upgrade the device once by hand instead: " + manual
		case have > 0 && have < MinRemoteUpgradeVersion:
			return fmt.Sprintf("The Executors panel's Upgrade button needs v%d, so upgrade the device once by "+
				"hand instead: %s", MinRemoteUpgradeVersion, manual)
		case have > 0:
			return fmt.Sprintf("Press Upgrade on the device's row in the Executors panel to install this hub's "+
				"own release, %s.", h.version)
		default:
			return fmt.Sprintf("Press Upgrade on the device's row in the Executors panel to install this hub's "+
				"own release, %s; a device whose agent speaks a protocol older than v%d has to be upgraded "+
				"once by hand instead: %s", h.version, MinRemoteUpgradeVersion, manual)
		}
	}

	newest, known := newestKnownRelease()
	var b strings.Builder
	fmt.Fprintf(&b, "The hub runs an unreleased build (%s)", h.version)
	if known && need > newest.Protocol {
		fmt.Fprintf(&b, ", so no published release may speak v%d yet — the newest this hub knows of, %s, "+
			"speaks v%d —", need, newest.Tag, newest.Protocol)
	} else {
		b.WriteString(",")
	}
	b.WriteString(" and the Executors panel's Upgrade button and auto-update install published releases only.")
	if known && need > 0 && need <= newest.Protocol && have >= MinRemoteUpgradeVersion {
		fmt.Fprintf(&b, " Pressing Upgrade on the device's row with %s as the target raises it to v%d; to "+
			"bring it level with the hub instead, %s", newest.Tag, newest.Protocol, h.buildSteps())
	} else {
		b.WriteString(" To move the device forward, " + h.buildSteps())
	}
	return b.String()
}

// AgentUpgradeAdvice is the remedy for a message that knows neither the
// device's protocol nor the one it needs: a static sentence in a remediation
// field, or a skew note about builds rather than protocols.
func AgentUpgradeAdvice() string { return AgentUpgradePath(0, 0) }

// ProtocolMismatchAdvice is the remedy for a device and a hub that share no
// protocol version at all. It is read on both sides — a device prints it when
// the hub refuses its hello — so unlike AgentUpgradePath it names no build: on
// the device, HubBuild is the device's own.
func ProtocolMismatchAdvice() string {
	return "Upgrade the hub if the device is the newer one. If the device is the older one, the Executors " +
		"panel's Upgrade button cannot reach it — there is no session to send the request on — so put a build " +
		"of the hub's own version on it by hand and run `sudo ./" + AgentUpgradeProcedure + " --insecure-skip-verify` " +
		"there (a binary built from source, or a release binary taken out of its signed archive, carries no " +
		"signature of its own); a plain --upgrade keeps the device's packet-filter grant as it is."
}

// ProtocolDrop is the refusal for an upgrade target that would lower the
// device's protocol: the device speaks have, target speaks targetProtocol (or at
// most that, when the release table can only bound it), and installing it would
// take away whatever needs the protocols in between. The path that moves the
// device forward instead follows.
func ProtocolDrop(subject string, have int, target string, targetProtocol int) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "The device's agent"
	}
	target = strings.TrimSpace(target)
	h := hubFacts()
	ownRelease := h.release && sameTag(target, h.version)
	speaks := fmt.Sprintf("speaks v%d", targetProtocol)
	if lo, hi := knownReleaseProtocol(target); !ownRelease && (lo != hi || hi != targetProtocol) {
		speaks = fmt.Sprintf("speaks at most v%d", targetProtocol)
	}
	lost := fmt.Sprintf("v%d", have)
	if targetProtocol+1 < have {
		lost = fmt.Sprintf("v%d–v%d", targetProtocol+1, have)
	}
	first := fmt.Sprintf("%s speaks protocol v%d; %s %s, so installing it would lower the device's protocol "+
		"and lose what needs %s.", subject, have, target, speaks, lost)

	if ownRelease {
		return first + " " + target + " is this hub's own release, so the device is ahead of the hub: " +
			"upgrade the hub rather than move the device back."
	}
	return first + " " + AgentUpgradePath(have, 0)
}

// UnpublishedTarget is the refusal for an upgrade target that is not a release
// tag at all — most often the hub's own unreleased version, which the Upgrade
// dialog used to prefill. A device resolves the target through its own release
// channel and verifies the archive's signature, so a name with no published
// release behind it cannot be installed that way; the path that does put the
// hub's code on the device follows.
func UnpublishedTarget(subject, target string, have int) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "the device"
	}
	target = strings.TrimSpace(target)
	h := hubFacts()
	if !h.release && target == h.version {
		return fmt.Sprintf("%s is this hub's own unreleased build, not a release tag: a device asked to upgrade "+
			"installs a published, signed release and nothing else, so %s cannot be sent it. To put the hub's "+
			"build on the device, %s", target, subject, h.buildSteps())
	}
	return fmt.Sprintf("%q is not a release tag: a device asked to upgrade installs a published, signed release "+
		"and nothing else, so %s cannot be sent it. %s", target, subject, AgentUpgradePath(have, 0))
}

// UpgradeOffer is what the Executors panel's Upgrade dialog offers a device
// whose agent speaks protocol have, on a hub speaking hubProtocol: the release
// to prefill, and the sentence explaining it.
//
// The target is the hub's own release when the hub is one; otherwise the newest
// published release this hub knows of, provided it does not lower the device's
// protocol; otherwise "" — there is no release the button could install that
// would not move the device backwards, and the note says what to do instead. A
// have of zero (an offline device) judges nothing about the device.
func UpgradeOffer(subject string, have, hubProtocol int) (target, note string) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "This device's agent"
	}
	if have > 0 && have < MinRemoteUpgradeVersion {
		return "", NeedsProtocol(subject, have, MinRemoteUpgradeVersion, "to upgrade it from the Executors panel", "")
	}
	h := hubFacts()
	if h.release {
		if have > 0 && hubProtocol > 0 && have > hubProtocol {
			return "", ProtocolDrop(subject, have, h.version, hubProtocol)
		}
		return h.version, "Upgrade installs this hub's own release, " + h.version + "."
	}
	newest, known := newestKnownRelease()
	if !known {
		return "", AgentUpgradePath(have, hubProtocol)
	}
	if have > newest.Protocol {
		return "", ProtocolDrop(subject, have, newest.Tag, newest.Protocol)
	}
	note = fmt.Sprintf("The hub runs an unreleased build (%s), which no published release matches, so Upgrade "+
		"offers the newest published release this hub knows of, %s, which speaks v%d.",
		h.version, newest.Tag, newest.Protocol)
	if hubProtocol > newest.Protocol {
		note += fmt.Sprintf(" To bring the device level with the hub (v%d), %s", hubProtocol, h.buildSteps())
	}
	return newest.Tag, note
}

// BuildFloorPath is the remedy for a device refused by the fleet's minimum
// agent build (executors.min_agent_build).
//
// A floor is a *release* version, so unlike a protocol shortfall it can only be
// met by a published release: a build made from source carries no version to
// order against it. A hub whose own release meets the floor names that; any
// other hub names the floor.
func BuildFloorPath(floor string) string {
	floor = strings.TrimSpace(floor)
	h := hubFacts()
	if h.release {
		if cmp, ok := version.Compare(h.version, floor); ok && cmp >= 0 {
			return AgentUpgradePath(0, 0)
		}
	}
	s := fmt.Sprintf("Install a published release at or above %s: press Upgrade on the device's row in the "+
		"Executors panel and give its tag, or — on a device whose agent speaks a protocol older than v%d — %s "+
		"A build made from source carries no release version, so it cannot meet the floor.",
		floor, MinRemoteUpgradeVersion, releaseSteps("that release's binary"))
	if newest, ok := newestKnownRelease(); ok {
		if cmp, ok := version.Compare(newest.Tag, floor); ok && cmp < 0 {
			s += fmt.Sprintf(" The newest release this hub knows of, %s, is below the floor.", newest.Tag)
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// The parts every remedy above is built from
// ---------------------------------------------------------------------------

// hubBuildFacts is what a remedy needs to know about the hub's own build.
type hubBuildFacts struct {
	// version is HubBuild(), e.g. "v0.2.0" or "dev+g8b418e2".
	version string
	// release reports that version is a release tag.
	release bool
	// source completes "build cloop ___" for an unreleased hub.
	source string
}

func hubFacts() hubBuildFacts {
	v := strings.TrimSpace(HubBuild())
	if v == "" {
		v = version.DevVersion
	}
	h := hubBuildFacts{version: v, release: version.IsRelease(v)}
	if !h.release {
		h.source = buildSource(v)
	}
	return h
}

// buildSource names the source an unreleased hub was built from, as precisely
// as its version string allows: "dev+g8b418e2" is a commit, ".dirty" a tree
// with uncommitted changes on top of one, and bare "dev" — a build from an
// export with no VCS data — says nothing more than that.
func buildSource(v string) string {
	rest, ok := strings.CutPrefix(v, version.DevVersion+"+g")
	if !ok {
		return "from the same source the hub was built from"
	}
	rev, dirty := strings.CutSuffix(rest, ".dirty")
	if !isHexRevision(rev) {
		return "from the same source the hub was built from"
	}
	if dirty {
		return "from the hub's own uncommitted source tree (on commit " + rev + ")"
	}
	return "at the hub's commit " + rev
}

func isHexRevision(s string) bool {
	if len(s) < 4 {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

// buildSteps is the one path that always moves a device to the hub's own code:
// build it, copy it over, install it. --insecure-skip-verify because a binary
// built by hand has no signature and cannot have one; the packet-filter note
// because a plain --upgrade neither adds nor removes the drop-in that lets the
// agent install sandbox firewalls, and an operator should not have to wonder.
func (h hubBuildFacts) buildSteps() string {
	return fmt.Sprintf("build cloop %s as a static binary (`%s`), copy it to the device and run `sudo ./%s "+
		"--insecure-skip-verify` there (a binary built by hand carries no signed provenance); a plain --upgrade "+
		"keeps the device's packet-filter grant as it is.", h.source, staticBuildCommand, AgentUpgradeProcedure)
}

// releaseSteps is the manual path to a published release, for a device too old
// to be upgraded remotely. what names the binary ("the v0.2.0 release binary").
// A release signs its archive rather than the executable inside it, so the
// extracted binary has no bundle of its own for `install --upgrade` to check.
func releaseSteps(what string) string {
	return fmt.Sprintf("copy %s to it and run `sudo ./%s --insecure-skip-verify` there (a release signs its "+
		"archive, not the binary inside, so verify the archive before extracting it); a plain --upgrade keeps "+
		"the device's packet-filter grant as it is.", what, AgentUpgradeProcedure)
}

// sameTag reports whether a and b name the same release.
func sameTag(a, b string) bool {
	cmp, ok := version.Compare(a, b)
	return ok && cmp == 0 && version.IsRelease(a) && version.IsRelease(b)
}

// joinSentences joins non-empty parts with a space, ending each with a full
// stop unless it already ends a sentence.
func joinSentences(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasSuffix(p, ".") && !strings.HasSuffix(p, "!") && !strings.HasSuffix(p, "?") {
			p += "."
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}
