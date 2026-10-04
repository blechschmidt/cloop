package executor

// protocolneed_test.go pins the sentences word for word. They are what an
// operator reads when a device cannot do what was asked of it, and the defect
// they replace was a sentence that read well and was wrong (Task 20371) — so
// every change to one should be a deliberate edit here, not a side effect.
//
// The hub's build and the table of published releases are both pinned: the
// advice depends on them, and the sentences must not change because the test
// binary is unstamped or because a release was added.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/version"
)

func withHub(t *testing.T, v string) {
	t.Helper()
	prev := HubBuild
	HubBuild = func() string { return v }
	t.Cleanup(func() { HubBuild = prev })
}

// withKnownReleases pins the published-release table to the one the
// reference deployment met: v0.0.1 speaking v6, v0.0.4 speaking v13.
func withKnownReleases(t *testing.T) {
	t.Helper()
	prev := knownReleases
	knownReleases = func() []version.Release {
		return []version.Release{{Tag: "v0.0.1", Protocol: 6}, {Tag: "v0.0.4", Protocol: 13}}
	}
	t.Cleanup(func() { knownReleases = prev })
}

const (
	unreleasedNote15 = "The hub runs an unreleased build (dev+g8b418e2), so no published release may speak v15 yet — " +
		"the newest this hub knows of, v0.0.4, speaks v13 — and the Executors panel's Upgrade button and " +
		"auto-update install published releases only."
	buildAt8b418e2 = "build cloop at the hub's commit 8b418e2 as a static binary (`CGO_ENABLED=0 go build -o cloop .`), " +
		"copy it to the device and run `sudo ./cloop executor agent install --upgrade --insecure-skip-verify` there " +
		"(a binary built by hand carries no signed provenance); a plain --upgrade keeps the device's packet-filter " +
		"grant as it is."
	releaseByHandV020 = "copy the v0.2.0 release binary to it and run `sudo ./cloop executor agent install --upgrade " +
		"--insecure-skip-verify` there (a release signs its archive, not the binary inside, so verify the archive " +
		"before extracting it); a plain --upgrade keeps the device's packet-filter grant as it is."
)

// TestNeedsProtocolOnAnUnreleasedHub is the reference deployment: a hub on
// dev+g8b418e2 speaking v16, a device speaking v14, and nothing published above
// v13. No release can help, the Upgrade button would move the device
// backwards, and the path that works is a build of the hub's commit.
func TestNeedsProtocolOnAnUnreleasedHub(t *testing.T) {
	withHub(t, "dev+g8b418e2")
	withKnownReleases(t)

	got := NeedsProtocol("agent sgx-1 (sgx)", 14, 15, "for firewall rules stored in the hub", "")
	want := "agent sgx-1 (sgx) speaks protocol v14, and the hub needs v15 for firewall rules stored in the hub. " +
		unreleasedNote15 + " To move the device forward, " + buildAt8b418e2
	if got != want {
		t.Errorf("need 15:\n got %q\nwant %q", got, want)
	}

	got = NeedsProtocol("agent sgx-1 (sgx)", 14, 16, "to ship the feature branch cloop/feature/x to it", "")
	want = "agent sgx-1 (sgx) speaks protocol v14, and the hub needs v16 to ship the feature branch " +
		"cloop/feature/x to it. The hub runs an unreleased build (dev+g8b418e2), so no published release may " +
		"speak v16 yet — the newest this hub knows of, v0.0.4, speaks v13 — and the Executors panel's Upgrade " +
		"button and auto-update install published releases only. To move the device forward, " + buildAt8b418e2
	if got != want {
		t.Errorf("need 16:\n got %q\nwant %q", got, want)
	}
}

// TestNeedsProtocolNamesTheSourceTheHubWasBuiltFrom: the build path is only as
// precise as the hub's version string — a commit, a dirty tree on a commit, or
// for a build from an export with no VCS data, nothing more than "the same
// source".
func TestNeedsProtocolNamesTheSourceTheHubWasBuiltFrom(t *testing.T) {
	withKnownReleases(t)
	for _, tc := range []struct{ hub, source string }{
		{"dev+g8b418e2.dirty", "from the hub's own uncommitted source tree (on commit 8b418e2)"},
		{"dev", "from the same source the hub was built from"},
	} {
		withHub(t, tc.hub)
		got := NeedsProtocol("agent sgx-1 (sgx)", 14, 15, "for firewall rules stored in the hub", "")
		want := "agent sgx-1 (sgx) speaks protocol v14, and the hub needs v15 for firewall rules stored in the hub. " +
			"The hub runs an unreleased build (" + tc.hub + "), so no published release may speak v15 yet — the " +
			"newest this hub knows of, v0.0.4, speaks v13 — and the Executors panel's Upgrade button and " +
			"auto-update install published releases only. To move the device forward, build cloop " + tc.source +
			" as a static binary (`CGO_ENABLED=0 go build -o cloop .`), copy it to the device and run `sudo " +
			"./cloop executor agent install --upgrade --insecure-skip-verify` there (a binary built by hand " +
			"carries no signed provenance); a plain --upgrade keeps the device's packet-filter grant as it is."
		if got != want {
			t.Errorf("hub %s:\n got %q\nwant %q", tc.hub, got, want)
		}
	}
}

// TestNeedsProtocolOnAReleasedHub: a hub that is a release hands its devices
// that release through the Upgrade button — or, for a device too old to be
// upgraded remotely, by hand once.
func TestNeedsProtocolOnAReleasedHub(t *testing.T) {
	withHub(t, "v0.2.0")
	withKnownReleases(t)

	got := NeedsProtocol("agent sgx-1 (sgx)", 14, 16, "to ship the feature branch cloop/feature/x to it", "")
	want := "agent sgx-1 (sgx) speaks protocol v14, and the hub needs v16 to ship the feature branch " +
		"cloop/feature/x to it. Press Upgrade on the device's row in the Executors panel to install this " +
		"hub's own release, v0.2.0."
	if got != want {
		t.Errorf("have 14 need 16:\n got %q\nwant %q", got, want)
	}

	got = NeedsProtocol("agent edge-9 (edge-9)", 9, 10, "to place the project's state on it", "")
	want = "agent edge-9 (edge-9) speaks protocol v9, and the hub needs v10 to place the project's state on it. " +
		"The Executors panel's Upgrade button needs v11, so upgrade the device once by hand instead: " +
		releaseByHandV020
	if got != want {
		t.Errorf("have 9 need 10:\n got %q\nwant %q", got, want)
	}

	// Asking for remote upgrade itself: the shortfall already says v11.
	got = NeedsProtocol("agent edge-9 (edge-9)", 9, MinRemoteUpgradeVersion, "to upgrade it from here", "")
	want = "agent edge-9 (edge-9) speaks protocol v9, and the hub needs v11 to upgrade it from here. " +
		"Upgrade the device once by hand instead: " + releaseByHandV020
	if got != want {
		t.Errorf("have 9 need 11:\n got %q\nwant %q", got, want)
	}
}

// TestNeedsProtocolOffersAPublishedReleaseThatSuffices: on an unreleased hub,
// when the newest published release does satisfy the need and the device can
// be upgraded remotely, pressing Upgrade with it is offered too — and the
// caller's alternative remedy ends the message.
func TestNeedsProtocolOffersAPublishedReleaseThatSuffices(t *testing.T) {
	withHub(t, "dev+g8b418e2")
	withKnownReleases(t)

	got := NeedsProtocol("agent edge-2 (edge-2)", 12, 13, "to send a seeded run's results back",
		"Or remove the grant from this project.")
	want := "agent edge-2 (edge-2) speaks protocol v12, and the hub needs v13 to send a seeded run's results " +
		"back. The hub runs an unreleased build (dev+g8b418e2), and the Executors panel's Upgrade button and " +
		"auto-update install published releases only. Pressing Upgrade on the device's row with v0.0.4 as the " +
		"target raises it to v13; to bring it level with the hub instead, " + buildAt8b418e2 +
		" Or remove the grant from this project."
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}

	// Below remote upgrade the button is not offered, however good the release.
	got = NeedsProtocol("agent edge-3 (edge-3)", 9, 10, "to place the project's state on it", "")
	if strings.Contains(got, "Pressing Upgrade") {
		t.Errorf("offered the Upgrade button to a device that cannot be sent the frame: %q", got)
	}
}

// TestProtocolDrop pins the refusal for an upgrade that would move a device
// backwards: the reference deployment pressing Upgrade with latest = v0.0.4.
func TestProtocolDrop(t *testing.T) {
	withHub(t, "dev+g8b418e2")
	withKnownReleases(t)

	got := ProtocolDrop("agent sgx-1 (sgx)", 14, "v0.0.4", 13)
	want := "agent sgx-1 (sgx) speaks protocol v14; v0.0.4 speaks v13, so installing it would lower the " +
		"device's protocol and lose what needs v14. The hub runs an unreleased build (dev+g8b418e2), and the " +
		"Executors panel's Upgrade button and auto-update install published releases only. To move the " +
		"device forward, " + buildAt8b418e2
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}

	// Several protocols lost read as a range; a tag the table can only bound
	// reads "at most".
	if got := ProtocolDrop("agent x (x)", 16, "v0.0.4", 13); !strings.Contains(got, "lose what needs v14–v16.") {
		t.Errorf("range: %q", got)
	}
	if got := ProtocolDrop("agent x (x)", 14, "v0.0.3", 13); !strings.Contains(got, "v0.0.3 speaks at most v13,") {
		t.Errorf("bound: %q", got)
	}

	// A released hub whose own release is the target: the device is ahead.
	withHub(t, "v0.0.4")
	got = ProtocolDrop("agent sgx-1 (sgx)", 14, "v0.0.4", 13)
	want = "agent sgx-1 (sgx) speaks protocol v14; v0.0.4 speaks v13, so installing it would lower the " +
		"device's protocol and lose what needs v14. v0.0.4 is this hub's own release, so the device is ahead " +
		"of the hub: upgrade the hub rather than move the device back."
	if got != want {
		t.Errorf("own release:\n got %q\nwant %q", got, want)
	}
}

// TestUnpublishedTarget: the old dialog prefilled the hub's own version, and
// on an unreleased hub that is no release at all.
func TestUnpublishedTarget(t *testing.T) {
	withHub(t, "dev+g8b418e2")
	withKnownReleases(t)
	got := UnpublishedTarget("agent sgx-1 (sgx)", "dev+g8b418e2", 14)
	want := "dev+g8b418e2 is this hub's own unreleased build, not a release tag: a device asked to upgrade " +
		"installs a published, signed release and nothing else, so agent sgx-1 (sgx) cannot be sent it. To put " +
		"the hub's build on the device, " + buildAt8b418e2
	if got != want {
		t.Errorf("hub's own build:\n got %q\nwant %q", got, want)
	}

	withHub(t, "v0.2.0")
	got = UnpublishedTarget("agent sgx-1 (sgx)", "nightly", 14)
	want = `"nightly" is not a release tag: a device asked to upgrade installs a published, signed release ` +
		"and nothing else, so agent sgx-1 (sgx) cannot be sent it. Press Upgrade on the device's row in the " +
		"Executors panel to install this hub's own release, v0.2.0."
	if got != want {
		t.Errorf("released hub:\n got %q\nwant %q", got, want)
	}
}

// TestUpgradeOffer is what the Upgrade dialog prefills: never the hub's own
// version unless it is a release, and never a release that would lower the
// device's protocol.
func TestUpgradeOffer(t *testing.T) {
	withKnownReleases(t)
	const subject = "This device's agent"

	withHub(t, "dev+g8b418e2")
	if target, note := UpgradeOffer(subject, 14, 16); target != "" || note != ProtocolDrop(subject, 14, "v0.0.4", 13) {
		t.Errorf("v14 device, unreleased hub: (%q, %q)", target, note)
	}
	target, note := UpgradeOffer(subject, 12, 16)
	wantNote := "The hub runs an unreleased build (dev+g8b418e2), which no published release matches, so " +
		"Upgrade offers the newest published release this hub knows of, v0.0.4, which speaks v13. To bring the " +
		"device level with the hub (v16), " + buildAt8b418e2
	if target != "v0.0.4" || note != wantNote {
		t.Errorf("v12 device, unreleased hub:\n got (%q, %q)\nwant (%q, %q)", target, note, "v0.0.4", wantNote)
	}
	if target, _ := UpgradeOffer(subject, 0, 16); target != "v0.0.4" {
		t.Errorf("offline device, unreleased hub: target %q, want the newest release", target)
	}
	if target, note := UpgradeOffer(subject, 9, 16); target != "" ||
		note != NeedsProtocol(subject, 9, MinRemoteUpgradeVersion, "to upgrade it from the Executors panel", "") {
		t.Errorf("pre-upgrade device: (%q, %q)", target, note)
	}

	withHub(t, "v0.2.0")
	if target, note := UpgradeOffer(subject, 14, 16); target != "v0.2.0" || note != "Upgrade installs this hub's own release, v0.2.0." {
		t.Errorf("released hub: (%q, %q)", target, note)
	}
	if target, note := UpgradeOffer(subject, 17, 16); target != "" || note != ProtocolDrop(subject, 17, "v0.2.0", 16) {
		t.Errorf("device ahead of a released hub: (%q, %q)", target, note)
	}
}

// TestBuildFloorPath: a floor is a release version, so only a published
// release meets it — the source build that answers a protocol shortfall on an
// unreleased hub would not.
func TestBuildFloorPath(t *testing.T) {
	withKnownReleases(t)

	withHub(t, "v0.2.0")
	if got := BuildFloorPath("v0.1.0"); got != AgentUpgradePath(0, 0) {
		t.Errorf("hub release meets the floor: %q", got)
	}

	withHub(t, "dev+g8b418e2")
	got := BuildFloorPath("v1.2.0")
	want := "Install a published release at or above v1.2.0: press Upgrade on the device's row in the Executors " +
		"panel and give its tag, or — on a device whose agent speaks a protocol older than v11 — copy that " +
		"release's binary to it and run `sudo ./cloop executor agent install --upgrade --insecure-skip-verify` " +
		"there (a release signs its archive, not the binary inside, so verify the archive before extracting it); " +
		"a plain --upgrade keeps the device's packet-filter grant as it is. A build made from source carries no " +
		"release version, so it cannot meet the floor. The newest release this hub knows of, v0.0.4, is below " +
		"the floor."
	if got != want {
		t.Errorf("unreleased hub:\n got %q\nwant %q", got, want)
	}
}

// TestProtocolShortfallWithAnUnknownProtocol: an offline device, or a driver
// that reports none, is said to speak an older protocol — what the caller
// established — never "v0".
func TestProtocolShortfallWithAnUnknownProtocol(t *testing.T) {
	got := ProtocolShortfall("Its agent", 0, 13, "to have a seeded run's outcome sent back")
	want := "Its agent speaks an older protocol, and the hub needs v13 to have a seeded run's outcome sent back."
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
}

// TestEveryRemedyNamesTheInstallCommand: whatever the hub, a device that has
// to be moved by hand is told the command that does it.
func TestEveryRemedyNamesTheInstallCommand(t *testing.T) {
	withKnownReleases(t)
	for _, hub := range []string{"v0.2.0", "dev+g8b418e2", "dev+g8b418e2.dirty", "dev", ""} {
		withHub(t, hub)
		for _, s := range []string{
			AgentUpgradeAdvice(),
			AgentUpgradePath(9, 10),
			BuildFloorPath("v9.0.0"),
			ProtocolMismatchAdvice(),
		} {
			if !strings.Contains(s, "sudo ./"+AgentUpgradeProcedure) {
				t.Errorf("hub %q: remedy names no install command: %q", hub, s)
			}
		}
	}
}
