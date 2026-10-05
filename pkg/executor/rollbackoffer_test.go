package executor

// rollbackoffer_test.go: the hub never offers a device a build its installer
// would refuse as earlier on main (Task 20380), and says why in one sentence
// wherever it declines.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/version"
)

func TestRollbackRefusal(t *testing.T) {
	got := RollbackRefusal("agent sgx-1 (sgx)", 4150, edgeTarget, 4100)
	want := "agent sgx-1 (sgx) runs a build at sequence 4150 on main, and " + edgeTarget + " is sequence 4100 on " +
		"main, 50 commit(s) earlier. The device refuses a build earlier on main than its own whoever asks, and " +
		"neither the hub nor force can change that; only root on the device can roll it back (`" +
		RollbackOptIn + "`)."
	if got != want {
		t.Errorf("rollback:\n got %q\nwant %q", got, want)
	}
	got = RollbackRefusal("agent sgx-1 (sgx)", 4150, "v0.0.4", 0)
	if !strings.Contains(got, "v0.0.4 carries no sequence — it was built before builds were stamped with their "+
		"place on main, so it is older") {
		t.Errorf("an unsequenced target: %q", got)
	}
	for _, c := range []struct{ have, target int }{{0, 4100}, {0, 0}, {4150, 4150}, {4150, 4200}} {
		if got := RollbackRefusal("x", c.have, edgeTarget, c.target); got != "" {
			t.Errorf("device at %d, target at %d refused: %q", c.have, c.target, got)
		}
	}
}

// TestEdgeUpgradeOfferNeverOffersAnEarlierBuild: the hub's build is offered
// only when it is not earlier on main than the device's — including when the
// hub's build is from before sequences and the device's is not.
func TestEdgeUpgradeOfferNeverOffersAnEarlierBuild(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	withKnownReleases(t)
	hubBuild := func(seq int) *EdgeBuild {
		return &EdgeBuild{Short: "a0f3870", Target: edgeTarget, Published: true, Protocol: 18, Sequence: seq}
	}

	target, label, note := EdgeUpgradeOffer("This device's agent", DeviceBuild{Protocol: 18, Sequence: 4100}, 18,
		hubBuild(4150))
	if target != edgeTarget || label != "this hub's build (a0f3870)" ||
		!strings.Contains(note, "signed commit a0f3870 on main (sequence 4150 on main), and it speaks protocol v18") {
		t.Fatalf("a later build was not offered: %q, %q, %q", target, label, note)
	}

	target, _, note = EdgeUpgradeOffer("This device's agent", DeviceBuild{Protocol: 18, Sequence: 4200}, 18,
		hubBuild(4150))
	if target != "" {
		t.Fatalf("an earlier build was offered: %q", target)
	}
	for _, want := range []string{
		"This hub's build (a0f3870) is not offered: this device's agent runs a build at sequence 4200 on main",
		"is sequence 4150 on main, 50 commit(s) earlier",
		"The device is ahead of the hub, so move the hub forward rather than the device back",
		// Nothing to fall back to: v0.0.4 speaks v13.
		"No published release can be offered instead",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not say %q: %q", want, note)
		}
	}

	// The hub's build was published before sequences; the device's build
	// carries one, so it would refuse the hub's as older.
	target, _, note = EdgeUpgradeOffer("This device's agent", DeviceBuild{Protocol: 18, Sequence: 4100}, 18,
		hubBuild(0))
	if target != "" || !strings.Contains(note, "carries no sequence") {
		t.Errorf("an unsequenced hub build was offered to a sequenced device: %q, %q", target, note)
	}

	// A device that reports no sequence cannot be ordered against; the
	// protocol rule alone decides, as before — and installing the build gives
	// it a sequence from then on.
	if target, _, _ = EdgeUpgradeOffer("This device's agent", DeviceBuild{Protocol: 18}, 18, hubBuild(4150)); target != edgeTarget {
		t.Errorf("a device without a sequence was not offered the hub's build: %q", target)
	}
	// The protocol rule stays, and is still the reason when both apply.
	target, _, note = EdgeUpgradeOffer("This device's agent", DeviceBuild{Protocol: 19, Sequence: 4200}, 19,
		hubBuild(4150))
	if target != "" || !strings.Contains(note, "it speaks v18, below the device's v19") {
		t.Errorf("a lower protocol: %q, %q", target, note)
	}
}

// TestGuardReleaseOfferWithdrawsAReleaseTheDeviceWouldRefuse: a release the
// hub knows to be earlier than the device's build — or to carry no sequence,
// which every release before Task 20380 does — is not offered.
func TestGuardReleaseOfferWithdrawsAReleaseTheDeviceWouldRefuse(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	prev := knownReleases
	knownReleases = func() []version.Release {
		return []version.Release{{Tag: "v0.0.4", Protocol: 13}, {Tag: "v0.1.0", Protocol: 18, Sequence: 4120}}
	}
	t.Cleanup(func() { knownReleases = prev })

	for _, c := range []struct {
		tag     string
		seq     int
		offered bool
	}{
		{"v0.1.0", 4100, true},  // later than the device's build
		{"v0.1.0", 4120, true},  // the same commit
		{"v0.1.0", 4150, false}, // earlier
		{"v0.0.4", 4100, false}, // carries none
		{"v0.0.4", 0, true},     // the device carries none: only the device can judge
		{"v9.9.9", 4150, true},  // a release this hub has never heard of: the device judges
	} {
		target, note := GuardReleaseOffer("This device's agent", c.seq, c.tag, "the offer")
		if offered := target == c.tag && note == "the offer"; offered != c.offered {
			t.Errorf("%s to a device at %d: offered=%t (%q, %q), want %t", c.tag, c.seq, offered, target, note,
				c.offered)
		}
	}
	if target, note := GuardReleaseOffer("x", 4150, "", "nothing to offer"); target != "" || note != "nothing to offer" {
		t.Errorf("an empty offer changed: %q, %q", target, note)
	}

	// This hub's own release is judged by its own stamp.
	withHub(t, "v0.2.0")
	prevSeq := version.Sequence
	t.Cleanup(func() { version.Sequence = prevSeq })
	version.Sequence = "4300"
	if seq, known := ReleaseSequence("v0.2.0"); !known || seq != 4300 {
		t.Errorf("the hub's own release: %d, %t", seq, known)
	}
}
