package executor

// edgeoffer_test.go pins what the Upgrade dialog says to a device on the edge
// channel (Task 20376), word for word like protocolneed_test.go, and the
// refusals an edge target can meet.

import (
	"strings"
	"testing"
)

const edgeTarget = "edge:a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

func TestEdgeUpgradeOfferOffersThePublishedBuild(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	withKnownReleases(t)
	target, label, note := EdgeUpgradeOffer("This device's agent", 16, 17,
		&EdgeBuild{Short: "a0f3870", Target: edgeTarget, Published: true, Protocol: 17})
	if target != edgeTarget || label != "this hub's build (a0f3870)" {
		t.Fatalf("offer = %q, %q", target, label)
	}
	want := "Upgrade installs this hub's build (a0f3870) from the edge channel: CI built and signed commit " +
		"a0f3870 on main, and it speaks protocol v17. The device verifies the signature against the edge " +
		"workflow's identity before installing it."
	if note != want {
		t.Errorf("note:\n got %q\nwant %q", note, want)
	}
}

// TestEdgeUpgradeOfferSaysWhyNot: an unpublished build or one that would
// lower the device's protocol is not offered, the reason leads the note, and
// what UpgradeOffer would offer follows.
func TestEdgeUpgradeOfferSaysWhyNot(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	withKnownReleases(t)

	target, label, note := EdgeUpgradeOffer("This device's agent", 12, 17, &EdgeBuild{Short: "a0f3870",
		Target: edgeTarget, WhyNot: "CI failed on commit a0f3870 (https://github.com/x/run), so no edge build " +
			"was published for it."})
	if target != "v0.0.4" || label != "" {
		t.Errorf("an unpublished build: offer %q, %q — want the newest release that does not lower v12", target, label)
	}
	if !strings.HasPrefix(note, "This hub's build (a0f3870) is not offered yet: CI failed on commit a0f3870 "+
		"(https://github.com/x/run), so no edge build was published for it. It is offered here once CI has "+
		"published it. Until then Upgrade offers v0.0.4.") {
		t.Errorf("the reason and the fallback do not lead the note: %q", note)
	}

	// A device ahead of every release: nothing to fall back to, and no advice
	// to join a channel it is already on.
	target, _, note = EdgeUpgradeOffer("This device's agent", 17, 17, &EdgeBuild{Short: "a0f3870",
		Target: edgeTarget, WhyNot: "CI has not published commit a0f3870 yet: CI is still running on it."})
	want := "This hub's build (a0f3870) is not offered yet: CI has not published commit a0f3870 yet: CI is " +
		"still running on it. It is offered here once CI has published it. No published release can be offered " +
		"instead without lowering the device's protocol: the newest this hub knows of, v0.0.4, speaks v13."
	if target != "" || note != want {
		t.Errorf("nothing to offer:\n got %q, %q\nwant %q", target, note, want)
	}

	target, _, note = EdgeUpgradeOffer("This device's agent", 17, 17, &EdgeBuild{Short: "a0f3870",
		Target: edgeTarget, Published: true, Protocol: 16})
	if target != "" || !strings.HasPrefix(note, "This hub's build (a0f3870) is not offered: it speaks v16, below "+
		"the device's v17, so installing it would lower the device's protocol — the device is ahead of the hub") {
		t.Errorf("a lower build: offer %q, note %q", target, note)
	}
}

// TestEdgeUpgradeOfferOnAReleasedHubIsTheRelease: a hub that is a release has
// no edge build to offer; its release is offered to a device on either channel.
func TestEdgeUpgradeOfferOnAReleasedHubIsTheRelease(t *testing.T) {
	withHub(t, "v0.2.0")
	withKnownReleases(t)
	target, label, _ := EdgeUpgradeOffer("This device's agent", 16, 17, nil)
	if target != "v0.2.0" || label != "" {
		t.Errorf("offer = %q, %q", target, label)
	}
}

func TestEdgeRefusals(t *testing.T) {
	got := EdgeChannelRefusal("agent sgx-1 (sgx)", edgeTarget)
	want := "agent sgx-1 (sgx) follows the stable channel and installs published releases only, so it cannot be " +
		"sent " + edgeTarget + ", a build of main. Only an operator on the device can change that — the hub " +
		"cannot: `sudo cloop executor agent install --upgrade --channel edge` there puts it on the edge channel."
	if got != want {
		t.Errorf("channel refusal:\n got %q\nwant %q", got, want)
	}
	got = EdgeProtocolUnknown("agent sgx-1 (sgx)", edgeTarget, "CI is still running on it.")
	want = "The hub could not read which protocol " + edgeTarget + " speaks, so it cannot rule out that " +
		"installing it would lower agent sgx-1 (sgx)'s: CI is still running on it."
	if got != want {
		t.Errorf("unknown protocol:\n got %q\nwant %q", got, want)
	}
	withHub(t, "dev+ga0f3870")
	withKnownReleases(t)
	got = ProtocolDrop("agent sgx-1 (sgx)", 17, edgeTarget, 16)
	want = "agent sgx-1 (sgx) speaks protocol v17; " + edgeTarget + " speaks v16, so installing it would lower " +
		"the device's protocol and lose what needs v17. The device is ahead of that build of main: move the " +
		"hub forward rather than the device back."
	if got != want {
		t.Errorf("edge protocol drop:\n got %q\nwant %q", got, want)
	}
}

func TestStableChannelHint(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	if got := StableChannelHint(); !strings.Contains(got, EdgeOptIn) || !strings.Contains(got, "dev+ga0f3870") {
		t.Errorf("hint = %q", got)
	}
	for _, hub := range []string{"v0.2.0", "dev", "dev+ga0f3870.dirty"} {
		withHub(t, hub)
		if got := StableChannelHint(); got != "" {
			t.Errorf("hub %s has no edge build to hint at, yet: %q", hub, got)
		}
	}
}
