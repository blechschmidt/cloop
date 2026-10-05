package executor

// rollbackoffer.go is the hub's half of rollback protection (Task 20380): the
// hub never offers a device a build its installer would refuse as earlier on
// main, and says so in one voice wherever it declines to.
//
// The device decides. Every release and edge build is stamped with its
// commit's first-parent position on main — its sequence — and the device's
// root helper refuses to install a build whose sequence is lower than the
// installed binary's, or one carrying none when the installed binary carries
// one. Neither the hub's upgrade frame nor the request the agent files can
// override that: only root on the device can, with --force. So a hub that
// offered such a build would offer something that cannot happen, and an
// operator pressing Upgrade would watch it be accepted and then refused in a
// journal on the device.
//
// What the hub knows of a target's sequence it reads from the target itself:
// an edge build's manifest (read unverified, as advice), or the published
// release table for a release. A target it knows nothing about — a release
// newer than this hub — is left for the device to judge.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// RollbackOptIn is what an operator runs on a device to move it back on main
// deliberately, the one way that remains.
const RollbackOptIn = "sudo cloop executor agent install --upgrade --to <target> --force"

// RollbackRefusal is the sentence for a target the device would refuse
// because it is earlier on main than the device's build: targetSeq below have,
// or zero — a build that carries no sequence — while have is not. It returns
// "" when the target would not be refused, or when have is unknown (zero).
func RollbackRefusal(subject string, have int, target string, targetSeq int) string {
	if have <= 0 || (targetSeq > 0 && targetSeq >= have) {
		return ""
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "The device's agent"
	}
	target = strings.TrimSpace(target)
	var why string
	if targetSeq <= 0 {
		why = fmt.Sprintf("%s runs a build at %s, and %s carries no sequence — it was built before builds were "+
			"stamped with their place on main, so it is older", subject, version.SequenceLabel(have), target)
	} else {
		why = fmt.Sprintf("%s runs a build at %s, and %s is %s, %d commit(s) earlier", subject,
			version.SequenceLabel(have), target, version.SequenceLabel(targetSeq), have-targetSeq)
	}
	return why + ". The device refuses a build earlier on main than its own whoever asks, and neither the hub " +
		"nor force can change that; only root on the device can roll it back (`" + RollbackOptIn + "`)."
}

// ReleaseSequence returns the sequence the release tag's binaries carry and
// whether the hub knows it: from the published release table, or — for this
// hub's own release — from the hub's own stamp. Unknown for a release newer
// than anything this hub knows of, and for anything that is not a release.
func ReleaseSequence(tag string) (seq int, known bool) {
	tag = strings.TrimSpace(tag)
	if !version.IsRelease(tag) {
		return 0, false
	}
	for _, r := range knownReleases() {
		if r.Tag == tag {
			return r.Sequence, true
		}
	}
	if h := hubFacts(); h.release && sameTag(tag, h.version) {
		seq, _ := version.BuildSequence()
		return seq, true
	}
	return 0, false
}

// ReleaseRollbackRefusal is RollbackRefusal for a release target, judged from
// what the hub knows of the release's sequence; "" when it would not be
// refused or the hub cannot tell.
func ReleaseRollbackRefusal(subject string, have int, tag string) string {
	seq, known := ReleaseSequence(tag)
	if !known {
		return ""
	}
	return RollbackRefusal(subject, have, tag, seq)
}

// DeviceBuild is what an offer needs to know about a device's build: the
// protocol its agent speaks and its place on main, each zero when unknown.
type DeviceBuild struct {
	Protocol int
	Sequence int
}

// GuardReleaseOffer withdraws a release offer the device would refuse as
// earlier on main, putting the reason in its place. A target that is empty,
// not a release, or not refused is returned unchanged.
func GuardReleaseOffer(subject string, have int, target, note string) (string, string) {
	if why := ReleaseRollbackRefusal(subject, have, target); why != "" {
		return "", why
	}
	return target, note
}
