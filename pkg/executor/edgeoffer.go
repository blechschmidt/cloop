package executor

// edgeoffer.go writes what the hub says about the edge channel (Task 20376):
// what the Upgrade dialog offers a device that follows it, and the refusals a
// request for an edge build can meet.
//
// The edge channel is the hub's own build, signed by CI: after CI passes on a
// commit on main, .github/workflows/edge.yml publishes it, and a device whose
// operator opted in can be moved to it from here. Whether the hub's commit has
// been published — and if not, why not — is resolved through GitHub by
// pkg/upgrade.ResolveEdgeBuild; this file only turns the answer into the
// sentences an operator reads, so the dialog, the planner and the REST
// refusals cannot describe one situation three ways.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// ChannelEdge and ChannelStable are the channel names a device reports in its
// hello (provenance.ChannelEdge/ChannelStable, which this package does not
// import).
const (
	ChannelEdge   = "edge"
	ChannelStable = "stable"
)

// EdgeOptIn is the command an operator runs on a device to put it on the edge
// channel. Mirrors agent.EdgeOptInCommand.
const EdgeOptIn = "sudo cloop executor agent install --upgrade --channel edge"

// EdgeBuild is what the hub knows about its own build's edge build.
type EdgeBuild struct {
	// Short is the hub's commit as its version carries it, e.g. "a0f3870".
	Short string
	// Target is "edge:<full commit>" once the commit is resolved.
	Target string
	// Published reports that CI published the build; Protocol is what its
	// manifest says it speaks.
	Published bool
	Protocol  int
	// WhyNot is the sentence saying why it is not published, when it is not
	// (pkg/upgrade.EdgeBuild.Reason).
	WhyNot string
}

// Label is how the dialog names the build.
func (b EdgeBuild) Label() string { return "this hub's build (" + b.Short + ")" }

// EdgeChannelRefusal is the refusal for an edge target on a device that
// follows the stable channel.
func EdgeChannelRefusal(subject, target string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "The device"
	}
	return fmt.Sprintf("%s follows the stable channel and installs published releases only, so it cannot be "+
		"sent %s, a build of main. Only an operator on the device can change that — the hub cannot: `%s` there "+
		"puts it on the edge channel.", subject, strings.TrimSpace(target), EdgeOptIn)
}

// EdgeProtocolUnknown is the refusal for an edge target whose protocol the hub
// could not read, so could not judge against the device's.
func EdgeProtocolUnknown(subject, target, why string) string {
	s := fmt.Sprintf("The hub could not read which protocol %s speaks, so it cannot rule out that installing it "+
		"would lower %s's", strings.TrimSpace(target), strings.TrimSpace(subject))
	if why = strings.TrimSpace(why); why != "" {
		s += ": " + strings.TrimSuffix(why, ".")
	}
	return s + "."
}

// EdgeUpgradeOffer is UpgradeOffer for a device on the edge channel: this
// hub's own build when CI has published it and it would not lower the device's
// protocol; otherwise what UpgradeOffer would offer, with the reason the hub's
// build is not offered in front of it. edge is nil when the hub has no edge
// build to speak of — it runs a release, which UpgradeOffer already offers.
//
// label names the target for the dialog ("this hub's build (a0f3870)"), empty
// for a release, which names itself.
func EdgeUpgradeOffer(subject string, have, hubProtocol int, edge *EdgeBuild) (target, label, note string) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "This device's agent"
	}
	fallback, fallbackNote := UpgradeOffer(subject, have, hubProtocol)
	if edge == nil || (have > 0 && have < MinRemoteUpgradeVersion) {
		return fallback, "", fallbackNote
	}
	switch {
	case edge.Published && edge.Target != "" && (have <= 0 || edge.Protocol >= have):
		return edge.Target, edge.Label(), fmt.Sprintf("Upgrade installs %s from the edge channel: CI built and "+
			"signed commit %s on main, and it speaks protocol v%d. The device verifies the signature against "+
			"the edge workflow's identity before installing it.", edge.Label(), edge.Short, edge.Protocol)
	case edge.Published:
		return edgeFallback(fmt.Sprintf("%s is not offered: it speaks v%d, below the device's v%d, so installing "+
			"it would lower the device's protocol — the device is ahead of the hub, so move the hub forward rather "+
			"than the device back", capitalize(edge.Label()), edge.Protocol, have), fallback, fallbackNote)
	}
	why := strings.TrimSpace(edge.WhyNot)
	if why == "" {
		why = "CI has not published it"
	}
	return edgeFallback(fmt.Sprintf("%s is not offered yet: %s It is offered here once CI has published it",
		capitalize(edge.Label()), joinSentences(why)), fallback, fallbackNote)
}

// edgeFallback completes the note for an edge-channel device whose hub build
// is not offered: what UpgradeOffer would offer instead, if anything. With
// nothing to offer, UpgradeOffer's own note — written for a device that still
// has to be put on the channel — is left out: this one is on it already.
func edgeFallback(lead, fallback, fallbackNote string) (target, label, note string) {
	if fallback != "" {
		return fallback, "", joinSentences(lead, "Until then Upgrade offers "+fallback+".", fallbackNote)
	}
	tail := "No published release can be offered instead without lowering the device's protocol."
	if newest, ok := newestKnownRelease(); ok {
		tail = fmt.Sprintf("No published release can be offered instead without lowering the device's protocol: "+
			"the newest this hub knows of, %s, speaks v%d.", newest.Tag, newest.Protocol)
	}
	return "", "", joinSentences(lead, tail)
}

// capitalize upper-cases the first letter, for a label that starts a sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// StableChannelHint is appended to the Upgrade dialog's note for a device on
// the stable channel when the hub runs an unreleased build of a commit: the
// way to let the dialog offer the hub's own build is on the device.
func StableChannelHint() string {
	h := hubFacts()
	if h.release {
		return ""
	}
	if _, ok := version.CommitOf(h.version); !ok {
		return ""
	}
	return fmt.Sprintf("This device follows the stable channel. To let Upgrade install this hub's own build "+
		"(%s) once CI has published it, put the device on the edge channel: `%s` on it.", h.version, EdgeOptIn)
}
