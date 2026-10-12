package executor

// bootstrapsource.go decides what the one-command installer a hub hands out
// installs on a new device (Task 20421).
//
// The installer used to fetch /releases/latest whatever the hub ran. A hub
// built from main speaks a newer executor protocol than any release — :8888
// spoke v21 while the latest release, v0.0.4, spoke v13 — so every device
// enrolled from its dashboard started eight protocol versions behind the hub
// that enrolled it, and was refused virtual executors, stored firewall rules,
// feature branches, secret refresh and the rest the moment it connected.
//
// So the source follows the hub's own build:
//
//   - A hub that is a release hands out the latest release, which speaks its
//     protocol or a newer one.
//   - A hub that runs a build of main CI signed and published on the edge
//     channel hands out that build, with an explicit `--channel edge` in the
//     command. Which builds a device accepts is its operator's decision, never
//     the hub's (pkg/provenance), so the choice is in the command the operator
//     reads and runs, not hidden in the script.
//   - Any other hub hands out the latest release, and says so when the hub
//     knows that release to speak an older protocol than its own.
//
// Whatever the source, the script itself refuses a binary that speaks an older
// protocol than the hub — downloaded, already on the device, or named by
// CLOOP_BIN — so no path installs an agent behind the hub that enrolled it.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/version"
)

// BootstrapSource is what the installer a hub hands out installs.
type BootstrapSource struct {
	// Edge reports that the command installs this hub's own build from the
	// edge channel: `install.sh --channel edge`.
	Edge bool
	// Commit is the full commit of the hub's published edge build: what
	// `--channel edge` installs, whether or not the command uses it. Empty when
	// there is none, and EdgeWhyNot then says why.
	Commit string
	// EdgeWhyNot says why `--channel edge` has nothing to install, for the
	// script's refusal of it. Empty when Commit is set.
	EdgeWhyNot string
	// Note is the sentence shown beside the command; empty when there is
	// nothing to add to it.
	Note string
	// Stopped reports that, as far as the hub knows, no signed build speaks
	// its protocol: the command's installer will stop at the protocol check on
	// a device without a newer cloop, and Note says what to do instead.
	Stopped bool
}

// ChooseBootstrapSource decides what the installer installs for a hub that
// speaks hubProtocol, from the hub's own build (HubBuild) and what it learned
// about that build's edge build. edge is nil when the hub runs a release, or
// when it could not be asked.
func ChooseBootstrapSource(hubProtocol int, edge *EdgeBuild) BootstrapSource {
	h := hubFacts()
	if h.release {
		return BootstrapSource{EdgeWhyNot: fmt.Sprintf("this hub runs the release %s, which has no edge build; "+
			"install without --channel edge to get the latest release", h.version)}
	}

	newest, known := newestKnownRelease()
	releaseKeepsUp := known && hubProtocol > 0 && newest.Protocol >= hubProtocol

	if commit, ok := publishedEdgeCommit(hubProtocol, edge); ok {
		var without string
		switch {
		case releaseKeepsUp:
			without = fmt.Sprintf("Without --channel edge it installs the latest release instead (%s when this "+
				"hub was built), on the stable channel.", newest.Tag)
		case known:
			without = fmt.Sprintf("Without --channel edge it would fetch the latest release instead — the newest "+
				"this hub knows of, %s, speaks protocol v%d, older than this hub's v%d — and refuse to install it.",
				newest.Tag, newest.Protocol, hubProtocol)
		default:
			without = "Without --channel edge it fetches the latest release instead, and refuses it if it speaks " +
				"an older protocol than this hub."
		}
		return BootstrapSource{
			Edge:   true,
			Commit: commit,
			Note: joinSentences(fmt.Sprintf("This hub runs %s, a build of main that CI signed and published "+
				"(commit %s, protocol v%d), so the command installs that build and puts the device on the edge "+
				"channel (--channel edge), where the Upgrade button can move it along with the hub. The device "+
				"verifies the build against the edge workflow's signing identity before installing it",
				h.version, shortCommit(commit), edge.Protocol), without),
		}
	}

	whyNot := edgeWhyNot(h, hubProtocol, edge)
	src := BootstrapSource{EdgeWhyNot: whyNot}
	switch {
	case releaseKeepsUp:
		src.Note = joinSentences(fmt.Sprintf("This hub runs %s, an unreleased build, and its own build is not "+
			"on the edge channel: %s", h.version, continueSentence(whyNot)),
			fmt.Sprintf("The command installs the latest release (%s when this hub was built), which speaks this "+
				"hub's protocol, v%d", newest.Tag, newest.Protocol))
	case known && hubProtocol > 0:
		src.Stopped = true
		src.Note = joinSentences(fmt.Sprintf("This hub runs %s at protocol v%d, ahead of the newest release it "+
			"knows of (%s, v%d), and its own build is not on the edge channel: %s", h.version, hubProtocol,
			newest.Tag, newest.Protocol, continueSentence(whyNot)),
			"The installer refuses to put an agent on the device that speaks an older protocol than this hub, so "+
				"on a device without a newer cloop the command stops there",
			bootstrapBuildSteps(h))
	}
	return src
}

// publishedEdgeCommit returns the full commit of the hub's own edge build when
// CI has published it and it speaks the hub's protocol.
func publishedEdgeCommit(hubProtocol int, edge *EdgeBuild) (string, bool) {
	if edge == nil || !edge.Published || edge.Target == "" || edge.Protocol < hubProtocol {
		return "", false
	}
	commit, err := version.ParseEdgeTarget(edge.Target)
	if err != nil || len(commit) != 40 {
		return "", false
	}
	return commit, true
}

// edgeWhyNot says why the hub's own build cannot be installed from the edge
// channel.
func edgeWhyNot(h hubBuildFacts, hubProtocol int, edge *EdgeBuild) string {
	switch {
	case h.commit == "":
		return fmt.Sprintf("this hub's build (%s) names no clean commit, so no edge build can match it", h.version)
	case edge == nil:
		return fmt.Sprintf("whether CI has published this hub's build (%s) could not be checked", h.version)
	case edge.Published && edge.Protocol < hubProtocol:
		return fmt.Sprintf("the edge build of commit %s speaks protocol v%d, older than this hub's v%d",
			edge.Short, edge.Protocol, hubProtocol)
	case edge.Published:
		return fmt.Sprintf("the hub could not name the commit of its own edge build (%s)", edge.Short)
	}
	if why := strings.TrimSpace(edge.WhyNot); why != "" {
		return why
	}
	return fmt.Sprintf("CI has not published this hub's build (%s) yet", h.version)
}

// bootstrapBuildSteps is how to enroll a device now, before any signed build
// speaks the hub's protocol: a build of the hub's own source, handed to the
// installer.
func bootstrapBuildSteps(h hubBuildFacts) string {
	s := fmt.Sprintf("To enroll a device now, build cloop %s, in a full clone, as a static binary (`%s`), copy it to the device and "+
		"run the command there with CLOOP_BIN=/path/to/cloop in front of it", h.source, staticBuildCommand)
	if h.commit != "" {
		s += "; once CI has published this hub's build, a newly minted command installs that build instead"
	}
	return s
}

// continueSentence fits a reason after a colon: its full stop dropped, and its
// first letter lowered unless it starts an acronym ("CI has not …").
func continueSentence(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if len(s) > 1 && strings.ToUpper(s[1:2]) == s[1:2] && strings.ToLower(s[1:2]) != s[1:2] {
		return s
	}
	return uncapitalize(s)
}

// shortCommit is the seven-digit form of a commit for a sentence.
func shortCommit(commit string) string {
	if len(commit) > 7 {
		return commit[:7]
	}
	return commit
}
