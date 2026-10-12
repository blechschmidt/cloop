package executor

// bootstrapsource_test.go holds what the installer a hub hands out installs
// (Task 20421): this hub's own build with a visible --channel edge once CI
// published it, the latest release otherwise, and a warning — never a quiet
// downgrade — when nothing signed speaks the hub's protocol.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/version"
)

const bootstrapHubCommit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

func publishedEdge(protocol int) *EdgeBuild {
	return &EdgeBuild{Short: "a0f3870", Target: version.EdgeTarget(bootstrapHubCommit), Published: true,
		Protocol: protocol, Sequence: 4300}
}

func TestChooseBootstrapSource(t *testing.T) {
	old := version.Release{Tag: "v0.0.4", Protocol: 13}
	level := version.Release{Tag: "v0.0.5", Protocol: 21, Sequence: 4280}
	ciRunning := &EdgeBuild{Short: "a0f3870", Target: version.EdgeTarget(bootstrapHubCommit),
		WhyNot: "CI has not published commit a0f3870 yet: CI is still running on it."}

	for _, tc := range []struct {
		name     string
		hub      string
		releases []version.Release
		edge     *EdgeBuild
		// want
		edgeSrc   bool
		commit    string
		stopped   bool
		note      []string
		noteEmpty bool
		whyNot    string
	}{
		{
			name: "a release hub hands out the latest release", hub: "v0.0.5",
			releases: []version.Release{old, level}, edge: nil,
			noteEmpty: true, whyNot: "this hub runs the release v0.0.5, which has no edge build; install without " +
				"--channel edge to get the latest release",
		},
		{
			name: "a signed hub ahead of every release hands out its own build", hub: "dev+ga0f3870",
			releases: []version.Release{old}, edge: publishedEdge(21),
			edgeSrc: true, commit: bootstrapHubCommit,
			note: []string{
				"This hub runs dev+ga0f3870, a build of main that CI signed and published (commit a0f3870, protocol v21)",
				"puts the device on the edge channel (--channel edge)",
				"Without --channel edge it would fetch the latest release instead — the newest this hub knows of, " +
					"v0.0.4, speaks protocol v13, older than this hub's v21 — and refuse to install it.",
			},
		},
		{
			name: "a signed hub level with a release still hands out its own build", hub: "dev+ga0f3870",
			releases: []version.Release{old, level}, edge: publishedEdge(21),
			edgeSrc: true, commit: bootstrapHubCommit,
			note: []string{"Without --channel edge it installs the latest release instead (v0.0.5 when this hub " +
				"was built), on the stable channel."},
		},
		{
			name: "an unpublished hub ahead of every release warns that the installer stops", hub: "dev+ga0f3870",
			releases: []version.Release{old}, edge: ciRunning,
			stopped: true, whyNot: ciRunning.WhyNot,
			note: []string{
				"This hub runs dev+ga0f3870 at protocol v21, ahead of the newest release it knows of (v0.0.4, v13), " +
					"and its own build is not on the edge channel: CI has not published commit a0f3870 yet: CI is still " +
					"running on it.",
				"the command stops there",
				"CLOOP_BIN=/path/to/cloop",
				"build cloop at the hub's commit a0f3870",
				"once CI has published this hub's build, a newly minted command installs that build instead",
			},
		},
		{
			name: "an unpublished hub level with a release hands out the release", hub: "dev+ga0f3870",
			releases: []version.Release{old, level}, edge: ciRunning, whyNot: ciRunning.WhyNot,
			note: []string{"The command installs the latest release (v0.0.5 when this hub was built), which speaks " +
				"this hub's protocol, v21."},
		},
		{
			name: "a dirty hub has no edge build", hub: "dev+ga0f3870.dirty",
			releases: []version.Release{old}, edge: nil, stopped: true,
			whyNot: "this hub's build (dev+ga0f3870.dirty) names no clean commit, so no edge build can match it",
			note:   []string{"build cloop from the hub's own uncommitted source tree (on commit a0f3870)"},
		},
		{
			name: "an edge build that lowers the protocol is not handed out", hub: "dev+ga0f3870",
			releases: []version.Release{old}, edge: publishedEdge(20), stopped: true,
			whyNot: "the edge build of commit a0f3870 speaks protocol v20, older than this hub's v21",
		},
		{
			name: "a hub that could not ask GitHub says so", hub: "dev+ga0f3870",
			releases: []version.Release{old, level}, edge: nil,
			whyNot: "whether CI has published this hub's build (dev+ga0f3870) could not be checked",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHub(t, tc.hub)
			withReleases(t, tc.releases...)
			got := ChooseBootstrapSource(21, tc.edge)
			if got.Edge != tc.edgeSrc || got.Commit != tc.commit || got.Stopped != tc.stopped {
				t.Errorf("source = edge %t commit %q stopped %t, want edge %t commit %q stopped %t\n  note: %s",
					got.Edge, got.Commit, got.Stopped, tc.edgeSrc, tc.commit, tc.stopped, got.Note)
			}
			if tc.noteEmpty && got.Note != "" {
				t.Errorf("note = %q, want none", got.Note)
			}
			for _, want := range tc.note {
				if !strings.Contains(got.Note, want) {
					t.Errorf("the note does not say %q:\n  %s", want, got.Note)
				}
			}
			if tc.whyNot != "" && got.EdgeWhyNot != tc.whyNot {
				t.Errorf("edge why-not = %q, want %q", got.EdgeWhyNot, tc.whyNot)
			}
			if got.Commit != "" && got.EdgeWhyNot != "" {
				t.Errorf("an edge build to install, and a reason there is none: %q", got.EdgeWhyNot)
			}
		})
	}
}

// TestBootstrapSourceNeverOffersAnEdgeBuildBehindTheHub: whatever the release
// table says, the command never names an edge build that speaks an older
// protocol than the hub, nor one whose commit the hub could not name.
func TestBootstrapSourceNeverOffersAnEdgeBuildBehindTheHub(t *testing.T) {
	withHub(t, "dev+ga0f3870")
	withReleases(t, version.Release{Tag: "v0.0.5", Protocol: 21})
	for _, edge := range []*EdgeBuild{
		publishedEdge(20),
		{Short: "a0f3870", Published: true, Protocol: 21},                         // no target
		{Short: "a0f3870", Target: "edge:a0f3870", Published: true, Protocol: 21}, // not a full commit
		{Short: "a0f3870", Target: version.EdgeTarget(bootstrapHubCommit), Protocol: 21},
	} {
		if got := ChooseBootstrapSource(21, edge); got.Edge || got.Commit != "" {
			t.Errorf("edge %+v: handed out as %+v", edge, got)
		}
	}
}
