package kubecontroller

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/version"
)

// TestTheDefaultRunnerImageFollowsTheControllersBuild: a pool that names no
// runner image runs cloop's harness image at the tag the controller's own
// image has, its release's for a release and edge for any other build.
//
// It used to be latest for a build that is not a release, which is the newest
// release: a controller from the edge image then started runners whose agent
// was the release before executor pools, with no --ephemeral, and every runner
// exited at once.
func TestTheDefaultRunnerImageFollowsTheControllersBuild(t *testing.T) {
	repo := defaultRunnerRepo()
	if got := defaultRunnerImageFor("v0.0.9"); got != repo+":0.0.9" {
		t.Errorf("a release's default runner image = %q, want %s:0.0.9", got, repo)
	}
	for _, v := range []string{"dev", "dev+g1a2b3c4", "", "v0.0.9+g1a2b3c4"} {
		got := defaultRunnerImageFor(v)
		if got != repo+":edge" {
			t.Errorf("build %q: default runner image = %q, want %s:edge", v, got, repo)
		}
		if strings.HasSuffix(got, ":latest") {
			t.Errorf("build %q runs its runners from latest, the newest release, whose agent may not have "+
				"the flags this controller starts runners with", v)
		}
		ctl, _ := ControllerImageTag(v)
		if !strings.HasSuffix(got, ":"+ctl) {
			t.Errorf("build %q: runners on %q but the controller on tag %q", v, got, ctl)
		}
	}
	// The default is resolved to a digest and verified like any image of
	// cloop's own, which only an image the policy knows as cloop's gets.
	if !imagepolicy.IsOwnImage(defaultRunnerImageFor("dev")) {
		t.Errorf("%s is not one of cloop's own images, so it would run unverified", defaultRunnerImageFor("dev"))
	}
	if DefaultRunnerImage() != defaultRunnerImageFor(version.String()) {
		t.Errorf("DefaultRunnerImage() = %q does not follow this build", DefaultRunnerImage())
	}
}
