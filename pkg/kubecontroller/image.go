package kubecontroller

// image.go decides what image a pool's runners start from.
//
// A template that names none gets cloop's own harness image — the tag of this
// build's release, or edge for a build that is not one — resolved at its
// registry to the digest it serves, and that digest's signature checked
// against the workflow that publishes cloop's images (imagepolicy's own-image
// check, the hub's for the same images). The Pod names the digest, so what a
// node pulls is what was verified, and a registry that moves the tag later
// changes nothing. A digest that cannot be resolved starts no runner: a tag
// is not what this default promises. A signature that is present and wrong
// always refuses; one that is absent or cannot be checked — no cosign beside
// the controller, a transparency log out of reach — is a warning, unless the
// controller runs with --image-provenance=required.
//
// An image the template names is the operator's choice and is used as it is
// written, except that one of cloop's own images named by tag is resolved and
// checked like the default.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/version"
)

// imageCacheTTL is how long a resolution is reused: a tag moves on a release,
// and every pool of one controller resolves the same default.
var (
	imageCacheTTL = 10 * time.Minute
	imageErrorTTL = 30 * time.Second
)

// DefaultRunnerImage is the image a template with none runs: cloop's harness
// image at the tag ControllerImageTag gives this build, which is its release's
// tag for a release and edge, the harness image CI publishes from main, for
// any other build.
//
// Never latest. latest moves only on a release, and a controller built from
// main starts its runners with flags of main's agent: the newest release's
// agent can be older than that, and the release before executor pools has no
// --ephemeral at all, so a runner started from it exits at once.
func DefaultRunnerImage() string { return defaultRunnerImageFor(version.String()) }

// defaultRunnerImageFor is DefaultRunnerImage for a controller of build
// version v.
func defaultRunnerImageFor(v string) string {
	tag, _ := ControllerImageTag(v)
	return defaultRunnerRepo() + ":" + tag
}

// imageChooser resolves and verifies runner images, with a cache.
type imageChooser struct {
	resolver imagepolicy.Resolver
	verifier imagepolicy.ProvenanceVerifier
	required bool
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]imageChoice
}

// imageChoice is one resolution.
type imageChoice struct {
	Image   string
	Warning string
	Err     error
	at      time.Time
	ttl     time.Duration
}

func newImageChooser(resolver imagepolicy.Resolver, verifier imagepolicy.ProvenanceVerifier, required bool) *imageChooser {
	return &imageChooser{resolver: resolver, verifier: verifier, required: required, now: time.Now,
		cache: map[string]imageChoice{}}
}

// choose returns the image a pool's runners run, or why there is none.
func (c *imageChooser) choose(ctx context.Context, pool *ExecutorPool) imageChoice {
	named := strings.TrimSpace(pool.Spec.Template.Image)
	ref := named
	if ref == "" {
		ref = DefaultRunnerImage()
	} else if !imagepolicy.IsOwnImage(ref) {
		return imageChoice{Image: ref}
	}

	if hit, ok := c.cached(ref); ok {
		return hit
	}

	field := "spec.template.image"
	if named == "" {
		field = "the default runner image"
	}
	check := imagepolicy.OwnImageCheck{Image: ref, Resolver: c.resolver, Verifier: c.verifier, Required: c.required,
		Subject: "the executor controller", Field: field}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	p, err := check.Run(rctx)
	cancel()
	choice := imageChoice{at: c.now(), ttl: imageCacheTTL}
	switch {
	case err != nil:
		choice.Err = fmt.Errorf("runner image %s: %w", ref, err)
	case p.Digest == "":
		choice.Err = fmt.Errorf("runner image %s could not be resolved to a digest at its registry (%s); "+
			"runners start from a verified digest, never a tag — let the controller reach the registry, "+
			"or set spec.template.image to a digest", ref, p.Detail)
	default:
		choice.Image = p.Ref
		if p.Status != imagepolicy.ProvenanceVerified {
			choice.Warning = fmt.Sprintf("runner image %s is %s: %s", p.Ref, p.Status, p.Detail)
		}
	}
	if choice.Err != nil {
		// A registry that did not answer is asked again soon, not in ten
		// minutes.
		choice.ttl = imageErrorTTL
	}
	c.remember(ref, choice)
	return choice
}

func (c *imageChooser) cached(ref string) (imageChoice, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit, ok := c.cache[ref]
	return hit, ok && c.now().Sub(hit.at) < hit.ttl
}

func (c *imageChooser) remember(ref string, choice imageChoice) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ref] = choice
}

// defaultRunnerRepo is the repository of the default runner image.
func defaultRunnerRepo() string {
	return strings.SplitN(executor.DefaultHarnessImage, ":", 2)[0]
}
