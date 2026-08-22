package container

// imagepolicy_test.go drives the hub's image trust policy against a real
// container runtime (Task 20177).
//
// The pure rules are covered exhaustively in pkg/imagepolicy. What can only be
// checked here is the wiring: that the policy runs *before* the image is
// inspected, built from or started, and that an accepted tag really is resolved
// against the local store and replaced by its digest. A unit test with a stub
// resolver cannot tell the difference between that and a policy that is
// consulted after the fact.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

func policyTestExecutor(t *testing.T, p imagepolicy.Policy) *Executor {
	t.Helper()
	return newTestExecutor(t, "alpine:3.20", func(o *Options) { o.ImagePolicy = p })
}

// TestSandboxImagePolicyRefusesADisallowedRegistry: the refusal must happen
// without the image being touched, so a reference that would otherwise resolve
// perfectly well is still refused when it is not on the allowlist.
func TestSandboxImagePolicyRefusesADisallowedRegistry(t *testing.T) {
	ex := policyTestExecutor(t, imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}})
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := ex.sandboxImage(ctx, executor.Spec{Image: image})
	if err == nil {
		t.Fatal("a present, resolvable image on a disallowed registry was accepted")
	}
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want a policy denial", err)
	}
	if denied.Rule != imagepolicy.RuleUnqualified && denied.Rule != imagepolicy.RuleRegistry {
		t.Fatalf("rule = %q, want a registry-related denial", denied.Rule)
	}
}

// TestSandboxImagePolicyResolvesAndPinsAnAcceptedTag is the TOCTOU property
// against a real store: the tag is accepted, then replaced by the digest the
// store reports, and that digest is what the workload would run.
func TestSandboxImagePolicyResolvesAndPinsAnAcceptedTag(t *testing.T) {
	ex := policyTestExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"docker.io"},
		DefaultRegistry:   "docker.io",
	})
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	got, err := ex.sandboxImage(ctx, executor.Spec{Image: image})
	if err != nil {
		t.Fatalf("sandboxImage: %v", err)
	}
	if !strings.Contains(got.Pinned(), "@sha256:") {
		t.Fatalf("Pinned() = %q, want a digest — the tag reached the runtime", got.Pinned())
	}
	if got.ID == "" {
		t.Fatal("no content id resolved")
	}
}

// TestSandboxImagePolicyRefusesAnUnpinnedTagWhenDigestsAreRequired: refused at
// the policy, not merely pinned afterwards. The distinction matters because the
// same policy governs Kubernetes, where pinning afterwards is impossible.
func TestSandboxImagePolicyRefusesAnUnpinnedTagWhenDigestsAreRequired(t *testing.T) {
	ex := policyTestExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"docker.io"},
		DefaultRegistry:   "docker.io",
		RequireDigest:     true,
	})
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := ex.sandboxImage(ctx, executor.Spec{Image: image})
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleDigest {
		t.Fatalf("sandboxImage = %v, want a %s denial", err, imagepolicy.RuleDigest)
	}
}

// TestSandboxImagePolicyLeavesTheOperatorsImageAlone: the executor's own image
// is the operator's choice, made in the same file as the policy. A spec with no
// override must still run even when that image would fail the project rules —
// otherwise the shipped chart default of "digests only" would refuse the hub's
// own tagged image at boot.
func TestSandboxImagePolicyLeavesTheOperatorsImageAlone(t *testing.T) {
	ex := policyTestExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := ex.sandboxImage(ctx, executor.Spec{}); err != nil {
		t.Fatalf("the executor's own image was refused by the project image policy: %v", err)
	}
}

// TestResolveDigestReportsErrNoDigestForALocalImage.
//
// "the image is not here" and "the image is here but has no digest" need
// opposite handling — one is an operator's missing pull, the other means there
// is nothing to pin or verify against. Collapsing them would make a locally
// built image look like a missing one.
func TestResolveDigestReportsErrNoDigestForALocalImage(t *testing.T) {
	ex := policyTestExecutor(t, imagepolicy.Policy{})
	image := requireImage(t, ex.rt, "alpine:3.20")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// A pulled image has a repo digest.
	digest, err := ex.ResolveDigest(ctx, image)
	if err != nil {
		t.Fatalf("ResolveDigest on a pulled image: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("ResolveDigest = %q, want a sha256 digest", digest)
	}

	// A missing one is a lookup failure naming the fix, not ErrNoDigest.
	_, err = ex.ResolveDigest(ctx, "localhost/cloop-does-not-exist:v0")
	if errors.Is(err, imagepolicy.ErrNoDigest) {
		t.Fatal("a missing image was reported as one with no digest")
	}
	if err == nil || !strings.Contains(err.Error(), "pull") {
		t.Fatalf("ResolveDigest on a missing image = %v, want an error naming the fix", err)
	}
}
