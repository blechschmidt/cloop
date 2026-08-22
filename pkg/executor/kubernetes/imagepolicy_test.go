package kubernetes

// imagepolicy_test.go covers the hub's image trust policy where it matters most
// (Task 20177).
//
// On the container backend a tag is resolved against a local store and the
// digest is what runs, so an unpinned reference is a reproducibility problem.
// Here it is a trust problem: the Pod carries whatever reference it was given
// to an API server, and some kubelet resolves it later, on a node, when it
// schedules. Nothing between the policy check and that pull is under the
// control plane's control. So the only thing that closes the gap is the digest
// being in the Pod spec, and that is what these tests assert.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

const testDigest = "sha256:" +
	"1a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f7890"

// policyExecutor builds an executor whose hub-wide image is untouched by the
// policy — only project overrides are governed — with policy applied.
func policyExecutor(t *testing.T, p imagepolicy.Policy) *Executor {
	t.Helper()
	ex, _, _ := newTestExecutor(t, func(o *Options) {
		o.Image = hubDefaultImage
		o.ImagePolicy = p
	})
	return ex
}

func harnessImage(t *testing.T, p *pod) string {
	t.Helper()
	for _, c := range p.Spec.Containers {
		if c.Name == ContainerName {
			return c.Image
		}
	}
	t.Fatalf("pod has no %q container", ContainerName)
	return ""
}

// TestPinnedDigestLandsInTheContainerSpec is the assertion the whole Kubernetes
// half of this feature exists for.
func TestPinnedDigestLandsInTheContainerSpec(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	})

	const ref = "ghcr.io/acme/rust@" + testDigest
	p, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: ref,
	}, "h1", "cloop", "")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}

	got := harnessImage(t, p)
	if got != ref {
		t.Fatalf("container image = %q, want the digest-pinned %q", got, ref)
	}
	if !strings.Contains(got, "@sha256:") {
		t.Fatal("the Pod would be scheduled with a mutable reference")
	}
}

// TestTagIsCanonicalisedIntoTheContainerSpec: a reference carrying both a tag
// and a digest is legal and resolves by digest, but the tag it carries is a
// claim nobody can check six months later. The Pod gets the canonical form.
func TestTagIsCanonicalisedIntoTheContainerSpec(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	})

	p, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: "ghcr.io/acme/rust:1.79@" + testDigest,
	}, "h1", "cloop", "")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}
	got := harnessImage(t, p)
	if got != "ghcr.io/acme/rust@"+testDigest {
		t.Fatalf("container image = %q, want the canonical digest form", got)
	}
	if strings.Contains(got, "1.79") {
		t.Errorf("the tag survived into the Pod spec: %q", got)
	}
}

// TestUnpinnedImageIsRefusedUnderRequireDigest: no Pod is built at all. The
// alternative — building it with a tag and hoping — is the failure this feature
// removes.
func TestUnpinnedImageIsRefusedUnderRequireDigest(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"ghcr.io"},
		RequireDigest:     true,
	})

	_, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: "ghcr.io/acme/rust:1.79",
	}, "h1", "cloop", "")
	if err == nil {
		t.Fatal("a tag-only image was scheduled under require_digest")
	}
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleDigest {
		t.Fatalf("error = %v, want a %s denial", err, imagepolicy.RuleDigest)
	}
	// Not ErrInvalidSpec: the file is well-formed, the hub's configuration is
	// what refuses it, and the API renders that as a conflict rather than a
	// syntax complaint the author cannot act on.
	if errors.Is(err, executor.ErrInvalidSpec) {
		t.Error("a policy conflict was reported as a malformed spec")
	}
}

// TestDisallowedRegistryNeverReachesAPod covers the confusion cases at the
// layer that builds the object, not only in the pure evaluator: the check has
// to be in the builder, or a second call path added later bypasses it.
func TestDisallowedRegistryNeverReachesAPod(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}})

	for name, ref := range map[string]string{
		"different registry":       "evil.example/acme/rust@" + testDigest,
		"allowed name as a path":   "evil.example/ghcr.io/rust@" + testDigest,
		"allowed name as a prefix": "ghcr.io.evil.example/acme/rust@" + testDigest,
		"homograph":                "ghсr.io/acme/rust@" + testDigest,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ex.buildPodFor(context.Background(), executor.Spec{
				Argv:  []string{"cloop", "run"},
				Image: ref,
			}, "h1", "cloop", "")
			if err == nil {
				t.Fatalf("a Pod was built for %q with image %q", ref, harnessImage(t, p))
			}
			if !errors.Is(err, imagepolicy.ErrDenied) {
				t.Fatalf("error = %v, want a policy denial", err)
			}
		})
	}
}

// TestMalformedImageStaysAnInvalidSpec: the two refusals must not be flattened.
// A malformed reference is a broken file the author fixes alone (400); a policy
// conflict may need an operator (409).
func TestMalformedImageStaysAnInvalidSpec(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}})

	_, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: "--privileged",
	}, "h1", "cloop", "")
	if !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("error = %v, want ErrInvalidSpec", err)
	}
}

// TestNoPolicyLeavesTheOverrideAlone: the feature must not change what an
// unconfigured hub does. Kubernetes cannot resolve a tag, so with no policy the
// Pod keeps exactly the reference the project wrote.
func TestNoPolicyLeavesTheOverrideAlone(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{})

	p, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: "ghcr.io/acme/rust:1.79",
	}, "h1", "cloop", "")
	if err != nil {
		t.Fatalf("buildPodFor: %v", err)
	}
	if got := harnessImage(t, p); got != "ghcr.io/acme/rust:1.79" {
		t.Fatalf("container image = %q, want the project's reference unchanged", got)
	}
}

// TestOperatorImageIsNotGovernedByThePolicy.
//
// The hub's own image is chosen by the same person who writes the policy, in
// the same file. Running it through the allowlist would be a lint rather than a
// control — and with the shipped chart default of require_digest it would
// refuse the hub's own tagged image at boot, which is how a safe default
// becomes one nobody can adopt.
func TestOperatorImageIsNotGovernedByThePolicy(t *testing.T) {
	ex := policyExecutor(t, imagepolicy.Policy{
		AllowedRegistries: []string{"quay.io"}, // hubDefaultImage is on ghcr.io
		RequireDigest:     true,                // and it is tagged, not pinned
	})

	p, err := ex.buildPodFor(context.Background(), executor.Spec{Argv: []string{"cloop"}}, "h2", "cloop", "")
	if err != nil {
		t.Fatalf("the executor's own image was refused by the project image policy: %v", err)
	}
	if got := harnessImage(t, p); got != hubDefaultImage {
		t.Fatalf("container image = %q, want the operator's %q", got, hubDefaultImage)
	}
}

// TestSignaturePolicyFailsClosedWithoutAVerifier: an Executor built by hand —
// as several tests in this package do — has no verifier, and must refuse rather
// than satisfy a signature requirement by having nothing to check with.
func TestSignaturePolicyFailsClosedWithoutAVerifier(t *testing.T) {
	ex := &Executor{
		id: "k8s",
		opts: Options{
			Image: hubDefaultImage,
			ImagePolicy: imagepolicy.Policy{
				AllowedRegistries: []string{"ghcr.io"},
				RequireSignature:  true,
				CosignPublicKeys:  []string{"/etc/cloop/cosign.pub"},
			},
		},
		handles: make(map[string]*record),
	}

	_, err := ex.buildPodFor(context.Background(), executor.Spec{
		Argv:  []string{"cloop", "run"},
		Image: "ghcr.io/acme/rust@" + testDigest,
	}, "h1", "cloop", "")
	if err == nil {
		t.Fatal("an unverified image was scheduled by an executor with no verifier")
	}
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleSignature {
		t.Fatalf("error = %v, want a %s denial", err, imagepolicy.RuleSignature)
	}
}

// TestOptionsRefuseAnUnusablePolicy: a policy that cannot be applied must be
// rejected where it was written, not silently reduced to one that allows
// everything.
func TestOptionsRefuseAnUnusablePolicy(t *testing.T) {
	_, err := Options{
		Image:       hubDefaultImage,
		Credentials: nil,
		ImagePolicy: imagepolicy.Policy{RequireSignature: true},
	}.Normalize()
	if err == nil {
		t.Fatal("Normalize accepted require_signature with nothing to verify against")
	}
	if !strings.Contains(err.Error(), "image policy") {
		t.Errorf("error = %q, want it to name the offending section", err)
	}
}
