package kubernetes

// provenance_test.go: the Kubernetes driver's check of cloop's own images (Task
// 20453). A cluster's image store is its nodes', so there is nothing to resolve
// a tag in: a digest is verified, and a tag is unverifiable — said, and refused
// when executors.image_provenance is required.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

const ownHarnessDigest = "ghcr.io/blechschmidt/cloop-harness@" + testDigest

// podVerifier answers one verdict for every digest and counts the asks.
type podVerifier struct {
	verdict imagepolicy.ProvenanceVerdict
	asked   atomic.Int32
}

func (v *podVerifier) VerifyProvenance(_ context.Context, ref string) imagepolicy.ProvenanceVerdict {
	v.asked.Add(1)
	if !strings.Contains(ref, "@sha256:") {
		return imagepolicy.ProvenanceVerdict{Status: imagepolicy.ProvenanceUnverifiable, Detail: "asked about a tag"}
	}
	return v.verdict
}

func (v *podVerifier) TrustRoot() (string, string) {
	return provenance.DefaultIssuer, provenance.ImagesIdentityRegexp
}

func podVerdict(s imagepolicy.ProvenanceStatus) *podVerifier {
	return &podVerifier{verdict: imagepolicy.ProvenanceVerdict{Status: s, Detail: string(s) + " by the stand-in"}}
}

// provenanceExecutor is a hub's Kubernetes driver configured with image and
// verifier.
func provenanceExecutor(t *testing.T, image string, v imagepolicy.ProvenanceVerifier, mutate func(*Options)) *Executor {
	t.Helper()
	ex, _, _ := newTestExecutor(t, func(o *Options) {
		o.Image = image
		o.VerifyOwnImages = true
		if mutate != nil {
			mutate(o)
		}
	})
	ex.provenance = v
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	return ex
}

func requireProvenance(t *testing.T, required bool) {
	t.Helper()
	prev := executor.SetImageProvenanceRequired(required)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
}

// TestADigestOfCloopsImageIsVerifiedBeforeAPodRunsIt: the Pod carries the
// verified digest, and the handle the verdict.
func TestADigestOfCloopsImageIsVerifiedBeforeAPodRunsIt(t *testing.T) {
	requireProvenance(t, true)
	v := podVerdict(imagepolicy.ProvenanceVerified)
	ex := provenanceExecutor(t, ownHarnessDigest, v, nil)
	req, err := ex.podRequestFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("podRequestFor: %v", err)
	}
	if req.Image != ownHarnessDigest || !req.ImageProvenance.Verified() || v.asked.Load() != 1 {
		t.Fatalf("Pod image %q with provenance %+v after %d verifications", req.Image, req.ImageProvenance, v.asked.Load())
	}

	h, err := ex.Start(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !h.ImageProvenance.Verified() || h.ImageProvenance.VerifiedDigest() != testDigest || h.Image != ownHarnessDigest {
		t.Errorf("handle = %+v, provenance %+v; want the verified digest recorded", h, h.ImageProvenance)
	}
}

// TestAWrongSignatureNeverReachesAPod: present and wrong refuses in both modes.
func TestAWrongSignatureNeverReachesAPod(t *testing.T) {
	for _, required := range []bool{false, true} {
		requireProvenance(t, required)
		ex := provenanceExecutor(t, ownHarnessDigest, podVerdict(imagepolicy.ProvenanceMismatch), nil)
		_, err := ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
		var denied *imagepolicy.DenyError
		if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleProvenance {
			t.Fatalf("required=%t: buildPodFor = %v, want a %s refusal", required, err, imagepolicy.RuleProvenance)
		}
	}
}

// TestAnUnsignedDigestWarnsOrIsRefused: an image published before signing
// began, by digest.
func TestAnUnsignedDigestWarnsOrIsRefused(t *testing.T) {
	requireProvenance(t, false)
	ex := provenanceExecutor(t, ownHarnessDigest, podVerdict(imagepolicy.ProvenanceUnsigned), nil)
	req, err := ex.podRequestFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("warn: %v", err)
	}
	if req.Image != ownHarnessDigest || req.ImageProvenance.Status != imagepolicy.ProvenanceUnsigned ||
		req.ImageProvenance.Warning == "" {
		t.Fatalf("warn: Pod image %q with provenance %+v", req.Image, req.ImageProvenance)
	}
	requireProvenance(t, true)
	if _, err := ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", ""); !errors.Is(err, imagepolicy.ErrDenied) {
		t.Fatalf("required: %v, want a refusal", err)
	}
}

// TestATagOfCloopsImageOnKubernetesIsSaidToBeUnverifiable: the default image is
// a tag; the hub cannot follow it on a cluster, says so — naming the digest
// pin that fixes it — and asks no verifier about a tag. Required refuses it.
func TestATagOfCloopsImageOnKubernetesIsSaidToBeUnverifiable(t *testing.T) {
	requireProvenance(t, false)
	v := podVerdict(imagepolicy.ProvenanceVerified)
	ex := provenanceExecutor(t, DefaultImage, v, nil)
	req, err := ex.podRequestFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil {
		t.Fatalf("warn: %v", err)
	}
	p := req.ImageProvenance
	if req.Image != DefaultImage || p.Status != imagepolicy.ProvenanceUnverifiable || v.asked.Load() != 0 {
		t.Fatalf("Pod image %q, provenance %+v, %d verifications", req.Image, p, v.asked.Load())
	}
	if !strings.Contains(p.Warning, "cannot resolve a tag") || !strings.Contains(p.Warning, "Pin executors.kubernetes.image by digest") {
		t.Errorf("the warning does not say why or what to do: %q", p.Warning)
	}
	requireProvenance(t, true)
	_, err = ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleProvenance {
		t.Fatalf("required: %v, want a %s refusal", err, imagepolicy.RuleProvenance)
	}
}

// TestAProjectNamingCloopsImageIsCheckedToo: the check is of the image, not of
// who chose it.
func TestAProjectNamingCloopsImageIsCheckedToo(t *testing.T) {
	requireProvenance(t, false)
	ex := provenanceExecutor(t, hubDefaultImage, podVerdict(imagepolicy.ProvenanceMismatch), nil)
	spec := testSpec()
	spec.Image = ownHarnessDigest
	if _, err := ex.buildPodFor(context.Background(), spec, "h1", "cloop", ""); !errors.Is(err, imagepolicy.ErrDenied) {
		t.Fatalf("a project's wrongly signed image of cloop's own = %v, want a refusal", err)
	}
}

// TestAnOperatorPodImageIsLeftAloneUnlessGoverned: an image that is not cloop's
// is neither verified against cloop's pin nor held to the project rules, until
// govern_operator_images says so.
func TestAnOperatorPodImageIsLeftAloneUnlessGoverned(t *testing.T) {
	requireProvenance(t, true)
	v := podVerdict(imagepolicy.ProvenanceMismatch)
	policy := imagepolicy.Policy{AllowedRegistries: []string{"quay.io"}, RequireDigest: true}
	ex := provenanceExecutor(t, hubDefaultImage, v, func(o *Options) { o.ImagePolicy = policy })
	p, err := ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil || harnessImage(t, p) != hubDefaultImage || v.asked.Load() != 0 {
		t.Fatalf("the operator's image = %v after %d verifications", err, v.asked.Load())
	}
	policy.GovernOperatorImages = true
	ex = provenanceExecutor(t, hubDefaultImage, v, func(o *Options) { o.ImagePolicy = policy })
	_, err = ex.buildPodFor(context.Background(), testSpec(), "h1", "cloop", "")
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleRegistry {
		t.Fatalf("governed: %v, want the registry allowlist's refusal", err)
	}
}

// TestWithoutVerifyOwnImagesNothingIsChecked: the switch the hub's reconcile
// sets; off, the driver behaves as before.
func TestWithoutVerifyOwnImagesNothingIsChecked(t *testing.T) {
	requireProvenance(t, true)
	v := podVerdict(imagepolicy.ProvenanceMismatch)
	ex := provenanceExecutor(t, DefaultImage, v, func(o *Options) { o.VerifyOwnImages = false })
	req, err := ex.podRequestFor(context.Background(), testSpec(), "h1", "cloop", "")
	if err != nil || req.ImageProvenance != nil || v.asked.Load() != 0 {
		t.Fatalf("%+v, %v after %d verifications", req.ImageProvenance, err, v.asked.Load())
	}
}
