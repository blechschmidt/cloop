package remote

// imagepolicy.go applies the hub's image trust policy to the image a project
// names before the hub dispatches it to a device (Task 20424).
//
// A device whose sandbox runs a container, and every virtual executor, runs the
// image a project's .cloop/sandbox.yaml names. The device's container driver is
// built with no policy: the policy is the hub's, and a device holding a copy of
// its own would be a device deciding its own containment. Before this file the
// hub checked such an image against the allowlists and the digest rule only
// (Policy.Evaluate, reached from pkg/ui's applySandbox), never its signature,
// so sandbox.image_policy.require_signature held on the hub's container and
// Kubernetes executors and on no device at all.
//
// So the hub does here what the container driver does for its own workloads —
// imagepolicy.Enforcer with the same cosign verifier — except that it has no
// image store to resolve a tag in. It asks the registry instead
// (imagepolicy.RegistryResolver), verifies the signature on the digest the
// registry named, and dispatches that digest. The device's driver never pulls,
// and inspects exactly the reference it is given, so it runs the verified bytes
// or refuses naming the pull for that digest.
//
// Every way of not verifying — no cosign on the hub, the registry unreachable
// from it, a missing or bad signature, a policy the hub cannot read — is an
// *imagepolicy.DenyError. The dispatch path audits that as the image denial it
// is (statedb.AuditImagePolicyDenial), and the dashboard renders its
// remediation.
//
// An operator's own image — the device's configured sandbox image, a virtual
// executor's — is not a project's and is not checked against the project
// rules, as the container driver does not check executors.container.image,
// unless the policy says govern_operator_images (Task 20453). One of cloop's
// own images is checked whoever chose it, against the pin of the workflow that
// publishes it: authorizeRunImage below.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// defaultImageVerifier is the cosign verifier executors share when their
// options name none, so its cache of verified digests is the process's.
var (
	defaultImageVerifierOnce sync.Once
	defaultImageVerifier     *imagepolicy.CosignVerifier
)

func sharedImageVerifier() imagepolicy.Verifier {
	defaultImageVerifierOnce.Do(func() { defaultImageVerifier = imagepolicy.NewCosignVerifier() })
	return defaultImageVerifier
}

// imageVerifier returns the verifier for signature checks.
func (o Options) imageVerifier() imagepolicy.Verifier {
	if o.ImageVerifier != nil {
		return o.ImageVerifier
	}
	return sharedImageVerifier()
}

// imageResolver returns the resolver that turns a tag into a digest.
func (o Options) imageResolver() imagepolicy.Resolver {
	if o.ImageResolver != nil {
		return o.ImageResolver
	}
	return imagepolicy.NewRegistryResolver()
}

// provenanceVerifier returns the verifier for cloop's own images.
func (o Options) provenanceVerifier() imagepolicy.ProvenanceVerifier {
	if o.ProvenanceVerifier != nil {
		return o.ProvenanceVerifier
	}
	return imagepolicy.SharedProvenanceVerifier()
}

// authorizeRunImage checks the image a dispatch's sandbox will run that the
// project's own check above did not reach (Task 20453), and returns what the
// check of one of cloop's own images found, or nil for any other image.
//
// The image is spec.Image when the project named one — already through the
// project rules — and otherwise the operator's: the virtual executor's sandbox
// image, the device's, or the device driver's default when neither names one.
//
//   - One of cloop's own, however it was chosen, is resolved at its registry —
//     the hub holds no store of the device's to read — and the digest is
//     verified against the workflow that publishes cloop's images. Verified,
//     spec.Image becomes that digest: the device's driver never pulls and
//     inspects exactly what it is given, so it runs the verified bytes or
//     refuses naming the pull. Wrongly signed, the dispatch is refused.
//     Unsigned or unverifiable, it is refused under
//     executor.ImageProvenanceRequired and otherwise runs with a warning, as
//     the tag the device pins in its own store — a digest the hub could not
//     verify buys nothing, and would only strand a device holding an older
//     copy of the tag.
//   - An operator's image that is not cloop's is held to the project rules
//     when the policy governs operator images, and dispatched as the
//     reference they admitted.
func (e *Executor) authorizeRunImage(ctx context.Context, spec *executor.Spec,
	sandbox executor.SandboxSettings, virtual *VirtualDispatch) (*imagepolicy.Provenance, error) {
	if !sandbox.RunsProjectImages() {
		return nil, nil
	}
	image, field := strings.TrimSpace(spec.Image), "image: in the project's .cloop/sandbox.yaml"
	if image == "" {
		image, field = strings.TrimSpace(sandbox.Image), "the sandbox image of "+e.subject()
		if virtual != nil {
			field = "the sandbox image of virtual executor " + virtual.ID
		}
		if image == "" {
			image, field = executor.DefaultHarnessImage, field+" (unset, so the default)"
		}
		if !imagepolicy.IsOwnImage(image) {
			return nil, e.governOperatorImage(ctx, spec, image)
		}
	}
	if !e.opts.VerifyOwnImages || !imagepolicy.IsOwnImage(image) {
		return nil, nil
	}
	subject := e.subject()
	if virtual != nil {
		subject = "virtual executor " + virtual.ID + " on " + subject
	}
	p, err := imagepolicy.OwnImageCheck{
		Image:    image,
		Resolver: e.opts.imageResolver(),
		Verifier: e.opts.provenanceVerifier(),
		Required: executor.ImageProvenanceRequired(),
		Subject:  subject,
		Field:    field,
	}.Run(ctx)
	recordAs := e.id
	if virtual != nil {
		recordAs = virtual.ID
	}
	if err != nil {
		var denied *imagepolicy.DenyError
		if errors.As(err, &denied) {
			imagepolicy.RecordProvenance(recordAs, p)
			if denied.Malformed() {
				return nil, fmt.Errorf("%w: sandbox image: %w", executor.ErrInvalidSpec, err)
			}
			return nil, err
		}
		// Not a verdict: every failure to resolve at the registry is one
		// (unverifiable), so this is a digest the registry answered that is
		// not one.
		return nil, fmt.Errorf("remote: check %s for %s against the workflow that publishes cloop's images: %w",
			image, subject, err)
	}
	imagepolicy.RecordProvenance(recordAs, p)
	if p.Verified() {
		spec.Image = p.Ref
	}
	return &p, nil
}

// governOperatorImage holds an operator's image that is not cloop's to the
// project rules when the policy says govern_operator_images, and points the
// dispatch at the reference they admitted — the verified digest under
// require_signature.
func (e *Executor) governOperatorImage(ctx context.Context, spec *executor.Spec, image string) error {
	if e.opts.ImagePolicy == nil {
		return nil
	}
	policy, err := e.opts.ImagePolicy()
	if err != nil {
		return &imagepolicy.DenyError{
			Ref:  image,
			Rule: imagepolicy.RuleConfig,
			Reason: fmt.Sprintf("the hub could not read its image trust policy (%v), so it cannot say whether "+
				"its policy governs %s's own image", err, e.subject()),
			Remediation: "Fix the hub's configuration — `cloop config validate` in the hub's directory names " +
				"what is wrong — and start the run again.",
		}
	}
	if !policy.GovernsOperatorImage(image) {
		return nil
	}
	enforcer := imagepolicy.Enforcer{Policy: policy, Verifier: e.opts.imageVerifier()}
	if policy.RequireSignature {
		enforcer.Resolver = e.opts.imageResolver()
	}
	res, err := enforcer.Authorize(ctx, image)
	if err != nil {
		var denied *imagepolicy.DenyError
		if errors.As(err, &denied) {
			return err
		}
		return unresolvedImage(image, e.subject(), err)
	}
	spec.Image = res.Ref
	return nil
}

// authorizeProjectImage applies the hub's image trust policy to the image spec
// names, for a dispatch whose sandbox runs it, and returns the reference the
// device must run and whether it is a digest the hub verified.
//
// Under require_signature that reference is the verified digest. Otherwise it
// is the reference as the policy read it — qualified with its default registry
// where it applied one, so the registry the allowlist admitted is the one the
// device pulls from rather than whichever its engine searches first — and the
// device pins a tag in its own store, as it always has.
func (e *Executor) authorizeProjectImage(ctx context.Context, spec executor.Spec,
	sandbox executor.SandboxSettings) (ref string, verified bool, err error) {
	image := strings.TrimSpace(spec.Image)
	if image == "" || !sandbox.RunsProjectImages() || e.opts.ImagePolicy == nil {
		return spec.Image, false, nil
	}
	policy, err := e.opts.ImagePolicy()
	if err != nil {
		// Never the zero policy: that admits every image, and "the hub's
		// configuration would not load" must not decide what a device runs.
		return "", false, &imagepolicy.DenyError{
			Ref:  image,
			Rule: imagepolicy.RuleConfig,
			Reason: fmt.Sprintf("the hub could not read its image trust policy (%v), and %s runs the image a "+
				"project names only once the hub has checked it", err, e.subject()),
			Remediation: "Fix the hub's configuration — `cloop config validate` in the hub's directory names " +
				"what is wrong — and start the run again.",
		}
	}
	enforcer := imagepolicy.Enforcer{Policy: policy, Verifier: e.opts.imageVerifier()}
	if policy.RequireSignature {
		// Resolved only when a signature is required: the device pins an
		// accepted tag in its own store otherwise, and a hub that cannot reach
		// a registry its devices can would refuse what it has no need to.
		enforcer.Resolver = e.opts.imageResolver()
	}
	res, err := enforcer.Authorize(ctx, image)
	if err != nil {
		var denied *imagepolicy.DenyError
		if errors.As(err, &denied) {
			if denied.Malformed() {
				// A broken file whose author can fix it alone, as the
				// container driver reports it.
				return "", false, fmt.Errorf("%w: sandbox image: %w", executor.ErrInvalidSpec, err)
			}
			return "", false, err
		}
		// Not a verdict on the image: the registry could not say what the tag
		// names, so there is no digest a signature could be checked against.
		return "", false, unresolvedImage(image, e.subject(), err)
	}
	if err := checkImageHarness(ctx, enforcer.Resolver, image, res, spec.Harness); err != nil {
		return "", false, err
	}
	return res.Ref, res.Verified, nil
}

// checkImageHarness refuses the image a project names when its label says it
// does not carry the harness the project's provider drives (Task 20450).
//
// Here, because this is where the hub already holds the image's manifest: under
// require_signature it has just resolved the tag at the registry and verified
// the digest. One more step along the same path reads the configuration that
// digest names, and a copilot project whose image lists claude, cloop and git
// is refused before anything is leased — instead of failing inside the sandbox
// once the run has its credentials, which is all checkHarness can promise in
// container mode, where it asks the device nothing.
//
// Nothing is resolved for this alone: without a resolver — no signature
// required, so the device pins the tag in its own store — the hub has no
// manifest and the device's container driver reads the label instead, before
// it runs the image. And a registry that will not say is unknown, never no:
// the digest was verified, and the labels are a convenience on top of it.
func checkImageHarness(ctx context.Context, resolver imagepolicy.Resolver, image string,
	res imagepolicy.Result, want string) error {
	labels, ok := resolver.(imagepolicy.LabelResolver)
	if !ok || !res.Pinned() || strings.TrimSpace(want) == "" {
		return nil
	}
	read, err := labels.Labels(ctx, res.Ref)
	if err != nil {
		return nil
	}
	return imagepolicy.CheckHarness(image, read, want,
		"name one that carries "+strings.TrimSpace(want)+" as image: in the project's .cloop/sandbox.yaml"+
			publishedImageClause(want))
}

// publishedImageClause names a published image that carries want, for a
// remedy, or says nothing when none does.
func publishedImageClause(want string) string {
	if ref := executor.HarnessImageFor(want); ref != "" {
		return " — " + ref + " does — or remove image: so the executor's own image is used"
	}
	return ", or remove image: so the executor's own image is used"
}

// unresolvedImage is the refusal of a tag the hub could not resolve to a
// digest under a policy requiring a signature on it.
func unresolvedImage(image, subject string, cause error) error {
	return &imagepolicy.DenyError{
		Ref:  image,
		Rule: imagepolicy.RuleResolution,
		Reason: fmt.Sprintf("this hub requires signed images, and runs a tag on %s only once it has resolved "+
			"the tag to a digest at its registry and verified that digest's signature — it could not "+
			"resolve it: %v", subject, cause),
		Remediation: "Pin the image by digest in .cloop/sandbox.yaml (image: registry/repository@sha256:…), " +
			"so the hub verifies that digest without resolving anything, or let the hub reach the " +
			"registry — with a login for a private repository in the Docker configuration of the user " +
			"the hub runs as.",
	}
}
