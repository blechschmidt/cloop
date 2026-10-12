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
// executor's — is not a project's and is not checked, as the container driver
// does not check executors.container.image. Only Spec.Image is: the field
// pkg/sandbox fills from the repository's file.

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
	return res.Ref, res.Verified, nil
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
