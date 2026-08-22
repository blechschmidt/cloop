package imagepolicy

// enforce.go composes the pure verdict in policy.go with the two impure steps a
// real enforcement needs: turning a tag into a digest, and checking a signature.
//
// # Why pinning is part of enforcement and not an optimisation
//
// A tag is a mutable pointer. Between the moment a policy accepts
// `ghcr.io/acme/tools:3.12` and the moment a runtime pulls it, whoever controls
// that repository can repoint the tag at a different artifact — and on the
// Kubernetes backend those two moments are separated by a scheduling decision,
// an image pull on some node, and possibly a retry an hour later. The check and
// the thing checked would be different artifacts. That is a time-of-check /
// time-of-use bug, and the fix is the ordinary one: resolve once, then refer to
// the result by content for the rest of the operation.
//
// So Authorize returns a *reference*, not a boolean. Callers run what it
// returns. A caller that evaluates the policy and then runs its own original
// string has re-introduced the window, which is why nothing here hands back a
// bare "allowed".

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoDigest is returned by a Resolver that reached the image but found no
// registry-reproducible digest for it — true for locally built images and for
// images loaded from a tarball. It is distinct from a lookup failure because
// the two need opposite handling: one is "there is nothing to pin to", the
// other is "the image is not there at all".
var ErrNoDigest = errors.New("imagepolicy: no digest is available for this reference")

// Resolver turns a reference into the digest it names right now.
//
// The container driver implements it against the local image store. The
// Kubernetes driver has none — a cluster has no image store the control plane
// can read — so it passes nil, and a policy that needs a pin there says so with
// RequireDigest instead of pretending it can resolve one.
type Resolver interface {
	// ResolveDigest returns the "sha256:…" digest for ref, or ErrNoDigest when
	// the image exists but carries none.
	ResolveDigest(ctx context.Context, ref string) (string, error)
}

// Verifier checks that an image carries a signature the policy accepts.
//
// ref is always a digest-pinned reference: verifying a tag would verify
// whatever the tag pointed at during the check, which is the problem this file
// exists to remove.
type Verifier interface {
	Verify(ctx context.Context, ref string, p Policy) error
}

// Result is an authorized image, ready to run.
type Result struct {
	// Ref is what the caller must actually run. It is the digest-pinned
	// canonical form whenever one could be obtained.
	Ref string `json:"ref"`
	// Digest is the pinned digest, empty when the reference could not be
	// pinned and the policy did not require it.
	Digest string `json:"digest,omitempty"`
	// Decision is the verdict Evaluate reached on the original reference.
	Decision Decision `json:"decision"`
	// Verified reports that a signature was checked and accepted.
	Verified bool `json:"verified,omitempty"`
	// Warnings describe an accepted-but-weaker outcome, e.g. an image that
	// could not be pinned on a hub that does not require pinning.
	Warnings []string `json:"warnings,omitempty"`
}

// Pinned reports whether Ref names an exact artifact.
func (r Result) Pinned() bool { return r.Digest != "" }

// Enforcer applies a Policy, using Resolver to pin and Verifier to check
// signatures. Both may be nil; a nil one fails closed wherever the policy
// actually needs it, and is simply unused where it does not.
type Enforcer struct {
	Policy   Policy
	Resolver Resolver
	Verifier Verifier
}

// Authorize evaluates ref, pins it, and verifies its signature.
//
// The returned Result.Ref is what the caller must run. On refusal the error is
// a *DenyError naming the rule; on an infrastructure failure (the image is not
// present, the registry is unreachable) it is that error, wrapped — the two are
// different problems for different people and must not be flattened into one.
func (e Enforcer) Authorize(ctx context.Context, ref string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	decision, err := e.Policy.Evaluate(ref)
	if err != nil {
		return Result{Decision: decision}, err
	}

	// An already-pinned reference is reduced to its canonical form, dropping
	// any tag it also carried. "repo:1.79@sha256:…" is legal and resolves by
	// digest, so this is not a security difference — it is so that one artifact
	// has one spelling. A resolved tag produces "repo@sha256:…" (see
	// Reference.WithDigest); if an author-written one produced something else,
	// the same image would appear under two names in Pod specs, audit rows and
	// artifacts depending only on how it was written.
	res := Result{Ref: decision.Ref.String(), Decision: decision, Digest: decision.Ref.Digest}
	if decision.Ref.Pinned() {
		res.Ref = decision.Ref.Canonical()
		res.Decision.Ref.Tag = ""
	}

	// --- pin --------------------------------------------------------------
	if decision.NeedsPin {
		pinned, warn, err := e.pin(ctx, decision)
		if err != nil {
			return res, err
		}
		if pinned.Pinned() {
			res.Ref, res.Digest = pinned.Canonical(), pinned.Digest
			res.Decision.Ref = pinned
		}
		res.Warnings = append(res.Warnings, warn...)
	}

	// --- signature --------------------------------------------------------
	if decision.NeedsSignature {
		if err := e.verify(ctx, res); err != nil {
			return res, err
		}
		res.Verified = true
	}
	return res, nil
}

// pin resolves a tag reference to a digest and re-evaluates the result.
func (e Enforcer) pin(ctx context.Context, decision Decision) (Reference, []string, error) {
	if e.Resolver == nil {
		// Nothing to resolve with. RequireDigest already refused a tag-only
		// reference, so reaching here means the policy tolerates one.
		if decision.NeedsSignature {
			d := deny(RuleSignature,
				fmt.Sprintf("%q is a tag and this executor cannot resolve it to a digest, so "+
					"there is nothing a signature could be verified against", decision.Ref.Original),
				"Pin the image by digest in .cloop/sandbox.yaml, or set "+
					"sandbox.image_policy.require_digest so the refusal happens at validation time.")
			d.Ref = decision.Ref
			d.PolicyActive = decision.PolicyActive
			return Reference{}, nil, d.Err()
		}
		return Reference{}, tagWarning(decision,
			"this executor cannot resolve it to a digest, so the artifact that runs is "+
				"whatever the tag points at when it is pulled"), nil
	}

	digest, err := e.Resolver.ResolveDigest(ctx, decision.Ref.String())
	switch {
	case errors.Is(err, ErrNoDigest):
		if decision.NeedsSignature {
			d := deny(RuleSignature,
				fmt.Sprintf("%q has no registry digest — it was built locally or loaded from a "+
					"tarball — so no signature can be verified for it", decision.Ref.Original),
				"Push the image to a registry and reference it from there, or turn off "+
					"sandbox.image_policy.require_signature.")
			d.Ref = decision.Ref
			d.PolicyActive = decision.PolicyActive
			return Reference{}, nil, d.Err()
		}
		return Reference{}, tagWarning(decision,
			"it has no registry digest — it was built locally or loaded from a tarball — so "+
				"the run is not reproducible from its reference alone"), nil
	case err != nil:
		// Not a policy problem: the image is missing or the store is broken.
		// Passed through so the driver's own diagnostic (which names the pull
		// command) is what the operator sees.
		return Reference{}, nil, err
	}

	pinned, err := decision.Ref.WithDigest(digest)
	if err != nil {
		return Reference{}, nil, fmt.Errorf("imagepolicy: resolver returned an unusable digest for %q: %w",
			decision.Ref.Original, err)
	}

	// Re-evaluate the pinned form. Resolution preserves the repository, so
	// this normally cannot change the verdict — which is exactly why it is
	// cheap enough to keep. A resolver that ever returned a digest under a
	// different name would otherwise have laundered an image past the
	// allowlist, and that failure would be silent.
	recheck, err := e.Policy.Evaluate(pinned.Canonical())
	if err != nil {
		return Reference{}, nil, err
	}
	if !recheck.Allowed {
		return Reference{}, nil, recheck.Err()
	}
	return pinned, nil, nil
}

// tagWarning reports an accepted-but-unpinned image, but only on a hub that
// configured a policy at all.
//
// A hub with no image policy has said it does not care where images come from;
// printing "this is not reproducible" on every single workload start would be
// noise, and noise is how operators learn to skim warnings. The advice is not
// lost — config.SandboxWarnings raises it once, against the configuration,
// which is where acting on it means editing something.
func tagWarning(d Decision, why string) []string {
	if !d.PolicyActive {
		return nil
	}
	return []string{fmt.Sprintf("image %q runs from a mutable tag: %s", d.Ref.Original, why)}
}

// verify runs the signature check, failing closed on every path that is not an
// explicit pass.
func (e Enforcer) verify(ctx context.Context, res Result) error {
	if !res.Pinned() {
		// pin() already refuses this; the check stays because "verify a tag"
		// must never become reachable through a future caller.
		d := deny(RuleSignature,
			fmt.Sprintf("%q is not digest-pinned, and a signature on a mutable tag verifies "+
				"whatever the tag pointed at during the check", res.Decision.Ref.Original),
			"Pin the image by digest in .cloop/sandbox.yaml.")
		d.Ref = res.Decision.Ref
		d.PolicyActive = true
		return d.Err()
	}
	if e.Verifier == nil {
		d := deny(RuleSignature,
			"the hub requires signed images but no signature verifier is available",
			"Install cosign on the hub (https://docs.sigstore.dev/cosign/installation/), "+
				"or turn off sandbox.image_policy.require_signature.")
		d.Ref = res.Decision.Ref
		d.PolicyActive = true
		return d.Err()
	}
	if err := e.Verifier.Verify(ctx, res.Ref, e.Policy); err != nil {
		if errors.Is(err, ErrDenied) {
			return err
		}
		d := deny(RuleSignature,
			fmt.Sprintf("signature verification of %s failed: %v", res.Ref, err),
			"Sign the image with a key or identity this hub accepts "+
				"(sandbox.image_policy.cosign_public_keys / cosign_identities).")
		d.Ref = res.Decision.Ref
		d.PolicyActive = true
		return d.Err()
	}
	return nil
}
