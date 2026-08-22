package config

// sandbox.go configures the envelope around a project's own
// .cloop/sandbox.yaml.
//
// It is its own section rather than a sub-key of executors.container because
// the policy is about what a *project* may ask for, and it must mean the same
// thing on every backend that honours an image override. Putting the image
// allowlist under one driver's config would produce a hub where the same
// sandbox.yaml is refused on Kubernetes and accepted on the container runtime,
// which is the kind of split-brain a security control cannot have.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// SandboxConfig groups the constraints applied to per-project sandbox specs.
type SandboxConfig struct {
	// ImagePolicy decides which container images a project may run in.
	// Absent means no constraint, which is the single-developer default: a
	// laptop's `image: python:3.12` must keep working after an upgrade.
	ImagePolicy ImagePolicyConfig `yaml:"image_policy,omitempty"`
}

// CosignIdentity is one keyless-signing identity in the config file.
type CosignIdentity struct {
	// Issuer is the exact OIDC issuer URL that minted the signing
	// certificate, e.g. https://token.actions.githubusercontent.com.
	Issuer string `yaml:"issuer"`
	// SubjectRegexp constrains which subject at that issuer is trusted.
	// Required: an issuer alone would trust every workflow at that provider,
	// including one in a repository the operator has never heard of.
	SubjectRegexp string `yaml:"subject_regexp"`
}

// ImagePolicyConfig is the YAML shape of imagepolicy.Policy.
//
// It is a separate struct from the policy type rather than a yaml-tagged reuse
// of it, for the same reason ContainerExecutorConfig is separate from
// container.Options: the file format is a compatibility surface an operator
// depends on, and the policy type is free to change shape without breaking it.
type ImagePolicyConfig struct {
	// AllowedRegistries are the registry hosts a project may name. Matching
	// is on the parsed host: "docker.io" does not match "docker.io.evil.com"
	// or "evil.com/docker.io/foo". "*.example.com" matches subdomains at a
	// label boundary; "*" matches any registry.
	AllowedRegistries []string `yaml:"allowed_registries,omitempty"`
	// AllowedRepos narrows further, e.g. "ghcr.io/acme/*". Empty means any
	// repository on an allowed registry.
	AllowedRepos []string `yaml:"allowed_repos,omitempty"`
	// RequireDigest refuses a reference pinned only to a tag.
	RequireDigest bool `yaml:"require_digest,omitempty"`
	// RequireSignature refuses an image cosign cannot verify. A hub with no
	// cosign installed then refuses every image rather than admitting them
	// unchecked — that is the intended behaviour, not a bug.
	RequireSignature bool `yaml:"require_signature,omitempty"`
	// CosignPublicKeys are paths to public keys; any one may carry the
	// signature.
	CosignPublicKeys []string `yaml:"cosign_public_keys,omitempty"`
	// CosignIdentities are keyless identities; any one may carry it.
	CosignIdentities []CosignIdentity `yaml:"cosign_identities,omitempty"`
	// DefaultRegistry qualifies a reference that names no registry. Without
	// it an unqualified name like "alpine:3" is refused, because which
	// registry it resolves to is the executor host's configuration rather
	// than anything this policy can see.
	DefaultRegistry string `yaml:"default_registry,omitempty"`
}

// Policy converts the config section into the enforcement type.
//
// It is the single conversion point, so the CLI validator, the hub's drivers
// and the sandbox parser cannot end up applying three different readings of
// the same file.
func (c ImagePolicyConfig) Policy() imagepolicy.Policy {
	ids := make([]imagepolicy.Identity, 0, len(c.CosignIdentities))
	for _, id := range c.CosignIdentities {
		ids = append(ids, imagepolicy.Identity{Issuer: id.Issuer, SubjectRegexp: id.SubjectRegexp})
	}
	p := imagepolicy.Policy{
		AllowedRegistries: c.AllowedRegistries,
		AllowedRepos:      c.AllowedRepos,
		RequireDigest:     c.RequireDigest,
		RequireSignature:  c.RequireSignature,
		CosignPublicKeys:  c.CosignPublicKeys,
		DefaultRegistry:   c.DefaultRegistry,
	}
	if len(ids) > 0 {
		p.CosignIdentities = ids
	}
	return p.Normalize()
}

// ValidateSandbox checks the sandbox section.
//
// Like the executor validators it runs even when the policy is inert, so a
// half-written allowlist is reported when it is saved rather than discovered
// by the first project whose run it refuses.
func ValidateSandbox(s SandboxConfig) error {
	if err := s.ImagePolicy.Policy().Validate(); err != nil {
		return fmt.Errorf("sandbox.image_policy: %w", err)
	}
	return nil
}

// SandboxWarnings returns advisory notes about a valid policy that is probably
// not what the operator meant.
//
// These are warnings and not errors because each describes a deployment that
// works — a hub with no image policy is the correct default for a laptop, and
// making it fatal would break every existing install on upgrade.
func SandboxWarnings(s SandboxConfig, executorsIsolated bool) []string {
	var out []string
	p := s.ImagePolicy.Policy()

	if !p.Configured() {
		if executorsIsolated {
			out = append(out, "sandbox.image_policy is not configured, so any project's "+
				".cloop/sandbox.yaml may name any container image and the hub will run it. "+
				"Set sandbox.image_policy.allowed_registries and require_digest.")
		}
		return out
	}
	if !p.RequireDigest {
		out = append(out, "sandbox.image_policy.require_digest is false, so a project may pin a "+
			"mutable tag. The container executor still resolves it to a digest before running, "+
			"but the Kubernetes executor cannot — there the artifact that runs is whatever the "+
			"tag points at when a node pulls it.")
	}
	for _, r := range p.AllowedRegistries {
		if r == "*" {
			out = append(out, "sandbox.image_policy.allowed_registries contains \"*\", which "+
				"allows every registry on the Internet. Combined with require_digest that is a "+
				"deliberate posture; on its own it constrains nothing.")
		}
	}
	return out
}
