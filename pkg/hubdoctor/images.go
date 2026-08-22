package hubdoctor

// Image trust checks.
//
// The image an executor runs is not data the sandbox processes — it *is* the
// sandbox. A project's .cloop/sandbox.yaml arrives by `git pull`, so without a
// policy "the hub never runs untrusted code on the host" is true and beside the
// point: the code inside the container was chosen by a pull request.
//
// Two things here are worth more than a schema check. The first is that the
// hub's *own* configured executor images are evaluated against the same policy
// a project's would be — a policy that would refuse the image the operator
// themselves configured is a policy about to produce a very confusing outage.
// The second is the cosign case: require_signature on an image with no cosign
// binary means every project image is refused rather than admitted unchecked,
// which is the safe direction and a total loss of function, so it must be said
// out loud rather than discovered.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

func checkImagePolicy(ctx context.Context, cfg *config.Config, opts Options, add addFn) {
	// Policy() is the single conversion point config exposes, so the doctor
	// evaluates exactly what the drivers enforce rather than a second reading
	// of the same YAML. It already normalizes.
	policy := cfg.Sandbox.ImagePolicy.Policy()
	usesImages := cfg.Executors.Container.Enabled || cfg.Executors.Kubernetes.Enabled

	if err := policy.Validate(); err != nil {
		add(Finding{
			Check: "images.policy", Title: "Image trust policy", Severity: SeverityFail,
			Message:     "sandbox.image_policy is invalid: " + err.Error(),
			Remediation: "Fix the named pattern; registries are hosts and repos are registry/path with an optional trailing /*",
		})
		return
	}

	if !policy.Configured() {
		sev, remediation := SeverityPass, ""
		msg := "no image policy; nothing runs container images on this hub"
		if usesImages {
			sev = SeverityWarn
			msg = "an image-running executor is enabled but sandbox.image_policy is empty, so a " +
				"project's .cloop/sandbox.yaml may name any image from any registry"
			remediation = "Set sandbox.image_policy.allowed_registries (and require_digest: true)"
		}
		add(Finding{
			Check: "images.policy", Title: "Image trust policy", Severity: sev,
			Message: msg, Remediation: remediation,
		})
		return
	}

	norm := policy
	add(Finding{
		Check: "images.policy", Title: "Image trust policy", Severity: SeverityPass,
		Message: fmt.Sprintf("deny-by-default over %d registry pattern(s) and %d repo pattern(s)",
			len(norm.AllowedRegistries), len(norm.AllowedRepos)),
		Details: map[string]any{
			"require_digest":    norm.RequireDigest,
			"require_signature": norm.RequireSignature,
		},
	})

	checkPinning(norm, usesImages, add)
	checkCosign(norm, opts, add)
	checkConfiguredImages(cfg, norm, add)
	checkRegistryReachability(ctx, norm, opts, add)
}

// checkPinning reports the tag-mutability gap. It matters most for Kubernetes,
// where the reference is handed to a kubelet that resolves it later on some
// node — a place nothing in cloop can close the gap.
func checkPinning(p imagepolicy.Policy, usesImages bool, add addFn) {
	if p.RequireDigest {
		add(Finding{
			Check: "images.digest_pinning", Title: "Digest pinning", Severity: SeverityPass,
			Message: "require_digest is on: a tag-only reference is refused",
		})
		return
	}
	sev := SeverityWarn
	if !usesImages {
		sev = SeverityPass
	}
	add(Finding{
		Check: "images.digest_pinning", Title: "Digest pinning", Severity: sev,
		Message: "require_digest is off, so an accepted tag can point at different bytes tomorrow " +
			"than it does today",
		Remediation: "Set sandbox.image_policy.require_digest: true",
	})
}

// checkCosign verifies the hub can do what its policy demands.
func checkCosign(p imagepolicy.Policy, opts Options, add addFn) {
	// A policy that requires a signature with no key or identity to check it
	// against is rejected by Policy.Validate, so by the time this runs there is
	// always something configured — the only remaining question is whether the
	// host can run the verifier.
	if !p.RequireSignature {
		return
	}
	look := opts.LookPath
	if look == nil {
		look = exec.LookPath
	}
	if _, err := look("cosign"); err != nil {
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityFail,
			Message: "require_signature is on but cosign is not on this host's PATH; a hub that " +
				"cannot verify refuses every project image rather than admitting it unchecked",
			Remediation: "Install cosign in the hub image, or set require_signature: false",
		})
		return
	}
	add(Finding{
		Check: "images.signature", Title: "Signature verification", Severity: SeverityPass,
		Message: fmt.Sprintf("cosign is available; %d key(s) and %d identity pattern(s) configured",
			len(p.CosignPublicKeys), len(p.CosignIdentities)),
	})
}

// checkConfiguredImages runs the operator's own executor images through the
// policy. This is the check most likely to fire on a real deployment: the
// policy is written for what projects may name, and the hub's own image is
// frequently somewhere else.
func checkConfiguredImages(cfg *config.Config, p imagepolicy.Policy, add addFn) {
	type candidate struct{ field, ref string }
	var cands []candidate
	if cfg.Executors.Container.Enabled && strings.TrimSpace(cfg.Executors.Container.Image) != "" {
		cands = append(cands, candidate{"executors.container.image", cfg.Executors.Container.Image})
	}
	if cfg.Executors.Kubernetes.Enabled && strings.TrimSpace(cfg.Executors.Kubernetes.Image) != "" {
		cands = append(cands, candidate{"executors.kubernetes.image", cfg.Executors.Kubernetes.Image})
	}
	for _, c := range cands {
		dec, err := p.Evaluate(c.ref)
		switch {
		case err != nil && !dec.Allowed:
			add(Finding{
				Check: "images.configured", Title: "Configured executor image", Severity: SeverityWarn,
				Message: fmt.Sprintf("%s (%s) would be refused by this hub's own image policy: %s",
					c.field, c.ref, dec.Reason),
				Remediation: firstNonEmpty(dec.Remediation,
					"Add its registry to sandbox.image_policy.allowed_registries, or change the image"),
			})
		default:
			add(Finding{
				Check: "images.configured", Title: "Configured executor image", Severity: SeverityPass,
				Message: fmt.Sprintf("%s (%s) satisfies the image policy", c.field, c.ref),
			})
		}
	}
}

// checkRegistryReachability probes each allowed registry's OCI distribution
// endpoint.
//
// /v2/ answering 401 is a *pass*: an authenticated registry challenges an
// anonymous request, which proves it is reachable and speaking the distribution
// API. What this catches is DNS that does not resolve and egress that is
// blocked — the failures that otherwise surface as an image pull timing out
// inside a Pod, several layers from the cause.
func checkRegistryReachability(ctx context.Context, p imagepolicy.Policy, opts Options, add addFn) {
	hosts := registryHosts(p)
	if len(hosts) == 0 {
		return
	}
	if opts.Offline {
		add(Finding{
			Check: "images.registry", Title: "Registry reachability", Severity: SeverityWarn,
			Message:     fmt.Sprintf("skipped for %d registry pattern(s): --offline was passed", len(hosts)),
			Remediation: "Re-run without --offline from the host that pulls images",
		})
		return
	}
	for _, host := range hosts {
		url := "https://" + host + "/v2/"
		status, err := probe(ctx, opts, url)
		switch {
		case err != nil:
			add(Finding{
				Check: "images.registry", Title: "Registry reachability", Severity: SeverityFail,
				Message:     fmt.Sprintf("%s is unreachable from this host: %v", url, err),
				Remediation: "Check DNS and egress from the hub (and from the nodes that pull images)",
			})
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			add(Finding{
				Check: "images.registry", Title: "Registry reachability", Severity: SeverityPass,
				Message: fmt.Sprintf("%s reachable (HTTP %d — an authenticated registry challenging an "+
					"anonymous probe)", host, status),
			})
		case status >= 200 && status < 400:
			add(Finding{
				Check: "images.registry", Title: "Registry reachability", Severity: SeverityPass,
				Message: fmt.Sprintf("%s reachable (HTTP %d)", host, status),
			})
		default:
			add(Finding{
				Check: "images.registry", Title: "Registry reachability", Severity: SeverityWarn,
				Message:     fmt.Sprintf("%s answered HTTP %d, which is not a distribution API response", url, status),
				Remediation: "Confirm the host in allowed_registries is a container registry",
			})
		}
	}
}

// registryHosts collects the concrete hosts worth probing: the registry
// allowlist, plus the registry half of each repo pattern. Wildcards are skipped
// — there is no single address to dial for "*.example.com".
func registryHosts(p imagepolicy.Policy) []string {
	seen := map[string]bool{}
	for _, r := range p.AllowedRegistries {
		if r != "" && !strings.Contains(r, "*") {
			seen[r] = true
		}
	}
	for _, repo := range p.AllowedRepos {
		host, _, ok := strings.Cut(repo, "/")
		if ok && host != "" && !strings.Contains(host, "*") {
			seen[host] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// probe performs one bounded GET and returns the status code.
func probe(ctx context.Context, opts Options, rawURL string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscoveryBody))
		_ = resp.Body.Close()
	}()
	return resp.StatusCode, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
