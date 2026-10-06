package hubdoctor

// Image trust checks.
//
// The image an executor runs is not data the sandbox processes — it *is* the
// sandbox. A project's .cloop/sandbox.yaml arrives by `git pull`, so without a
// policy "the hub never runs untrusted code on the host" is true and beside the
// point: the code inside the container was chosen by a pull request.
//
// Every verdict here is the policy's own: imagepolicy.Policy.Evaluate decides
// whether it constrains anything, Policy.RegistryHosts which registries it
// names, and the cosign case is judged where the drivers that verify are. Two
// of those used to be restated here and had drifted (Task 20387): repo entries
// were split on their first "/" — "acme/tools" became a registry called acme,
// probed and failed — and the operator's own executor images were reported as
// "refused by this hub's own policy", which the drivers deliberately never
// apply to them.
//
// The cosign case is worth more than a schema check: require_signature with no
// cosign binary means the container and Kubernetes executors refuse every
// project image rather than admit it unchecked, which is the safe direction
// and a total loss of function, so it must be said out loud rather than
// discovered. And where a device runs project images, the signature is not
// checked at all — which has to be said too.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkImagePolicy(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	// Policy() is the single conversion point config exposes, so the doctor
	// evaluates exactly what the drivers enforce rather than a second reading
	// of the same YAML. It already normalizes.
	policy := cfg.Sandbox.ImagePolicy.Policy()
	// A device or virtual executor whose sandbox runs a container runs the
	// images projects name too, and the hub checks them against this policy
	// before dispatch. One the database cannot tell about counts, rather than
	// passing on a lookup that never happened.
	n, known := imageDevices(dir)
	devices := n > 0 || !known
	usesImages := cfg.Executors.Container.Enabled || cfg.Executors.Kubernetes.Enabled || devices

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
		msg := "no image policy; no configured executor or device runs project images on this hub"
		if usesImages {
			sev = SeverityWarn
			msg = "project images run on this hub — an image-running executor is enabled, or a device's " +
				"sandbox runs a container — but sandbox.image_policy is empty, so a project's " +
				".cloop/sandbox.yaml may name any image from any registry"
			remediation = "Set sandbox.image_policy.allowed_registries (and require_digest: true)"
		}
		add(Finding{
			Check: "images.policy", Title: "Image trust policy", Severity: sev,
			Message: msg, Remediation: remediation,
		})
		return
	}

	// "Configured" is not "constrains where images come from": require_digest
	// alone, or allowed_registries: ["*"], admits every registry. The policy
	// is asked, with an image from a registry nobody would list.
	details := map[string]any{
		"require_digest":    policy.RequireDigest,
		"require_signature": policy.RequireSignature,
	}
	if admitted, any := policy.AdmitsAnyRegistry(); any {
		add(Finding{
			Check: "images.policy", Title: "Image trust policy", Severity: SeverityWarn,
			Message: "sandbox.image_policy admits images from any registry — its own evaluation admits " +
				admitted + " — so it constrains how an image is named, not where it comes from",
			Remediation: "List the registries projects may pull from in sandbox.image_policy.allowed_registries " +
				"(a \"*\" entry allows them all)",
			Details: details,
		})
	} else {
		add(Finding{
			Check: "images.policy", Title: "Image trust policy", Severity: SeverityPass,
			Message: fmt.Sprintf("deny-by-default over %d registry pattern(s) and %d repo pattern(s)",
				len(policy.AllowedRegistries), len(policy.AllowedRepos)),
			Details: details,
		})
	}

	checkPinning(policy, usesImages, add)
	checkCosign(policy, cfg, devices, opts, add)
	checkConfiguredImages(cfg, policy, add)
	checkRegistryReachability(ctx, policy, opts, add)
}

// imageDevices counts the enrolled devices and virtual executors that run the
// images projects name: those whose recorded sandbox settings run payloads in
// a container (executor.SandboxSettings.RunsProjectImages, which is when a
// device advertises SupportsImageOverride). A device in host mode runs no
// image, and counting every enrolled one warned fleets of them about a policy
// that decides nothing they run. known is false when the database exists and
// could not be read.
func imageDevices(dir string) (n int, known bool) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return 0, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return 0, false
	}
	defer func() { _ = db.Close() }()
	revoked := map[string]bool{}
	if store, err := executorstore.New(db); err == nil {
		if agents, err := store.ListAgents(); err == nil {
			for _, a := range agents {
				if a.Revoked() {
					revoked[a.AgentID] = true
				}
			}
		}
	}
	rows, err := db.ListExecutors()
	if err != nil {
		return 0, false
	}
	for _, row := range rows {
		if (row.Kind != executor.KindRemoteAgent && row.Kind != executor.KindVirtual) || revoked[row.ID] {
			continue
		}
		settings, err := statedb.SandboxSettingsFor(db, row.ID)
		if err != nil {
			return n, false
		}
		if settings.Normalize().RunsProjectImages() {
			n++
		}
	}
	return n, true
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

// checkCosign verifies the hub can do what its policy demands, where it is
// demanded. Signatures are verified by the container and Kubernetes drivers
// (imagepolicy.Enforcer with a CosignVerifier); a device runs project images
// the hub checked against the allowlists and the digest rule only.
func checkCosign(p imagepolicy.Policy, cfg *config.Config, devices bool, opts Options, add addFn) {
	// A policy that requires a signature with no key or identity to check it
	// against is rejected by Policy.Validate, so by the time this runs there is
	// always something configured.
	if !p.RequireSignature {
		return
	}
	if devices {
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityWarn,
			Message: "require_signature is on, but devices whose sandbox runs a container run project images without it: " +
				"the hub checks theirs against the allowlists and the digest rule only, and no device " +
				"verifies a signature",
			Remediation: "Run projects whose images must be signed on the container or Kubernetes " +
				"executor, or restrict allowed_repos to a repository only your signing pipeline pushes to",
		})
	}
	if !cfg.Executors.Container.Enabled && !cfg.Executors.Kubernetes.Enabled {
		return // no verifying executor here, so nothing on this host runs cosign
	}

	look := opts.LookPath
	if look == nil {
		look = exec.LookPath
	}
	if _, err := look(imagepolicy.CosignBinary); err != nil {
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityFail,
			Message: "require_signature is on but cosign is not on this host's PATH; the container and " +
				"Kubernetes executors refuse every project image rather than admit it unchecked",
			Remediation: "Install cosign in the hub image, or set require_signature: false",
		})
		return
	}
	// cosign is handed each key as written, and the keys are alternatives:
	// the verifier refuses an image no usable key or identity verifies. Only
	// a plain path can be judged from here — a KMS or Kubernetes reference
	// (awskms://, k8s://, pkcs11:…) is cosign's to resolve.
	var unreadable []string
	for _, k := range p.CosignPublicKeys {
		if strings.Contains(k, "://") || strings.HasPrefix(k, "pkcs11:") {
			continue
		}
		if fi, err := os.Stat(k); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", k, err))
		} else if !fi.Mode().IsRegular() {
			unreadable = append(unreadable, k+" (not a file)")
		}
	}
	switch {
	case len(unreadable) > 0 && len(unreadable) == len(p.CosignPublicKeys) && len(p.CosignIdentities) == 0:
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityFail,
			Message: "no configured cosign key can be read — " + strings.Join(unreadable, "; ") +
				" — and no identity is configured, so every project image is refused",
			Remediation: "Point sandbox.image_policy.cosign_public_keys at readable key files",
		})
	case len(unreadable) > 0:
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityWarn,
			Message:     "cosign key(s) that cannot be read verify nothing: " + strings.Join(unreadable, "; "),
			Remediation: "Fix or remove the unreadable entries in sandbox.image_policy.cosign_public_keys",
		})
	default:
		add(Finding{
			Check: "images.signature", Title: "Signature verification", Severity: SeverityPass,
			Message: fmt.Sprintf("cosign is available; %d key(s) and %d identity pattern(s) configured",
				len(p.CosignPublicKeys), len(p.CosignIdentities)),
		})
	}
}

// checkConfiguredImages reports the operator's own executor images. The
// drivers run them as configured — the policy governs the images a project
// names in .cloop/sandbox.yaml, which is the untrusted input; applying an
// allowlist to the operator's own choice, made in the same file, would be a
// lint, not a control (see container.Options.ImagePolicy). The doctor used to
// report them as "refused by this hub's own policy", which the hub never does.
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
		msg := fmt.Sprintf("%s (%s) is the operator's own and runs as configured; the image policy "+
			"governs the images projects name", c.field, c.ref)
		details := map[string]any{"image": c.ref}
		if dec, err := p.Evaluate(c.ref); err != nil && !dec.Allowed {
			msg += "; a project naming this image would be refused: " + dec.Reason
			details["refused_for_projects"] = dec.Reason
		}
		add(Finding{
			Check: "images.configured", Title: "Configured executor image", Severity: SeverityPass,
			Message: msg, Details: details,
		})
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
	hosts := p.RegistryHosts()
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
		// Docker Hub's distribution endpoint is not the name policies use for
		// it; the policy folds registry-1.docker.io into docker.io.
		endpoint := host
		if host == imagepolicy.DockerHub {
			endpoint = "registry-1.docker.io"
		}
		url := "https://" + endpoint + "/v2/"
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

// maxProbeBody bounds what a probe drains from an endpoint before closing it.
// A registry response is a few kilobytes; a megabyte cap means a hostile or
// misrouted endpoint cannot exhaust a CLI that is trying to diagnose it.
const maxProbeBody = 1 << 20

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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
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
