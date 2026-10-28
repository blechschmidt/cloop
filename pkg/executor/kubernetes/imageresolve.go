package kubernetes

// imageresolve.go pins every tag a Pod would carry to the digest its registry
// serves for it, before the Pod is built (Task 20457).
//
// # The gap it closes
//
// A Pod spec is handed to an API server and acted on later, by a kubelet, on a
// node, whenever the Pod is scheduled — and a tag in it is resolved then, by
// that node. Until this file the hub had no way to resolve one first: a
// cluster's image store belongs to its nodes, and the image policy ran with no
// Resolver. So a tag a project named reached the kubelet as a tag, and the
// artifact that ran was whatever the tag pointed at when some node pulled it —
// not the one anything evaluated. The only protection was a refusal:
// require_digest refused the tag outright (the shipped chart set it, so every
// project image named by tag was refused on Kubernetes), or require_signature
// did, having nothing to check a signature on.
//
// The kubelet pulls from a registry, and the hub can ask that registry what a
// tag names, as it already does for a device's project image (Task 20424). So
// it does, for every tag the Pod would carry — the image a project names, the
// operator's executors.kubernetes.image, and one of cloop's own — and the Pod
// carries repo@sha256:<digest>. Past that point the tag does not exist: the
// kubelet pulls the digest, a registry that repoints the tag a second later
// changes nothing, and under require_signature the digest whose signature was
// verified is the digest that runs.
//
// # Whose login
//
// A private registry is asked with the login in the registry secret the hub
// holds for this executor (executors.kubernetes.registry_secret), or
// anonymously. Never with the namespace's imagePullSecrets: they are the
// kubelet's, and the executor Role reads no Secret
// (TestExecutorRoleNeverReadsSecretsOrMutatesWhatItCreated). And never with
// the hub user's own Docker logins, which are nobody's decision for this
// executor. The secret is opened at every dispatch, so rotating or deleting it
// takes effect on the next Pod, and a secret that cannot be read is a failure
// to resolve — never an anonymous attempt in its place.
//
// # When the registry will not say
//
// Unreachable, refusing, or not knowing the tag: under require_digest or
// require_signature the dispatch is refused, naming the registry and what to do
// — those settings say no tag reaches this hub's Pods. Otherwise the tag goes
// into the Pod as it always did, with the warning a policy-bearing hub has
// always printed for it, now on the run's log too.
//
// An executor built without ResolveTags — every embedder that is not the hub's
// own driver — resolves nothing, as before Task 20457.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// RegistryLoginSource supplies the registry logins a Kubernetes executor
// resolves image tags, and fetches their signatures, with.
type RegistryLoginSource interface {
	// RegistryLogins returns the logins, or an error saying why the secret
	// could not be used. It is called at every dispatch.
	RegistryLogins(ctx context.Context) (imagepolicy.DockerLogins, error)
	// Describe names where the logins come from, for messages: "registry
	// secret ghcr-robot".
	Describe() string
}

// BrokerRegistryLogins reads the registry secret the hub holds for an
// executor from its secret store, as a credential the hub presents as itself
// (secretbroker.HubRegistryConfig) — never through a grant, which would lease
// it to every workload on the executor too.
type BrokerRegistryLogins struct {
	Broker *secretbroker.Broker
	// Secret is the secret's name or ID, as executors.kubernetes.registry_secret
	// writes it.
	Secret string
}

// RegistryLogins implements RegistryLoginSource.
func (s BrokerRegistryLogins) RegistryLogins(context.Context) (imagepolicy.DockerLogins, error) {
	raw, err := s.Broker.HubRegistryConfig(s.Secret)
	if err != nil {
		return imagepolicy.DockerLogins{}, fmt.Errorf("the registry secret %q could not be read: %w", s.Secret, err)
	}
	defer zero(raw)
	logins, err := imagepolicy.ParseDockerConfig(raw)
	if err != nil {
		return imagepolicy.DockerLogins{}, fmt.Errorf("the registry secret %q is unusable: %w", s.Secret, err)
	}
	return logins, nil
}

// Describe implements RegistryLoginSource.
func (s BrokerRegistryLogins) Describe() string { return "registry secret " + s.Secret }

// UnavailableRegistryLogins stands in for a registry secret that is configured
// and that this process has no secret store to read — an in-cluster hub with no
// sealing key, say. It fails every dispatch's resolution with Reason rather
// than letting the hub resolve anonymously beside a login the operator meant
// it to use.
type UnavailableRegistryLogins struct {
	Secret string
	Reason string
}

// RegistryLogins implements RegistryLoginSource.
func (s UnavailableRegistryLogins) RegistryLogins(context.Context) (imagepolicy.DockerLogins, error) {
	return imagepolicy.DockerLogins{}, fmt.Errorf("the registry secret %q could not be read: %s", s.Secret, s.Reason)
}

// Describe implements RegistryLoginSource.
func (s UnavailableRegistryLogins) Describe() string { return "registry secret " + s.Secret }

// imageResolution is one Pod's resolving: the logins, read once, the resolver
// built over them, and what came of it for the run's log.
type imageResolution struct {
	e *Executor
	// resolver is nil when the executor resolves nothing.
	resolver imagepolicy.Resolver
	// login names the registry secret, empty when there is none.
	login string
	// logins are the secret's, for the resolver and for cosign.
	logins imagepolicy.DockerLogins
	// strict is require_digest or require_signature: no tag reaches a Pod.
	strict bool
	// notes and warnings go on the run's log, as "[cloop] …" lines.
	notes    []string
	warnings []string
}

// failingResolver answers every resolution with err: the registry secret could
// not be read, and resolving without it is not what the operator configured.
type failingResolver struct{ err error }

func (f failingResolver) ResolveDigest(context.Context, string) (string, error) { return "", f.err }

// newImageResolution prepares one Pod's resolving, and returns the context its
// signature checks run under — carrying the registry login, so cosign fetches
// the signature as the identity that resolved the tag.
func (e *Executor) newImageResolution(ctx context.Context) (*imageResolution, context.Context) {
	policy := e.opts.ImagePolicy
	r := &imageResolution{e: e, strict: policy.RequireDigest || policy.RequireSignature}
	if !e.opts.ResolveTags && e.opts.ImageResolver == nil {
		return r, ctx
	}
	if src := e.opts.RegistryLogins; src != nil {
		r.login = src.Describe()
		logins, err := src.RegistryLogins(ctx)
		if err != nil {
			r.resolver = failingResolver{err: fmt.Errorf("%w: %v", imagepolicy.ErrRegistry, err)}
			return r, ctx
		}
		r.logins = logins
		ctx = imagepolicy.WithRegistryLogins(ctx, logins)
	}
	if e.opts.ImageResolver != nil {
		r.resolver = e.opts.ImageResolver
		return r, ctx
	}
	r.resolver = &imagepolicy.RegistryResolver{
		Client: e.opts.RegistryClient,
		// Only the registry secret's, or none: never the hub user's own
		// Docker logins, which DockerConfigCredential would read.
		Credentials: r.logins.Login,
	}
	return r, ctx
}

// signedIn says which login a resolution at registry used, for the run's log.
func (r *imageResolution) signedIn(registry string) string {
	if _, ok := r.logins.Login(registry); ok {
		return ", signed in with the " + r.login
	}
	return ""
}

// noteResolved records a tag resolved to the digest the Pod carries.
func (r *imageResolution) noteResolved(tag, pinned string) {
	parsed, err := imagepolicy.ParseReference(pinned)
	if err != nil {
		return
	}
	r.notes = append(r.notes, fmt.Sprintf("image %s resolved at %s to %s%s", tag, parsed.Registry, pinned,
		r.signedIn(parsed.Registry)))
}

// warn records a weaker outcome for the run's log, and the hub's.
func (r *imageResolution) warn(w string) {
	fmt.Fprintf(os.Stderr, "[kubernetes] sandbox image: %s\n", w)
	r.warnings = append(r.warnings, w)
}

// authorizeProject applies the hub's image trust policy to an image the
// project rules govern — one a project named, or the operator's under
// govern_operator_images — and returns the reference the Pod must carry: the
// digest the tag resolved to, verified under require_signature.
func (r *imageResolution) authorizeProject(ctx context.Context, ref string) (string, error) {
	enforcer := imagepolicy.Enforcer{
		Policy:   r.e.opts.ImagePolicy,
		Resolver: r.resolver,
		Verifier: r.e.verifier,
	}
	res, err := enforcer.Authorize(ctx, ref)
	if err != nil {
		if r.resolver == nil || !errors.Is(err, imagepolicy.ErrRegistry) {
			return "", classifyImageDenial(err)
		}
		// The registry did not resolve the tag. Under a policy that admits
		// only digests to a Pod that is a refusal; otherwise the tag goes in
		// as it always did, saying why.
		if r.strict {
			return "", r.unresolvedProjectImage(res.Decision.Ref, err)
		}
		if res.Decision.PolicyActive {
			r.warn(fmt.Sprintf("image %q runs from a mutable tag: the hub could not resolve it at its "+
				"registry (%v), so the artifact that runs is whatever the tag points at when a node pulls it",
				ref, trimRegistryErr(err)))
		}
		return res.Ref, nil
	}
	for _, w := range res.Warnings {
		r.warn(w)
	}
	if res.Pinned() {
		if parsed, perr := imagepolicy.ParseReference(ref); perr == nil && !parsed.Pinned() {
			r.noteResolved(ref, res.Ref)
		}
	}
	return res.Ref, nil
}

// pinOperator resolves the operator's executors.kubernetes.image when it is a
// tag the project rules do not govern, and returns what the Pod carries.
//
// The policy's allowlists do not apply to it — it was chosen by the person who
// wrote them, in the same file — but the policy's word on tags does: under
// require_digest or require_signature a tag that cannot be resolved is not sent
// to a kubelet, the operator's included.
func (r *imageResolution) pinOperator(ctx context.Context, image, field string) (string, error) {
	if r.resolver == nil {
		return image, nil
	}
	parsed, err := imagepolicy.ParseReference(image)
	if err != nil || parsed.Pinned() {
		// Already a digest, or not a reference ValidateImageRef would let
		// through — which refuses it below with its own message.
		return image, nil
	}
	if !parsed.Qualified {
		why := fmt.Errorf("%w: %q names no registry, so which registry a node pulls it from is the "+
			"node's configuration, which the hub cannot read", imagepolicy.ErrRegistry, image)
		return r.unresolvedOperatorImage(image, field, parsed, why)
	}
	digest, err := r.resolver.ResolveDigest(ctx, parsed.String())
	if err != nil {
		if !errors.Is(err, imagepolicy.ErrRegistry) && !errors.Is(err, imagepolicy.ErrNoDigest) {
			return "", fmt.Errorf("kubernetes: resolve %s (%s): %w", image, field, err)
		}
		return r.unresolvedOperatorImage(image, field, parsed, err)
	}
	pinned, err := parsed.WithDigest(digest)
	if err != nil {
		return "", fmt.Errorf("kubernetes: the registry answered an unusable digest for %s (%s): %w", image, field, err)
	}
	r.noteResolved(image, pinned.Canonical())
	return pinned.Canonical(), nil
}

// unresolvedOperatorImage is what becomes of an operator's tag the registry
// did not resolve: a refusal under a policy that admits only digests to a
// Pod, the tag with a warning otherwise.
func (r *imageResolution) unresolvedOperatorImage(image, field string, parsed imagepolicy.Reference,
	cause error) (string, error) {
	if r.strict {
		return "", r.unresolvedTag(image, field, parsed, cause)
	}
	if r.e.opts.ImagePolicy.Configured() {
		r.warn(fmt.Sprintf("image %q (%s) runs from a mutable tag: the hub could not resolve it at its "+
			"registry (%v), so the artifact that runs is whatever the tag points at when a node pulls it",
			image, field, trimRegistryErr(cause)))
	}
	return image, nil
}

// checkOwnImage verifies one of cloop's own images for a Pod (Task 20453),
// resolving a tag at its registry first (Task 20457), and refuses one it could
// not resolve when the policy admits only digests to a Pod.
func (r *imageResolution) checkOwnImage(ctx context.Context, image, field string) (imagepolicy.Provenance, error) {
	p, err := r.e.ownImageCheck(ctx, image, field, r.resolver)
	if err != nil {
		return p, err
	}
	parsed, perr := imagepolicy.ParseReference(image)
	if perr != nil || parsed.Pinned() {
		return p, nil
	}
	if p.Digest == "" {
		if r.resolver != nil && r.strict {
			return p, r.unresolvedTag(image, field, parsed, fmt.Errorf("%w: %s", imagepolicy.ErrRegistry, p.Detail))
		}
		return p, nil
	}
	r.noteResolved(image, p.Ref)
	return p, nil
}

// unresolvedTag refuses a tag the registry did not resolve, for a Pod under a
// policy that admits only digests to one.
func (r *imageResolution) unresolvedTag(image, field string, parsed imagepolicy.Reference, cause error) error {
	registry := parsed.Registry
	if registry == "" {
		registry = "its registry"
	}
	return &imagepolicy.DenyError{
		Ref:  image,
		Rule: imagepolicy.RuleResolution,
		Reason: fmt.Sprintf("this hub's image policy (%s) sends no tag to a Kubernetes Pod, so executor %s "+
			"runs %s (%s) only as the digest %s serves for it — and the hub could not resolve it there: %v",
			r.strictRules(), r.e.id, image, field, registry, trimRegistryErr(cause)),
		Remediation: r.remedy(registry, "Pin "+field+" by digest (`docker buildx imagetools inspect "+
			parsed.Name()+":"+orLatest(parsed.Tag)+"` prints it), so nothing has to be resolved"),
	}
}

// unresolvedProjectImage refuses a tag a project's rules admitted and the
// registry did not resolve, under require_signature.
func (r *imageResolution) unresolvedProjectImage(ref imagepolicy.Reference, cause error) error {
	registry := ref.Registry
	if registry == "" {
		registry = "its registry"
	}
	return &imagepolicy.DenyError{
		Ref:  ref.Original,
		Rule: imagepolicy.RuleResolution,
		Reason: fmt.Sprintf("this hub's image policy (%s) builds a Pod for a tag only once it has resolved the "+
			"tag to a digest at its registry%s — it could not resolve it at %s: %v",
			r.strictRules(), signatureClause(r.e.opts.ImagePolicy), registry, trimRegistryErr(cause)),
		Remediation: r.remedy(registry, "Pin the image by digest in .cloop/sandbox.yaml "+
			"(image: registry/repository@sha256:…), so nothing has to be resolved"),
	}
}

// remedy is what to do about a tag the registry did not resolve: pin it, or
// let the hub reach the registry — with the login it needs, when it is private.
func (r *imageResolution) remedy(registry, pin string) string {
	reach := "or let the hub reach " + registry + " over https"
	if r.login != "" {
		reach += " — and check that the " + r.login + " holds a login for it (`cloop executor test " +
			r.e.id + "` names the registries it covers)"
	} else {
		reach += " — with a login for it in a registry secret (`cloop secret mint <name> --kind registry " +
			"--file config.json`) named by executors.kubernetes.registry_secret, if the repository is private"
	}
	return pin + ", " + reach + "."
}

// strictRules names the settings that make a tag a refusal.
func (r *imageResolution) strictRules() string {
	p := r.e.opts.ImagePolicy
	switch {
	case p.RequireDigest && p.RequireSignature:
		return "require_digest and require_signature"
	case p.RequireSignature:
		return "require_signature"
	}
	return "require_digest"
}

// signatureClause adds the signature step to a refusal under require_signature.
func signatureClause(p imagepolicy.Policy) string {
	if p.RequireSignature {
		return " and verified that digest's signature"
	}
	return ""
}

// trimRegistryErr drops the package prefix ErrRegistry puts on every
// resolution failure, which says nothing a reader of the refusal needs.
func trimRegistryErr(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, imagepolicy.ErrRegistry.Error()+": ")
	return s
}

// orLatest is a tag, or the one a reference without one means.
func orLatest(tag string) string {
	if tag == "" {
		return "latest"
	}
	return tag
}

// imageLogLines are what a Pod's image resolution puts at the top of its run's
// log: what was resolved to what, then what ran weaker than it should have.
func (r *imageResolution) imageLogLines() []string {
	out := make([]string, 0, len(r.notes)+len(r.warnings))
	for _, n := range r.notes {
		out = append(out, "[cloop] "+n+"\n")
	}
	for _, w := range r.warnings {
		out = append(out, "[cloop] warning: "+w+"\n")
	}
	return out
}

var (
	_ RegistryLoginSource  = BrokerRegistryLogins{}
	_ RegistryLoginSource  = UnavailableRegistryLogins{}
	_ imagepolicy.Resolver = failingResolver{}
)
