package sandbox

// resolve.go turns a parsed Spec into the two things the rest of cloop needs
// from it: a set of placement requirements, and a mutation of executor.Spec.
//
// Keeping both here — rather than letting each caller read the struct and
// decide for itself what `capabilities.network: ci` implies — is what makes the
// "can only narrow" guarantee checkable. There is exactly one function that
// widens nothing and one that turns a request into a constraint, and the
// security review reads those two instead of every call site.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// GrantChecker reports whether a project already holds an active egress grant
// by that name.
//
// It is an interface, and a nil one denies, because of what the alternative
// would be. If this package imported pkg/egressbroker directly it would need a
// broker instance at every call site, and the call sites that could not supply
// one (the CLI validator, tests, `cloop sandbox check`) would end up passing a
// permissive stub. Denying by default means the awkward path is the safe one.
type GrantChecker interface {
	// HasEgressGrant reports whether projectPath currently holds an active
	// grant named grantID.
	HasEgressGrant(projectPath, grantID string) bool
}

// Resolved is a spec together with everything derived from it that a caller
// needs to keep: its identity, and the warnings raised while normalizing it.
type Resolved struct {
	// Spec is the validated spec, or nil when the project has none.
	Spec *Spec
	// Hash identifies the spec's content. It is recorded in the task artifact
	// so a run can be tied back to the exact file that shaped it, including
	// after the file changes.
	Hash string
	// Warnings are the clamps applied while parsing.
	Warnings []string
	// Source is the path the spec was read from, for error messages.
	Source string
}

// Present reports whether a spec was found and asks for anything.
func (r *Resolved) Present() bool {
	return r != nil && r.Spec != nil && !r.Spec.IsZero()
}

// Resolve loads the spec for a project, if it has one.
//
// A missing file is not an error: it returns a Resolved whose Present() is
// false, so callers need no special case for the overwhelmingly common project
// that never writes one.
func Resolve(projectDir string) (*Resolved, error) {
	spec, warnings, err := Load(projectDir)
	switch {
	case err == ErrNotFound:
		return &Resolved{}, nil
	case err != nil:
		return &Resolved{Warnings: warnings}, err
	}
	res := &Resolved{
		Spec:     spec,
		Hash:     spec.Hash(),
		Warnings: warnings,
		Source:   FileName,
	}
	return res, nil
}

// Hash returns a stable content hash of the spec.
//
// It hashes a canonical rendering of the *normalized* fields rather than the
// raw file bytes, so reformatting the YAML or reordering keys does not change
// the identity of the environment it describes — which matters because the hash
// is also the cache key for the derived sandbox image. Two files that mean the
// same thing must not build two images.
func (s *Spec) Hash() string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "image=%s\n", s.Image)
	for _, cmd := range s.Setup {
		fmt.Fprintf(&b, "setup=%s\n", cmd)
	}
	// Env and mounts are sorted: the set of forwarded names is what matters,
	// not the order someone happened to type them in.
	env := append([]string(nil), s.Env...)
	sort.Strings(env)
	for _, name := range env {
		fmt.Fprintf(&b, "env=%s\n", name)
	}
	fmt.Fprintf(&b, "cpu=%v\nmemory=%s\npids=%d\n", s.Resources.CPU, s.Resources.Memory, s.Resources.PIDs)
	fmt.Fprintf(&b, "git=%t\nnetwork=%s\n", s.Capabilities.Git, s.Capabilities.Network)
	mounts := append([]Mount(nil), s.Mounts...)
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Target < mounts[j].Target })
	for _, m := range mounts {
		fmt.Fprintf(&b, "mount=%s:%s:%t\n", m.Source, m.Target, m.ReadOnly)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// SetupHash identifies just the image-build inputs, which is what the derived
// image is keyed by. It is separate from Hash because changing `env:` or
// `resources:` must not invalidate a built image — those are applied per run.
func (s *Spec) SetupHash() string {
	if s == nil || len(s.Setup) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "image=%s\n", s.Image)
	for _, cmd := range s.Setup {
		fmt.Fprintf(&b, "run=%s\n", cmd)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// CheckImagePolicy evaluates the spec's image against the hub's trust policy.
//
// This is the *validation* surface, not the enforcement one. Enforcement lives
// in the executors, where the reference is about to become a runtime argument
// and can additionally be pinned and signature-checked. This runs earlier, from
// the same place that parses the file, so a project whose image is refused
// learns it as a config error naming the rule — before a run starts, before a
// container is created, and in the same response as every other thing wrong
// with its sandbox.yaml.
//
// The returned Decision is populated whether or not the image was allowed, so
// the UI can render "this would be refused, because X" without an error path.
// A spec with no image, or an unconfigured policy, yields a zero Decision and a
// nil error.
func (r *Resolved) CheckImagePolicy(p imagepolicy.Policy) (imagepolicy.Decision, error) {
	if !r.Present() || r.Spec.Image == "" {
		return imagepolicy.Decision{}, nil
	}
	decision, err := p.Evaluate(r.Spec.Image)
	if err != nil {
		// Wrapped with the file name because the author needs to be told which
		// of their files is wrong, not only which rule refused it.
		return decision, fmt.Errorf("%s: image: %w", FileName, err)
	}
	return decision, nil
}

// Requirements returns the placement constraints this spec implies.
//
// Every entry is a capability the executor must genuinely have. Nothing here is
// advisory: a requirement that placement cannot satisfy produces a refusal
// naming the constraint, which is the whole point — a sandbox spec that is
// quietly ignored is worse than one that is rejected, because the task then
// runs in an environment nobody described.
func (r *Resolved) Requirements() executor.Requirements {
	req := executor.Requirements{}
	if !r.Present() {
		return req
	}
	s := r.Spec
	if s.Image != "" {
		req.RequireImageOverride = true
	}
	if len(s.Setup) > 0 {
		req.RequireSandboxBuild = true
	}
	if s.Resources.CPU > 0 || s.Resources.Memory != "" || s.Resources.PIDs > 0 {
		req.RequireResourceLimits = true
	}
	if s.Capabilities.Network != "" {
		// The grant says the project is *allowed* egress. The executor still
		// has to have some. Requiring it here is what turns "your grant exists
		// but the sandbox you are bound to has --network=none" into a refusal
		// instead of a task that fails on its first `git fetch`.
		req.RequireNetworkEgress = true
	}
	if s.Capabilities.Git {
		req.Harnesses = append(req.Harnesses, "git")
	}
	return req
}

// ApplyTo writes the spec onto an executor.Spec.
//
// projectPath and grants are used only for the egress capability: a spec naming
// a grant the project does not hold is refused, and a spec naming no grant at
// all takes the network away. Those are the only two outcomes — there is no
// third in which the workload ends up with more network than the executor was
// configured to give it.
//
// Callers must still run executor.CheckSandboxSupport against the bound
// executor; ApplyTo shapes the request, it does not decide whether the request
// can be honoured.
func (r *Resolved) ApplyTo(spec *executor.Spec, projectPath string, grants GrantChecker) error {
	if spec == nil {
		return fmt.Errorf("sandbox: nil executor spec")
	}
	if !r.Present() {
		return nil
	}
	s := r.Spec

	if s.Image != "" {
		spec.Image = s.Image
	}
	if len(s.Setup) > 0 {
		spec.SetupCommands = append([]string(nil), s.Setup...)
	}
	if m := s.SpecMounts(); len(m) > 0 {
		spec.Mounts = append(spec.Mounts, m...)
	}
	spec.SandboxHash = r.Hash

	// --- resources -------------------------------------------------------
	if s.Resources.CPU > 0 {
		spec.ResourceLimits.CPUMillis = int(s.Resources.CPU * 1000)
	}
	if s.Resources.Memory != "" {
		mb, err := config.ParseMemoryMB(s.Resources.Memory)
		if err != nil {
			// normalize() already accepted it, so this is unreachable short of
			// a caller hand-building a Spec. Refusing beats running unbounded.
			return fmt.Errorf("sandbox: resources.memory %q: %w", s.Resources.Memory, err)
		}
		spec.ResourceLimits.MemoryMB = mb
	}
	if s.Resources.PIDs > 0 {
		spec.ResourceLimits.PIDs = s.Resources.PIDs
	}

	// --- network ---------------------------------------------------------
	// The asymmetry is the security property. No grant named → the network is
	// removed. A grant named → it must already exist, and if it does the
	// executor's own network stands unchanged. Nothing here can add one.
	if s.Capabilities.Network == "" {
		spec.DisableNetwork = true
		return nil
	}
	if grants == nil || !grants.HasEgressGrant(projectPath, s.Capabilities.Network) {
		return &GrantDeniedError{
			ProjectPath: projectPath,
			GrantID:     s.Capabilities.Network,
		}
	}
	// The env allowlist is applied by the caller, which is the only layer that
	// knows what the project was actually granted; see FilterEnv.
	return nil
}

// FilterEnv returns the subset of env (K=V entries) whose names the spec asked
// for, plus every entry the spec did not mention that the caller marked
// mandatory.
//
// The direction matters: this filters an environment the caller already
// assembled from the project's grants. It cannot introduce a variable, only
// remove ones the spec did not ask for. A name in `env:` that the project holds
// no grant for therefore forwards nothing, silently and correctly — the spec
// expressed a wish, not an entitlement.
//
// A spec with no `env:` at all is not an empty allowlist; it is no opinion, and
// the caller's environment passes through untouched. Reading an absent key as
// "forward nothing" would break every project that adds a sandbox.yaml purely
// to pin an image, by stripping the API key its harness needs.
func (r *Resolved) FilterEnv(env []string) []string {
	if !r.Present() || len(r.Spec.Env) == 0 {
		return env
	}
	allow := make(map[string]struct{}, len(r.Spec.Env))
	for _, name := range r.Spec.Env {
		allow[name] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if _, ok := allow[kv[:i]]; ok {
			out = append(out, kv)
		}
	}
	return out
}

// GrantDeniedError reports a sandbox spec asking for an egress grant the
// project does not hold.
//
// It is typed for the same reason executor.HostExecutionDeniedError is: the
// developer who wrote the YAML and the operator who can issue the grant are
// different people, so the error has to carry enough for the first to file a
// useful request to the second.
type GrantDeniedError struct {
	ProjectPath string
	GrantID     string
}

// Error implements error.
func (e *GrantDeniedError) Error() string {
	return fmt.Sprintf("sandbox: %s requests network egress via grant %q, "+
		"which project %q does not hold. %s", FileName, e.GrantID, e.ProjectPath, e.Remediation())
}

// Remediation returns the "what to do about it" half, for UI surfaces that
// render cause and fix separately.
func (e *GrantDeniedError) Remediation() string {
	return fmt.Sprintf("Ask an operator to create an egress grant named %q for this project "+
		"(Secrets & Grants tab, or `cloop egress grant`), or remove capabilities.network "+
		"from %s to run without the network.", e.GrantID, FileName)
}
