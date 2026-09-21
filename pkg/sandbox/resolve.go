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
	fmt.Fprintf(&b, "cpu=%v\nmemory=%s\npids=%d\ndisk=%s\n",
		s.Resources.CPU, s.Resources.Memory, s.Resources.PIDs, s.Resources.Disk)
	fmt.Fprintf(&b, "git=%t\nnetwork=%s\n", s.Capabilities.Git, s.Capabilities.Network)
	// Every capability field belongs in the hash, because the hash is what the
	// audit trail uses to say "this container was shaped by that spec". A
	// confinement key left out here would let two runs with materially different
	// boundaries — one kernel-isolated and cut off from private space, one not —
	// record the same sandbox identity.
	fmt.Fprintf(&b, "virtualized=%t\nkernel_isolated=%t\negress=%s\n",
		s.Capabilities.Virtualized, s.Capabilities.KernelIsolated, s.Capabilities.Egress)
	// Sorted for the reason env is: the set of selected devices is what matters,
	// not the order they were typed in.
	devices := append([]string(nil), s.Capabilities.Devices...)
	sort.Strings(devices)
	for _, name := range devices {
		fmt.Fprintf(&b, "device=%s\n", name)
	}
	ifaces := append([]string(nil), s.Capabilities.Interfaces...)
	sort.Strings(ifaces)
	for _, name := range ifaces {
		fmt.Fprintf(&b, "interface=%s\n", name)
	}
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
	if s.Resources.CPU > 0 || s.Resources.Memory != "" || s.Resources.PIDs > 0 || s.Resources.Disk != "" {
		req.RequireResourceLimits = true
	}
	if s.Capabilities.Network != "" {
		// The grant says the project is *allowed* egress. The executor still
		// has to have some. Requiring it here is what turns "your grant exists
		// but the sandbox you are bound to has --network=none" into a refusal
		// instead of a task that fails on its first `git fetch`.
		req.RequireNetworkEgress = true
	}
	if len(s.Capabilities.Devices) > 0 {
		// The same argument as Network, for the other grant-backed capability.
		// The grant says the project is allowed the hardware; the executor still
		// has to be able to expose it, and only a driver advertising
		// SupportsDevices can. Without this, CheckSandboxSupport would accept a
		// node that cannot deliver a device the spec names.
		//
		// Keyed on the selector rather than on the grant because this function
		// only sees the repo's file. An *empty* selector means "every device
		// this project holds", which is usually none, so requiring the
		// capability for it would refuse ordinary projects on ordinary
		// executors. That case is carried by Spec.SandboxRequirements instead,
		// which counts the devices actually attached.
		req.RequireDevices = true
	}
	if len(s.Capabilities.Interfaces) > 0 {
		// The same argument as Devices, for the narrower capability. An empty
		// selector is again carried by Spec.SandboxRequirements instead, which
		// counts the interfaces actually attached.
		req.RequireInterfaces = true
	}
	if s.Capabilities.Git {
		req.Harnesses = append(req.Harnesses, "git")
	}
	if s.Capabilities.KernelIsolated {
		// Like Virtualized, one of the few requirements asking for *more*
		// confinement than the executor would otherwise apply, so it needs no
		// grant. Set independently of Virtualized rather than implied by it:
		// every virtualized executor is kernel-isolated, so a spec that sets
		// both gets the stricter check and neither requirement has to know
		// about the other.
		req.RequireKernelIsolation = true
	}
	if scope := executor.EgressScope(s.Capabilities.Egress); scope.NeedsFilter() {
		// Only a scope that needs a ruleset installed becomes a requirement.
		// `none` is honourable by any driver with a network to take away, so
		// requiring the capability for it would refuse executors that deliver
		// exactly what was asked for. See Spec.SandboxRequirements, which draws
		// the same line for the same reason.
		req.RequireEgressScope = true
		req.RequireNetworkEgress = true
	}
	if s.Capabilities.Virtualized {
		// One of the few requirements that asks for *more* confinement than the
		// executor would otherwise apply, which is why it needs no grant. If no
		// bound executor is hypervisor-backed the project does not run, and
		// that refusal is the feature: a repo that declares it must not share a
		// kernel with the host has said something placement can honour exactly
		// or not at all.
		req.RequireVirtualization = true
	}
	// Deliberately absent: RequireWorkspaceProvisioning, even though
	// resources.disk feeds Workspace.SizeLimitMB.
	//
	// The workspace *kind* is the hub's decision, not the repo's. A
	// repo-committed file that could ask to be provisioned would be a file that
	// arranges its own clone — from a URL in the same pull request. There is no
	// key in this schema that names a repository, for exactly that reason, and a
	// requirement inferred from one would be the same power arriving sideways.
	// All a spec may do is bound a fetch the hub already decided to perform.
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
	if s.Resources.Disk != "" {
		mb, err := config.ParseDiskMB(s.Resources.Disk)
		if err != nil {
			// normalize() already accepted it, so this is unreachable short of
			// a caller hand-building a Spec. Refusing beats running unbounded.
			return fmt.Errorf("sandbox: resources.disk %q: %w", s.Resources.Disk, err)
		}
		spec.ResourceLimits.DiskMB = mb
		// The same number in two places, because two different mechanisms
		// enforce it and neither covers the other. ResourceLimits.DiskMB
		// becomes the volume's own ceiling — a Kubernetes emptyDir sizeLimit,
		// which the kubelet enforces by evicting the Pod. Workspace.SizeLimitMB
		// is checked by the provisioner right after the fetch, which is what
		// turns "the repository is bigger than the allowance" into a legible
		// refusal instead of a Pod that vanishes mid-run.
		//
		// Only this field is written. The caller sets spec.Workspace itself —
		// the kind, the repo, the ref and the grant are all the hub's decisions
		// (see Requirements) — so assigning a whole Workspace here would silently
		// discard them.
		spec.Workspace.SizeLimitMB = mb
	}

	// --- egress scope ----------------------------------------------------
	// Written before the network grant is resolved, because the two are
	// independent narrowings and a scope must survive the early return below.
	// Both can only remove reach, so their order does not change the outcome —
	// but a scope dropped by an early return would be a confinement the author
	// asked for and did not get, which is the one failure direction this
	// package does not permit.
	if s.Capabilities.Egress != "" {
		scope, err := executor.ParseEgressScope(s.Capabilities.Egress)
		if err != nil {
			// normalize() already accepted it, so this is unreachable short of a
			// caller hand-building a Spec. Refusing beats running unconfined.
			return fmt.Errorf("sandbox: capabilities.egress %q: %w", s.Capabilities.Egress, err)
		}
		spec.EgressScope = scope
	}

	// --- devices ---------------------------------------------------------
	// Selection, never addition. spec.Devices already holds whatever the
	// project's host_device grants delivered (see pkg/ui.applyDeviceGrants), so
	// this narrows that list and can only shorten it.
	if sel := s.Capabilities.Devices; len(sel) > 0 {
		kept, missing := selectDevices(spec.Devices, sel)
		if len(missing) > 0 {
			// An error rather than a silent omission, unlike `env`. A missing
			// variable degrades a run; a missing device node makes the task
			// meaningless, and a firmware build that starts with no serial port
			// reports on hardware it never reached.
			return &DeviceNotGrantedError{ProjectPath: projectPath, Names: missing}
		}
		spec.Devices = kept
	}

	// --- interfaces ------------------------------------------------------
	// Selection, never addition, exactly as for devices: spec.Interfaces
	// already holds whatever the project's host_interface grants delivered
	// (see pkg/ui.applyInterfaceGrants), so this can only shorten it.
	if sel := s.Capabilities.Interfaces; len(sel) > 0 {
		kept, missing := selectInterfaces(spec.Interfaces, sel)
		if len(missing) > 0 {
			return &InterfaceNotGrantedError{ProjectPath: projectPath, Names: missing}
		}
		spec.Interfaces = kept
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

// selectDevices narrows a granted device list to the names a spec asked for.
//
// It returns the kept devices in the *spec's* order rather than the grant's,
// because the spec's order is the one its author wrote down and the one any
// diagnostic they read will list. The second return is the names that matched
// nothing, which is what the caller turns into a refusal.
func selectDevices(granted []executor.HostDevice, want []string) ([]executor.HostDevice, []string) {
	byName := make(map[string]executor.HostDevice, len(granted))
	for _, d := range granted {
		byName[strings.TrimSpace(d.Name)] = d
	}
	kept := make([]executor.HostDevice, 0, len(want))
	var missing []string
	for _, name := range want {
		name = strings.TrimSpace(name)
		d, ok := byName[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		kept = append(kept, d)
	}
	return kept, missing
}

// selectInterfaces narrows a granted interface list to the names a spec asked
// for. It is selectDevices for the other grant-backed list and, like it, can
// only shorten what it is given.
func selectInterfaces(granted []executor.HostInterface, want []string) ([]executor.HostInterface, []string) {
	byName := make(map[string]executor.HostInterface, len(granted))
	for _, n := range granted {
		byName[strings.TrimSpace(n.Name)] = n
	}
	kept := make([]executor.HostInterface, 0, len(want))
	var missing []string
	for _, name := range want {
		name = strings.TrimSpace(name)
		n, ok := byName[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		kept = append(kept, n)
	}
	return kept, missing
}

// InterfaceNotGrantedError is returned when a sandbox spec names an interface
// the project holds no host_interface grant for.
//
// Typed for the reason DeviceNotGrantedError is, and separate from it because
// the remediation names a different flag on a different inventory: an operator
// reading "grant the device" when the missing thing is a network segment would
// go looking in the wrong secret.
type InterfaceNotGrantedError struct {
	ProjectPath string
	Names       []string
}

func (e *InterfaceNotGrantedError) Error() string {
	return fmt.Sprintf("%s: capabilities.interfaces names %s, which this project holds no "+
		"host_interface grant for", FileName, strings.Join(e.Names, ", "))
}

// Remediation is the operator-facing next step, kept beside the error so the UI
// and the CLI print the same sentence.
func (e *InterfaceNotGrantedError) Remediation() string {
	return fmt.Sprintf("grant the interface to this project: cloop secret grant "+
		"<inventory-secret> --subject project:%s --interfaces %s",
		e.ProjectPath, strings.Join(e.Names, ","))
}

// DeviceNotGrantedError is returned when a sandbox spec names a device the
// project holds no host_device grant for.
//
// A typed error for the reason GrantDeniedError is one: the two outcomes need
// different HTTP statuses and different remediation. This one is a 409 — the
// file is well-formed and this deployment has not been told to honour it — and
// the fix is an operator running secret.grant, not an edit to the repo.
type DeviceNotGrantedError struct {
	ProjectPath string
	Names       []string
}

func (e *DeviceNotGrantedError) Error() string {
	return fmt.Sprintf("%s: capabilities.devices names %s, which this project holds no "+
		"host_device grant for", FileName, strings.Join(e.Names, ", "))
}

// Remediation is the operator-facing next step, kept beside the error so the UI
// and the CLI print the same sentence.
func (e *DeviceNotGrantedError) Remediation() string {
	return fmt.Sprintf("grant the device to this project: cloop secret grant <inventory-secret> "+
		"--subject project:%s --devices %s", e.ProjectPath, strings.Join(e.Names, ","))
}
