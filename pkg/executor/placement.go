package executor

// placement.go answers "which executor should run this task?"
//
// Until now the answer was Registry.Resolve: whatever the project is bound to,
// or the default. That is a *binding* lookup, not a scheduling decision — it
// cannot express "this task needs the claude harness on an arm64 device with a
// network egress path", and it has no opinion about whether the node it names
// is currently alive. On a fleet of flapping edge devices those are the only
// two questions that matter.
//
// Two properties are non-negotiable here, and both are about failing loudly:
//
//   - Deny by default. If nothing satisfies the requirements, placement
//     returns an error. It never widens the search, never drops the
//     constraint it could not satisfy, and above all never falls back to the
//     control-plane host. Silently running an isolated workload on the host
//     because no sandbox was available is precisely the failure this whole
//     subsystem exists to prevent.
//   - Name the constraint. "No executor available" sends an operator reading
//     logs; "no executor satisfies harness=claude (3 candidates rejected:
//     edge-1 lacks it, edge-2 is unreachable, host is denied by policy)" sends
//     them to the fix. PlacementError carries the per-candidate reasons.
//
// Select is a pure function over a caller-assembled candidate list rather than
// something that reaches into the Registry itself. That is what keeps this file
// free of the import cycle that would otherwise exist (agent capabilities live
// in pkg/executor/remote, which imports this package), and it is what makes the
// placement matrix testable without a database, a registry, or a clock.

import (
	"fmt"
	"sort"
	"strings"
)

// Constraint identifies which requirement eliminated a candidate. It is a
// string rather than an int so it can cross the API boundary into a JSON error
// body and still mean something to whoever reads it.
type Constraint string

const (
	ConstraintNoCandidates     Constraint = "no_candidates"
	ConstraintExecutorID       Constraint = "executor_id"
	ConstraintHealth           Constraint = "health"
	ConstraintHostPolicy       Constraint = "host_execution_policy"
	ConstraintIsolation        Constraint = "isolation"
	ConstraintLabels           Constraint = "labels"
	ConstraintPlatform         Constraint = "platform"
	ConstraintArch             Constraint = "arch"
	ConstraintHarness          Constraint = "harness"
	ConstraintContainerRuntime Constraint = "container_runtime"
	ConstraintNetworkEgress    Constraint = "network_egress"
	ConstraintResourceLimits   Constraint = "resource_limits"
	ConstraintStream           Constraint = "stream"
	ConstraintSignal           Constraint = "signal"
	ConstraintMemory           Constraint = "memory"
	ConstraintCapacity         Constraint = "capacity"
	ConstraintImageOverride    Constraint = "image_override"
	ConstraintSandboxBuild     Constraint = "sandbox_build"
	ConstraintSandboxMounts    Constraint = "sandbox_mounts"
	ConstraintWorkspace        Constraint = "workspace"
	ConstraintWriteBack        Constraint = "write_back"
)

// Candidate is one executor offered to the scheduler, together with everything
// placement needs to judge it.
//
// The caller assembles this from the registry, the health store, and (for
// remote agents) the capabilities the device advertised at enrollment. Bundling
// it into a value keeps Select pure and keeps this package independent of both
// storage and the remote protocol.
type Candidate struct {
	// Executor is the driver instance. Select returns the Candidate, so the
	// caller gets this back to Start on.
	Executor Executor
	// Health is the supervisor's current view. A zero value normalizes to
	// ready, so a caller with no health store still gets sane placement.
	Health Health
	// Labels are operator-assigned scheduler selectors (region, tier, owner).
	Labels map[string]string
	// Harnesses are the agent CLIs available on the node, as detected by
	// pkg/executor/agent.Detect ("claude", "codex", "cloop", ...).
	Harnesses []string
	// ContainerRuntimes are the container runtimes the node can drive.
	ContainerRuntimes []string
	// MemoryMB is total system memory on the node; 0 means unknown, which is
	// never treated as "too small".
	MemoryMB int
	// InFlight is the number of sessions currently running on the node, and
	// InFlightKnown says whether that number is real. A driver that cannot
	// enumerate reports InFlightKnown=false, and capacity is then not
	// enforced — refusing to schedule because load is unknown would make
	// every non-enumerating driver unusable.
	InFlight      int
	InFlightKnown bool
}

// ID returns the candidate's executor ID, or "" for a malformed candidate.
func (c Candidate) ID() string {
	if c.Executor == nil {
		return ""
	}
	return c.Executor.ID()
}

// Requirements describes what a task needs from a node. The zero value means
// "anything healthy", so a caller with no special needs still benefits from
// health filtering and capacity-aware tie-breaking.
type Requirements struct {
	// ExecutorID pins placement to one node. It is still checked for health
	// and policy: a pin is a statement about *where*, not a license to run on
	// a dead or forbidden node.
	ExecutorID string
	// Labels is a selector; every key must be present on the candidate with
	// the same value.
	Labels map[string]string
	// Harnesses lists agent CLIs the task will invoke. A candidate must
	// advertise all of them, unless it advertises none at all (see
	// hasHarness).
	Harnesses []string
	// Platform and Arch constrain the execution target (GOOS/GOARCH style).
	Platform string
	Arch     string
	// MinMemoryMB rejects nodes that report less memory than this. Nodes
	// reporting 0 (unknown) are not rejected.
	MinMemoryMB int
	// RequireIsolation rejects any node that shares the control-plane host.
	RequireIsolation bool
	// AllowedIsolations, when non-empty, restricts placement to these
	// isolation kinds. Isolation is not a total order (a container and a
	// remote device are differently, not more or less, isolated), so this is
	// a set rather than a minimum.
	AllowedIsolations []Isolation
	// RequireContainerRuntime demands a node that can drive containers.
	RequireContainerRuntime bool
	// RequireNetworkEgress demands a node whose workloads can reach the
	// network.
	RequireNetworkEgress bool
	// RequireResourceLimits demands a node that actually enforces
	// Spec.ResourceLimits rather than ignoring them.
	RequireResourceLimits bool
	// RequireImageOverride demands a node that honours Spec.Image, i.e. that
	// a per-project sandbox can choose its own toolchain there.
	//
	// This is the constraint that makes per-project sandboxes honest. Without
	// it a project pinning `image: rust:1.79` placed on the host driver would
	// run against whatever toolchain the control plane happens to have, get a
	// plausible-looking build failure, and send its author hunting through
	// their own code. Refusing placement and naming the reason is the only
	// outcome that points at the deployment instead.
	RequireImageOverride bool
	// RequireSandboxBuild demands a node that can bake Spec.SetupCommands
	// into a derived image.
	RequireSandboxBuild bool
	// RequireSandboxMounts demands a node that honours Spec.Mounts.
	RequireSandboxMounts bool
	// RequireWorkspaceProvisioning demands a node that can materialise the
	// source tree itself, because this workload's tree is not already there.
	//
	// Without this constraint the failure mode is the worst kind: the harness
	// starts, finds an empty directory, and reports back on a repository it
	// never saw. Refusing placement converts that into a message naming the
	// executor that cannot fetch.
	RequireWorkspaceProvisioning bool
	// RequireHostFilesystemWorkspace demands a node whose WorkDir really is a
	// path on the control-plane host, because the workload was dispatched with
	// Workspace.Kind "bind" — i.e. with the tree assumed to be there already.
	RequireHostFilesystemWorkspace bool
	// RequireWriteBack demands a node that can return the files the workload
	// changes, because this one's tree does not survive the run.
	//
	// It is the workspace constraint's mirror image, and its failure is the
	// worse of the two. An executor that cannot fetch produces a harness that
	// reports on a repository it never saw; one that cannot write back produces
	// a harness that reports, accurately, on work that is then discarded with
	// the sandbox. The first is confusing on arrival, the second is invisible
	// until someone goes looking for the commit.
	RequireWriteBack bool
	// RequireStream and RequireSignal demand live output and the ability to
	// stop a workload — the two capabilities the Web UI's run panel needs.
	RequireStream bool
	RequireSignal bool
	// AllowDegraded permits placement on a degraded node. Default true via
	// the zero value being "not forbidden"; set ForbidDegraded to tighten.
	ForbidDegraded bool
	// IgnoreCapacity skips the MaxConcurrent check.
	IgnoreCapacity bool
}

// Rejection records why one candidate was not chosen.
type Rejection struct {
	ExecutorID string     `json:"executor_id"`
	Constraint Constraint `json:"constraint"`
	Detail     string     `json:"detail"`
}

// PlacementError is returned when no candidate satisfies the requirements.
//
// It is a typed error carrying structured rejections rather than a formatted
// string because three different surfaces need to render it differently: the
// CLI prints a table, the Web UI shows a per-node badge, and the failover path
// logs it as an event payload.
type PlacementError struct {
	// Constraint is the headline reason — the requirement that eliminated
	// the most candidates, which is nearly always the one to fix.
	Constraint Constraint
	// Rejections is the per-candidate detail, ordered by executor ID.
	Rejections []Rejection
	// Considered is how many candidates were offered.
	Considered int
}

// Error implements error.
func (e *PlacementError) Error() string {
	if e.Considered == 0 {
		return "executor: no executor available: none registered"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "executor: no executor satisfies %s (%d candidate(s) rejected",
		e.Constraint, len(e.Rejections))
	if len(e.Rejections) > 0 {
		b.WriteString(": ")
		parts := make([]string, 0, len(e.Rejections))
		for _, r := range e.Rejections {
			parts = append(parts, fmt.Sprintf("%s %s", r.ExecutorID, r.Detail))
		}
		b.WriteString(strings.Join(parts, "; "))
	}
	b.WriteString(")")
	return b.String()
}

// Unwrap lets callers match with errors.Is(err, ErrNoPlacement).
func (e *PlacementError) Unwrap() error { return ErrNoPlacement }

// Select chooses the best candidate satisfying req, or returns a
// *PlacementError naming the constraint that could not be met.
//
// Ranking among satisfying candidates, in order:
//
//  1. ready before degraded — a node whose probes are landing is a better bet
//     than one that is merely not yet given up on;
//  2. more free capacity first, so a fleet fills evenly instead of piling
//     every task onto whichever node sorts first alphabetically;
//  3. isolated before un-isolated, so a deployment that permits host execution
//     still prefers a sandbox when one is free;
//  4. executor ID, purely so the result is deterministic and tests are not
//     flaky.
func Select(candidates []Candidate, req Requirements) (Candidate, error) {
	if len(candidates) == 0 {
		return Candidate{}, &PlacementError{Constraint: ConstraintNoCandidates}
	}

	var (
		eligible   []Candidate
		rejections []Rejection
	)
	for _, c := range candidates {
		if c.Executor == nil {
			continue
		}
		if rej, ok := reject(c, req); ok {
			rejections = append(rejections, rej)
			continue
		}
		eligible = append(eligible, c)
	}

	if len(eligible) == 0 {
		sort.Slice(rejections, func(i, j int) bool {
			return rejections[i].ExecutorID < rejections[j].ExecutorID
		})
		return Candidate{}, &PlacementError{
			Constraint: headlineConstraint(rejections),
			Rejections: rejections,
			Considered: len(candidates),
		}
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		return lessCandidate(eligible[i], eligible[j])
	})
	return eligible[0], nil
}

// CheckSandboxSupport verifies that the executor a project is *already bound
// to* can honour req, and returns a typed error naming the gap if it cannot.
//
// Binding and placement are different questions — Registry.Resolve answers
// "which executor is this project pointed at", not "which executor should run
// this" — but they must not answer the capability question differently. So this
// runs the bound executor through the same reject() the scheduler uses, as a
// candidate list of one. A constraint added to Select is therefore enforced on
// the binding path for free, which is the opposite of how the two usually drift.
//
// The error type is chosen by what the operator has to *do*:
//
//   - a gap that is really "this workload cannot run beside the control plane"
//     becomes *HostExecutionDeniedError, whose Remediation() already names the
//     isolated executors to bind to instead. The UI renders that verbatim.
//   - anything else becomes the *PlacementError from reject(), which names the
//     single constraint the bound executor failed.
//
// A nil executor, or a req nothing rejects, returns nil.
func CheckSandboxSupport(ex Executor, req Requirements, projectPath string) error {
	if ex == nil {
		return fmt.Errorf("%w: nil executor", ErrExecutorNotFound)
	}
	// IgnoreCapacity: this is a support question, not a scheduling one. A busy
	// executor is still the one the project is bound to, and reporting "at
	// capacity" as if it were a sandbox incompatibility would send the reader
	// to edit their sandbox.yaml over a transient load spike.
	req.IgnoreCapacity = true
	rej, rejected := reject(Candidate{Executor: ex, Health: Health{State: NodeReady}}, req)
	if !rejected {
		return nil
	}
	switch rej.Constraint {
	case ConstraintHostPolicy, ConstraintIsolation:
		return hostDenied(ex, projectPath)
	case ConstraintWorkspace, ConstraintWriteBack:
		// Never folded into hostDenied. "Bind this project to a sandbox" is
		// the opposite of the fix here: the bound executor is *already*
		// isolated and that is precisely why it cannot see the tree. The
		// constraint-specific message names the real remedy.
		return &PlacementError{Constraint: rej.Constraint, Rejections: []Rejection{rej}, Considered: 1}
	case ConstraintImageOverride, ConstraintSandboxBuild, ConstraintSandboxMounts,
		ConstraintNetworkEgress, ConstraintResourceLimits:
		// These are capability gaps, not policy ones — but on an un-isolated
		// executor the remedy is identical to the policy case ("bind this
		// project to a sandbox"), and it is the remedy, not the taxonomy, that
		// the person reading the 409 needs. An isolated executor that merely
		// lacks the capability gets the constraint-specific error instead,
		// because there "use a sandbox" would be advice it has already taken.
		if !isolatesFromHost(ex) {
			return hostDenied(ex, projectPath)
		}
	}
	return &PlacementError{
		Constraint: rej.Constraint,
		Rejections: []Rejection{rej},
		Considered: 1,
	}
}

// hostDenied builds the shared "run this somewhere else" error, complete with
// the currently-registered isolated executors to name as alternatives.
func hostDenied(ex Executor, projectPath string) *HostExecutionDeniedError {
	return &HostExecutionDeniedError{
		ExecutorID:   ex.ID(),
		ProjectPath:  projectPath,
		Alternatives: DefaultRegistry.IsolatedIDs(),
	}
}

// reject evaluates one candidate against req, returning the first unsatisfied
// constraint. Order matters for the quality of the message: health and policy
// are checked first because "the node is down" or "policy forbids it" explains
// a rejection better than "it lacks the claude harness", even when both are
// true.
func reject(c Candidate, req Requirements) (Rejection, bool) {
	id := c.ID()
	no := func(k Constraint, format string, args ...any) (Rejection, bool) {
		return Rejection{ExecutorID: id, Constraint: k, Detail: fmt.Sprintf(format, args...)}, true
	}

	if req.ExecutorID != "" && id != req.ExecutorID {
		return no(ConstraintExecutorID, "is not the pinned executor %q", req.ExecutorID)
	}

	health := c.Health.Normalize()
	if !health.State.Schedulable() {
		return no(ConstraintHealth, "is %s", health.State)
	}
	if req.ForbidDegraded && health.State == NodeDegraded {
		return no(ConstraintHealth, "is degraded and degraded placement is forbidden")
	}

	caps := c.Executor.Capabilities()

	// The process-wide no-host-execution switch is enforced here as well as in
	// Resolve. Placement is a second entry point into "start a workload", and
	// a security control with one enforcement point is a security control with
	// a bypass.
	if !HostExecutionAllowed() && caps.Isolation == IsolationNone {
		return no(ConstraintHostPolicy, "runs on the control-plane host, which policy forbids")
	}
	if req.RequireIsolation && caps.Isolation == IsolationNone {
		return no(ConstraintIsolation, "offers no isolation from the host")
	}
	if len(req.AllowedIsolations) > 0 && !containsIsolation(req.AllowedIsolations, caps.Isolation) {
		return no(ConstraintIsolation, "has isolation %q, want one of %s",
			caps.Isolation, joinIsolations(req.AllowedIsolations))
	}

	for k, want := range req.Labels {
		got, ok := c.Labels[k]
		if !ok {
			return no(ConstraintLabels, "has no label %q", k)
		}
		if got != want {
			return no(ConstraintLabels, "has label %s=%q, want %q", k, got, want)
		}
	}

	if req.Platform != "" && caps.Platform != "" && !strings.EqualFold(caps.Platform, req.Platform) {
		return no(ConstraintPlatform, "is %s, want %s", caps.Platform, req.Platform)
	}
	if req.Arch != "" && caps.Arch != "" && !strings.EqualFold(caps.Arch, req.Arch) {
		return no(ConstraintArch, "is %s, want %s", caps.Arch, req.Arch)
	}

	for _, h := range req.Harnesses {
		if !hasHarness(c.Harnesses, h) {
			return no(ConstraintHarness, "does not advertise the %s harness", h)
		}
	}
	if req.RequireContainerRuntime && len(c.ContainerRuntimes) == 0 {
		return no(ConstraintContainerRuntime, "advertises no container runtime")
	}
	if req.RequireNetworkEgress && !caps.NetworkEgress {
		return no(ConstraintNetworkEgress, "has no network egress")
	}
	if req.RequireResourceLimits && !caps.SupportsResourceLimits {
		return no(ConstraintResourceLimits, "does not enforce resource limits")
	}
	if req.RequireImageOverride && !caps.SupportsImageOverride {
		return no(ConstraintImageOverride, "cannot run a per-project sandbox image "+
			"(.cloop/sandbox.yaml sets image:)")
	}
	if req.RequireSandboxBuild && !caps.SupportsSandboxBuild {
		return no(ConstraintSandboxBuild, "cannot build a sandbox image "+
			"(.cloop/sandbox.yaml sets setup:); pre-build it and reference it as image: instead")
	}
	if req.RequireSandboxMounts && !caps.SupportsSandboxMounts {
		return no(ConstraintSandboxMounts, "cannot apply per-project mounts "+
			"(.cloop/sandbox.yaml sets mounts:)")
	}
	if req.RequireWorkspaceProvisioning && !caps.SupportsWorkspaceProvisioning {
		return no(ConstraintWorkspace, "cannot materialise a source tree, so the harness "+
			"would run against an empty directory")
	}
	if req.RequireHostFilesystemWorkspace && !caps.SharesHostFilesystem {
		return no(ConstraintWorkspace, "does not share the control-plane filesystem, so "+
			"a bind workspace would be an empty directory there")
	}
	if req.RequireWriteBack && !caps.SupportsWriteBack {
		return no(ConstraintWriteBack, "cannot return the files a task changes, so the work "+
			"would be discarded with the sandbox when the run ends")
	}
	if req.RequireStream && !caps.SupportsStream {
		return no(ConstraintStream, "cannot stream output")
	}
	if req.RequireSignal && !caps.SupportsSignal {
		return no(ConstraintSignal, "cannot signal workloads")
	}
	if req.MinMemoryMB > 0 && c.MemoryMB > 0 && c.MemoryMB < req.MinMemoryMB {
		return no(ConstraintMemory, "has %d MB, want >= %d MB", c.MemoryMB, req.MinMemoryMB)
	}
	if !req.IgnoreCapacity && caps.MaxConcurrent > 0 && c.InFlightKnown && c.InFlight >= caps.MaxConcurrent {
		return no(ConstraintCapacity, "is at capacity (%d/%d)", c.InFlight, caps.MaxConcurrent)
	}
	return Rejection{}, false
}

// headlineConstraint picks the constraint to blame when everything was
// rejected: the one that eliminated the most candidates, with the constraint
// name as a deterministic tiebreak.
func headlineConstraint(rejections []Rejection) Constraint {
	if len(rejections) == 0 {
		return ConstraintNoCandidates
	}
	counts := make(map[Constraint]int, len(rejections))
	for _, r := range rejections {
		counts[r.Constraint]++
	}
	best, bestN := rejections[0].Constraint, 0
	for k, n := range counts {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

// lessCandidate implements the ranking documented on Select.
func lessCandidate(a, b Candidate) bool {
	aReady := a.Health.Normalize().State == NodeReady
	bReady := b.Health.Normalize().State == NodeReady
	if aReady != bReady {
		return aReady
	}
	if af, bf := freeSlots(a), freeSlots(b); af != bf {
		return af > bf
	}
	aIso := a.Executor.Capabilities().Isolation != IsolationNone
	bIso := b.Executor.Capabilities().Isolation != IsolationNone
	if aIso != bIso {
		return aIso
	}
	return a.ID() < b.ID()
}

// freeSlots reports remaining capacity for ranking. Unknown load and unbounded
// capacity both sort as "plenty" rather than as zero, so a driver that cannot
// enumerate is not permanently starved by one that can.
func freeSlots(c Candidate) int {
	const plenty = 1 << 30
	caps := c.Executor.Capabilities()
	if caps.MaxConcurrent <= 0 || !c.InFlightKnown {
		return plenty
	}
	if free := caps.MaxConcurrent - c.InFlight; free > 0 {
		return free
	}
	return 0
}

// hasHarness reports whether the node advertises a harness.
//
// A node that advertises *no* harnesses at all satisfies any harness
// requirement. That is not laxity: capability detection is best-effort (see
// pkg/executor/agent/capabilities.go, where every probe degrades to empty), and
// treating "we could not detect anything" as "it has nothing" would make an
// agent on an unusual filesystem layout permanently unschedulable. A node that
// reports a non-empty list is taken at its word.
func hasHarness(advertised []string, want string) bool {
	if len(advertised) == 0 {
		return true
	}
	for _, h := range advertised {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}

func containsIsolation(set []Isolation, want Isolation) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

func joinIsolations(set []Isolation) string {
	parts := make([]string, 0, len(set))
	for _, s := range set {
		parts = append(parts, string(s))
	}
	return strings.Join(parts, ", ")
}
