// ceilingpolicy.go holds the fleet-wide resource ceiling for the process.
//
// It is the same shape as the min-agent-build switch in agentbuild.go, and for
// the same reason. A control plane reads many projects' config.yaml — every
// project it serves has one, and each is a file inside a repository that the
// project's own developers control. Installing those settings symmetrically
// would let one tenant's file raise a cap that applies to every other tenant in
// the process, which is not a configuration mistake but a privilege escalation
// with a YAML interface.
//
// So the switch only ever tightens. Loosening a fleet ceiling means restarting
// with the looser config: deliberate, explicit, and performed by whoever
// controls the hub rather than by whoever controls a repository.
package executor

import "sync/atomic"

// fleetCeiling is the ceiling in force for this process. A nil pointer means no
// ceiling has been installed, which is distinct from a zero ceiling only in
// intent — both bound nothing — and is kept distinct so a future reader of the
// switch can tell "never configured" from "configured to cap nothing".
var fleetCeiling atomic.Pointer[ResourceCeiling]

// FleetResourceCeiling returns the ceiling in force, or the zero ceiling if
// none was installed.
func FleetResourceCeiling() ResourceCeiling {
	if p := fleetCeiling.Load(); p != nil {
		return *p
	}
	return ResourceCeiling{}
}

// ApplyResourceCeiling installs c as a ratchet: the result is the tighter of
// what was already in force and what c asks for, resource by resource.
//
// This is what every bootstrap path should call. A ceiling naming a looser cap
// than the one already installed, or naming none at all, leaves the switch
// alone — so the order in which a hub happens to read its projects' config
// files cannot change the policy it ends up enforcing.
//
// An invalid ceiling is ignored rather than installed. The safe reading of "I
// cannot understand this rule" is not "refuse every workload on the fleet",
// which would turn a typo into an outage; config.ValidateExecutorLimits rejects
// one arriving through `cloop config set`, and config.ExecutorLimitWarnings
// surfaces a hand-edited one as a banner saying no ceiling is being enforced —
// the fact an operator must not be left to assume the other way round.
func ApplyResourceCeiling(c ResourceCeiling) {
	if c.IsZero() || c.Validate() != nil {
		return
	}
	for {
		old := fleetCeiling.Load()
		next := c
		if old != nil {
			next = old.Tighten(c)
			if next == *old {
				return
			}
		}
		if fleetCeiling.CompareAndSwap(old, &next) {
			return
		}
	}
}

// ResetResourceCeiling clears the switch. It exists for tests, which would
// otherwise leak a ceiling from one case into the next through process state —
// and because the ratchet means a test cannot undo itself by installing a
// looser value, which is exactly the property being tested.
func ResetResourceCeiling() {
	fleetCeiling.Store(nil)
	projectCeilingLookup.Store(nil)
	executorCeilingLookup.Store(nil)
}

// projectCeilingLookup resolves a project's own ceiling.
//
// A hook rather than a direct read, for the reason SetBindingLookup is one: the
// ceiling lives in the control plane's SQLite database, and this package cannot
// import pkg/statedb without a cycle. The control plane installs the lookup at
// startup; a process that never installs one — the CLI, a test — sees fleet
// ceilings only, which is correct, because a per-project ceiling it cannot read
// is not one it should guess at.
var projectCeilingLookup atomic.Pointer[func(projectPath string) (ResourceCeiling, bool)]

// SetProjectCeilingLookup installs the per-project ceiling resolver.
func SetProjectCeilingLookup(fn func(projectPath string) (ResourceCeiling, bool)) {
	if fn == nil {
		projectCeilingLookup.Store(nil)
		return
	}
	projectCeilingLookup.Store(&fn)
}

// ProjectResourceCeiling returns the ceiling recorded for projectPath — for a
// feature worktree, its parent project's (see PolicyProjectPath).
func ProjectResourceCeiling(projectPath string) (ResourceCeiling, bool) {
	p := projectCeilingLookup.Load()
	if p == nil || projectPath == "" {
		return ResourceCeiling{}, false
	}
	return (*p)(PolicyProjectPath(projectPath))
}

// executorCeilingLookup resolves one executor's own ceiling.
//
// The same hook shape as projectCeilingLookup, installed by the control plane
// for the same reason: the row lives in SQLite, which this package cannot
// import. A process that never installs one sees fleet ceilings only.
var executorCeilingLookup atomic.Pointer[func(executorID string) (ResourceCeiling, bool)]

// SetExecutorCeilingLookup installs the per-executor ceiling resolver.
func SetExecutorCeilingLookup(fn func(executorID string) (ResourceCeiling, bool)) {
	if fn == nil {
		executorCeilingLookup.Store(nil)
		return
	}
	executorCeilingLookup.Store(&fn)
}

// ExecutorResourceCeiling returns the ceiling recorded for executorID.
func ExecutorResourceCeiling(executorID string) (ResourceCeiling, bool) {
	p := executorCeilingLookup.Load()
	if p == nil || executorID == "" {
		return ResourceCeiling{}, false
	}
	return (*p)(executorID)
}

// CeilingFor returns the single ceiling in force for a workload: the fleet's,
// the executor's and the project's, tightened together.
//
// This is what a driver calls, passing its own ID as executorID. The drivers
// need it because they, not this package, hold the last word on what a workload
// is given — see BoundSpec for why the ceiling cannot simply be written onto
// the Spec ahead of them.
//
// An empty executorID asks only the fleet and the project. That is the honest
// answer for a caller that does not know where the workload will land, and it
// errs in the safe direction: a ceiling this function did not apply is one the
// driver still applies for itself, because the driver always knows its own ID.
func CeilingFor(projectPath, executorID string) ResourceCeiling {
	ceiling := FleetResourceCeiling()
	if ex, ok := ExecutorResourceCeiling(executorID); ok {
		ceiling = ceiling.Tighten(ex)
	}
	if project, ok := ProjectResourceCeiling(projectPath); ok {
		ceiling = ceiling.Tighten(project)
	}
	return ceiling
}

// BoundLimit returns the limit a driver should apply for one resource.
//
// effective is what the driver resolved on its own — the Spec's request if it
// made one, otherwise the executor's configured default. cap is the ceiling; 0
// means there is none.
//
// The two zero cases are different and both matter. A cap of 0 is no ceiling,
// so effective stands. An *effective* of 0 is "nothing has bounded this yet",
// which is the case a ceiling exists for: a project that requested nothing on an
// executor configured with no default would otherwise run unbounded.
func BoundLimit(effective, cap int) int {
	switch {
	case cap <= 0:
		return effective
	case effective <= 0 || effective > cap:
		return cap
	}
	return effective
}

// BoundCPUs is BoundLimit for a core allowance, whose units are the runtimes'
// fractional cores rather than milli-cores.
func BoundCPUs(effective float64, capMillis int) float64 {
	if capMillis <= 0 {
		return effective
	}
	capCores := float64(capMillis) / 1000.0
	if effective <= 0 || effective > capCores {
		return capCores
	}
	return effective
}

// BoundSpec lowers spec's *stated* resource requests to the ceilings in force
// for projectPath, and bounds the workspace fetch. It returns what it changed.
//
// Every dispatch site calls it, and it lives here rather than beside any one of
// them because there are five: the Web UI's detached and synchronous paths, the
// failover supervisor, the reproduction runner and the REST API.
//
// # Why this does not fill in an unstated request
//
// It is tempting to write the ceiling into a limit the project left at zero —
// zero means *no limit*, so leaving it alone looks like leaving the hole open.
// Doing that is wrong, and subtly so: it converts "this project stated nothing"
// into "this project explicitly requests the ceiling", and the drivers resolve
// a stated request as *more specific* than the executor's configured default.
// A hub with `executors.container.memory: 4g` under an 8 GB fleet ceiling would
// then give an unconfigured project 8 GB — the ceiling would have *raised* the
// limit, which is the one thing a ceiling may never do.
//
// So the unstated case is closed one layer down, by the driver, which applies
// BoundLimit after it has resolved the request against its own default. This
// function handles what the driver cannot see: a stated request, which it
// lowers here so that the Spec persisted for failover, recorded in the
// provenance file and shown in the audit trail is the one that actually ran.
//
// It never fails. A ceiling is a bound, not an admission decision: the outcome
// of asking for too much is a smaller sandbox, not a refused run.
func BoundSpec(spec *Spec, projectPath, executorID string) []Clamp {
	if spec == nil {
		return nil
	}
	ceiling := CeilingFor(projectPath, executorID)
	if ceiling.IsZero() {
		return nil
	}
	var clamps []Clamp

	// Fleet first, then executor, then project: widest scope to narrowest, so
	// that when two ceilings would clamp to the same number the reported source
	// is the one that binds the most other workloads too. Of several true
	// answers, "your hub caps this" is more useful than "this machine does" to
	// the person who has to go and ask — and both are more useful than the
	// project's own cap, which the asker may well have set themselves.
	if fleet := FleetResourceCeiling(); !fleet.IsZero() {
		var c []Clamp
		spec.ResourceLimits, c = fleet.applyStated(spec.ResourceLimits, CeilingSourceFleet)
		clamps = append(clamps, c...)
	}
	if ex, ok := ExecutorResourceCeiling(executorID); ok && !ex.IsZero() {
		var c []Clamp
		spec.ResourceLimits, c = ex.applyStated(spec.ResourceLimits, CeilingSourceExecutor)
		clamps = append(clamps, c...)
	}
	if project, ok := ProjectResourceCeiling(projectPath); ok && !project.IsZero() {
		var c []Clamp
		spec.ResourceLimits, c = project.applyStated(spec.ResourceLimits, CeilingSourceProject)
		clamps = append(clamps, c...)
	}
	// A disk request a ceiling lowered is the ceiling's limit now, and the
	// driver that stops the workload at it has to say whom to ask for more.
	for _, c := range clamps {
		if c.Resource == "disk" {
			MarkDiskLimitFromCeiling(spec)
			break
		}
	}

	// The workspace fetch is the one limit no driver applies, because it is
	// enforced before the workload starts: the provisioner measures the tree it
	// cloned and refuses a run that would exceed its allowance. So it is bound
	// here, and from the *effective* disk ceiling rather than only from a stated
	// request — an unstated one still has a ceiling, and a project able to clone
	// a repository larger than its own cap fails mid-run on a message about the
	// repository rather than about the limit.
	if size := BoundLimit(spec.ResourceLimits.DiskMB, ceiling.DiskMB); size > 0 {
		if spec.Workspace.SizeLimitMB == 0 || spec.Workspace.SizeLimitMB > size {
			spec.Workspace.SizeLimitMB = size
		}
	}
	return clamps
}

// CeilingUnenforceable reports that a ceiling in force for this workload binds
// something ex will not hold it to.
//
// Two ways, and they differ in what triggers them. A driver that enforces no
// limits at all — the host-process driver, a remote agent running payloads on
// its host — carries whatever a ceiling lowered on the spec and applies none
// of it; that is reported when a ceiling actually lowered something (clamps).
// A disk ceiling is reported whenever one is in force on a driver that does
// not bound disk (Task 20405), clamp or no clamp: the ceiling exists for the
// workload that asked for nothing, which is the one no clamp is ever recorded
// for — and before this an executor capped at 20 GB was capped at nothing and
// told nothing.
//
// It changes nothing about the run. Having set a cap, an operator will assume
// it holds everywhere; this is what lets the caller say where it does not.
func CeilingUnenforceable(ex Executor, ceiling ResourceCeiling, clamps []Clamp) bool {
	if ex == nil {
		return false
	}
	caps := ex.Capabilities()
	if len(clamps) > 0 && !caps.SupportsResourceLimits {
		return true
	}
	return DiskCeilingUnenforceable(caps, ceiling)
}

// DiskCeilingUnenforceable reports a disk ceiling in force on a driver that
// does not bound disk.
func DiskCeilingUnenforceable(caps Capabilities, ceiling ResourceCeiling) bool {
	return ceiling.DiskMB > 0 && !caps.DiskEnforcement.Enforced()
}
