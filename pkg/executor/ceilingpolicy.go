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

// ProjectResourceCeiling returns the ceiling recorded for projectPath.
func ProjectResourceCeiling(projectPath string) (ResourceCeiling, bool) {
	p := projectCeilingLookup.Load()
	if p == nil || projectPath == "" {
		return ResourceCeiling{}, false
	}
	return (*p)(projectPath)
}

// CeilingFor returns the single ceiling in force for projectPath: the fleet's
// and the project's, tightened together.
//
// This is what a driver calls. The drivers need it because they, not this
// package, hold the last word on what a workload is given — see BoundSpec for
// why the ceiling cannot simply be written onto the Spec ahead of them.
func CeilingFor(projectPath string) ResourceCeiling {
	ceiling := FleetResourceCeiling()
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
func BoundSpec(spec *Spec, projectPath string) []Clamp {
	if spec == nil {
		return nil
	}
	ceiling := CeilingFor(projectPath)
	if ceiling.IsZero() {
		return nil
	}
	var clamps []Clamp

	// Fleet first, so that when both ceilings would clamp to the same number
	// the reported source is the hub-wide one. Of two true answers, "your hub
	// caps this" is the more useful to the person who has to go and ask.
	if fleet := FleetResourceCeiling(); !fleet.IsZero() {
		var c []Clamp
		spec.ResourceLimits, c = fleet.applyStated(spec.ResourceLimits, CeilingSourceFleet)
		clamps = append(clamps, c...)
	}
	if project, ok := ProjectResourceCeiling(projectPath); ok && !project.IsZero() {
		var c []Clamp
		spec.ResourceLimits, c = project.applyStated(spec.ResourceLimits, CeilingSourceProject)
		clamps = append(clamps, c...)
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

// CeilingUnenforceable reports that a ceiling bounded this spec but ex cannot
// hold it to the result.
//
// Remote agents advertise SupportsResourceLimits false — they report the
// device's capacity for placement and do not confine a workload to a share of
// it — so a spec dispatched to one carries limits nothing will apply. That is a
// pre-existing property of the driver, not something a ceiling introduces, but
// it changes what an operator is entitled to believe: having set a cap, they
// will assume it holds everywhere. It does not, and this is what lets the
// caller say so rather than leave them to assume.
func CeilingUnenforceable(ex Executor, clamps []Clamp) bool {
	return len(clamps) > 0 && ex != nil && !ex.Capabilities().SupportsResourceLimits
}
