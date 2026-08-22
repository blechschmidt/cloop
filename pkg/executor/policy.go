package executor

// policy.go implements strict no-host-execution mode (Task 20160).
//
// The project goal this serves is blunt: "the web UI will never directly spawn
// a harness/agent on the host". The localprocess driver exists anyway, because
// a single-machine `cloop ui` on a laptop is the overwhelmingly common case and
// should need no configuration. So the guarantee cannot come from *not having*
// a host driver; it has to come from a policy that turns the host driver off.
//
// The policy is process-global rather than per-Registry on purpose. It is a
// deployment property ("this control plane is not allowed to run agent code
// next to itself"), not a property of one registry instance, and a driver
// asked to Start must be able to honour it without knowing which registry it
// was resolved through. Two enforcement points share this one flag:
//
//   - Registry.Resolve, which produces the actionable error the UI turns into
//     a 409 (it is the only place that knows the project path and which
//     isolated executors exist), and
//   - the driver's own Start, which is the backstop for a caller holding a
//     direct *localprocess.Executor reference and never going through Resolve.
//
// Default is permissive, matching config's `executors.allow_host_process:
// true` default. Flipping it is the one switch an enterprise deployment must
// throw, and the UI surfaces the resulting mode as a banner so nobody has to
// guess which side of the boundary they are on.

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// allowHostExecution is the process-wide switch. It starts permissive so a
// binary that never touches the policy behaves exactly as it did before this
// file existed.
var allowHostExecution = func() *atomic.Bool {
	b := new(atomic.Bool)
	b.Store(true)
	return b
}()

// SetAllowHostExecution sets whether workloads may run on the control-plane
// host with no isolation boundary (the localprocess driver).
//
// It returns the previous value so callers — tests especially — can restore it
// without keeping a separate copy.
func SetAllowHostExecution(allowed bool) bool {
	return allowHostExecution.Swap(allowed)
}

// HostExecutionAllowed reports whether un-isolated host execution is permitted.
func HostExecutionAllowed() bool { return allowHostExecution.Load() }

// ApplyHostExecutionPolicy installs a configured policy as a ratchet: it can
// only ever tighten. A config that permits host execution leaves the switch
// alone; only a config that forbids it moves the switch.
//
// This is what every bootstrap path should call. SetAllowHostExecution is the
// raw switch, and outside of tests, calling it with true is almost always a
// bug — the asymmetry exists because the two directions are not symmetric in
// consequence:
//
//   - A control plane manages many projects, each with its own config.yaml.
//     Applying them symmetrically would mean one tenant's permissive config
//     re-enables host execution for the whole process, which is a privilege
//     escalation by way of a file the tenant controls.
//   - Constructing a second Server (pkg/ui does this per instance, and tests
//     do it constantly) would otherwise silently reset a security control
//     that something earlier had deliberately set.
//
// Loosening is therefore deliberate and explicit: restart the process with a
// permissive config, which is the same ceremony every other security-relevant
// setting requires.
func ApplyHostExecutionPolicy(allowed bool) {
	if allowed {
		return
	}
	allowHostExecution.Store(false)
	// Evict anything that was registered while the switch was still
	// permissive. Bootstrap order is not something a security guarantee can
	// depend on: `cloop ui` registers the host driver from several entry
	// points (Server construction, the first workload, tests building a
	// Server literal), and any one of them running before the config is read
	// would otherwise leave a host driver registered — and therefore
	// eligible to be the registry's default — in a deployment that forbids
	// host execution.
	DefaultRegistry.evictNonIsolating()
}

// evictNonIsolating unregisters every executor that puts no boundary between
// a workload and the control-plane host.
func (r *Registry) evictNonIsolating() {
	for _, ex := range r.List() {
		if !isolatesFromHost(ex) {
			r.Unregister(ex.ID())
		}
	}
}

// HostExecutionDeniedError explains a refusal to run a workload on the host
// and, critically, names what the operator can do instead.
//
// A bare "denied by policy" is the kind of error that generates a support
// ticket: the person who hits it in the UI is usually not the person who wrote
// the config. Carrying the alternatives in the error means the 409 the browser
// receives already contains the remediation, and `cloop run` prints the same
// sentence in a terminal.
type HostExecutionDeniedError struct {
	// ExecutorID is the un-isolated executor that was resolved.
	ExecutorID string
	// ProjectPath is the project whose workload was refused; may be empty
	// for workloads not tied to a project.
	ProjectPath string
	// Alternatives are the IDs of registered executors that *do* isolate,
	// ordered for stable output. Empty means none are configured, which is a
	// materially different (and much more urgent) situation.
	Alternatives []string
}

// Error implements error.
func (e *HostExecutionDeniedError) Error() string {
	var b strings.Builder
	b.WriteString("executor: host execution is disabled by policy (executors.allow_host_process: false)")
	if e.ProjectPath != "" {
		fmt.Fprintf(&b, "; project %q", e.ProjectPath)
	}
	if e.ExecutorID != "" {
		fmt.Fprintf(&b, " resolved to the un-isolated executor %q", e.ExecutorID)
	}
	if len(e.Alternatives) > 0 {
		fmt.Fprintf(&b, ". Bind it to an isolated executor instead — available: %s",
			strings.Join(e.Alternatives, ", "))
		return b.String()
	}
	b.WriteString(". No isolated executor is configured: enable executors.container " +
		"in .cloop/config.yaml, or enroll a remote agent from the Executors tab " +
		"(`cloop executor enroll`)")
	return b.String()
}

// Unwrap lets callers match with errors.Is(err, ErrHostExecutionDenied)
// without caring whether they got the rich form or a plain wrap.
func (e *HostExecutionDeniedError) Unwrap() error { return ErrHostExecutionDenied }

// Remediation returns just the "what to do about it" half of the message, for
// UI surfaces that render the cause and the fix in separate elements.
func (e *HostExecutionDeniedError) Remediation() string {
	if len(e.Alternatives) > 0 {
		return "Bind this project to an isolated executor: " + strings.Join(e.Alternatives, ", ")
	}
	return "No isolated executor is configured. Enable executors.container in " +
		".cloop/config.yaml, or enroll a remote agent from the Executors tab."
}

// isolatesFromHost reports whether ex puts any boundary between the workload
// and the control-plane host.
//
// The check is on Capabilities().Isolation rather than on Kind so a future
// driver gets the right answer by describing itself honestly, rather than by
// being added to a list here that someone has to remember to update.
//
// It allow-lists the known isolating levels rather than denying IsolationNone.
// The difference only shows up for a driver that does not set Isolation at
// all — a new backend mid-development, or a struct built by a caller who did
// not know the field mattered — and there the two spellings disagree in the
// worst possible direction. Denying "none" would treat an undeclared driver
// as isolated and let it run under strict mode; allow-listing treats silence
// as "no boundary claimed", which is the only safe reading of it.
func isolatesFromHost(ex Executor) bool {
	if ex == nil {
		return false
	}
	switch ex.Capabilities().Isolation {
	case IsolationContainer, IsolationVM, IsolationRemote:
		return true
	default:
		return false
	}
}
