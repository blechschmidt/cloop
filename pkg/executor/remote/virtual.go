package remote

// virtual.go is the control-plane half of a virtual executor (Task 20345): a
// sub-executor that dispatches through an enrolled device's session with a
// sandbox configuration of its own.
//
// # What it is, mechanically
//
// A Virtual is registered in the executor registry under its own ID, so
// projects bind to it, placement sees it, and every control keyed by executor
// ID — resource ceilings, the access list — applies to it independently of its
// parent. Everything else is the parent's: the session, the handle map, the
// lease index, the revocation log. A workload started through a Virtual lives
// in the parent's handle map with a note saying which Virtual started it, so
// the device keeps one view of what it is running and a hub restart rehydrates
// it through the parent exactly as before.
//
// # Why the parent keeps revocation
//
// The UI's revocation fan-out walks the registry and asks every executor that
// holds a lease to give it back. If a Virtual answered "I hold it" by
// delegating, the same lease would be revoked twice on the same device — two
// frames, two audit rows, and a revocation log entry reopened after it had
// settled. So a Virtual says it can revoke (placement must know that) and says
// it holds nothing; the parent, which really holds the material, is asked.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// ErrVirtualExecutorUnsupported reports a virtual executor whose firewall or
// device list the device cannot apply.
var ErrVirtualExecutorUnsupported = errors.New("remote: device cannot apply this virtual executor's configuration")

// VirtualSource reads a virtual executor's configuration. A function, consulted
// on every dispatch, for the reason Options.Sandbox is one: an admin edits the
// configuration in the dashboard and the next task must honour it.
type VirtualSource func() (executor.VirtualSpec, error)

// Virtual is a sub-executor of a remote agent.
type Virtual struct {
	id     string
	name   string
	parent *Executor
	source VirtualSource
}

// NewVirtual builds a virtual executor over parent. It does no I/O.
func NewVirtual(parent *Executor, id, name string, source VirtualSource) (*Virtual, error) {
	if parent == nil {
		return nil, fmt.Errorf("%w: virtual executor %q has no parent", executor.ErrInvalidSpec, id)
	}
	if !virtualIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: virtual executor id %q must be 3-63 characters of [a-z0-9-] "+
			"starting with a letter or digit", executor.ErrInvalidSpec, id)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: virtual executor %q has no configuration source", executor.ErrInvalidSpec, id)
	}
	if strings.TrimSpace(name) == "" {
		name = id
	}
	return &Virtual{id: id, name: name, parent: parent, source: source}, nil
}

// ValidVirtualID reports whether id can name a virtual executor.
func ValidVirtualID(id string) bool { return virtualIDPattern.MatchString(id) }

// ID implements executor.Executor.
func (v *Virtual) ID() string { return v.id }

// Kind implements executor.Executor.
func (v *Virtual) Kind() string { return executor.KindVirtual }

// Name is the operator-facing label.
func (v *Virtual) Name() string { return v.name }

// Parent is the device this virtual executor dispatches through.
func (v *Virtual) Parent() *Executor { return v.parent }

// ParentID is the parent executor's ID.
func (v *Virtual) ParentID() string { return v.parent.ID() }

// Spec reads and normalizes the current configuration.
func (v *Virtual) Spec() (executor.VirtualSpec, error) {
	raw, err := v.source()
	if err != nil {
		return executor.VirtualSpec{}, err
	}
	return raw.Normalize()
}

// Capabilities implements executor.Executor: the parent's, as they would be
// under this virtual executor's sandbox settings, narrowed by what the device
// can apply of its firewall.
//
// Devices are deliberately not advertised. SupportsDevices describes whether a
// project's host_device *grant* can be honoured, and those grants name paths
// with no machine attached to them; this executor's hardware is part of its
// own definition, chosen from its parent's inventory by an admin, and needs no
// grant to reach the sandbox.
func (v *Virtual) Capabilities() executor.Capabilities {
	spec, err := v.Spec()
	if err != nil {
		// The claim that grants the least, as in Executor.Capabilities: an
		// unreadable definition places nothing that requires a boundary, and
		// Start refuses outright.
		caps := v.parent.capabilitiesFor(executor.SandboxSettings{}, err)
		caps.NetworkEgress = false
		return caps
	}
	caps := v.parent.capabilitiesFor(spec.Sandbox, nil)
	caps.SupportsDevices = false
	caps.SupportsInterfaces = false
	caps.NetworkEgress = spec.NetworkEgress()
	caps.FilteredEgress = spec.FilteredEgress() && v.parent.canApply(&VirtualDispatch{ID: v.id, Spec: spec}) == nil
	// A project may narrow this executor's firewall further with an egress
	// scope — the device's container driver does the narrowing — but only
	// where there is a firewall to narrow and a device able to install it.
	caps.SupportsEgressScope = caps.FilteredEgress
	return caps
}

// Start implements executor.Executor.
func (v *Virtual) Start(ctx context.Context, spec executor.Spec) (executor.Handle, error) {
	vs, err := v.Spec()
	if err != nil {
		// Fatal, for the reason an unreadable sandbox row is fatal on the
		// device's own path: "the database was busy" must not decide, in the
		// weaker direction, whether a sandbox gets its firewall.
		return executor.Handle{}, fmt.Errorf("%w: virtual executor %s (%s): %w — refusing to dispatch "+
			"rather than start a sandbox without the configuration an admin gave it",
			ErrSandboxModeUnavailable, v.id, v.name, err)
	}
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	} else {
		labels := make(map[string]string, len(spec.Labels)+1)
		for k, val := range spec.Labels {
			labels[k] = val
		}
		spec.Labels = labels
	}
	spec.Labels["virtual_executor"] = v.id
	spec.ResourceLimits = fillCeiling(spec.ResourceLimits, executor.CeilingFor(projectOf(spec), v.id))

	h, err := v.parent.start(ctx, spec, &VirtualDispatch{ID: v.id, Name: v.name, Spec: vs})
	if err != nil {
		return executor.Handle{}, err
	}
	h.ExecutorID = v.id
	return h, nil
}

// fillCeiling fills a workload's unset limits from this executor's ceiling.
//
// The device-side container driver has no ceiling lookup of its own — the
// ceilings live in the control plane's database — so a limit the project did
// not ask for would otherwise be no limit at all on the device. The hub has
// already lowered every limit the project *did* ask for (executor.BoundSpec);
// this supplies the rest. Disk is left alone: the container driver refuses a
// writable-layer quota it cannot enforce, and the workspace bound is carried
// separately.
func fillCeiling(rl executor.ResourceLimits, c executor.ResourceCeiling) executor.ResourceLimits {
	rl.CPUMillis = executor.BoundLimit(rl.CPUMillis, c.CPUMillis)
	rl.MemoryMB = executor.BoundLimit(rl.MemoryMB, c.MemoryMB)
	rl.PIDs = executor.BoundLimit(rl.PIDs, c.PIDs)
	return rl
}

// Signal implements executor.Executor.
func (v *Virtual) Signal(ctx context.Context, handleID string, sig executor.Signal) error {
	return v.parent.Signal(ctx, handleID, sig)
}

// Status implements executor.Executor.
func (v *Virtual) Status(ctx context.Context, handleID string) (executor.Status, error) {
	st, err := v.parent.Status(ctx, handleID)
	if err == nil {
		st.ExecutorID = v.id
	}
	return st, err
}

// Stream implements executor.Executor.
func (v *Virtual) Stream(ctx context.Context, handleID string) (<-chan executor.LogLine, error) {
	return v.parent.Stream(ctx, handleID)
}

// HealthCheck implements executor.Executor. A virtual executor is exactly as
// reachable as the device under it, plus one thing only it can get wrong: a
// definition that no longer validates.
func (v *Virtual) HealthCheck(ctx context.Context) error {
	if err := v.parent.HealthCheck(ctx); err != nil {
		return err
	}
	vs, err := v.Spec()
	if err != nil {
		return fmt.Errorf("virtual executor %s: %w", v.id, err)
	}
	return v.parent.canApply(&VirtualDispatch{ID: v.id, Name: v.name, Spec: vs})
}

// HandleStatuses implements executor.Lister for the workloads this virtual
// executor started.
func (v *Virtual) HandleStatuses(ctx context.Context) ([]executor.Status, error) {
	return v.parent.handleStatusesFor(ctx, v.id)
}

// Attach implements executor.Attacher through the parent's session.
func (v *Virtual) Attach(ctx context.Context, req executor.AttachRequest) (executor.AttachConn, error) {
	return v.parent.Attach(ctx, req)
}

// WriteBackBundle implements executor.WriteBackFetcher.
func (v *Virtual) WriteBackBundle(handleID string) ([]byte, error) {
	return v.parent.WriteBackBundle(handleID)
}

// ProjectResult implements executor.ProjectResultFetcher.
func (v *Virtual) ProjectResult(handleID string) (executor.ProjectResult, error) {
	return v.parent.ProjectResult(handleID)
}

// AgentVersion implements executor.BuildReporter, so a fleet build floor
// applies to a virtual executor exactly as it applies to its device.
func (v *Virtual) AgentVersion() string { return v.parent.AgentVersion() }

// SupportsRevocation implements executor.Revoker: placement must know that a
// lease put here can be taken back, and it can — by the parent.
func (v *Virtual) SupportsRevocation() bool { return v.parent.SupportsRevocation() }

// HoldsLease implements executor.Revoker. Always false; see the file comment.
func (v *Virtual) HoldsLease(string) bool { return false }

// Leases implements executor.Revoker. Always empty; the parent holds them.
func (v *Virtual) Leases() []string { return nil }

// RevokeLease implements executor.Revoker by reporting "not here": the parent,
// which holds the material, is asked by the fan-out directly.
func (v *Virtual) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{
		ExecutorID: v.id,
		LeaseID:    req.LeaseID,
		State:      executor.RevokeStateRevoked,
	}
}

// Revocations implements executor.Revoker. Empty; the parent's log is the one.
func (v *Virtual) Revocations() []executor.RevokeOutcome { return nil }

// ExplainEgressScopeRefusal implements executor.EgressScopeExplainer.
func (v *Virtual) ExplainEgressScopeRefusal() string {
	vs, err := v.Spec()
	if err == nil && vs.Firewall == nil {
		return "virtual executor " + v.id + " has no firewall to narrow; give it one in the Executors " +
			"panel, or drop capabilities.egress from .cloop/sandbox.yaml"
	}
	if caps := v.parent.AgentCapabilities(); !caps.PacketFilter {
		return "its device cannot install a packet filter (" + packetFilterIssue(caps) + ")"
	}
	return "its device's agent is too old to apply a virtual executor's firewall; upgrade it"
}

// checkVirtual refuses a dispatch the device cannot apply in full. Nil for a
// direct dispatch.
func (e *Executor) checkVirtual(sess *Session, virtual *VirtualDispatch) error {
	if virtual == nil {
		return nil
	}
	if !virtual.needsAgent() {
		return nil
	}
	if !SupportsVirtualExecutor(sess.Version()) {
		return fmt.Errorf("%w: virtual executor %s gives its sandboxes %s, which agent %s (%s) must "+
			"apply itself, but it speaks protocol v%d (needs v%d) and would start the sandbox without "+
			"them; upgrade the agent with `cloop executor agent install --upgrade`",
			ErrVirtualExecutorUnsupported, virtual.ID, describeVirtualNeeds(virtual), e.id, e.name,
			sess.Version(), MinVirtualExecutorVersion)
	}
	return e.canApply(virtual)
}

// canApply reports whether the device, as last advertised, can apply the
// virtual executor's configuration. It needs no session, so the dashboard can
// ask it of an offline device.
func (e *Executor) canApply(virtual *VirtualDispatch) error {
	if virtual == nil || virtual.Spec.Firewall == nil {
		return nil
	}
	caps := e.AgentCapabilities()
	if !caps.PacketFilter {
		return fmt.Errorf("%w: virtual executor %s has a firewall, but device %s (%s) cannot install one "+
			"(%s); grant the agent CAP_NET_ADMIN (see `cloop executor agent install --packet-filter`) "+
			"or remove the firewall — a sandbox is never started unfiltered in its place",
			ErrVirtualExecutorUnsupported, virtual.ID, e.id, e.name, packetFilterIssue(caps))
	}
	return nil
}

// packetFilterIssue is the device's own explanation, or a generic one.
func packetFilterIssue(caps AgentCapabilities) string {
	if s := strings.TrimSpace(caps.PacketFilterIssue); s != "" {
		return s
	}
	return "the agent did not report a packet filter; it may predate protocol v14"
}

// describeVirtualNeeds names what only the device can apply.
func describeVirtualNeeds(v *VirtualDispatch) string {
	var parts []string
	if v.Spec.Firewall != nil {
		parts = append(parts, "a firewall")
	}
	if n := len(v.Spec.Devices); n > 0 {
		parts = append(parts, fmt.Sprintf("%d host device(s)", n))
	}
	return strings.Join(parts, " and ")
}

// virtualIDOf is the handle-state note for a dispatch.
func virtualIDOf(v *VirtualDispatch) string {
	if v == nil {
		return ""
	}
	return v.ID
}

// handleStatusesFor lists the statuses of the workloads one virtual executor
// started, under that executor's ID.
func (e *Executor) handleStatusesFor(ctx context.Context, virtualID string) ([]executor.Status, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	e.mu.RLock()
	states := make([]*handleState, 0, len(e.handles))
	for _, hs := range e.handles {
		if hs.virtualID == virtualID {
			states = append(states, hs)
		}
	}
	e.mu.RUnlock()
	out := make([]executor.Status, 0, len(states))
	for _, hs := range states {
		st := hs.snapshotStatus()
		st.ExecutorID = virtualID
		out = append(out, st)
	}
	return out, nil
}

// The interfaces a virtual executor must satisfy to stand in for its device
// everywhere the device could be used. A missing one would not fail to compile
// at the call site — the callers type-assert — it would silently lose the
// feature: no stop button for attach, no work product for write-back, a build
// floor that never applies.
var (
	_ executor.Executor             = (*Virtual)(nil)
	_ executor.Lister               = (*Virtual)(nil)
	_ executor.Attacher             = (*Virtual)(nil)
	_ executor.WriteBackFetcher     = (*Virtual)(nil)
	_ executor.ProjectResultFetcher = (*Virtual)(nil)
	_ executor.BuildReporter        = (*Virtual)(nil)
	_ executor.Revoker              = (*Virtual)(nil)
	_ executor.EgressScopeExplainer = (*Virtual)(nil)
)
