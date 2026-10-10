package remote

// disklimit.go carries a workload's disk limit to a device (Task 20405).
//
// The device's container driver holds a workload to ResourceLimits.DiskMB the
// way the hub's does — by sampling its workspace — from protocol v20; before
// that it refused any disk limit outright. And it reads no ceiling of its own:
// the fleet's, the device's and the project's live in the hub's database. So
// the hub decides here what the device is asked to hold, and refuses what it
// cannot.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// checkDiskLimit refuses a stated disk limit the device cannot hold: one bound
// for a device that runs payloads on its host, or for an agent too old to
// enforce one. Placement refuses both first (RequireDiskLimit); this is the
// backstop for a dispatch that did not ask it.
func (e *Executor) checkDiskLimit(sess *Session, spec executor.Spec, sandbox executor.SandboxSettings) error {
	mb := spec.ResourceLimits.DiskMB
	if mb <= 0 {
		return nil
	}
	limit := executor.FormatMB(mb) + " (" +
		executor.DiskLimitSourcePhrase(executor.DiskLimitSourceOf(spec, mb, executor.ResourceCeiling{})) + ")"
	if !sandbox.RunsProjectImages() {
		return fmt.Errorf("%w: %s runs payloads on the device's host, which bounds no disk use, and this "+
			"workload carries a disk limit of %s; set the executor's sandbox mode to container in the "+
			"Executors panel, or drop resources.disk from .cloop/sandbox.yaml",
			executor.ErrUnsupported, e.subject(), limit)
	}
	if !SupportsDiskLimit(sess.Version()) {
		return fmt.Errorf("%w: %s", executor.ErrUnsupported, executor.NeedsProtocol(
			e.subject(), sess.Version(), MinDiskLimitVersion,
			"to hold this workload to its disk limit of "+limit,
			"Or drop resources.disk from .cloop/sandbox.yaml."))
	}
	return nil
}

// fillCeiling fills a workload's unset limits from the ceiling in force for
// the executor it is dispatched as — the device, or one of its virtual
// executors — and reports whether the ceiling decided its disk limit.
//
// The device-side container driver has no ceiling lookup of its own, so a
// limit the project did not ask for would otherwise be no limit at all on the
// device. The hub has already lowered every limit the project *did* ask for
// (executor.BoundSpec); this supplies the rest, as the hub's own container
// driver does for itself. disk says whether the device will hold a disk
// limit: one it would refuse is left out, and the hub reports the ceiling as
// unenforced there instead (executor.CeilingUnenforceable).
func fillCeiling(rl executor.ResourceLimits, c executor.ResourceCeiling, disk bool) (executor.ResourceLimits, bool) {
	rl.CPUMillis = executor.BoundLimit(rl.CPUMillis, c.CPUMillis)
	rl.MemoryMB = executor.BoundLimit(rl.MemoryMB, c.MemoryMB)
	rl.PIDs = executor.BoundLimit(rl.PIDs, c.PIDs)
	if !disk || c.DiskMB <= 0 {
		return rl, false
	}
	filled := rl.DiskMB <= 0 || rl.DiskMB > c.DiskMB
	rl.DiskMB = executor.BoundLimit(rl.DiskMB, c.DiskMB)
	return rl, filled
}

// applyDeviceCeiling fills spec's unset limits from the ceiling in force for
// the executor it is dispatched as, when the device runs it in a container —
// a payload on the device's host is bounded by nothing a limit could set.
func (e *Executor) applyDeviceCeiling(spec *executor.Spec, sess *Session, sandbox executor.SandboxSettings,
	virtual *VirtualDispatch) {
	if !sandbox.RunsProjectImages() {
		return
	}
	id := e.id
	if virtual != nil {
		id = virtual.ID
	}
	var fromCeiling bool
	spec.ResourceLimits, fromCeiling = fillCeiling(spec.ResourceLimits,
		executor.CeilingFor(projectOf(*spec), id), SupportsDiskLimit(sess.Version()))
	if fromCeiling {
		executor.MarkDiskLimitFromCeiling(spec)
	}
}

// ExplainDiskLimitRefusal implements executor.DiskLimitExplainer.
func (e *Executor) ExplainDiskLimitRefusal() string {
	sandbox, err := e.opts.sandboxSettings()
	return e.explainDiskLimit(sandbox, err)
}

// explainDiskLimit says why a device under these sandbox settings cannot hold
// a workload to a disk limit.
func (e *Executor) explainDiskLimit(sandbox executor.SandboxSettings, sandboxErr error) string {
	if sandboxErr == nil && !sandbox.RunsProjectImages() {
		return "it runs payloads on the device's host, which bounds no disk use; set its sandbox mode " +
			"to container in the Executors panel, or bind the project to a container or Kubernetes executor"
	}
	if v := e.ProtocolVersion(); v > 0 && !SupportsDiskLimit(v) {
		return executor.NeedsProtocol(e.subject(), v, MinDiskLimitVersion,
			"to hold a workload to a disk limit", "")
	}
	return ""
}

// ExplainDiskLimitRefusal implements executor.DiskLimitExplainer for a virtual
// executor: its parent's reasons, under its own sandbox settings.
func (v *Virtual) ExplainDiskLimitRefusal() string {
	spec, err := v.Spec()
	if err != nil {
		return v.parent.explainDiskLimit(executor.SandboxSettings{}, err)
	}
	return v.parent.explainDiskLimit(spec.Sandbox, nil)
}
