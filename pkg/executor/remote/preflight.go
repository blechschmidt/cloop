package remote

// preflight.go answers "will a workload dispatched to this device actually
// run?" before one is.
//
// Every other executor kind had this and the remote one did not, which is
// backwards: it is the only kind where the machine being asked about is not the
// machine running the check. `cloop executor test <id>` fell through to "this
// executor has no preflight" and went straight to a smoke test, so the two
// conditions that stop a Kata sandbox — no /dev/kvm, an agent too old to be
// asked — were discoverable only by dispatching real work and reading the
// failure. For the KVM case that failure is a ~50s QMP socket timeout raised by
// the shim on the device, which names neither KVM nor this executor.
//
// The findings deliberately mirror the container driver's preflight in shape
// and vocabulary (Finding, LevelOK/Warn/Fail, a Fix on everything that is not
// OK) so `cloop executor test` renders all three kinds through one printer and
// an operator reads one checklist regardless of where the work lands.

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Preflight levels, matching the container driver's vocabulary.
const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelFail = "fail"
)

// Finding is one preflight check's result.
type Finding struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// PreflightReport is the result of checking a remote executor.
type PreflightReport struct {
	ExecutorID string    `json:"executor_id"`
	Findings   []Finding `json:"findings"`
}

// OK reports whether nothing fatal was found. Warnings do not fail a report:
// they describe a working deployment an operator may want to change.
func (r PreflightReport) OK() bool {
	for _, f := range r.Findings {
		if f.Level == LevelFail {
			return false
		}
	}
	return true
}

// Err summarises the fatal findings, or nil when there are none.
func (r PreflightReport) Err() error {
	for _, f := range r.Findings {
		if f.Level == LevelFail {
			return fmt.Errorf("remote executor %s: %s: %s", r.ExecutorID, f.Name, f.Message)
		}
	}
	return nil
}

// Preflight checks the device behind this executor against the sandbox the
// admin configured for it.
//
// It asks only what the wire can already answer — the live session's protocol
// version and the capabilities the agent reported at hello — so it costs no
// round trip and cannot hang on an unresponsive device. That is also its limit:
// a finding here describes what the device said when it connected, so an
// operator who has just enabled nested virtualization must reconnect the agent
// before this says so.
func (e *Executor) Preflight() PreflightReport {
	report := PreflightReport{ExecutorID: e.id}
	add := func(name, level, msg, fix string) {
		report.Findings = append(report.Findings, Finding{name, level, msg, fix})
	}

	sess := e.currentSession()
	if sess == nil {
		add("agent", LevelFail,
			fmt.Sprintf("no agent is connected for %s (%s), so nothing can be dispatched here", e.id, e.name),
			"start the agent on the device (`systemctl start cloop-executor`) and check it can "+
				"reach this hub; `cloop executor list` shows the last time it was seen")
		return report
	}
	caps := e.AgentCapabilities()
	add("agent", LevelOK,
		fmt.Sprintf("connected, protocol v%d, %s/%s, %d CPU(s)", sess.Version(), caps.OS, caps.Arch, caps.CPUs), "")

	// What the admin asked for. An unreadable configuration is the same fatal
	// condition here as it is in Start, and for the same reason: nobody can say
	// what containment this executor is supposed to provide.
	sandbox, err := e.opts.sandboxSettings()
	if err != nil {
		add("sandbox", LevelFail,
			fmt.Sprintf("cannot read this executor's sandbox configuration: %v", err),
			"check the hub's state database is writable; dispatch refuses while this is unreadable")
		return report
	}
	add("sandbox", LevelOK, sandbox.Describe(), "")

	if sandbox.Mode == executor.SandboxModeContainer && !SupportsSandboxMode(sess.Version()) {
		add("sandbox-mode", LevelFail,
			fmt.Sprintf("device speaks protocol v%d but container mode needs v%d, so payloads would "+
				"run on the device's host", sess.Version(), MinSandboxModeVersion),
			"upgrade the agent with `cloop executor agent install --upgrade`, or set this "+
				"executor's sandbox mode back to host")
	}

	e.preflightVirtualization(sandbox, sess.Version(), add)
	return report
}

// preflightVirtualization reports whether the device can honour a
// hypervisor-backed sandbox, and is the reason this file exists.
func (e *Executor) preflightVirtualization(sandbox executor.SandboxSettings, version int, add func(name, level, msg, fix string)) {
	// gVisor first: it is kernel isolation without a hypervisor, so asking
	// about /dev/kvm below would be noise, and an operator who typed a name
	// cloop did not recognise needs to hear that rather than nothing.
	if sandbox.IsKernelIsolated() && !sandbox.IsVirtualized() {
		add("gvisor", LevelOK,
			fmt.Sprintf("%q is recognised as gVisor: workload syscalls are served by the Sentry "+
				"rather than the device's kernel, and no hypervisor is required", sandbox.Runtime), "")
		return
	}
	if !sandbox.IsVirtualized() {
		return
	}

	// A Kata runtime is configured. Whether the device can honour it is the
	// question, and below v9 the device was never asked — so say that, rather
	// than passing the check silently and leaving the operator to find out by
	// dispatching.
	if !SupportsVirtualizationProbe(version) {
		add("virtualization", LevelWarn,
			fmt.Sprintf("device speaks protocol v%d, which predates the virtualization probe (v%d), "+
				"so cloop cannot tell whether it can start a VM under %q",
				version, MinVirtualizationProbeVersion, sandbox.Runtime),
			"upgrade the agent with `cloop executor agent install --upgrade` to have the device "+
				"report whether "+agentKVMDevice+" is usable")
		return
	}
	if !e.AgentCapabilities().Virtualization {
		add("virtualization", LevelFail,
			fmt.Sprintf("device reports no usable %s, so %q cannot start a VM there; dispatch to "+
				"this executor is refused", agentKVMDevice, sandbox.Runtime),
			"enable nested virtualization on the hypervisor hosting this device (GCP: "+
				"--enable-nested-virtualization; AWS: a metal instance type) and reconnect the "+
				"agent, or set this executor's sandbox runtime to runsc for gVisor's userspace "+
				"kernel, or leave it unset for a plain container")
		return
	}
	add("virtualization", LevelOK,
		fmt.Sprintf("device reports %s is usable; %q payloads run in a VM with their own kernel",
			agentKVMDevice, sandbox.Runtime), "")
}
