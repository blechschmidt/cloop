package executor

// isolation.go makes a runtime's isolation claim something placement checks
// against evidence rather than takes on its name (Task 20439).
//
// Capabilities.Virtualized and KernelIsolated come from IsVirtualizedRuntime
// and IsUserspaceKernelRuntime, which read a runtime's name — the only thing
// the OCI and RuntimeClass APIs show a client. A daemon.json alias, or a
// RuntimeClass whose handler is runc, therefore claimed a VM while running its
// workloads on the host kernel, and placement believed it: a project whose
// .cloop/sandbox.yaml demanded a hypervisor ran beside the host's kernel with
// nothing on record to say so.
//
// The claim is now checked. Each executor whose payloads run under a runtime
// runs pkg/isolationprobe's probe under it — at reconcile, at a device's hello,
// after its runtime changes, and daily — and the hub records the verdict per
// executor and runtime. Placement reads that record here, through the same
// process-wide indirection the agent-build floor uses (agentbuild.go), so that
// reject() — shared by Select and CheckSandboxSupport — is its one enforcement
// point:
//
//   - evidence that contradicts the claim refuses a project requiring kernel
//     isolation or virtualization, always, naming the evidence;
//   - an executor never verified is admitted with a warning on the run's
//     journal, unless executors.isolation_evidence is "required", which
//     refuses it too.
//
// Only projects that ask for isolation are affected. An executor whose
// evidence contradicts its name still runs everything else, because nothing
// else relied on the name — and the card says what it really runs on.

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// IsolationProbe is what one run of the isolation probe saw, and the host
// kernel it is to be compared with.
type IsolationProbe struct {
	// Runtime is the runtime the sandbox ran under — the name the executor's
	// claim rests on. Empty is the engine's or the cluster's default.
	Runtime string `json:"runtime"`
	// Image is the image whose root filesystem the probe ran in: the
	// executor's own, never a project's. Nothing the probe reads comes from
	// it; it is recorded so a failed probe can be traced.
	Image string `json:"image,omitempty"`
	// Engine is the container engine the sandbox ran through, when there was
	// one ("docker", "podman"); empty for a Kubernetes Pod.
	Engine string `json:"engine,omitempty"`
	// Evidence is what the probe read inside the sandbox.
	Evidence isolationprobe.Evidence `json:"evidence"`
	// Reference is the executing host's own kernel.
	Reference isolationprobe.Reference `json:"reference"`
}

// Verdict classifies the probe.
func (p IsolationProbe) Verdict() isolationprobe.Verdict {
	return isolationprobe.Classify(p.Evidence, p.Reference)
}

// IsolationClaimer is implemented by executors whose Capabilities' Virtualized
// and KernelIsolated are read off a runtime's name.
type IsolationClaimer interface {
	Executor
	// IsolationRuntime returns the runtime the claim rests on — an OCI runtime,
	// a RuntimeClass, a device's sandbox runtime — and false when this
	// executor's payloads run under no runtime at all, as on a device in host
	// mode, where there is no claim to verify.
	IsolationRuntime() (runtime string, ok bool)
}

// IsolationProber is implemented by executors that can run the probe under
// the runtime they claim.
type IsolationProber interface {
	IsolationClaimer
	// ProbeIsolation runs the probe once. It starts a sandbox, so it can take
	// as long as a VM's boot; callers run it off the request path.
	ProbeIsolation(ctx context.Context) (IsolationProbe, error)
}

// IsolationRuntimeOf returns ex's claimed runtime, if it has one.
func IsolationRuntimeOf(ex Executor) (string, bool) {
	c, ok := ex.(IsolationClaimer)
	if !ok {
		return "", false
	}
	return c.IsolationRuntime()
}

// IsolationClaim is what a runtime's name claims.
func IsolationClaim(runtime string) isolationprobe.Kind {
	switch {
	case IsVirtualizedRuntime(runtime):
		return isolationprobe.KindVM
	case IsUserspaceKernelRuntime(runtime):
		return isolationprobe.KindUserspaceKernel
	}
	return isolationprobe.KindHostKernel
}

// claimOf is what an executor claims right now, read from its Capabilities —
// which already narrow a name the device cannot honour (a Kata runtime on a
// machine with no /dev/kvm claims nothing).
func claimOf(caps Capabilities) isolationprobe.Kind {
	switch {
	case caps.Virtualized:
		return isolationprobe.KindVM
	case caps.KernelIsolated:
		return isolationprobe.KindUserspaceKernel
	}
	return isolationprobe.KindHostKernel
}

// Probe points: where a probe was run from, recorded with its verdict.
const (
	ProbePointReconcile     = "reconcile"
	ProbePointHello         = "hello"
	ProbePointRuntimeChange = "runtime_change"
	ProbePointDaily         = "daily"
	ProbePointManual        = "manual"
)

// IsolationRecord is the hub's latest word on one executor's runtime.
type IsolationRecord struct {
	ExecutorID string `json:"executor_id"`
	Runtime    string `json:"runtime"`
	// Claim is what the runtime's name claims.
	Claim isolationprobe.Kind `json:"claim"`
	// Verdict is what the latest probe that ran found; KindUnknown when none
	// has.
	Verdict isolationprobe.Kind `json:"verdict"`
	// Detail is the evidence the verdict rests on, in a sentence.
	Detail string `json:"detail,omitempty"`
	// ProbedAt is when the verdict was reached; zero when no probe has run.
	ProbedAt time.Time `json:"probed_at,omitempty"`
	// AttemptedAt and Error describe the latest attempt, which may have failed
	// to run at all. A failed attempt never replaces a verdict: a probe that
	// could not start says nothing about the runtime, and letting it clear a
	// contradiction would make a broken probe the way to escape one.
	AttemptedAt time.Time `json:"attempted_at,omitempty"`
	Error       string    `json:"error,omitempty"`
	// Point is where the latest attempt was made from.
	Point string `json:"point,omitempty"`
}

// Status judges the record's verdict against its claim.
func (r IsolationRecord) Status() isolationprobe.Status {
	return isolationprobe.Judge(r.Claim, r.Verdict)
}

// ---------------------------------------------------------------------------
// The process-wide source and policy
// ---------------------------------------------------------------------------

// IsolationEvidenceSource answers placement's question: the record for one
// executor and runtime, and whether there is one.
type IsolationEvidenceSource func(executorID, runtime string) (IsolationRecord, bool)

var isolationSource atomic.Pointer[IsolationEvidenceSource]

// SetIsolationEvidenceSource installs where placement reads isolation evidence
// from, returning the previous source so tests can restore it. Nil removes it,
// and every executor then reads as never verified.
func SetIsolationEvidenceSource(fn IsolationEvidenceSource) IsolationEvidenceSource {
	var next *IsolationEvidenceSource
	if fn != nil {
		next = &fn
	}
	old := isolationSource.Swap(next)
	if old == nil {
		return nil
	}
	return *old
}

// LookupIsolationEvidence returns the record for executorID and runtime.
func LookupIsolationEvidence(executorID, runtime string) (IsolationRecord, bool) {
	p := isolationSource.Load()
	if p == nil || *p == nil {
		return IsolationRecord{}, false
	}
	return (*p)(executorID, strings.TrimSpace(runtime))
}

// Isolation evidence policies: executors.isolation_evidence.
const (
	// IsolationEvidencePolicyWarn admits a never-verified executor to a
	// project requiring isolation, and journals a warning on the run. The
	// default.
	IsolationEvidencePolicyWarn = "warn"
	// IsolationEvidencePolicyRequired refuses it.
	IsolationEvidencePolicyRequired = "required"
)

// ValidIsolationEvidencePolicy reports whether v is a policy this build
// knows; empty is the default.
func ValidIsolationEvidencePolicy(v string) bool {
	switch strings.TrimSpace(v) {
	case "", IsolationEvidencePolicyWarn, IsolationEvidencePolicyRequired:
		return true
	}
	return false
}

var isolationEvidenceRequired atomic.Bool

// SetIsolationEvidenceRequired is the raw switch, returning the previous
// value. Bootstrap paths call ApplyIsolationEvidencePolicy instead.
func SetIsolationEvidenceRequired(v bool) bool { return isolationEvidenceRequired.Swap(v) }

// IsolationEvidenceRequired reports whether a never-verified executor is
// refused.
func IsolationEvidenceRequired() bool { return isolationEvidenceRequired.Load() }

// ApplyIsolationEvidencePolicy installs a configured policy as a ratchet: it
// can make the hub stricter and never looser, for the reason on
// ApplyMinAgentBuild — a control plane reads many projects' config.yaml, and
// one of them must not relax a fleet-wide floor for the whole process.
func ApplyIsolationEvidencePolicy(v string) {
	if strings.TrimSpace(v) == IsolationEvidencePolicyRequired {
		isolationEvidenceRequired.Store(true)
	}
}

// ---------------------------------------------------------------------------
// Judgement
// ---------------------------------------------------------------------------

// IsolationStanding is one executor's claim judged against its evidence: what
// placement decides on and the Executors panel renders.
type IsolationStanding struct {
	// Runtime is the runtime the claim rests on; HasRuntime is false for an
	// executor whose payloads run under none.
	Runtime    string
	HasRuntime bool
	// Claim is what the runtime's name claims, or for an executor with no
	// runtime what its Capabilities claim.
	Claim isolationprobe.Kind
	// Status is the claim against the record.
	Status isolationprobe.Status
	// Record is the evidence, nil when none has ever been recorded.
	Record *IsolationRecord
}

// JudgeIsolation reads ex's isolation standing.
//
// The claim judged is the runtime's name's, when there is a runtime: that is
// what an operator configured and what the evidence answers. Capabilities may
// claim less — a device with no /dev/kvm does not advertise its kata runtime as
// a VM — and placement never reaches the evidence for a property they do not
// claim, so judging the name only changes what the card says: "claims kata,
// runs on the host kernel" for a kata that is runc there too.
func JudgeIsolation(ex Executor) IsolationStanding {
	st := IsolationStanding{Claim: claimOf(ex.Capabilities()), Status: isolationprobe.StatusUnverified}
	st.Runtime, st.HasRuntime = IsolationRuntimeOf(ex)
	if st.HasRuntime {
		st.Claim = IsolationClaim(st.Runtime)
	}
	rec, ok := LookupIsolationEvidence(ex.ID(), st.Runtime)
	if !ok {
		return st
	}
	st.Record = &rec
	st.Status = isolationprobe.Judge(st.Claim, rec.Verdict)
	return st
}

// runtimeLabel names the runtime for a sentence: `"kata"`, or "the default
// runtime".
func (st IsolationStanding) runtimeLabel() string {
	if strings.TrimSpace(st.Runtime) == "" {
		return "the default runtime"
	}
	return fmt.Sprintf("%q", st.Runtime)
}

// Summary renders the standing as the Executors panel shows it: "claims kata,
// runs on the host kernel", "claims runsc, verified: a userspace kernel
// (gVisor)", "claims kata, never verified".
func (st IsolationStanding) Summary() string {
	claim := "claims " + st.Runtime
	if strings.TrimSpace(st.Runtime) == "" {
		claim = "runs the default runtime"
	}
	switch {
	case st.Record == nil || st.Record.ProbedAt.IsZero():
		if st.Record != nil && st.Record.Error != "" {
			return claim + ", not verified: the probe could not run"
		}
		return claim + ", never verified"
	case st.Status == isolationprobe.StatusContradicted:
		return claim + ", runs on " + st.Record.Verdict.Phrase()
	case st.Status == isolationprobe.StatusVerified:
		return claim + ", verified: " + st.Record.Verdict.Phrase()
	}
	return claim + ", not verified: " + st.Record.Verdict.Phrase()
}

// unverifiedReason says why a standing is unverified, as a clause.
func (st IsolationStanding) unverifiedReason() string {
	switch {
	case st.Record == nil:
		return "no isolation probe has run under it yet"
	case st.Record.ProbedAt.IsZero() && st.Record.Error != "":
		return "its isolation probe could not run (" + st.Record.Error + ")"
	case st.Record.ProbedAt.IsZero():
		return "no isolation probe has completed under it"
	}
	return "its isolation probe was inconclusive: " + st.Record.Detail
}

// rejectForIsolationEvidence decides whether ex's evidence disqualifies it for
// a workload requiring kernel isolation or virtualization. It is reached only
// once the executor's Capabilities claim what the workload needs; this asks
// whether that claim holds up.
func rejectForIsolationEvidence(ex Executor) (detail string, rejected bool) {
	st := JudgeIsolation(ex)
	switch st.Status {
	case isolationprobe.StatusVerified:
		return "", false
	case isolationprobe.StatusContradicted:
		r := st.Record
		return fmt.Sprintf("claims %s through the runtime %s, but its isolation probe on %s found %s: %s; "+
			"register the runtime it is named for (or rename it to what it is) and press Re-probe on its "+
			"card, or bind this project to an executor whose probe verifies its claim",
			st.Claim.Phrase(), st.runtimeLabel(), r.ProbedAt.UTC().Format("2006-01-02 15:04 UTC"),
			r.Verdict.Phrase(), r.Detail), true
	}
	if !IsolationEvidenceRequired() {
		return "", false
	}
	return fmt.Sprintf("claims %s through the runtime %s, which has never been verified — %s — and "+
		"executors.isolation_evidence is %q; press Re-probe on its card once the probe can run, or "+
		"set executors.isolation_evidence to %q to admit unverified executors with a warning",
		st.Claim.Phrase(), st.runtimeLabel(), st.unverifiedReason(), IsolationEvidencePolicyRequired,
		IsolationEvidencePolicyWarn), true
}

// IsolationAdmissionWarning returns the warning a run's journal carries when
// it was placed on ex for a workload requiring isolation (req) while ex's claim
// is unverified, and "" otherwise — including when the policy would have
// refused it, since then it was not placed.
func IsolationAdmissionWarning(ex Executor, req Requirements) string {
	if ex == nil || !(req.RequireVirtualization || req.RequireKernelIsolation) || IsolationEvidenceRequired() {
		return ""
	}
	st := JudgeIsolation(ex)
	if st.Status != isolationprobe.StatusUnverified || st.Claim == isolationprobe.KindHostKernel {
		return ""
	}
	need := "kernel isolation"
	if req.RequireVirtualization {
		need = "a hypervisor"
	}
	return fmt.Sprintf("This run was placed on %s, which claims %s through the runtime %s, but %s. "+
		"The project's .cloop/sandbox.yaml requires %s, and the claim rests on the runtime's name alone; "+
		"executors.isolation_evidence: required would refuse such a placement.",
		ex.ID(), st.Claim.Phrase(), st.runtimeLabel(), st.unverifiedReason(), need)
}
