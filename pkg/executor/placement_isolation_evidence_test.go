package executor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// claimExec is a candidate whose Capabilities come from a runtime name, as a
// container, Kubernetes or device executor's do.
type claimExec struct {
	*capExec
	runtime string
}

func (c *claimExec) IsolationRuntime() (string, bool) { return c.runtime, true }

// newClaimExec builds an executor that claims what runtime's name claims.
func newClaimExec(id, runtime string) *claimExec {
	return &claimExec{capExec: newCapExec(id, Capabilities{
		Isolation:      IsolationContainer,
		Virtualized:    IsVirtualizedRuntime(runtime),
		KernelIsolated: IsKernelIsolatedRuntime(runtime),
	}), runtime: runtime}
}

// withEvidence installs a source holding recs for the test, and the policy.
func withEvidence(t *testing.T, required bool, recs ...IsolationRecord) {
	t.Helper()
	byKey := map[string]IsolationRecord{}
	for _, r := range recs {
		byKey[r.ExecutorID+"\x00"+r.Runtime] = r
	}
	prev := SetIsolationEvidenceSource(func(id, runtime string) (IsolationRecord, bool) {
		r, ok := byKey[id+"\x00"+runtime]
		return r, ok
	})
	prevReq := SetIsolationEvidenceRequired(required)
	t.Cleanup(func() {
		SetIsolationEvidenceSource(prev)
		SetIsolationEvidenceRequired(prevReq)
	})
}

var probedAt = time.Date(2026, 10, 17, 5, 1, 0, 0, time.UTC)

// hostKernelOnSgx is the verdict a runc container on sgx produced, recorded
// for an executor whose runtime is named kata.
func hostKernelOnSgx(id, runtime string) IsolationRecord {
	return IsolationRecord{ExecutorID: id, Runtime: runtime, Claim: IsolationClaim(runtime),
		Verdict: isolationprobe.KindHostKernel, ProbedAt: probedAt,
		Detail: "the sandbox's kernel is the host's own: it reports the host's boot ID (2d725fb0…) and its " +
			"kernel, 6.8.0-79-generic #79-Ubuntu SMP PREEMPT_DYNAMIC Tue Aug 12 14:42:46 UTC 2025"}
}

func placementErr(t *testing.T, err error) *PlacementError {
	t.Helper()
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want *PlacementError", err, err)
	}
	return pe
}

// TestSelectRefusesAContradictedClaim: an executor whose runtime is named kata
// and whose probe found the host kernel is refused for a workload requiring a
// hypervisor or kernel isolation — always, whatever the policy — and the
// refusal names the evidence.
func TestSelectRefusesAContradictedClaim(t *testing.T) {
	for _, required := range []bool{false, true} {
		withEvidence(t, required, hostKernelOnSgx("kata-box", "kata"))
		for _, req := range []Requirements{{RequireVirtualization: true}, {RequireKernelIsolation: true}} {
			_, err := Select([]Candidate{{Executor: newClaimExec("kata-box", "kata"), Health: Health{State: NodeReady}}}, req)
			pe := placementErr(t, err)
			if pe.Constraint != ConstraintIsolationEvidence {
				t.Fatalf("constraint = %s, want %s", pe.Constraint, ConstraintIsolationEvidence)
			}
			msg := err.Error()
			for _, want := range []string{"kata-box", `runtime "kata"`, "the host kernel", "2d725fb0", "2026-10-17 05:01 UTC"} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal %q does not name %q", msg, want)
				}
			}
		}
	}
}

// TestSelectRefusesGVisorClaimingToBeAVM: "at least the isolation claimed".
// gVisor behind a Kata name has no hypervisor, so a kernel-isolation-only
// workload is refused on it too: the executor's claim is false.
func TestSelectRefusesGVisorClaimingToBeAVM(t *testing.T) {
	rec := hostKernelOnSgx("kata-box", "kata")
	rec.Verdict, rec.Detail = isolationprobe.KindUserspaceKernel, "gVisor's userspace kernel served the probe"
	withEvidence(t, false, rec)
	_, err := Select([]Candidate{{Executor: newClaimExec("kata-box", "kata"), Health: Health{State: NodeReady}}},
		Requirements{RequireKernelIsolation: true})
	if pe := placementErr(t, err); pe.Constraint != ConstraintIsolationEvidence {
		t.Fatalf("constraint = %s", pe.Constraint)
	}
}

// TestSelectAdmitsAVerifiedClaim: evidence that bears the claim out places, and
// raises no warning.
func TestSelectAdmitsAVerifiedClaim(t *testing.T) {
	vm := hostKernelOnSgx("kata-box", "kata")
	vm.Verdict, vm.Detail = isolationprobe.KindVM, "a kernel of the sandbox's own, behind a hypervisor"
	gv := hostKernelOnSgx("gvisor-box", "runsc")
	gv.Verdict = isolationprobe.KindUserspaceKernel
	withEvidence(t, true, vm, gv)

	got, err := Select([]Candidate{{Executor: newClaimExec("kata-box", "kata"), Health: Health{State: NodeReady}}},
		Requirements{RequireVirtualization: true})
	if err != nil || got.ID() != "kata-box" {
		t.Fatalf("Select = %v, %v", got.ID(), err)
	}
	for _, ex := range []Executor{newClaimExec("kata-box", "kata"), newClaimExec("gvisor-box", "runsc")} {
		if w := IsolationAdmissionWarning(ex, Requirements{RequireKernelIsolation: true}); w != "" {
			t.Errorf("a verified executor warned: %s", w)
		}
		if _, err := Select([]Candidate{{Executor: ex, Health: Health{State: NodeReady}}},
			Requirements{RequireKernelIsolation: true}); err != nil {
			t.Errorf("%s: %v", ex.ID(), err)
		}
	}
}

// TestSelectAdmitsAnUnverifiedClaimWithAWarning: never verified is admitted by
// default, with a warning for the run's journal; executors.isolation_evidence:
// required refuses it instead, naming why it is unverified.
func TestSelectAdmitsAnUnverifiedClaimWithAWarning(t *testing.T) {
	failed := IsolationRecord{ExecutorID: "sgx", Runtime: "kata", Claim: isolationprobe.KindVM,
		Verdict: isolationprobe.KindUnknown, AttemptedAt: probedAt,
		Error: "agent sgx (sgx) speaks protocol v25, and the hub needs v26 to probe what its sandbox runtime really is."}
	cases := []struct {
		name   string
		recs   []IsolationRecord
		reason string
	}{
		{"never probed", nil, "no isolation probe has run under it yet"},
		{"the probe could not run", []IsolationRecord{failed}, "needs v26"},
		{"an inconclusive verdict", []IsolationRecord{{ExecutorID: "sgx", Runtime: "kata", Claim: isolationprobe.KindVM,
			Verdict: isolationprobe.KindUnknown, ProbedAt: probedAt, Detail: "there is nothing to compare it with"}},
			"inconclusive: there is nothing to compare it with"},
		// Evidence about another runtime says nothing about this one.
		{"evidence for another runtime", []IsolationRecord{hostKernelOnSgx("sgx", "runsc")}, "no isolation probe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := newClaimExec("sgx", "kata")
			req := Requirements{RequireVirtualization: true}

			withEvidence(t, false, tc.recs...)
			if _, err := Select([]Candidate{{Executor: ex, Health: Health{State: NodeReady}}}, req); err != nil {
				t.Fatalf("an unverified executor was refused under the default policy: %v", err)
			}
			w := IsolationAdmissionWarning(ex, req)
			if !strings.Contains(w, tc.reason) || !strings.Contains(w, "requires a hypervisor") ||
				!strings.Contains(w, "executors.isolation_evidence: required") {
				t.Errorf("warning %q does not say why, what was required and how to refuse", w)
			}

			withEvidence(t, true, tc.recs...)
			_, err := Select([]Candidate{{Executor: ex, Health: Health{State: NodeReady}}}, req)
			pe := placementErr(t, err)
			if pe.Constraint != ConstraintIsolationEvidence || !strings.Contains(err.Error(), tc.reason) ||
				!strings.Contains(err.Error(), "never been verified") {
				t.Fatalf("under required: %v", err)
			}
			if w := IsolationAdmissionWarning(ex, req); w != "" && !strings.Contains(w, tc.reason) {
				t.Errorf("warning %q", w)
			}
		})
	}
}

// TestContradictedEvidenceOnlyMattersToIsolatedWork: a project that asks for
// no isolation never relied on the runtime's name, so a contradiction does not
// stop it — and an executor claiming nothing is never refused for evidence.
func TestContradictedEvidenceOnlyMattersToIsolatedWork(t *testing.T) {
	withEvidence(t, true, hostKernelOnSgx("kata-box", "kata"), hostKernelOnSgx("runc-box", ""))
	if _, err := Select([]Candidate{{Executor: newClaimExec("kata-box", "kata"), Health: Health{State: NodeReady}}},
		Requirements{}); err != nil {
		t.Fatalf("a workload asking for no isolation was refused: %v", err)
	}
	if w := IsolationAdmissionWarning(newClaimExec("runc-box", ""), Requirements{RequireKernelIsolation: true}); w != "" {
		t.Errorf("an executor claiming nothing warned: %s", w)
	}
}

// TestCheckSandboxSupportNamesTheEvidence: on the bound-executor path the
// refusal is the evidence, not "bind to a sandbox" — the executor already is
// one, it just is not the one its name says.
func TestCheckSandboxSupportNamesTheEvidence(t *testing.T) {
	withEvidence(t, false, hostKernelOnSgx("kata-box", "kata"))
	err := CheckSandboxSupport(newClaimExec("kata-box", "kata"), Requirements{RequireVirtualization: true}, "/srv/p")
	var denied *HostExecutionDeniedError
	if errors.As(err, &denied) {
		t.Fatalf("CheckSandboxSupport = %v; a contradicted claim is not a host-execution refusal", err)
	}
	if pe := placementErr(t, err); pe.Constraint != ConstraintIsolationEvidence {
		t.Fatalf("constraint = %s", pe.Constraint)
	}
}

// TestJudgeIsolationSummaries is what the Executors panel shows.
func TestJudgeIsolationSummaries(t *testing.T) {
	vm := hostKernelOnSgx("verified", "kata")
	vm.Verdict = isolationprobe.KindVM
	failed := IsolationRecord{ExecutorID: "failed", Runtime: "kata", Verdict: isolationprobe.KindUnknown,
		AttemptedAt: probedAt, Error: "no image"}
	withEvidence(t, false, hostKernelOnSgx("contra", "kata"), vm, failed)
	cases := map[string]string{
		"contra":   "claims kata, runs on the host kernel",
		"verified": "claims kata, verified: a virtual machine",
		"failed":   "claims kata, not verified: the probe could not run",
		"never":    "claims kata, never verified",
	}
	for id, want := range cases {
		if got := JudgeIsolation(newClaimExec(id, "kata")).Summary(); got != want {
			t.Errorf("%s: Summary = %q, want %q", id, got, want)
		}
	}
}

// TestTheCardJudgesTheRuntimesName: a device with no /dev/kvm does not
// advertise its kata runtime as a VM, so placement never asks the evidence
// about it — but the card still says what the name claims and what was found.
func TestTheCardJudgesTheRuntimesName(t *testing.T) {
	withEvidence(t, false, hostKernelOnSgx("no-kvm", "kata"))
	demoted := &claimExec{capExec: newCapExec("no-kvm", Capabilities{Isolation: IsolationRemote}), runtime: "kata"}
	st := JudgeIsolation(demoted)
	if st.Claim != isolationprobe.KindVM || st.Status != isolationprobe.StatusContradicted ||
		st.Summary() != "claims kata, runs on the host kernel" {
		t.Fatalf("standing = %+v (%q)", st, st.Summary())
	}
}

// TestApplyIsolationEvidencePolicyIsARatchet: one project's config.yaml cannot
// relax a hub that requires evidence.
func TestApplyIsolationEvidencePolicyIsARatchet(t *testing.T) {
	prev := SetIsolationEvidenceRequired(false)
	t.Cleanup(func() { SetIsolationEvidenceRequired(prev) })
	ApplyIsolationEvidencePolicy("")
	ApplyIsolationEvidencePolicy(IsolationEvidencePolicyWarn)
	if IsolationEvidenceRequired() {
		t.Fatal("warn or unset turned the requirement on")
	}
	ApplyIsolationEvidencePolicy(IsolationEvidencePolicyRequired)
	ApplyIsolationEvidencePolicy(IsolationEvidencePolicyWarn)
	if !IsolationEvidenceRequired() {
		t.Fatal("a later warn relaxed a required policy")
	}
	for _, v := range []string{"", "warn", "required"} {
		if !ValidIsolationEvidencePolicy(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	if ValidIsolationEvidencePolicy("strict") {
		t.Error("an unknown policy validated")
	}
}
