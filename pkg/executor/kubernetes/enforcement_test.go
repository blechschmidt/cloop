package kubernetes

// enforcement_test.go pins down which evidence wins.
//
// Every case here is a precedence question, and precedence is the whole
// security argument: the resolution decides whether a project that asked to be
// confined is placed on a cluster that might ignore the request. The two
// directions fail very differently — refusing a working cluster is an
// annoyance, admitting a non-enforcing one is the silent over-permission this
// feature exists to prevent — so the tests are written from the second one.

import (
	"strings"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

// freshVerdict is a verdict recorded now, by this binary's probe version.
func freshVerdict(enforced bool, executorID string) ProbeVerdict {
	return ProbeVerdict{
		Enforced:     enforced,
		ObservedAt:   time.Now(),
		Namespace:    "cloop",
		ExecutorID:   executorID,
		ProbeVersion: CurrentProbeVersion,
	}
}

// TestResolve_Precedence is the table the capability gate rests on.
func TestResolve_Precedence(t *testing.T) {
	now := time.Now()
	old := ProbeVerdict{
		Enforced: true, ObservedAt: now.Add(-90 * 24 * time.Hour),
		ExecutorID: "k8s", ProbeVersion: CurrentProbeVersion,
	}

	cases := []struct {
		name     string
		in       NetworkPolicyEnforcement
		want     EnforcementStatus
		enforced bool
	}{
		{
			name: "nothing known refuses",
			in:   NetworkPolicyEnforcement{},
			want: EnforcementUnverified, enforced: false,
		},
		{
			name: "operator assertion alone is enough",
			in:   NetworkPolicyEnforcement{Assertion: boolp(true)},
			want: EnforcementAsserted, enforced: true,
		},
		{
			name: "a fresh proof is enough with no assertion",
			in:   NetworkPolicyEnforcement{Verdict: freshVerdict(true, "k8s")},
			want: EnforcementProven, enforced: true,
		},
		{
			// The rule the whole design turns on. An operator can be wrong about
			// their own cluster — a CNI swap they were not told about is the
			// usual way — and the measurement is what catches it.
			name: "a refutation beats a positive assertion",
			in: NetworkPolicyEnforcement{
				Assertion: boolp(true),
				Verdict:   freshVerdict(false, "k8s"),
			},
			want: EnforcementRefuted, enforced: false,
		},
		{
			// And the reverse: an explicit no is honoured immediately, so that
			// switching the capability off after a CNI change does not mean
			// racing a recorded verdict that is still inside its expiry.
			name: "an explicit denial beats a positive proof",
			in: NetworkPolicyEnforcement{
				Assertion: boolp(false),
				Verdict:   freshVerdict(true, "k8s"),
			},
			want: EnforcementDenied, enforced: false,
		},
		{
			name: "a stale proof falls through to the assertion",
			in:   NetworkPolicyEnforcement{Assertion: boolp(true), Verdict: old},
			want: EnforcementAsserted, enforced: true,
		},
		{
			// A stale verdict is not evidence for anything, so with nothing else
			// to go on the answer is "nobody knows" — which refuses.
			name: "a stale proof with no assertion is unverified",
			in:   NetworkPolicyEnforcement{Verdict: old},
			want: EnforcementUnverified, enforced: false,
		},
		{
			// Executors differ in namespace and in the credential they connect
			// with, and a NetworkPolicy is namespaced. One executor's
			// measurement is not another's.
			name: "a verdict recorded for another executor is ignored",
			in:   NetworkPolicyEnforcement{Verdict: freshVerdict(true, "other-cluster")},
			want: EnforcementUnverified, enforced: false,
		},
		{
			// A probe version this binary does not recognise proved something,
			// but not necessarily *this* claim. Inheriting its authority would
			// let an old record vouch for an experiment it never ran.
			name: "a verdict from an unknown probe version is ignored",
			in: NetworkPolicyEnforcement{Verdict: ProbeVerdict{
				Enforced: true, ObservedAt: now, ExecutorID: "k8s",
				ProbeVersion: CurrentProbeVersion + 1,
			}},
			want: EnforcementUnverified, enforced: false,
		},
		{
			// A timestamp in the future means a clock jumped or a record was
			// copied between hosts. Honouring it would buy unlimited authority
			// for a claim nobody re-checked.
			name: "a verdict from the future is not trusted",
			in: NetworkPolicyEnforcement{Verdict: ProbeVerdict{
				Enforced: true, ObservedAt: now.Add(48 * time.Hour), ExecutorID: "k8s",
				ProbeVersion: CurrentProbeVersion,
			}},
			want: EnforcementUnverified, enforced: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := tc.in.Resolve("k8s", now)
			if got != tc.want {
				t.Errorf("status = %q, want %q (reason: %s)", got, tc.want, reason)
			}
			if got.Enforced() != tc.enforced {
				t.Errorf("Enforced() = %v, want %v", got.Enforced(), tc.enforced)
			}
			if strings.TrimSpace(reason) == "" {
				t.Error("resolution carries no reason; it is printed in a placement refusal " +
					"and in preflight, and an unexplained refusal gets resolved by disabling the feature")
			}
		})
	}
}

// TestResolve_UnverifiedNamesTheRealRisk: the default message has to say what
// goes wrong, because the operator reading it has to decide between running a
// probe and typing `true`. "Unverified" alone invites the second.
func TestResolve_UnverifiedNamesTheRealRisk(t *testing.T) {
	_, reason := NetworkPolicyEnforcement{}.Resolve("k8s", time.Now())
	if !strings.Contains(reason, "flannel") {
		t.Errorf("unverified reason does not name the failure mode: %q", reason)
	}
}

// TestProbeVerdict_StaleBoundary checks the expiry edge rather than trusting
// the comparison operator, because a verdict that expires a day late is a
// firewall claim nobody re-checked.
func TestProbeVerdict_StaleBoundary(t *testing.T) {
	now := time.Now()
	v := ProbeVerdict{Enforced: true, ObservedAt: now, ProbeVersion: CurrentProbeVersion}

	if v.Stale(now.Add(DefaultVerdictMaxAge-time.Minute), 0) {
		t.Error("a verdict just inside the window is stale")
	}
	if !v.Stale(now.Add(DefaultVerdictMaxAge+time.Minute), 0) {
		t.Error("a verdict just outside the window is not stale")
	}
	if (ProbeVerdict{}).Recorded() {
		t.Error("a zero verdict reports itself as a recorded observation")
	}
	if !(ProbeVerdict{}).Stale(now, 0) {
		t.Error("a zero verdict is not stale, so it could be read as evidence")
	}
}

// TestExplainEgressScopeRefusal_NamesTheRightRemedy.
//
// "Nobody has checked" and "your CNI ignores policies" are different problems,
// and telling the second operator to re-run the probe sends them round a loop
// that cannot terminate. The refusal is also the only place most people will
// ever read about the probe, so it has to name the command.
func TestExplainEgressScopeRefusal_NamesTheRightRemedy(t *testing.T) {
	ex, _, _ := newTestExecutor(t, nil)

	t.Run("unverified points at the probe", func(t *testing.T) {
		msg := ex.ExplainEgressScopeRefusal()
		if !strings.Contains(msg, ProbeCommand(ex.ID())) {
			t.Errorf("refusal does not name the probe command: %q", msg)
		}
	})

	t.Run("refuted does not point at the probe", func(t *testing.T) {
		ex.RecordNetworkPolicyVerdict(freshVerdict(false, ex.ID()))
		msg := ex.ExplainEgressScopeRefusal()
		if strings.Contains(msg, ProbeCommand(ex.ID())) {
			t.Errorf("a refuted cluster is told to re-run the probe, which cannot change the "+
				"answer: %q", msg)
		}
		if !strings.Contains(strings.ToLower(msg), "cni") {
			t.Errorf("a refuted cluster is not told the CNI is the problem: %q", msg)
		}
	})
}

// TestProbeCommand_IsRunnable guards the string an operator copies out of a
// refusal. A command with the wrong flag is worse than no command: it looks
// authoritative and fails.
func TestProbeCommand_IsRunnable(t *testing.T) {
	got := ProbeCommand("k8s-prod")
	for _, want := range []string{"cloop hub doctor", "--probe-network-policy", "--executor k8s-prod"} {
		if !strings.Contains(got, want) {
			t.Errorf("ProbeCommand = %q, missing %q", got, want)
		}
	}
	if strings.Contains(ProbeCommand("  "), "--executor") {
		t.Errorf("ProbeCommand with no id emits a bare --executor flag: %q", ProbeCommand("  "))
	}
}
