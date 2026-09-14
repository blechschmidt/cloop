package hubdoctor

// netpol_test.go covers the wiring around the probe rather than the experiment
// itself — that lives in pkg/executor/kubernetes, against a fake API server.
//
// What has to hold here is that the only check in this package that *mutates an
// operator's cluster* never runs unless it was asked for, and that when it
// cannot run it says so rather than staying silent. A diagnostic that quietly
// skips is worse than one that fails: the operator reads a clean report and
// concludes the question was answered.

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
)

// netpolCheckID is the stable id a CI pipeline greps for.
const netpolCheckID = "executors.network_policy_probe"

// runNetpolCheck drives the check alone, without the rest of the report.
func runNetpolCheck(t *testing.T, cfg *config.Config, opts Options) []Finding {
	t.Helper()
	var got []Finding
	checkNetworkPolicyEnforcement(context.Background(), t.TempDir(), cfg,
		opts, func(f Finding) { got = append(got, f) })
	return got
}

// TestProbeIsOptIn is the guarantee that makes this check safe to ship.
//
// Every other hub-doctor check reads. This one creates Pods and a default-deny
// NetworkPolicy in a namespace an operator cares about, so a plain `cloop hub
// doctor` — the thing people run against production to see what is wrong — must
// not do it.
func TestProbeIsOptIn(t *testing.T) {
	cfg := &config.Config{}
	if got := runNetpolCheck(t, cfg, Options{}); len(got) != 0 {
		t.Fatalf("the probe emitted findings without --probe-network-policy: %+v", got)
	}

	// And through the full report, which is what the command actually calls.
	byCheck := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if got := byCheck[netpolCheckID]; len(got) != 0 {
		t.Errorf("a plain run produced probe findings: %+v", got)
	}
}

// TestProbeWithOfflineSaysSoInsteadOfSkipping.
//
// --offline and --probe-network-policy contradict each other: the probe has to
// reach the cluster. Silently doing nothing would let an operator believe they
// had proved something.
func TestProbeWithOfflineSaysSoInsteadOfSkipping(t *testing.T) {
	got := runNetpolCheck(t, &config.Config{}, Options{ProbeNetworkPolicy: true, Offline: true})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want exactly one explaining the contradiction: %+v", len(got), got)
	}
	if got[0].Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn: nothing was probed, but nothing is broken either",
			got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "offline") {
		t.Errorf("the finding does not name the flag that suppressed the probe: %q", got[0].Message)
	}
}

// TestProbeWithNoKubernetesExecutorIsAWarning.
//
// The overwhelmingly common case for an operator who types the flag out of
// curiosity. It is not a failure — there is nothing wrong with a hub that runs
// containers — but it must not read as a pass either, because "we did not look"
// and "we looked and it was fine" are different answers.
func TestProbeWithNoKubernetesExecutorIsAWarning(t *testing.T) {
	got := runNetpolCheck(t, &config.Config{}, Options{ProbeNetworkPolicy: true})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want one: %+v", len(got), got)
	}
	if got[0].Severity != SeverityWarn {
		t.Errorf("severity = %q, want warn", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "Kubernetes executor") {
		t.Errorf("the finding does not say what was missing: %q", got[0].Message)
	}
}

// TestProbeNamingAnUnknownExecutorSaysWhichOne: a typo in --executor must not
// silently probe nothing and report a clean run.
func TestProbeNamingAnUnknownExecutorSaysWhichOne(t *testing.T) {
	got := runNetpolCheck(t, &config.Config{}, Options{
		ProbeNetworkPolicy: true,
		ProbeExecutorID:    "k8s-typo",
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want one: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "k8s-typo") {
		t.Errorf("the finding does not name the executor that was asked for: %q", got[0].Message)
	}
}

// TestProbeFindingIDIsStable pins the check id, which is what a CI pipeline
// greps for. Renaming it is a breaking change to every gate built on it.
func TestProbeFindingIDIsStable(t *testing.T) {
	got := runNetpolCheck(t, &config.Config{}, Options{ProbeNetworkPolicy: true})
	if len(got) == 0 || got[0].Check != netpolCheckID {
		t.Fatalf("check id changed: %+v", got)
	}
}
