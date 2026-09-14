package hubdoctor

// The NetworkPolicy enforcement probe: the one hub-doctor check that changes
// the hub rather than only reporting on it.
//
// Every other check here reads. This one, when asked, creates two throwaway
// Pods and a default-deny NetworkPolicy in the executor's namespace, watches
// whether a connection that worked stops working, records the verdict and
// deletes everything it made. That is a mutation of an operator's cluster, so
// it is opt-in behind --probe-network-policy and never runs as part of a plain
// `cloop hub doctor`.
//
// Why it is worth a mutation: the Kubernetes driver creates a per-run
// NetworkPolicy to confine a project's egress, and a cluster whose CNI does not
// implement NetworkPolicy accepts that object and enforces nothing. The API
// server cannot be asked which case you are in. Without a probe the only
// options are to trust an operator's word or to refuse every project that asks
// to be confined — so the probe is what turns a refusal into a capability.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DefaultNetworkPolicyProbeTimeout bounds one probe. Three pods have to be
// scheduled, pull an image and run, and the policed one spends six seconds
// waiting for a connection that never completes — on a cold node with a cold
// image cache that adds up, and a probe that times out reports nothing rather
// than reporting the wrong thing.
const DefaultNetworkPolicyProbeTimeout = 3 * time.Minute

// checkNetworkPolicyEnforcement runs the probe against every registered
// Kubernetes executor (or just the one named) and records what it found.
//
// It runs after checkExecutors, and depends on it: reconciliation is what puts
// the drivers in the registry, and a probe needs a live driver holding a
// cluster credential. Calling it on a hub with no Kubernetes executor is not an
// error — it reports that there was nothing to probe, which is the honest
// answer for the great majority of deployments.
func checkNetworkPolicyEnforcement(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	if cfg == nil || !opts.ProbeNetworkPolicy {
		return
	}
	if opts.Offline {
		add(Finding{
			Check: "executors.network_policy_probe", Title: "NetworkPolicy enforcement",
			Severity: SeverityWarn,
			Message:  "--probe-network-policy was requested alongside --offline, so nothing was probed",
			Remediation: "Drop --offline: the probe has to create Pods in the cluster, which is the " +
				"only way to tell an enforced policy from a decorative one",
		})
		return
	}

	targets := kubernetesExecutors(opts.ProbeExecutorID)
	if len(targets) == 0 {
		msg := "no Kubernetes executor is registered, so there is no cluster to probe"
		if id := strings.TrimSpace(opts.ProbeExecutorID); id != "" {
			msg = fmt.Sprintf("no Kubernetes executor named %q is registered", id)
		}
		add(Finding{
			Check: "executors.network_policy_probe", Title: "NetworkPolicy enforcement",
			Severity: SeverityWarn, Message: msg,
			Remediation: "Configure executors.kubernetes and re-run, or drop --probe-network-policy",
		})
		return
	}

	for _, ex := range targets {
		probeOne(ctx, dir, ex, opts, add)
	}
}

// probeOne runs the experiment against a single executor and persists what it
// learned.
//
// The verdict is saved *and* pushed onto the live driver. Saving alone would
// leave the running hub still refusing placements until someone restarted it;
// pushing alone would lose the result at the next restart. A probe an operator
// just paid three minutes for should take effect in both senses at once.
func probeOne(ctx context.Context, dir string, ex *kubernetes.Executor, opts Options, add addFn) {
	id := ex.ID()
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = DefaultNetworkPolicyProbeTimeout
	}

	verdict, err := ex.ProbeNetworkPolicyEnforcement(ctx, kubernetes.ProbeOptions{
		Image:   strings.TrimSpace(opts.ProbeImage),
		Timeout: timeout,
		Logf:    opts.probeLogf,
	})
	if err != nil {
		// Inconclusive is a warning, not a failure. The probe proved nothing in
		// either direction, so the hub is exactly as safe as it was before —
		// it keeps refusing egress-scoped projects — and calling that a failure
		// would make a CI gate go red over a cluster that is merely unproven.
		sev := SeverityWarn
		if !errors.Is(err, kubernetes.ErrProbeInconclusive) {
			sev = SeverityFail
		}
		add(Finding{
			Check: "executors.network_policy_probe", Title: "NetworkPolicy enforcement",
			Severity: sev,
			Message:  fmt.Sprintf("executor %s: %v", id, err),
			Remediation: "Resolve the cause and re-run `" + kubernetes.ProbeCommand(id) + "`; until a " +
				"probe succeeds or executors.kubernetes.network_policy_enforced is set, projects " +
				"with capabilities.egress are refused on this executor",
			Details: map[string]any{"executor": id},
		})
		return
	}

	ex.RecordNetworkPolicyVerdict(verdict)
	saved, saveErr := saveVerdict(dir, id, verdict)

	details := map[string]any{
		"executor":  id,
		"namespace": verdict.Namespace,
		"enforced":  verdict.Enforced,
		"persisted": saved,
	}

	switch {
	case verdict.Enforced:
		f := Finding{
			Check: "executors.network_policy_probe", Title: "NetworkPolicy enforcement",
			Severity: SeverityPass,
			Message: fmt.Sprintf("executor %s: %s — per-project egress scopes are now honoured here",
				id, verdict.Detail),
			Details: details,
		}
		if !saved {
			// The measurement is good and only the bookkeeping failed, so this
			// stays a pass with the consequence spelled out: the capability is
			// live in this process and will be gone at the next restart.
			f.Severity = SeverityWarn
			f.Message += fmt.Sprintf(", but the verdict could not be recorded (%v), so it will be "+
				"lost when the hub restarts", saveErr)
			f.Remediation = "Check that the control-plane database at " + state.DBPath(dir) +
				" is writable, then re-run the probe"
		}
		add(f)
	default:
		add(Finding{
			Check: "executors.network_policy_probe", Title: "NetworkPolicy enforcement",
			Severity: SeverityFail,
			Message:  fmt.Sprintf("executor %s: %s", id, verdict.Detail),
			Remediation: "Any executors.kubernetes.egress_filter configured here is stored by the API " +
				"server and applied by nothing. Install a CNI that implements NetworkPolicy " +
				"(Calico, Cilium, Antrea), or stop relying on egress filtering on this cluster",
			Details: details,
		})
	}
}

// saveVerdict persists the result, reporting whether it landed.
//
// Failure is returned rather than added as its own finding, because the caller
// is already producing a finding about this probe and two lines about one event
// — one saying the cluster enforces policies, one saying a database write
// failed — read as two unrelated problems.
func saveVerdict(dir, id string, v kubernetes.ProbeVerdict) (bool, error) {
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return false, err
	}
	defer db.Close()
	if err := reconcile.SaveNetworkPolicyVerdict(db, id, v); err != nil {
		return false, err
	}
	return true, nil
}

// kubernetesExecutors returns the registered Kubernetes drivers, optionally
// narrowed to one id.
//
// Type-asserted out of the registry rather than rebuilt from config: the probe
// needs a driver holding a live cluster credential, and constructing a second
// one would lease a second kubeconfig for the same cluster and leave the hub's
// own executor none the wiser about the result.
func kubernetesExecutors(only string) []*kubernetes.Executor {
	want := strings.TrimSpace(only)
	var out []*kubernetes.Executor
	for _, ex := range executor.DefaultRegistry.List() {
		k, ok := ex.(*kubernetes.Executor)
		if !ok {
			continue
		}
		if want != "" && k.ID() != want {
			continue
		}
		out = append(out, k)
	}
	return out
}
