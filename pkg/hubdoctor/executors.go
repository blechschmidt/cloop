package hubdoctor

// Executor checks: is there anywhere for work to go, and can it be reached?
//
// This is the check that catches the failure Task 20170 was written for and
// that /readyz now gates on: a hub with executors.allow_host_process=false and
// no isolating driver registered comes up correctly, refuses host execution
// correctly, and cannot execute anything. Reconciliation already produces a
// structured diagnostic per configured driver; what this adds is (a) running
// that reconciliation from the CLI, before deploying, rather than discovering
// it from a running hub, and (b) an actual liveness probe and capability report
// per executor, which reconciliation's preflight does not repeat once a driver
// is registered.
//
// The capability report is not decoration. "Which executor can provision a
// workspace" and "which can write results back" are the two questions that
// decide whether a project can be bound to a given backend at all, and today
// the only way to answer them is to bind a project and watch the dispatch fail.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkExecutors(ctx context.Context, dir string, cfg *config.Config, opts Options, add addFn) {
	// Apply the config's policy to this process before reconciling, so a
	// doctor run reproduces the registry the hub would build rather than the
	// permissive default a CLI starts with. The ratchet only tightens, so
	// this cannot loosen a process that was already strict.
	executor.ApplyHostExecutionPolicy(cfg.Executors.HostProcessAllowed())

	// Reconcile without publishing: `cloop hub doctor` may be run alongside a
	// hub in the same directory, and overwriting the live report with a CLI
	// run's would make the Executors panel describe a process that has exited.
	noPublish := false
	report := reconcile.FromConfig(ctx, dir, cfg, reconcile.Options{
		SkipPreflight:    opts.Offline,
		Publish:          &noPublish,
		QuietWhenHealthy: true,
		Logf:             func(string, ...any) {},
	})
	for _, d := range report.Diagnostics {
		add(diagnosticFinding(d))
	}

	registered := executor.DefaultRegistry.List()
	isolated := executor.IsolatedIDs()

	// Enrolled remote agents are not in this process's registry — the hub
	// restores them from its database when it starts, and a CLI run has not.
	// Counting them separately is what keeps the verdict honest for the
	// topology the eval stack creates, where the *only* isolating executor is
	// a device that dialled in.
	enrolled := enrolledAgents(dir)

	// The strict-mode gate, stated as the readiness probe states it.
	switch {
	case !cfg.Executors.HostProcessAllowed() && len(isolated) == 0 && len(enrolled) > 0:
		add(Finding{
			Check: "executors.available", Title: "Dispatch targets", Severity: SeverityWarn,
			Message: fmt.Sprintf("no executor is configured in this file, but %d remote agent(s) are "+
				"enrolled; the hub can dispatch only while one of them is connected", len(enrolled)),
			Remediation: "Check they are connected in the Executors panel, or enable a configured " +
				"executor so the hub does not depend on a device being awake",
			Details: map[string]any{"enrolled": strings.Join(enrolled, ", ")},
		})
	case !cfg.Executors.HostProcessAllowed() && len(isolated) == 0:
		add(Finding{
			Check: "executors.available", Title: "Dispatch targets", Severity: SeverityFail,
			Message: "strict mode is on, no isolating executor is configured and no remote agent is " +
				"enrolled: every run will be refused with 409 and /readyz will report this hub as not ready",
			Remediation: "Enable executors.container or executors.kubernetes, or enroll a remote agent " +
				"with `cloop executor enroll --name <device>`",
		})
	case len(registered) == 0:
		add(Finding{
			Check: "executors.available", Title: "Dispatch targets", Severity: SeverityFail,
			Message:     "no executor is registered at all, so no work can be dispatched",
			Remediation: "Enable an executor under executors: in .cloop/config.yaml, or enroll a remote agent",
		})
	default:
		add(Finding{
			Check: "executors.available", Title: "Dispatch targets", Severity: SeverityPass,
			Message: fmt.Sprintf("%d executor(s) registered, %d of them isolating",
				len(registered), len(isolated)),
		})
	}

	sort.Slice(registered, func(i, j int) bool { return registered[i].ID() < registered[j].ID() })
	for _, ex := range registered {
		add(executorFinding(ctx, ex, opts))
	}
}

// diagnosticFinding maps a reconciliation diagnostic onto a doctor finding.
// The severities line up one for one: failed means the driver could not be
// built, degraded means it was built and its preflight found a fatal problem.
func diagnosticFinding(d reconcile.Diagnostic) Finding {
	sev := SeverityPass
	switch d.Status {
	case reconcile.StatusFailed:
		sev = SeverityFail
	case reconcile.StatusDegraded:
		sev = SeverityWarn
	}
	f := Finding{
		Check:       "executors.configured",
		Title:       "Configured executor " + d.ID,
		Severity:    sev,
		Message:     d.Message,
		Remediation: d.Remediation,
	}
	if len(d.Findings) > 0 {
		var problems []string
		for _, pf := range d.Findings {
			if pf.Level == "ok" {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: %s", pf.Name, pf.Message))
		}
		if len(problems) > 0 {
			f.Details = map[string]any{"preflight": strings.Join(problems, "; ")}
		}
	}
	return f
}

// executorFinding probes one registered executor and reports its capabilities.
//
// A probe failure is a warning rather than a failure: HealthCheck is a
// point-in-time dial of a possibly-remote system, and an edge device that is
// asleep is not a misconfigured hub. It becomes a failure only when it is the
// *only* thing left to dispatch to, which the executors.available check above
// already covers.
func executorFinding(ctx context.Context, ex executor.Executor, opts Options) Finding {
	caps := ex.Capabilities()
	details := map[string]any{
		"kind":            ex.Kind(),
		"isolation":       string(caps.Isolation),
		"virtualized":     caps.Virtualized,
		"workspace":       caps.SupportsWorkspaceProvisioning,
		"write_back":      caps.SupportsWriteBack,
		"secret_files":    caps.SupportsSecretFiles,
		"network_egress":  caps.NetworkEgress,
		"resource_limits": caps.SupportsResourceLimits,
	}
	if caps.MaxConcurrent > 0 {
		details["max_concurrent"] = caps.MaxConcurrent
	}
	if caps.Platform != "" {
		details["platform"] = caps.Platform + "/" + caps.Arch
	}

	title := "Executor " + ex.ID()
	if opts.Offline {
		return Finding{
			Check: "executors.health", Title: title, Severity: SeverityWarn,
			Message:     "capabilities reported; liveness not probed (--offline)",
			Remediation: "Re-run without --offline to dial it",
			Details:     details,
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	if err := ex.HealthCheck(probeCtx); err != nil {
		return Finding{
			Check: "executors.health", Title: title, Severity: SeverityWarn,
			Message:     fmt.Sprintf("unreachable: %v", err),
			Remediation: remediationFor(ex),
			Details:     details,
		}
	}
	return Finding{
		Check: "executors.health", Title: title, Severity: SeverityPass,
		Message: fmt.Sprintf("reachable, isolation %q", caps.Isolation),
		Details: details,
	}
}

// enrolledAgents lists the names of remote agents this control plane has
// enrolled and not revoked.
//
// Best-effort by design: a database that will not open is checkStorage's
// finding to report, and an executor verdict that could not read it should say
// "no agents" rather than double-report a storage failure as an executor one.
func enrolledAgents(dir string) []string {
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil
	}
	defer func() { _ = db.Close() }()

	store, err := executorstore.New(db)
	if err != nil {
		return nil
	}
	agents, err := store.ListAgents()
	if err != nil {
		return nil
	}
	var names []string
	for _, a := range agents {
		if !a.RevokedAt.IsZero() {
			continue
		}
		name := a.Name
		if name == "" {
			name = a.AgentID
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// remediationFor names the action that fits the kind of executor that failed,
// because "it is unreachable" has four different fixes.
func remediationFor(ex executor.Executor) string {
	switch ex.Kind() {
	case executor.KindContainer:
		return "Check the container runtime is running and this user may talk to it (`podman info`)"
	case executor.KindKubernetes:
		return "Check the cluster credential and that the namespace exists (`cloop executor test " + ex.ID() + "`)"
	case executor.KindRemoteAgent:
		return "The device is offline or its agent stopped; restart `cloop executor agent` on it, " +
			"or re-enroll with `cloop executor enroll`"
	default:
		return "Run `cloop executor test " + ex.ID() + "` for the driver's own diagnosis"
	}
}
