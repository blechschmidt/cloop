package ui

// firewall_dispatch.go puts the stored firewall levels on a workload on its way
// to an executor (Task 20363): the dispatch-time half of the containment rule.
//
// firewall_api.go checks at save time, where the message lands on the form,
// but against whichever executor the project resolved to *then*. A project can
// be rebound, its virtual executor edited or its device tightened afterwards,
// and only here is the executor finally known. The driver checks once more
// before it installs anything; see fwpolicy.CheckAtDriver.

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// controlPlaneFirewalls reads the stored levels from the control plane's
// database for pkg/fwpolicy.
//
// A hub with no control plane yet (before bootstrap) has no stored levels, and
// says so with nil rather than an error. A database that exists and cannot be
// read is an error, which fwpolicy turns into a refused dispatch: falling
// through to "no rules" would widen a sandbox on a storage fault.
type controlPlaneFirewalls struct{}

func (controlPlaneFirewalls) open() (*statedb.DB, bool, error) {
	dir := controlPlaneDir()
	if strings.TrimSpace(dir) == "" {
		return nil, false, nil
	}
	// Stat before opening: statedb.Open creates and migrates, and asking
	// whether there are rules must not materialise a database where none is.
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	db, err := longLivedDB(path)
	if err != nil {
		return nil, false, err
	}
	return db, true, nil
}

func (c controlPlaneFirewalls) DeviceFirewall(executorID string) (*executor.FirewallRules, error) {
	db, ok, err := c.open()
	if !ok {
		return nil, err
	}
	rec, found, err := db.ExecutorFirewall(executorID)
	if err != nil || !found {
		return nil, err
	}
	return &rec.Rules, nil
}

func (c controlPlaneFirewalls) ProjectFirewall(projectPath string) (*executor.FirewallRules, error) {
	db, ok, err := c.open()
	if !ok {
		return nil, err
	}
	// A feature worktree runs under its parent project's rules, as it runs on
	// its parent's executor and under its parent's ceiling.
	rec, found, err := db.ProjectFirewall(executor.PolicyProjectPath(projectPath))
	if err != nil || !found {
		return nil, err
	}
	return &rec.Rules, nil
}

var firewallSourceOnce sync.Once

// installFirewallSource wires the control plane into pkg/fwpolicy. Idempotent,
// and called from registerBuiltinExecutors for the reason the ceiling lookups
// are installed on the dispatch path: a Server built as a struct literal must
// still enforce the stored rules.
func installFirewallSource() {
	firewallSourceOnce.Do(func() { fwpolicy.SetSource(controlPlaneFirewalls{}) })
}

// applyFirewall composes the stored firewall levels for one workload on ex and
// records the result on spec, refusing the dispatch when they do not nest or
// cannot be enforced there. A workload under no stored rule set is unchanged.
func applyFirewall(spec executor.Spec, ex executor.Executor, workDir string) (executor.Spec, error) {
	installFirewallSource()
	res, err := fwpolicy.Resolve(&spec, ex, workDir)
	if err != nil {
		state.LogEvent(workDir, state.EventRow{
			Type:    state.EventFirewall,
			Step:    state.NoStep,
			Message: "firewall refused this run: " + err.Error(),
		})
		return spec, err
	}
	if res.Applied() {
		// The project's own event log, where whoever wonders why a fetch timed
		// out will look: which levels shaped this run, and what came of them.
		state.LogEvent(workDir, state.EventRow{
			Type:    state.EventFirewall,
			Step:    state.NoStep,
			Message: fmt.Sprintf("%s on executor %s", res.Describe(), ex.ID()),
		})
	}
	return spec, nil
}
