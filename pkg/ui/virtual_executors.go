package ui

// virtual_executors.go wires virtual executors (Task 20345) into the hub: it
// registers each stored one in the executor registry once its parent device is
// there, and puts what the Executors panel needs on their cards.
//
// Registration happens inside the agent hub's construction, right after the
// enrolled devices are restored, for the reason restoreEnrolledExecutors gives:
// a project bound to a virtual executor must resolve from the first request,
// not from whenever something happened to touch the hub. A virtual executor
// whose parent is gone (its enrollment revoked) is skipped with a log line and
// stays in the database, so the panel can show it and an admin can delete it;
// dispatching to it fails as "executor not registered", which is the truthful
// answer.

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// longLivedDBs are control-plane database handles that outlive any request,
// keyed by path. A virtual executor reads its configuration on every dispatch
// and every capability query — the Executors panel asks on each render — and
// statedb.Open is not a cheap accessor (it creates and migrates), so each
// virtual executor reads through one handle opened once. The agent hub's own
// handle is seeded in for its path, so production opens nothing extra.
var (
	longLivedDBMu sync.Mutex
	longLivedDBs  = map[string]*statedb.DB{}
)

// seedLongLivedDB registers an already-open handle for path.
func seedLongLivedDB(path string, db *statedb.DB) {
	longLivedDBMu.Lock()
	defer longLivedDBMu.Unlock()
	if _, ok := longLivedDBs[path]; !ok && db != nil {
		longLivedDBs[path] = db
	}
}

// longLivedDB returns the process-wide handle for path, opening it on first use.
func longLivedDB(path string) (*statedb.DB, error) {
	longLivedDBMu.Lock()
	defer longLivedDBMu.Unlock()
	if db, ok := longLivedDBs[path]; ok {
		return db, nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil, err
	}
	longLivedDBs[path] = db
	return db, nil
}

// virtualSpecSource reads a virtual executor's configuration on every dispatch,
// so an edit in the panel governs the next task.
func virtualSpecSource(dbPath, id string) remote.VirtualSource {
	return func() (executor.VirtualSpec, error) {
		db, err := longLivedDB(dbPath)
		if err != nil {
			return executor.VirtualSpec{}, fmt.Errorf("read virtual executor %s: %w", id, err)
		}
		v, ok, err := db.VirtualExecutor(id)
		if err != nil {
			return executor.VirtualSpec{}, err
		}
		if !ok {
			return executor.VirtualSpec{}, fmt.Errorf("virtual executor %s has been deleted", id)
		}
		return v.Spec, nil
	}
}

// registerVirtualExecutor builds and registers one virtual executor, replacing
// a previous registration under the same ID (a rename rebuilds it: the label is
// captured at construction).
//
// The parent is found in the registry rather than asked of the agent hub:
// every enrolled device is registered there from startup (Hub.Restore), and
// the registry is the one place both production and tests put executors.
func registerVirtualExecutor(dbPath string, v statedb.VirtualExecutor) error {
	parent, ok := remoteParent(v.ParentID)
	if !ok {
		return fmt.Errorf("parent device %s is not enrolled with this hub", v.ParentID)
	}
	vx, err := remote.NewVirtual(parent, v.ID, v.Name, virtualSpecSource(dbPath, v.ID))
	if err != nil {
		return err
	}
	if existing, err := executor.Get(v.ID); err == nil {
		if _, isVirtual := existing.(*remote.Virtual); !isVirtual {
			return fmt.Errorf("executor id %s is already taken by a %s executor", v.ID, existing.Kind())
		}
		executor.DefaultRegistry.Unregister(v.ID)
	}
	return executor.DefaultRegistry.Register(vx)
}

// remoteParent finds an enrolled device in the registry.
func remoteParent(id string) (*remote.Executor, bool) {
	ex, err := executor.Get(id)
	if err != nil {
		return nil, false
	}
	parent, ok := ex.(*remote.Executor)
	return parent, ok
}

// restoreVirtualExecutors registers every stored virtual executor.
func restoreVirtualExecutors(dbPath string, db *statedb.DB) {
	seedLongLivedDB(dbPath, db)
	rows, err := db.ListVirtualExecutors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ui: restore virtual executors: %v\n", err)
		return
	}
	for _, v := range rows {
		if err := registerVirtualExecutor(dbPath, v); err != nil {
			fmt.Fprintf(os.Stderr, "ui: virtual executor %s not registered: %v\n", v.ID, err)
		}
	}
}

// virtualExecutorSummary is what a card shows about a virtual executor.
type virtualExecutorSummary struct {
	ParentID   string `json:"parent_id"`
	ParentName string `json:"parent_name,omitempty"`
	// Firewall and Devices are one-line summaries; the editor fetches the
	// full configuration.
	Firewall string   `json:"firewall,omitempty"`
	Devices  []string `json:"devices,omitempty"`
	// Issue says why the device cannot apply this configuration right now —
	// no packet filter, an agent too old — so the card shows it before a task
	// fails on it.
	Issue string `json:"issue,omitempty"`
}

// applyVirtualExecutors annotates the virtual executors' cards, and the count
// of each device's virtual executors on its own card.
func applyVirtualExecutors(views []executorView, db *statedb.DB) []executorView {
	if db == nil || len(views) == 0 {
		return views
	}
	rows, err := db.ListVirtualExecutors()
	if err != nil || len(rows) == 0 {
		return views
	}
	byID := make(map[string]statedb.VirtualExecutor, len(rows))
	children := map[string]int{}
	for _, r := range rows {
		byID[r.ID] = r
		children[r.ParentID]++
	}
	names := make(map[string]string, len(views))
	for _, v := range views {
		names[v.ID] = v.Name
	}
	for i := range views {
		views[i].VirtualCount = children[views[i].ID]
		rec, ok := byID[views[i].ID]
		if !ok {
			continue
		}
		spec := rec.Spec
		sum := &virtualExecutorSummary{ParentID: rec.ParentID, ParentName: names[rec.ParentID]}
		if spec.Firewall != nil {
			sum.Firewall = spec.Firewall.Describe()
		}
		for _, d := range spec.Devices {
			sum.Devices = append(sum.Devices, d.Describe())
		}
		if ex, err := executor.Get(rec.ID); err == nil {
			if vx, ok := ex.(*remote.Virtual); ok {
				if norm, err := spec.Normalize(); err == nil {
					sum.Issue = virtualIssue(vx, norm)
				} else {
					sum.Issue = err.Error()
				}
			}
		} else {
			sum.Issue = "not registered: its device is not enrolled with this hub"
		}
		views[i].Virtual = sum
		views[i].Kind = executor.KindVirtual
		views[i].Sandbox = &executorSandboxSummary{
			Mode:       string(spec.Sandbox.Mode),
			Engine:     spec.Sandbox.Engine,
			Runtime:    spec.Sandbox.Runtime,
			Image:      spec.Sandbox.Image,
			Configured: true,
		}
		if spec.Firewall != nil {
			views[i].Sandbox.Network = "firewalled"
		} else {
			views[i].Sandbox.Network = spec.Sandbox.Network
		}
	}
	return views
}

// virtualIssue is the sentence a card shows when the device cannot apply the
// configuration, or "" when it can as far as the hub knows.
func virtualIssue(vx *remote.Virtual, spec executor.VirtualSpec) string {
	parent := vx.Parent()
	if spec.Firewall == nil && len(spec.Devices) == 0 {
		return ""
	}
	if v := parent.ProtocolVersion(); v > 0 && !remote.SupportsVirtualExecutor(v) {
		return fmt.Sprintf("its device's agent speaks protocol v%d; a firewall or devices need v%d — upgrade the agent",
			v, remote.MinVirtualExecutorVersion)
	}
	if spec.Firewall != nil && !parent.AgentCapabilities().PacketFilter {
		issue := strings.TrimSpace(parent.AgentCapabilities().PacketFilterIssue)
		if issue == "" {
			issue = "the device has not reported one"
		}
		return "its device cannot install the firewall: " + issue
	}
	return ""
}
