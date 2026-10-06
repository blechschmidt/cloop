package cmd

// executor_list_inventory.go is `cloop executor list --inventory`: the
// registered backends, then what the fleet looks like underneath them — each
// enrolled device's hardware and build, and the tasks failover has quarantined
// for taking nodes down (Task 20391).

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// printFleetInventory prints the sections --inventory adds to the listing.
// Every section degrades on its own: a control plane whose database cannot be
// read still gets the backend table above it.
func printFleetInventory(header, dim *color.Color) error {
	store, db, err := openExecutorStore()
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Println()
	header.Println("Enrolled devices")
	agents, err := store.ListAgents()
	switch {
	case err != nil:
		dim.Printf("  could not read the enrolled agents: %v\n", err)
	case len(agents) == 0:
		dim.Println("  none")
	default:
		inventory := map[string]statedb.ExecutorInventory{}
		sequences := map[string]int{}
		if rows, lErr := db.ListExecutors(); lErr == nil {
			for _, r := range rows {
				inventory[r.ID] = r.Inventory
				sequences[r.ID] = remote.StoredBuildSequence(r.Capabilities)
			}
		}
		for _, a := range agents {
			st := "active"
			if a.Revoked() {
				st = "revoked"
			}
			fmt.Printf("  %-20s %-16s %s\n", a.AgentID, a.Name, st)
			printAgentInventory(dim, inventory[a.AgentID], sequences[a.AgentID])
		}
	}

	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		return err
	}
	return printSuspectedNodeKillers(header, dim, sched)
}

// suspectedNodeKiller is one quarantined task, located.
type suspectedNodeKiller struct {
	project string
	task    statedb.QuarantinedTask
}

// printSuspectedNodeKillers lists every task quarantined as a suspected node
// killer, in every project a failover has touched and in this hub's own.
func printSuspectedNodeKillers(header, dim *color.Color, sched *executorstore.Scheduler) error {
	fmt.Println()
	header.Println("Suspected node killers (held until an explicit reset)")
	found, problems := collectSuspectedNodeKillers(sched)
	for _, p := range problems {
		dim.Printf("  note: %s\n", p)
	}
	if len(found) == 0 {
		dim.Println("  none")
		return nil
	}
	warn := color.New(color.FgYellow, color.Bold)
	for _, f := range found {
		title := f.task.Title
		if title == "" {
			title = "(task no longer in the plan)"
		}
		warn.Printf("  %s  task #%d  %s\n", f.project, f.task.TaskID, title)
		nodes := pm.DistinctNodes(f.task.Mark.Nodes)
		dim.Printf("      %d node(s) lost: %s\n", len(nodes), pm.DescribeNodeLosses(f.task.Mark.Nodes))
		if !f.task.Mark.MarkedAt.IsZero() {
			dim.Printf("      marked:  %s\n", f.task.Mark.MarkedAt.UTC().Format("2006-01-02T15:04:05Z"))
		}
		dim.Printf("      release: (cd %s && cloop task reset %d)\n", shellQuote(f.project), f.task.TaskID)
	}
	return nil
}

// collectSuspectedNodeKillers reads the quarantined tasks of every project a
// session was failed over for, plus the hub's own directory. Each project's
// database is only peeked at: this command must not migrate a project it is
// merely reporting on.
func collectSuspectedNodeKillers(sched *executorstore.Scheduler) ([]suspectedNodeKiller, []string) {
	var problems []string
	projects, err := sched.FailedOverProjects()
	if err != nil {
		problems = append(problems, fmt.Sprintf("could not read which projects failed over: %v", err))
	}
	if wd, err := os.Getwd(); err == nil {
		projects = append(projects, wd)
	}
	seen := map[string]bool{}
	var out []suspectedNodeKiller
	for _, p := range projects {
		p = filepath.Clean(p)
		if seen[p] || !filepath.IsAbs(p) {
			continue
		}
		seen[p] = true
		dbPath := state.DBPath(p)
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		marked, err := statedb.PeekTaskQuarantines(dbPath)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		for _, q := range marked {
			out = append(out, suspectedNodeKiller{project: p, task: q})
		}
	}
	return out, problems
}
