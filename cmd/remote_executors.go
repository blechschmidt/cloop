package cmd

// `cloop remote executors` (Task 20417): the executors a project of yours may
// be bound to — GET /api/executors, as the Executors panel calls it, narrowed
// to the ones an administrator has made available to you. An executor whose
// access list does not include you is not offered: binding a project to it
// would be refused, and so would every run.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var remoteExecutorsCmd = &cobra.Command{
	Use:   "executors",
	Short: "List the executors you may run projects on",
	Long: `List the executors on the hub that are open to you: every executor without an
access list, and those whose access list an administrator put you on. One you
could bind but that cannot run anything now — blocked by the hub's policy, or not
connected — is listed with the reason.

Bind a new project to one with ` + "`cloop remote init --executor <id>`" + `. Binding is
an administrator's decision on a hub with role mappings (executor.manage); without
it the project runs on the hub's default executor.`,
	Args: cobra.NoArgs,
	RunE: runRemoteExecutors,
}

// executorsView is what `executors --json` prints.
type executorsView struct {
	Hub       string               `json:"hub"`
	DefaultID string               `json:"default_id"`
	Executors []hubclient.Executor `json:"executors"`
}

func runRemoteExecutors(cmd *cobra.Command, _ []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	list, err := c.Executors(remoteContext(cmd))
	if err != nil {
		return remoteErr(c, err)
	}
	open := availableExecutors(list)
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(executorsView{Hub: c.Base, DefaultID: list.DefaultID, Executors: open})
	}
	if len(open) == 0 {
		fmt.Fprintf(out, "No executor on %s is open to you. Ask an administrator to put you on one's access list "+
			"(Executors → the executor → Access).\n", c.Base)
		return nil
	}
	printExecutors(out, open, list.DefaultID)
	return nil
}

// availableExecutors is the executors the caller may use, in the hub's order
// with the default first: everything not restricted, and the restricted ones
// whose access list admits them.
func availableExecutors(list *hubclient.ExecutorList) []hubclient.Executor {
	out := make([]hubclient.Executor, 0, len(list.Executors))
	for _, e := range list.Executors {
		if e.Admitted {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ID == list.DefaultID && out[j].ID != list.DefaultID
	})
	return out
}

func printExecutors(out io.Writer, execs []hubclient.Executor, defaultID string) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tKIND\tISOLATION\tSTATUS\tNOTES")
	for _, e := range execs {
		var notes []string
		if e.ID == defaultID {
			notes = append(notes, "the hub's default")
		}
		if e.Restricted {
			notes = append(notes, "restricted; you are on its access list")
		}
		if e.Virtual != nil && e.Virtual.Parent != "" {
			notes = append(notes, "virtual, on "+e.Virtual.Parent)
		}
		if ok, why := e.Usable(); !ok {
			notes = append(notes, "cannot run now: "+why)
		}
		status := orDash(e.Status)
		if e.SchedState != "" && e.SchedState != "ready" {
			status += " (" + e.SchedState + ")"
		}
		name := e.Name
		if name == "" || name == e.ID {
			name = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, truncateField(name, 24), orDash(e.Kind),
			orDash(e.Isolation), status, strings.Join(notes, "; "))
	}
	_ = w.Flush()
}

// resolveExecutor finds the executor ref names — its id, or its name — among
// those open to the caller. An executor that exists but whose access list
// does not admit the caller is refused here with the reason, as the hub would
// refuse the binding.
func resolveExecutor(list *hubclient.ExecutorList, ref string) (hubclient.Executor, error) {
	ref = strings.TrimSpace(ref)
	var byName []hubclient.Executor
	for _, e := range list.Executors {
		if e.ID == ref {
			return admittedExecutor(e, list)
		}
		if strings.EqualFold(e.Name, ref) {
			byName = append(byName, e)
		}
	}
	switch len(byName) {
	case 1:
		return admittedExecutor(byName[0], list)
	case 0:
		return hubclient.Executor{}, fmt.Errorf("no executor %q on this hub; the ones open to you: %s "+
			"(see `cloop remote executors`)", ref, executorIDs(availableExecutors(list)))
	}
	ids := make([]string, 0, len(byName))
	for _, e := range byName {
		ids = append(ids, e.ID)
	}
	return hubclient.Executor{}, fmt.Errorf("%q names %d executors — use an id: %s", ref, len(byName), strings.Join(ids, ", "))
}

func admittedExecutor(e hubclient.Executor, list *hubclient.ExecutorList) (hubclient.Executor, error) {
	if !e.Admitted {
		return hubclient.Executor{}, fmt.Errorf("executor %q is restricted and your account is not on its access list — "+
			"ask an administrator to admit you, or choose one that is open to you: %s",
			e.ID, executorIDs(availableExecutors(list)))
	}
	if ok, why := e.Usable(); !ok {
		return hubclient.Executor{}, fmt.Errorf("executor %q cannot run anything now: %s", e.ID, why)
	}
	return e, nil
}

func executorIDs(execs []hubclient.Executor) string {
	if len(execs) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(execs))
	for _, e := range execs {
		ids = append(ids, e.ID)
	}
	return strings.Join(ids, ", ")
}

func init() {
	remoteExecutorsCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	remoteCmd.AddCommand(remoteExecutorsCmd)
}
