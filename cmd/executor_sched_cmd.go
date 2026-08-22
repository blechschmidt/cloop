package cmd

// executor_sched_cmd.go is the operator's control surface for the fleet's
// *scheduling* state (Task 20162), as opposed to executor_cmd.go's inventory of
// what is configured. `cloop executor list` answers "what backends exist and
// what do they isolate"; `cloop executor ls` answers "which of them is alive,
// how loaded are they, and when did we last hear from one".
//
// The three mutating commands exist because before them the only way to stop
// sending work to a misbehaving node was to delete it, which also killed
// whatever it was already running. Cordon/uncordon/drain separate "take it out
// of rotation" from "destroy it":
//
//	cordon    stop new placement, leave in-flight work alone
//	uncordon  put it back, at whatever health its probes actually justify
//	drain     stop new placement and wait for in-flight to reach zero
//
// The supervisor these commands build is a *client* of the persisted state, not
// a running prober: it is never Start()ed. A CLI invocation lives for
// milliseconds, and a probe loop spun up for that long would only add latency,
// half-finished health writes, and a thundering herd against a fleet of edge
// devices every time somebody typed `cloop executor ls`. Reading and writing
// the same rows the long-lived control plane maintains is the whole point — a
// cordon typed here is honoured by the server there.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// drainPollInterval is how often a waiting drain re-reads the in-flight count.
// Two seconds is short enough that the progress line tracks reality and long
// enough that a drain of an hour-long task is not a busy loop against SQLite.
const drainPollInterval = 2 * time.Second

// openScheduler opens the control plane's scheduling state and wires a
// supervisor over it, mirroring openExecutorStore's shape.
//
// Like enrollment, health and session rows live in the control plane's own
// database rather than any managed project's: a node is not owned by a project,
// and its cordon must outlive whichever project happened to notice it was sick.
//
// The returned supervisor is deliberately not started. See the file comment.
func openScheduler() (*executor.Supervisor, *executorstore.Scheduler, func(), error) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("determine working directory: %w", err)
	}
	db, err := statedb.Open(state.DBPath(workdir))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open control-plane database: %w", err)
	}
	sched, err := executorstore.NewScheduler(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}
	sv := executor.NewSupervisor(executor.DefaultRegistry, executor.DefaultSupervisorConfig(),
		executor.WithHealthStore(sched),
		executor.WithSessionStore(sched),
		// "cli" rather than "supervisor": an audit entry for a cordon should
		// say a human ordered it, not that a probe loop decided it.
		executor.WithEventSink(sched.WithActor("cli")),
	)
	return sv, sched, func() { _ = db.Close() }, nil
}

// schedNode is one row of `cloop executor ls`, and the full record --json
// emits. executor.Health is embedded so the JSON carries every persisted field
// (failure counter, last probe, state-change time) rather than only the four
// the table has room for.
type schedNode struct {
	executor.Health
	// Kind is the driver implementation, empty for a health row whose
	// executor is not registered in this process.
	Kind string `json:"kind,omitempty"`
	// Registered reports presence in the live registry. A false value means
	// the row survives from an earlier configuration: the cordon is still
	// honoured, but nothing here can dispatch to it.
	Registered bool   `json:"registered"`
	Isolation  string `json:"isolation,omitempty"`
	Default    bool   `json:"default,omitempty"`
	// InFlight is the number of running sessions, valid only when
	// InFlightKnown. An unreadable count renders as "-" rather than "0",
	// because claiming a node is idle when it may be saturated is the worse
	// of the two wrong answers.
	InFlight      int  `json:"in_flight"`
	InFlightKnown bool `json:"in_flight_known"`
	// Schedulable is whether placement would consider this node right now.
	Schedulable bool `json:"schedulable"`

	// These three shadow the embedded Health's timestamps in the JSON output.
	// encoding/json's omitempty does not omit a zero struct, so a node that
	// has never been probed would otherwise report last_seen as
	// "0001-01-01T00:00:00Z" — a timestamp a consumer has every reason to
	// believe. A field at shallower depth wins the name, so these emit null
	// (or nothing) instead. The Go names differ so `n.LastSeen` still reaches
	// the real value.
	SeenAt    *time.Time `json:"last_seen,omitempty"`
	ProbedAt  *time.Time `json:"last_probe,omitempty"`
	ChangedAt *time.Time `json:"state_changed_at,omitempty"`
}

// timePtr renders a timestamp for JSON, mapping the zero time to nil.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

var executorLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "Show fleet scheduling state: health, in-flight work, and last contact",
	Long: `List every executor with the state the scheduler places work on.

This is the fleet-health view; ` + "`cloop executor list`" + ` is the inventory view (what
each backend isolates). The states are:

  ready        probes succeeding; takes new work
  degraded     probes failing but not given up on; takes work as a last resort
  unreachable  probes failed past the threshold; takes no work, in-flight work
               is failed over to another node
  cordoned     an operator took it out of rotation; in-flight work continues
  draining     an operator is retiring it; done when in-flight reaches zero

An executor that has never been probed by this control plane shows as ready
with a last-seen of "never": refusing to schedule on a backend merely because
the supervisor has not reached its first tick would make every fresh install
briefly unable to run anything.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")

		sv, sched, closeDB, err := openScheduler()
		if err != nil {
			return err
		}
		defer closeDB()

		nodes := collectSchedNodes(sv, sched)

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(nodes)
		}

		if len(nodes) == 0 {
			fmt.Println("No executors are registered.")
			return nil
		}

		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)
		now := time.Now()

		header.Printf("%-20s %-14s %-12s %-9s %-12s %s\n",
			"ID", "KIND", "STATE", "IN-FLIGHT", "LAST-SEEN", "REASON")
		for _, n := range nodes {
			kind := n.Kind
			if kind == "" {
				kind = "-"
			}
			inFlight := "-"
			if n.InFlightKnown {
				inFlight = fmt.Sprintf("%d", n.InFlight)
			}
			reason := truncate(n.Reason, 40)
			if !n.Registered {
				reason = strings.TrimSpace(reason + " [not registered here]")
			}
			fmt.Printf("%-20s %-14s %s %-9s %-12s %s\n",
				truncate(n.ExecutorID, 20), truncate(kind, 14),
				padColored(colorNodeState(n.State), string(n.State), 12),
				inFlight, relativeAge(n.LastSeen, now), reason)
		}
		dim.Println("\nTake a node out of rotation with `cloop executor cordon <id>`, " +
			"retire it with `cloop executor drain <id>`.")
		return nil
	},
}

// collectSchedNodes joins the registry with the persisted health and session
// rows.
//
// It is a union rather than a walk of either side alone. A registered executor
// with no health row is the normal state of a fresh control plane and must
// appear (as ready/never). A health row with no registration is a backend whose
// config section was removed while it was cordoned; hiding it would make the
// operator wonder where their cordon went.
func collectSchedNodes(sv *executor.Supervisor, sched *executorstore.Scheduler) []schedNode {
	byID := make(map[string]*schedNode)
	defaultID := executor.DefaultRegistry.DefaultID()

	for _, ex := range executor.List() {
		id := ex.ID()
		byID[id] = &schedNode{
			// Supervisor.Health normalizes a missing row into "ready", which
			// is the same answer placement gets, so the table cannot disagree
			// with the scheduler.
			Health:     sv.Health(id),
			Kind:       ex.Kind(),
			Registered: true,
			Isolation:  string(ex.Capabilities().Isolation),
			Default:    id == defaultID,
		}
	}
	if rows, err := sched.ListHealth(); err == nil {
		for _, h := range rows {
			if _, ok := byID[h.ExecutorID]; ok {
				continue
			}
			byID[h.ExecutorID] = &schedNode{Health: h.Normalize()}
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]schedNode, 0, len(ids))
	for _, id := range ids {
		n := byID[id]
		if count, err := sched.CountRunning(id); err == nil {
			n.InFlight, n.InFlightKnown = count, true
		}
		n.Schedulable = n.State.Schedulable()
		n.SeenAt, n.ProbedAt, n.ChangedAt =
			timePtr(n.LastSeen), timePtr(n.LastProbe), timePtr(n.StateChangedAt)
		out = append(out, *n)
	}
	return out
}

var executorCordonCmd = &cobra.Command{
	Use:   "cordon <executor-id>",
	Short: "Stop placing new work on an executor, without disturbing what it is running",
	Long: `Take an executor out of the scheduler's rotation.

In-flight work continues to completion — only new placement is refused. This is
the command for "something looks wrong with edge-1, stop giving it work while I
look at it", and unlike revoking or deleting the executor it does not kill the
task that is running there right now.

A cordon is admin-held: no probe result can lift it, so a node that answers a
health check three seconds later does not silently re-enter rotation. Failures
keep being counted while it is held, which is what lets ` + "`uncordon`" + ` restore the
state the evidence actually supports.

The cordon is persisted, so a long-lived control plane and the Web UI honour it
too.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		reason, _ := cmd.Flags().GetString("reason")

		sv, _, closeDB, err := openScheduler()
		if err != nil {
			return err
		}
		defer closeDB()

		before := sv.Health(id).State
		h, err := sv.Cordon(id, reason)
		if err != nil {
			return err
		}
		dim := color.New(color.Faint)

		if before == h.State {
			fmt.Printf("%s is already %s.\n", id, colorNodeState(h.State))
			if h.Reason != "" {
				dim.Printf("  reason: %s\n", h.Reason)
			}
			return nil
		}
		printStateChange(id, before, h)
		dim.Printf("New work goes elsewhere; in-flight work continues. "+
			"Return it to rotation with `cloop executor uncordon %s`.\n", id)
		return nil
	},
}

var executorUncordonCmd = &cobra.Command{
	Use:   "uncordon <executor-id>",
	Short: "Return a cordoned or draining executor to the scheduler's rotation",
	Long: `Undo a cordon or a drain.

Uncordon does not unconditionally return the node to "ready". It returns it to
the state its probe history justifies: a node cordoned because it was
misbehaving, and still failing its probes, comes back degraded or unreachable.
Otherwise uncordon would be a way to launder a broken node into the schedulable
set, and the next task placed on it would fail for exactly the reason the
operator just told the system to ignore.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		sv, _, closeDB, err := openScheduler()
		if err != nil {
			return err
		}
		defer closeDB()

		before := sv.Health(id).State
		h, err := sv.Uncordon(id)
		if err != nil {
			return err
		}
		dim := color.New(color.Faint)
		warn := color.New(color.FgYellow, color.Bold)

		if !before.AdminHeld() {
			fmt.Printf("%s is %s; it was not cordoned, so nothing changed.\n", id, colorNodeState(h.State))
			return nil
		}
		printStateChange(id, before, h)

		if h.State == executor.NodeReady {
			return nil
		}
		// The interesting case: the operator asked for the node back and got
		// something other than ready. Saying so here is the difference between
		// "uncordon is broken" and "your node is still sick".
		warn.Printf("Came back %s rather than ready: %d consecutive probe failure(s).\n",
			h.State, h.ConsecutiveFailures)
		if h.State.Schedulable() {
			dim.Println("It will take work, but placement prefers a ready node.")
		} else {
			dim.Println("It takes no new work until a probe succeeds. " +
				"Check it with `cloop executor test " + id + "`.")
		}
		return nil
	},
}

var executorDrainCmd = &cobra.Command{
	Use:   "drain <executor-id>",
	Short: "Retire an executor: refuse new work and wait for in-flight work to finish",
	Long: `Take an executor out of rotation and wait for it to go idle.

Draining differs from cordoning only in intent: somebody is waiting for the
in-flight count to reach zero so the machine can be rebooted, reimaged, or
unplugged. New placement is refused immediately; running work is left alone.

The node STAYS draining whether or not the wait succeeds — the timeout governs
how long this command blocks, not whether the drain took effect. Put it back in
rotation with ` + "`cloop executor uncordon <id>`" + `.

Exit codes:
  0  the node reached zero in-flight sessions (or --force was given)
  2  the timeout elapsed with work still running`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		timeout, _ := cmd.Flags().GetDuration("timeout")
		force, _ := cmd.Flags().GetBool("force")

		sv, sched, closeDB, err := openScheduler()
		if err != nil {
			return err
		}
		defer closeDB()

		before := sv.Health(id).State
		h, err := sv.Drain(id, "")
		if err != nil {
			return err
		}
		ok := color.New(color.FgGreen, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		dim := color.New(color.Faint)

		if before == h.State {
			fmt.Printf("%s is already %s.\n", id, colorNodeState(h.State))
		} else {
			printStateChange(id, before, h)
		}

		remaining, waitErr := waitForDrain(cmd.Context(), sv, sched, id, timeout)
		switch {
		case waitErr == nil:
			ok.Printf("%s is drained: no sessions are in flight.\n", id)
			dim.Printf("It stays out of rotation until `cloop executor uncordon %s`.\n", id)
			return nil

		case errors.Is(waitErr, executor.ErrDrainTimeout) && force:
			warn.Printf("Timed out after %s with %d session(s) still running on %s.\n",
				timeout, remaining, id)
			dim.Printf("--force: not waiting any longer. %s stays draining and accepts no new "+
				"work; the %d running session(s) are still running and were not touched.\n",
				id, remaining)
			return nil

		case errors.Is(waitErr, executor.ErrDrainTimeout):
			return errExit{code: 2, err: fmt.Errorf(
				"%w\n\n%s is still draining with %d session(s) in flight after %s. It accepts no "+
					"new work either way. Wait longer with --timeout (0 waits indefinitely), stop "+
					"waiting with --force, or return it to rotation with `cloop executor uncordon %s`",
				waitErr, id, remaining, timeout, id)}

		default:
			return waitErr
		}
	},
}

// waitForDrain blocks until the executor is idle, reporting progress whenever
// the in-flight count changes.
//
// Supervisor.WaitForDrain is the authority on when the drain is done and on the
// timeout; it just has no progress callback. So the wait runs in a goroutine and
// this loop reads the count alongside it purely to print. An operator draining a
// node holding a 40-minute task needs to see the number falling, otherwise the
// only honest reading of a silent terminal is "this hung".
func waitForDrain(
	ctx context.Context,
	sv *executor.Supervisor,
	sched *executorstore.Scheduler,
	id string,
	timeout time.Duration,
) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		remaining int
		err       error
	}
	done := make(chan result, 1)
	// Cancelled on return so the waiter cannot outlive this call and write to
	// a database handle the caller is about to close.
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		n, err := sv.WaitForDrain(waitCtx, id, timeout, drainPollInterval)
		done <- result{n, err}
	}()

	dim := color.New(color.Faint)
	last := -1
	report := func() {
		n, err := sched.CountRunning(id)
		if err != nil || n == last || n == 0 {
			return
		}
		last = n
		dim.Printf("waiting for %d session(s)…\n", n)
	}
	report()

	ticker := time.NewTicker(drainPollInterval)
	defer ticker.Stop()
	for {
		select {
		case res := <-done:
			return res.remaining, res.err
		case <-ticker.C:
			report()
		}
	}
}

// printStateChange renders an admin transition the same way the event log does.
func printStateChange(id string, from executor.NodeState, h executor.Health) {
	fmt.Printf("%s: %s -> %s\n", id, from, colorNodeState(h.State))
	if h.Reason != "" {
		color.New(color.Faint).Printf("  reason: %s\n", h.Reason)
	}
}

// colorNodeState colours a scheduling state by what an operator should do about
// it: green needs nothing, yellow is watching, red is broken, cyan is a
// deliberate human decision rather than a fault.
func colorNodeState(s executor.NodeState) string {
	switch s {
	case executor.NodeReady:
		return color.New(color.FgGreen).Sprint(string(s))
	case executor.NodeDegraded:
		return color.New(color.FgYellow).Sprint(string(s))
	case executor.NodeUnreachable:
		return color.New(color.FgRed).Sprint(string(s))
	case executor.NodeCordoned, executor.NodeDraining:
		return color.New(color.FgCyan).Sprint(string(s))
	default:
		return string(s)
	}
}

// padColored left-aligns a coloured cell to width using the *uncoloured*
// length. fmt counts the ANSI escape bytes, so "%-12s" on a coloured string
// pads it several characters short and shears every column to its right.
func padColored(colored, plain string, width int) string {
	if pad := width - len(plain); pad > 0 {
		return colored + strings.Repeat(" ", pad)
	}
	return colored
}

// relativeAge renders a timestamp as a short human age: "12s ago", "4m ago",
// "never".
//
// A fleet table is read by scanning for the outlier, and "3 minutes ago" versus
// "2026-08-21T09:14:02Z" is the difference between spotting the dead node
// immediately and doing arithmetic on six rows of RFC 3339. Resolution
// deliberately coarsens with age: nobody cares whether a node was last seen 61
// or 74 seconds ago, but the difference between seconds and days is the whole
// signal.
func relativeAge(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	if d < 0 {
		// Clock skew between the control plane that wrote the row and this
		// process. "in 4s" would be noise; treat the future as now.
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func init() {
	executorLsCmd.Flags().Bool("json", false,
		"emit the full health and load records as JSON")

	executorCordonCmd.Flags().String("reason", "",
		"why the node is being taken out of rotation (shown in `cloop executor ls` and the audit log)")

	executorDrainCmd.Flags().Duration("timeout", 5*time.Minute,
		"how long to wait for in-flight work to finish (0 waits indefinitely)")
	executorDrainCmd.Flags().Bool("force", false,
		"stop waiting when the timeout elapses instead of failing; the node stays draining")

	executorCmd.AddCommand(executorLsCmd)
	executorCmd.AddCommand(executorCordonCmd)
	executorCmd.AddCommand(executorUncordonCmd)
	executorCmd.AddCommand(executorDrainCmd)
}
