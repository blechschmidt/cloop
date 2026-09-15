package cmd

// `cloop audit-log --task <id>` — one task's whole story (Task 20282).
//
// The compliance question this exists to answer is:
//
//	which executor ran task 63, under which secret leases, and how did it end?
//
// Before this, answering it meant reading task.upsert rows and inferring status
// transitions from the differences between consecutive payloads, then guessing
// which of the project's secret.lease rows belonged to the run in question by
// comparing timestamps. Both halves were inference. This renders the answer.
//
// The reconstruction underneath (pkg/statedb.ReconstructTask) reads audit_events
// and no other table, which is what makes this a proof of the trail's
// sufficiency rather than a pretty view over the plan. That restriction is
// enforced by a test, not just documented here.

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/fatih/color"
)

// runAuditLogTask reconstructs and prints one task's history.
func runAuditLogTask(taskID int) error {
	log, err := openAuditLog()
	if err != nil {
		return err
	}
	defer log.Close()

	story, err := log.ReconstructTask(taskID)
	if err != nil {
		return err
	}
	printTaskStory(story)
	return nil
}

// printTaskStory renders the reconstruction.
//
// Written to stdout so it can be piped; the "nothing found" advice goes to
// stderr so a script redirecting stdout gets an empty file rather than prose it
// would have to parse around.
func printTaskStory(story eventlog.TaskStory) {
	var (
		bold = color.New(color.Bold)
		dim  = color.New(color.Faint)
		red  = color.New(color.FgRed)
		grn  = color.New(color.FgGreen)
		ylw  = color.New(color.FgYellow)
	)

	title := story.Title
	if title == "" {
		title = "(no title recorded in the trail)"
	}
	bold.Printf("Task #%d — %s\n", story.TaskID, title)

	if len(story.Runs) == 0 {
		dim.Printf("%d audit row(s) name this task, none of them an execution.\n", story.Unattributed)
		fmt.Fprintf(os.Stderr,
			"\nNo dispatch has been recorded for task %d. That is expected for a task "+
				"that never ran, or one whose history predates the task.dispatch event "+
				"(Task 20282). It is NOT expected for a task the plan shows as done — "+
				"if it is, the trail has a gap.\n", story.TaskID)
		if len(story.Events) > 0 {
			fmt.Println()
			printStoryEvents(story.Events, dim)
		}
		return
	}

	// Plural is the interesting case and the reason the run id exists: a task
	// that ran five times has five sets of credentials, and a reader who
	// assumes one would attribute four of them wrongly.
	dim.Printf("%d execution(s) recorded\n", len(story.Runs))

	for i, run := range story.Runs {
		fmt.Println()
		bold.Printf("── run %d/%d  %s\n", i+1, len(story.Runs), run.RunID)

		executor := run.ExecutorID
		if executor == "" {
			executor = "(unregistered)"
		}
		fmt.Printf("   executor    %s", executor)
		if run.ExecutorKind != "" {
			fmt.Printf("  kind=%s", run.ExecutorKind)
		}
		if run.Isolation != "" {
			fmt.Printf("  isolation=%s", run.Isolation)
		}
		fmt.Println()
		if run.RanOnHost() {
			// The hub's headline claim is that the web UI never spawns a
			// harness on the host. This is the row that would disprove it, so
			// it is called out rather than left for the reader to infer from
			// "isolation=none".
			ylw.Println("   ⚠ ran on the hub's own machine, with its filesystem and network")
		}
		if run.Actor != "" {
			fmt.Printf("   actor       %s\n", run.Actor)
		}
		if run.PinnedImage != "" {
			fmt.Printf("   image       %s", run.PinnedImage)
			if !strings.Contains(run.PinnedImage, "@sha256:") {
				ylw.Printf("  (tag, not a digest — not reproducible)")
			}
			fmt.Println()
		}
		if run.SpecHash != "" {
			fmt.Printf("   sandbox     spec sha256:%s\n", short(run.SpecHash))
		}

		printRunCredentials(run, dim)

		switch {
		case run.Finished == nil:
			ylw.Println("   outcome     no terminal row — still running, or the hub died holding it")
		default:
			outcome := run.Outcome
			c := grn
			if outcome == "failed" || outcome == "timed_out" || outcome == "pending" {
				c = red
			}
			fmt.Printf("   outcome     ")
			c.Printf("%s", outcome)
			if d := run.Duration(); d != "" {
				dim.Printf("  after %s", d)
			}
			fmt.Println()
			if run.Reason != "" {
				fmt.Printf("   reason      %s\n", run.Reason)
			}
		}
	}

	fmt.Println()
	bold.Println("── trail")
	printStoryEvents(story.Events, dim)
}

// printRunCredentials renders what the run held, distinguishing the two
// independent records of it.
func printRunCredentials(run eventlog.TaskRunStory, dim *color.Color) {
	if len(run.LeaseIDs) == 0 && len(run.LeaseEvents) == 0 {
		fmt.Printf("   leases      none\n")
		return
	}
	if len(run.LeaseIDs) > 0 {
		fmt.Printf("   leases      %s\n", strings.Join(run.LeaseIDs, ", "))
	}
	for _, ev := range run.LeaseEvents {
		dim.Printf("               %s  %s  %s\n",
			ev.Timestamp.UTC().Format("2006-01-02 15:04:05"), ev.EventType, ev.EntityID)
	}
	if len(run.LeaseEvents) == 0 {
		// The dispatch row claims credentials the broker has no row for. That
		// is the shape a forged lease list would take, since the dispatch row's
		// ids come through a file the workload can write.
		dim.Println("               (no broker rows corroborate these ids)")
	}
}

// printStoryEvents prints the raw rows behind the summary, so a reader can
// check the rendering against the evidence rather than trusting it.
func printStoryEvents(events []eventlog.AuditEvent, dim *color.Color) {
	for _, ev := range events {
		dim.Printf("  %6d  ", ev.ID)
		fmt.Printf("%s  %-22s %-10s %s\n",
			ev.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			ev.EventType, ev.Actor, ev.EntityType+"/"+ev.EntityID)
	}
}

// short truncates a hex digest for display. The full value stays in the raw
// rows below, so nothing is lost by shortening it in the summary.
func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
