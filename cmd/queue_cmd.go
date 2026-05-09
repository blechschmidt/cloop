package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blechschmidt/cloop/pkg/taskqueue"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	queueLimit      int
	queueKindFilter string
	queueStatusFlag string
)

var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Show the central work queue (every PM task, heal retry, evolve cycle, external merge)",
	Long: `Display recent entries from the central work queue.

Every unit of work cloop performs is recorded here:
  - PM task executions (kind=task)
  - Auto-heal retries  (kind=heal)
  - Evolve discovery cycles (kind=evolve)
  - Externally-added tasks merged in (kind=external)
  - Session-level work like decompose (kind=session)

This is the single source of truth for "what cloop has been doing."`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		q, err := taskqueue.Open(workdir)
		if err != nil {
			return fmt.Errorf("opening queue: %w", err)
		}
		defer q.Close()

		opts := taskqueue.ListOptions{Limit: queueLimit}
		if queueKindFilter != "" {
			opts.Kind = taskqueue.Kind(queueKindFilter)
		}
		if queueStatusFlag != "" {
			opts.Status = taskqueue.Status(queueStatusFlag)
		}

		entries, err := q.List(opts)
		if err != nil {
			return fmt.Errorf("listing queue: %w", err)
		}

		stats, _ := q.Stats()
		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		header.Printf("\n  Work Queue (%s)\n", workdir)
		dim.Printf("  Running: %d  Queued: %d  Done: %d  Failed: %d  Skipped: %d\n\n",
			stats[taskqueue.StatusRunning],
			stats[taskqueue.StatusQueued],
			stats[taskqueue.StatusDone],
			stats[taskqueue.StatusFailed],
			stats[taskqueue.StatusSkipped],
		)

		if len(entries) == 0 {
			dim.Printf("  No queue entries yet.\n\n")
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  ID\tKIND\tSTATUS\tTASK\tDURATION\tTITLE\n")
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			"——", "———", "—————", "—", "———", "—————")
		for _, e := range entries {
			tasked := "—"
			if e.TaskID != 0 {
				tasked = fmt.Sprintf("#%d", e.TaskID)
			}
			dur := "—"
			if e.StartedAt != nil {
				end := time.Now()
				if e.CompletedAt != nil {
					end = *e.CompletedAt
				}
				dur = end.Sub(*e.StartedAt).Round(time.Second).String()
			}
			title := e.Title
			if len(title) > 60 {
				title = title[:57] + "…"
			}
			title = strings.ReplaceAll(title, "\n", " ")
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\t%s\n",
				e.ID, e.Kind, statusColor(e.Status), tasked, dur, title)
		}
		tw.Flush()
		fmt.Println()
		return nil
	},
}

func statusColor(s taskqueue.Status) string {
	switch s {
	case taskqueue.StatusDone:
		return color.New(color.FgGreen).Sprintf("%s", s)
	case taskqueue.StatusFailed:
		return color.New(color.FgRed).Sprintf("%s", s)
	case taskqueue.StatusRunning:
		return color.New(color.FgCyan).Sprintf("%s", s)
	case taskqueue.StatusSkipped:
		return color.New(color.Faint).Sprintf("%s", s)
	default:
		return string(s)
	}
}

func init() {
	queueCmd.Flags().IntVarP(&queueLimit, "limit", "n", 50, "Max rows to show")
	queueCmd.Flags().StringVar(&queueKindFilter, "kind", "", "Filter by kind: task|heal|evolve|external|session")
	queueCmd.Flags().StringVar(&queueStatusFlag, "status", "", "Filter by status: queued|running|done|failed|skipped")
	rootCmd.AddCommand(queueCmd)
}
