package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/ical"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var icalOutput string

var taskIcalCmd = &cobra.Command{
	Use:   "ical",
	Short: "Export task schedule as an iCalendar file (RFC 5545)",
	Long: `Export tasks with deadlines and estimated durations as a VCALENDAR document
importable into Google Calendar, Outlook, Apple Calendar, and any RFC 5545
compliant calendar application.

Each task is exported as a VTODO component with:
  - UID        — stable identifier (cloop-task-<id>)
  - SUMMARY    — task title
  - DESCRIPTION — task description
  - DUE        — deadline (if set)
  - DTSTART    — deadline minus EstimatedMinutes (or 1h before deadline)
  - STATUS     — COMPLETED / IN-PROCESS / NEEDS-ACTION / CANCELLED
  - PRIORITY   — P0→1 (highest), P1→2, P2→5, P3→9 (lowest)
  - CATEGORIES — task tags
  - DURATION   — estimated duration in ISO 8601 format

Examples:
  cloop task ical                          # print to stdout
  cloop task ical --output tasks.ics       # write to file
  cloop task ical -o ~/Desktop/sprint.ics  # write to absolute path`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		cal := ical.Build(s.Plan)

		if icalOutput == "" || icalOutput == "-" {
			fmt.Print(cal)
			return nil
		}

		if err := os.WriteFile(icalOutput, []byte(cal), 0o644); err != nil {
			return fmt.Errorf("writing iCalendar file: %w", err)
		}

		successColor := color.New(color.FgGreen)
		dimColor := color.New(color.Faint)
		successColor.Printf("Exported %d task(s) to %s\n", len(s.Plan.Tasks), icalOutput)
		dimColor.Printf("  Import into Google Calendar: Settings > Import\n")
		dimColor.Printf("  Import into Apple Calendar:  File > Import\n")
		dimColor.Printf("  Import into Outlook:         File > Open & Export > Import/Export\n")
		return nil
	},
}

func init() {
	taskIcalCmd.Flags().StringVarP(&icalOutput, "output", "o", "", "Output file path (default: stdout)")
	taskCmd.AddCommand(taskIcalCmd)
}
