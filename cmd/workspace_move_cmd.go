package cmd

// `cloop workspace move-seed`, `move-verify` and `move-probe` (Task 20494):
// the half of a project move that runs on the target. The hub dispatches them
// into the project's working directory on a device: move-probe says what the
// directory holds before a seed, move-seed turns a directory provisioned from
// the move's carrier branch into the project's working copy, and move-verify
// reports a seeded copy as it stands. Each prints one report line
// (projectmove.ReportMarker + JSON), which the hub compares with what it
// captured.
//
// `cloop workspace move-discard` (Task 20496) runs on the source instead: once
// a verified move's cleanup is confirmed, it removes the working copy the move
// left on the device — and nothing at all unless the copy is still the one the
// move captured (projectmove.DiscardWorkingCopy).
//
// None of them opens or creates a state database: a probe must find an empty
// directory empty, and the copy a seed builds is the project's working copy,
// not a place for the root command to reconcile executors into
// (seedsAMove, root.go).

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/projectmove"
)

var (
	workspaceMoveID string
	// What move-discard checks the copy against (Task 20496).
	workspaceMoveDiscard projectmove.DiscardOptions
)

var workspaceMoveSeedCmd = &cobra.Command{
	Use:    "move-seed",
	Short:  "Turn a directory provisioned from a project move's carrier into the project's working copy",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runWorkspaceMove(cmd, projectmove.SeedWorkingCopy)
	},
}

var workspaceMoveVerifyCmd = &cobra.Command{
	Use:    "move-verify",
	Short:  "Report a working copy a project move seeded, for the hub to compare with what it captured",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runWorkspaceMove(cmd, projectmove.ReportWorkingCopy)
	},
}

var workspaceMoveProbeCmd = &cobra.Command{
	Use:    "move-probe",
	Short:  "Say what a project's working directory holds before a project move seeds it",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runWorkspaceMove(cmd, projectmove.ProbeWorkingCopy)
	},
}

var workspaceMoveDiscardCmd = &cobra.Command{
	Use:    "move-discard",
	Short:  "Remove the working copy a verified project move left on this device, if it is unchanged since the capture",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if workspaceMoveDiscard.Snapshot == "" || workspaceMoveDiscard.Refs == "" || workspaceMoveDiscard.Files == "" {
			return errors.New("--snapshot, --refs and --files name what the move captured")
		}
		return runWorkspaceMove(cmd, func(ctx context.Context, dir, id string) (projectmove.WorkingCopyReport, error) {
			opts := workspaceMoveDiscard
			opts.MoveID = id
			return projectmove.DiscardWorkingCopy(ctx, dir, opts)
		})
	},
}

// runWorkspaceMove runs one of the move's steps in the current directory and
// prints its report.
func runWorkspaceMove(cmd *cobra.Command, step func(context.Context, string, string) (projectmove.WorkingCopyReport, error)) error {
	if workspaceMoveID == "" {
		return errors.New("--move names the move")
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	report, err := step(ctx, dir, workspaceMoveID)
	if err != nil {
		return err
	}
	line, err := projectmove.FormatReport(report)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), line)
	return nil
}

// seedsAMove reports whether cmd is one of the move's steps on a target.
func seedsAMove(cmd *cobra.Command) bool {
	switch cmd {
	case workspaceMoveSeedCmd, workspaceMoveVerifyCmd, workspaceMoveProbeCmd, workspaceMoveDiscardCmd:
		return true
	}
	return false
}

func init() {
	for _, c := range []*cobra.Command{workspaceMoveSeedCmd, workspaceMoveVerifyCmd, workspaceMoveProbeCmd, workspaceMoveDiscardCmd} {
		c.Flags().StringVar(&workspaceMoveID, "move", "", "the move's id")
		workspaceCmd.AddCommand(c)
	}
	f := workspaceMoveDiscardCmd.Flags()
	f.StringVar(&workspaceMoveDiscard.Snapshot, "snapshot", "", "the snapshot commit the move recorded")
	f.StringVar(&workspaceMoveDiscard.Refs, "refs", "", "the digest of the branches, tags and stash the move captured")
	f.StringVar(&workspaceMoveDiscard.Files, "files", "", "the digest of the .cloop files the move delivered")
	f.BoolVar(&workspaceMoveDiscard.DiscardIgnored, "discard-ignored", false, "remove the files git ignores too")
}
