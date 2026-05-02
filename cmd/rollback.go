package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var rollbackYes bool

var rollbackCmd = &cobra.Command{
	Use:   "rollback [snapshot-id]",
	Short: "Restore the plan to a previous snapshot",
	Long: `List available plan snapshots or restore the plan to a chosen one.

Without an argument, prints a numbered list of all snapshots with their
timestamp and task counts so you can pick the version you want.

With a snapshot ID (version number), prompts for confirmation and then
replaces the current plan with the snapshot's plan.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		if len(args) == 0 {
			return runRollbackList(workdir)
		}
		return runRollbackRestore(workdir, args[0])
	},
}

func runRollbackList(workdir string) error {
	metas, err := pm.ListSnapshots(workdir)
	if err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}
	if len(metas) == 0 {
		fmt.Println("No plan snapshots found. Snapshots are saved automatically during PM-mode runs.")
		return nil
	}

	fmt.Printf("%-6s  %-20s  %5s  %s\n", "ID", "Timestamp", "Tasks", "Summary")
	fmt.Println(strings.Repeat("-", 72))
	for _, m := range metas {
		ts := m.Timestamp.Local().Format("2006-01-02 15:04:05")
		summary := m.Summary
		if len(summary) > 40 {
			summary = summary[:37] + "..."
		}
		fmt.Printf("v%-5d  %-20s  %5d  %s\n", m.Version, ts, m.TaskCount, summary)
	}
	fmt.Printf("\nUse 'cloop rollback <ID>' to restore a snapshot (e.g. cloop rollback %d).\n",
		metas[len(metas)-1].Version)
	return nil
}

func runRollbackRestore(workdir, snapshotID string) error {
	// Strip optional "v" prefix so both "3" and "v3" work.
	id := strings.TrimPrefix(snapshotID, "v")

	plan, err := pm.RestoreSnapshot(workdir, id)
	if err != nil {
		return err
	}

	// Show what we are about to restore.
	done, total := 0, len(plan.Tasks)
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone {
			done++
		}
	}
	fmt.Printf("Snapshot v%s  —  %d tasks (%d done)\n", id, total, done)
	fmt.Printf("Goal: %s\n\n", plan.Goal)

	if !rollbackYes {
		fmt.Print("Restore this snapshot? Current plan will be overwritten. [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Rollback cancelled.")
			return nil
		}
	}

	// Load current state and replace the plan.
	s, err := state.Load(workdir)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	s.Plan = plan
	s.PMMode = true
	if err := s.Save(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	fmt.Printf("Plan restored to snapshot v%s (%d tasks).\n", id, total)
	return nil
}

func init() {
	rollbackCmd.Flags().BoolVarP(&rollbackYes, "yes", "y", false, "Skip confirmation prompt")
	rootCmd.AddCommand(rollbackCmd)
}
