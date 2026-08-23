package cmd

// worktree_cmd.go is the operator's view of the git worktrees parallel task
// execution leaves on disk (Task 20191).
//
// The hub prunes on its own at startup, but deliberately does the conservative
// half only: it removes directories older than a grace period and never
// touches a branch. That is the right default for something that runs
// unattended on every restart — an unmerged cloop/task-N-* branch is the only
// copy of that task's work, and a sweep that guesses wrong destroys it with no
// way back.
//
// So the branch half needs a human, and this is where they say so. `list` is
// what they read first, `prune --dry-run` is what they read second, and
// `--delete-branches` is the deliberate act. That last flag still cannot
// delete unmerged work: pkg/worktree gates it on `git for-each-ref --merged`
// and then uses `git branch -d` rather than `-D`, so being wrong about the
// merge base fails the delete instead of losing the commits.

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/worktree"
)

var worktreeCmd = &cobra.Command{
	Use:   "worktree",
	Short: "Inspect and clean up the git worktrees used for parallel task execution",
	Long: `When cloop runs tasks in parallel it gives each one its own git worktree
under .cloop/worktrees/task-<id>, on a branch named cloop/task-<id>-<slug>,
so concurrent tasks cannot step on each other's files. The worktree is
removed and the branch merged when the task finishes.

A run that is killed between those two points leaves both behind. The hub
collects the directories on its next start; the branches it leaves for you,
because an unmerged one is the only copy of that task's work.`,
}

var worktreeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List task worktrees and the task branches that outlived them",
	Long: `List every cloop task worktree under .cloop/worktrees, whether git still
registers it, and how old it is — plus the cloop/task-* branches present in
the repository.

Two shapes are both leaks and both appear here: a directory git no longer
knows about (its administrative entry was pruned) and a registration whose
directory is gone (the tree was deleted by hand).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		entries, err := worktree.List(dir)
		if err != nil {
			return err
		}
		branches, err := worktree.ListBranches(dir)
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		if len(entries) == 0 {
			fmt.Println("No task worktrees.")
		} else {
			header.Printf("%-8s %-38s %-10s %-10s %s\n", "TASK", "BRANCH", "DIR", "GIT", "AGE")
			for _, e := range entries {
				age := "—"
				if !e.ModTime.IsZero() {
					age = time.Since(e.ModTime).Round(time.Minute).String()
				}
				fmt.Printf("%-8d %-38s %-10s %-10s %s\n",
					e.TaskID, orDash(e.Branch), yesNo(e.DirExists), yesNo(e.Registered), age)
			}
		}

		if len(branches) > 0 {
			sort.Strings(branches)
			fmt.Println()
			header.Printf("%d task branch(es):\n", len(branches))
			for _, b := range branches {
				fmt.Printf("  %s\n", b)
			}
			dim.Println("\nBranches are never removed automatically. `cloop worktree prune " +
				"--delete-branches` removes the ones already merged into the base branch.")
		}
		return nil
	},
}

var worktreePruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Remove leaked task worktrees, and optionally their merged branches",
	Long: `Remove task worktrees left behind by a crashed parallel run.

Only worktrees older than --min-age are touched. That guard is what makes the
command safe to run against a repository with work in progress: a live
parallel run's worktrees are in that directory right now, and removing one
destroys in-flight work irrecoverably. Pass --min-age 0 only when you know
nothing is running.

--delete-branches additionally removes cloop/task-* branches whose commits are
already contained in the base branch. A branch that is not merged is kept and
reported, and the check is enforced twice — by an explicit merged-ref query
and by using 'git branch -d' rather than '-D' — so an error in the first
still cannot destroy unmerged work.

Start with --dry-run.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		minAge, _ := cmd.Flags().GetDuration("min-age")
		deleteBranches, _ := cmd.Flags().GetBool("delete-branches")
		base, _ := cmd.Flags().GetString("base")

		// Cobra cannot distinguish "--min-age 0" from "flag absent", and the
		// two must mean different things here: absent has to inherit
		// worktree.DefaultMinAge, while an explicit zero is the operator
		// disabling the guard. pkg/worktree spells that as a negative value.
		if cmd.Flags().Changed("min-age") && minAge == 0 {
			minAge = -1
		}

		res, err := worktree.Prune(dir, worktree.PruneOptions{
			DryRun:         dryRun,
			MinAge:         minAge,
			DeleteBranches: deleteBranches,
			BaseBranch:     base,
		})
		if err != nil {
			return err
		}

		dim := color.New(color.Faint)
		for _, e := range res.Removed {
			verb := "removed"
			if res.DryRun {
				verb = "would remove"
			}
			line := fmt.Sprintf("%s task-%d (%s)", verb, e.TaskID, e.Path)
			switch {
			case e.BranchDeleted:
				line += fmt.Sprintf(" and branch %s", e.Branch)
			case e.BranchKept != "":
				line += fmt.Sprintf("; branch %s kept: %s", e.Branch, e.BranchKept)
			}
			fmt.Println(line)
		}
		for _, k := range res.Kept {
			dim.Printf("kept task-%d: %s\n", k.TaskID, k.Reason)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
		fmt.Println(res.Summary())

		// A wedged worktree is worth a non-zero exit so a cleanup script does
		// not report success while leaving the leak in place.
		if len(res.Errors) > 0 {
			return fmt.Errorf("%d worktree(s) could not be pruned", len(res.Errors))
		}
		return nil
	},
}

// yesNo renders a presence flag. orDash lives in hub_key_cmd.go.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func init() {
	worktreePruneCmd.Flags().Bool("dry-run", false,
		"report what would be removed without changing anything")
	worktreePruneCmd.Flags().Duration("min-age", 0,
		fmt.Sprintf("only prune worktrees idle for at least this long (default %s; 0 disables the guard)",
			worktree.DefaultMinAge))
	worktreePruneCmd.Flags().Bool("delete-branches", false,
		"also delete cloop/task-* branches that are already merged into the base branch")
	worktreePruneCmd.Flags().String("base", "",
		"branch to test merged-ness against (default: the currently checked-out branch)")

	worktreeCmd.AddCommand(worktreeListCmd)
	worktreeCmd.AddCommand(worktreePruneCmd)
	rootCmd.AddCommand(worktreeCmd)
}
