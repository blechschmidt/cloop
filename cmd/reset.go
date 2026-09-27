package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset progress (keep goal, clear steps)",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}

		s.Steps = []state.StepResult{}
		s.CurrentStep = 0
		s.Status = "initialized"
		if err := s.Save(); err != nil {
			return err
		}

		color.Green("✓ Progress reset. Goal preserved: %s", s.Goal)
		return nil
	},
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove .cloop directory entirely",
	Long: `Remove the project's .cloop directory: its task list, history and settings.

A project with features (cloop feature) keeps them in .cloop/features, each a
git worktree that may hold uncommitted work. clean refuses to delete those
unless --force is given, and then removes each through git so the repository
does not keep records of worktrees that no longer exist. Their branches are
kept.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		force, _ := cmd.Flags().GetBool("force")
		features, _ := feature.List(workdir)
		orphans, _ := feature.Orphans(workdir)
		if n := len(features) + len(orphans); n > 0 {
			if !force {
				return fmt.Errorf("this project has %d feature worktree(s) under .cloop/features, which can hold "+
					"uncommitted work — remove them with 'cloop feature remove', or pass --force to delete them too "+
					"(their branches are kept)", n)
			}
			if multiui.IsCloopRunningUnder(feature.Dir(workdir)) {
				return errors.New("a feature has a run in progress — stop it first")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			slugs := make([]string, 0, len(features)+len(orphans))
			for _, f := range features {
				slugs = append(slugs, f.Meta.Slug)
			}
			// A half-made feature (no record) is still a registered, locked
			// worktree: remove it through git too, or its lock outlives it.
			for dir := range orphans {
				if feature.ValidSlug(filepath.Base(dir)) == nil {
					slugs = append(slugs, filepath.Base(dir))
				}
			}
			for _, slug := range slugs {
				if _, err := featureops.Remove(ctx, featureops.RemoveOptions{
					ProjectDir: workdir, Slug: slug, Force: true,
				}); err != nil {
					return fmt.Errorf("remove feature %s: %w", slug, err)
				}
			}
		}
		if err := os.RemoveAll(fmt.Sprintf("%s/.cloop", workdir)); err != nil {
			return err
		}
		color.Green("✓ Removed .cloop/")
		return nil
	},
}

func init() {
	cleanCmd.Flags().Bool("force", false, "also delete the project's feature worktrees, discarding uncommitted work in them")
	rootCmd.AddCommand(resetCmd)
	rootCmd.AddCommand(cleanCmd)
}
