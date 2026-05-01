package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloop",
	Short: "Autonomous feedback loop for Claude Code",
	Long: `cloop wraps Claude Code in a goal-driven feedback loop.

Define a project goal, and cloop will autonomously drive Claude Code
through multiple iterations until the goal is complete.

  cloop init "Build a REST API with user auth and CRUD endpoints"
  cloop run
  cloop status
  cloop log`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
