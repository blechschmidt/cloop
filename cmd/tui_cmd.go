package cmd

import (
	"os"

	"github.com/blechschmidt/cloop/pkg/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Terminal UI dashboard (alternative to cloop ui)",
	Long: `Launch a full-screen terminal dashboard for monitoring and controlling cloop.

The TUI shows:
  • Task list panel with status indicators and priority badges
  • Live log panel streaming the latest step output
  • Stats bar with token counts, cost estimate, and elapsed time

Keyboard shortcuts:
  r        run (cloop run in background)
  s        stop (write .cloop/stop signal)
  a        add a new task
  ↑ / k    move selection up
  ↓ / j    move selection down
  enter    show task detail / artifact
  q        quit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		return tui.Run(workdir)
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
