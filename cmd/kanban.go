package cmd

import (
	"os"

	"github.com/blechschmidt/cloop/pkg/kanban"
	"github.com/spf13/cobra"
)

var kanbanCmd = &cobra.Command{
	Use:   "kanban",
	Short: "Interactive terminal kanban board",
	Long: `Launch a full-screen kanban board with four columns:
  Pending | In Progress | Done | Failed/Skipped

Keyboard shortcuts:
  ← / →   switch column
  ↑ / ↓   navigate tasks within column
  enter    view task details
  d        mark selected task as done
  f        mark selected task as failed
  s        mark selected task as skipped
  r        enter move mode (pick a new column with ← → then enter to drop)
  a        add a new task
  q        quit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		return kanban.Run(workdir)
	},
}

func init() {
	rootCmd.AddCommand(kanbanCmd)
}
