package cmd

// `cloop executor runner-storage` is what a runner volume's init container
// runs (Task 20484): it wipes the volume when the executor controller asks,
// keeps the subdirectories the pool's mounts name, holds the volume to its
// free-space floor, and reports on the container's termination log. It runs
// as the runner's own user, with the volume mounted and nothing else.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/kubecontroller"
)

var executorRunnerStorageCmd = &cobra.Command{
	Use:   "runner-storage",
	Short: "Prepare an executor pool runner's volume before the runner starts (an init container's command)",
	Long: `Prepare an executor pool runner's persistent volume, as the init container the
executor controller adds to a runner Pod does: empty it when --wipe is given
(it last held another project's data, or whose is unknown), keep the
subdirectories --dirs names and remove the others, and clear the caches — then
everything — when it has less than --min-free bytes free. A volume still under
the floor once empty fails the step, so the runner never starts on a disk its
run would fill. One line of JSON describing what was done goes to --report.`,
	Args:   cobra.NoArgs,
	Hidden: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		root, _ := cmd.Flags().GetString("root")
		dirs, _ := cmd.Flags().GetString("dirs")
		wipe, _ := cmd.Flags().GetBool("wipe")
		minFree, _ := cmd.Flags().GetInt64("min-free")
		report, _ := cmd.Flags().GetString("report")
		if strings.TrimSpace(root) == "" {
			return errors.New("--root is required")
		}
		if minFree < 0 {
			return errors.New("--min-free cannot be negative")
		}
		var keep []string
		for _, d := range strings.Split(dirs, ",") {
			if d = strings.TrimSpace(d); d != "" {
				keep = append(keep, d)
			}
		}
		rep, err := kubecontroller.PrepareStorage(kubecontroller.PrepareOptions{Root: root, Dirs: keep, Wipe: wipe,
			MinFree: minFree})
		if werr := rep.WriteReport(report); werr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "runner-storage: write the report to %s: %v\n", report, werr)
		}
		line, _ := jsonLine(rep)
		fmt.Fprintln(cmd.OutOrStdout(), line)
		if err != nil {
			return fmt.Errorf("runner-storage: %w", err)
		}
		return nil
	},
}

// jsonLine renders v as one line of JSON.
func jsonLine(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func init() {
	f := executorRunnerStorageCmd.Flags()
	f.String("root", "", "where the volume is mounted")
	f.String("dirs", "workspace,git,tools", "the subdirectories to keep, comma-separated: workspace, git, tools")
	f.Bool("wipe", false, "empty the volume first")
	f.Int64("min-free", 0, "the free bytes the runner must start with; 0 for no floor")
	f.String("report", "", "write the JSON report to this file as well (the container's termination log)")
	executorCmd.AddCommand(executorRunnerStorageCmd)
}
