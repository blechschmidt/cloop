package cmd

// `cloop remote move cleanup` (Task 20494): remove what an ended project move
// kept — the snapshot refs it wrote into the project's repository and its
// bundle in the hub's move store. A move never removes its source by itself;
// a done move's record names this command. The project's directory on the hub
// is its home and is never removed.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var remoteMoveCmd = &cobra.Command{
	Use:   "move",
	Short: "Clean up after a project's moves",
}

var remoteMoveCleanupCmd = &cobra.Command{
	Use:   "cleanup <project> <move-id>",
	Short: "Remove the snapshot refs and the bundle an ended move kept",
	Long: `Remove what an ended move of a project kept: the snapshot of its working tree
on refs/cloop/move/<id> (and the move's other hidden refs) in the project's
repository, and the move's bundle and files in the hub's move store. The
project's directory on the hub stays: it holds the project's state and its
features.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		id := strings.TrimSpace(args[1])
		var out struct {
			Move struct {
				ID       string `json:"id"`
				Phase    string `json:"phase"`
				Retained *struct {
					Refs      []string `json:"refs"`
					Store     string   `json:"store"`
					CleanedAt string   `json:"cleaned_at"`
				} `json:"retained"`
			} `json:"move"`
		}
		if err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/projects/%d/moves/%s/cleanup", p.Idx, id), nil, map[string]any{}, &out); err != nil {
			return remoteErr(c, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Cleaned up after move %s of %s (%s).\n", out.Move.ID, p.Name, out.Move.Phase)
		return nil
	},
}

func init() {
	remoteMoveCmd.AddCommand(remoteMoveCleanupCmd)
	remoteCmd.AddCommand(remoteMoveCmd)
}
