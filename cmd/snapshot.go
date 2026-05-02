package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/snapshot"
	"github.com/spf13/cobra"
)

var snapshotYes bool

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Atomic backup and restore of the full .cloop directory",
	Long: `Manage full-project snapshots of the .cloop directory.

Snapshots are stored as gzip-compressed tar archives in .cloop/snapshots/.
They capture everything: state.db, config.yaml, secrets, the knowledge base,
artifacts, plan history, env vars, and any other .cloop files.

Use snapshots as a safety net before risky operations like cloop rollback,
cloop pivot, or cloop run with destructive tasks.`,
}

var snapshotSaveCmd = &cobra.Command{
	Use:   "save [name]",
	Short: "Create a new snapshot",
	Long: `Create a timestamped .tar.gz snapshot of the full .cloop directory.

The optional name argument is a human-readable label that is embedded in the
snapshot filename, e.g. "before-refactor" → 20240112-150405-before-refactor.tar.gz.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		name := ""
		if len(args) == 1 {
			name = args[0]
		}

		fmt.Print("Creating snapshot... ")
		meta, err := snapshot.Save(workDir, name)
		if err != nil {
			fmt.Println("failed.")
			return err
		}
		fmt.Println("done.")
		fmt.Printf("  ID:      %s\n", meta.ID)
		if meta.Name != "" {
			fmt.Printf("  Name:    %s\n", meta.Name)
		}
		fmt.Printf("  Created: %s\n", meta.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		fmt.Printf("  Size:    %s\n", snapshotFormatBytes(meta.Size))
		fmt.Printf("  Path:    %s\n", meta.Path)
		return nil
	},
}

var snapshotListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available snapshots",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		metas, err := snapshot.List(workDir)
		if err != nil {
			return err
		}
		if len(metas) == 0 {
			fmt.Println("No snapshots found. Use 'cloop snapshot save' to create one.")
			return nil
		}

		fmt.Printf("%-35s  %-20s  %9s  %s\n", "ID", "Created", "Size", "Name")
		fmt.Println(strings.Repeat("-", 80))
		for _, m := range metas {
			ts := m.CreatedAt.Local().Format("2006-01-02 15:04:05")
			name := m.Name
			if name == "" {
				name = "-"
			}
			fmt.Printf("%-35s  %-20s  %9s  %s\n", m.ID, ts, snapshotFormatBytes(m.Size), name)
		}
		fmt.Printf("\n%d snapshot(s). Use 'cloop snapshot restore <id>' to restore.\n", len(metas))
		return nil
	},
}

var snapshotRestoreCmd = &cobra.Command{
	Use:   "restore <id>",
	Short: "Restore the .cloop directory from a snapshot",
	Long: `Extract a snapshot archive and replace the current .cloop directory contents.

The snapshots/ subdirectory is preserved so existing snapshots are not lost.
All other .cloop files are replaced with the contents of the selected snapshot.

You may supply a partial ID prefix as long as it uniquely identifies one snapshot.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		meta, err := snapshot.FindByPrefix(workDir, args[0])
		if err != nil {
			return err
		}

		fmt.Printf("Snapshot:  %s\n", meta.ID)
		if meta.Name != "" {
			fmt.Printf("Name:      %s\n", meta.Name)
		}
		fmt.Printf("Created:   %s\n", meta.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		fmt.Printf("Size:      %s\n\n", snapshotFormatBytes(meta.Size))

		if !snapshotYes {
			fmt.Print("Restore this snapshot? Current .cloop contents will be replaced. [y/N] ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Restore cancelled.")
				return nil
			}
		}

		fmt.Print("Restoring... ")
		if err := snapshot.Restore(workDir, meta.ID); err != nil {
			fmt.Println("failed.")
			return err
		}
		fmt.Println("done.")
		fmt.Printf("Restored snapshot %s.\n", meta.ID)
		return nil
	},
}

var snapshotDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a snapshot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		meta, err := snapshot.FindByPrefix(workDir, args[0])
		if err != nil {
			return err
		}

		if !snapshotYes {
			fmt.Printf("Delete snapshot %s (%s)? [y/N] ", meta.ID, snapshotFormatBytes(meta.Size))
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Delete cancelled.")
				return nil
			}
		}

		if err := snapshot.Delete(workDir, meta.ID); err != nil {
			return err
		}
		fmt.Printf("Snapshot %s deleted.\n", meta.ID)
		return nil
	},
}

func snapshotFormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func init() {
	snapshotSaveCmd.Flags().BoolVarP(&snapshotYes, "yes", "y", false, "Skip confirmation prompts")
	snapshotRestoreCmd.Flags().BoolVarP(&snapshotYes, "yes", "y", false, "Skip confirmation prompt")
	snapshotDeleteCmd.Flags().BoolVarP(&snapshotYes, "yes", "y", false, "Skip confirmation prompt")

	snapshotCmd.AddCommand(snapshotSaveCmd)
	snapshotCmd.AddCommand(snapshotListCmd)
	snapshotCmd.AddCommand(snapshotRestoreCmd)
	snapshotCmd.AddCommand(snapshotDeleteCmd)
	rootCmd.AddCommand(snapshotCmd)
}
