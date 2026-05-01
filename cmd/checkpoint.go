package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const checkpointDir = ".cloop/checkpoints"

var checkpointCmd = &cobra.Command{
	Use:   "checkpoint",
	Short: "Save, restore, or list named state snapshots",
	Long: `Manage named checkpoints of your cloop project state.

Checkpoints let you save the current plan and task progress, then restore
it if a run goes wrong or you want to experiment safely.

Examples:
  cloop checkpoint save before-deploy
  cloop checkpoint list
  cloop checkpoint restore before-deploy
  cloop checkpoint delete before-deploy`,
}

var checkpointSaveCmd = &cobra.Command{
	Use:   "save [name]",
	Short: "Save current state as a named checkpoint",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		src := filepath.Join(workdir, ".cloop", "state.json")
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("no cloop project state found: %w", err)
		}

		name := time.Now().Format("20060102-150405")
		if len(args) > 0 {
			name = sanitizeName(args[0])
		}

		dir := filepath.Join(workdir, checkpointDir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating checkpoint directory: %w", err)
		}

		dst := filepath.Join(dir, name+".json")
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("saving checkpoint: %w", err)
		}

		color.New(color.FgGreen, color.Bold).Printf("✓ Checkpoint saved: %s\n", name)
		color.New(color.Faint).Printf("  Restore with: cloop checkpoint restore %s\n", name)
		return nil
	},
}

var checkpointRestoreCmd = &cobra.Command{
	Use:   "restore <name>",
	Short: "Restore state from a named checkpoint",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		name := sanitizeName(args[0])
		src := filepath.Join(workdir, checkpointDir, name+".json")
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("checkpoint %q not found: %w", name, err)
		}

		// Back up current state before overwriting
		currentState := filepath.Join(workdir, ".cloop", "state.json")
		if cur, readErr := os.ReadFile(currentState); readErr == nil {
			backupDir := filepath.Join(workdir, checkpointDir)
			backupName := "pre-restore-" + time.Now().Format("20060102-150405")
			_ = os.WriteFile(filepath.Join(backupDir, backupName+".json"), cur, 0o644)
			color.New(color.Faint).Printf("  Current state backed up as: %s\n", backupName)
		}

		if err := os.WriteFile(currentState, data, 0o644); err != nil {
			return fmt.Errorf("restoring checkpoint: %w", err)
		}

		color.New(color.FgGreen, color.Bold).Printf("✓ Restored checkpoint: %s\n", name)
		return nil
	},
}

var checkpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all saved checkpoints",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		dir := filepath.Join(workdir, checkpointDir)

		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No checkpoints found. Use 'cloop checkpoint save <name>' to create one.")
				return nil
			}
			return fmt.Errorf("listing checkpoints: %w", err)
		}

		type cpEntry struct {
			name    string
			modTime time.Time
			size    int64
		}
		var checkpoints []cpEntry
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			info, _ := e.Info()
			checkpoints = append(checkpoints, cpEntry{
				name:    strings.TrimSuffix(e.Name(), ".json"),
				modTime: info.ModTime(),
				size:    info.Size(),
			})
		}

		if len(checkpoints) == 0 {
			fmt.Println("No checkpoints found. Use 'cloop checkpoint save <name>' to create one.")
			return nil
		}

		// Sort newest first
		sort.Slice(checkpoints, func(i, j int) bool {
			return checkpoints[i].modTime.After(checkpoints[j].modTime)
		})

		header := color.New(color.FgCyan, color.Bold)
		header.Printf("Checkpoints (%d):\n", len(checkpoints))
		dim := color.New(color.Faint)
		for _, cp := range checkpoints {
			fmt.Printf("  %-40s", cp.name)
			dim.Printf("  %s  (%s)\n", cp.modTime.Format("2006-01-02 15:04:05"), formatBytes(cp.size))
		}
		return nil
	},
}

var checkpointDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm"},
	Short:   "Delete a named checkpoint",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		name := sanitizeName(args[0])
		path := filepath.Join(workdir, checkpointDir, name+".json")
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("checkpoint %q not found", name)
			}
			return fmt.Errorf("deleting checkpoint: %w", err)
		}
		color.New(color.FgGreen).Printf("✓ Deleted checkpoint: %s\n", name)
		return nil
	},
}

func init() {
	checkpointCmd.AddCommand(checkpointSaveCmd)
	checkpointCmd.AddCommand(checkpointRestoreCmd)
	checkpointCmd.AddCommand(checkpointListCmd)
	checkpointCmd.AddCommand(checkpointDeleteCmd)
	rootCmd.AddCommand(checkpointCmd)
}

// sanitizeName replaces path separators and whitespace to produce a safe filename.
func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", "\\", "-", " ", "-", "..", "")
	return r.Replace(s)
}

func formatBytes(b int64) string {
	const kb = 1024
	if b < kb {
		return fmt.Sprintf("%dB", b)
	}
	return fmt.Sprintf("%.1fKB", float64(b)/kb)
}
