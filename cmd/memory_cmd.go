package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var memoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Manage the project's persistent memory (cross-session learnings)",
	Long: `Manage the project's persistent memory stored in .cloop/memory.json.

Memory entries are key learnings extracted from past sessions that are injected
into future session prompts via --use-memory. Use --learn to auto-extract
learnings at the end of a session.`,
}

var memoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored memory entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		mem, err := memory.Load(workdir)
		if err != nil {
			return err
		}
		if len(mem.Entries) == 0 {
			fmt.Println("No memory entries stored. Run with --learn to start accumulating knowledge.")
			return nil
		}
		header := color.New(color.FgCyan, color.Bold)
		header.Printf("Project Memory (%d entries)\n\n", len(mem.Entries))
		for _, e := range mem.Entries {
			age := memory.FormatAge(e.Timestamp)
			source := ""
			if e.Source == "user" {
				source = " [user]"
			}
			fmt.Printf("  #%d [%s ago%s] %s\n", e.ID, age, source, e.Content)
		}
		return nil
	},
}

var memoryAddCmd = &cobra.Command{
	Use:   "add <content>",
	Short: "Manually add a memory entry",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		mem, err := memory.Load(workdir)
		if err != nil {
			return err
		}
		content := strings.Join(args, " ")
		e := mem.Add(content, "user", "", nil)
		if err := mem.Save(workdir); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Added memory #%d: %s\n", e.ID, content)
		return nil
	},
}

var memoryClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete all memory entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		mem, err := memory.Load(workdir)
		if err != nil {
			return err
		}
		count := len(mem.Entries)
		mem.Clear()
		if err := mem.Save(workdir); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Cleared %d memory entries.\n", count)
		return nil
	},
}

var memoryDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a specific memory entry by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		var id int
		if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
			return fmt.Errorf("invalid ID %q: %w", args[0], err)
		}
		mem, err := memory.Load(workdir)
		if err != nil {
			return err
		}
		if !mem.Delete(id) {
			return fmt.Errorf("no memory entry with ID %d", id)
		}
		if err := mem.Save(workdir); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Deleted memory #%d.\n", id)
		return nil
	},
}

func init() {
	memoryCmd.AddCommand(memoryListCmd)
	memoryCmd.AddCommand(memoryAddCmd)
	memoryCmd.AddCommand(memoryClearCmd)
	memoryCmd.AddCommand(memoryDeleteCmd)
	rootCmd.AddCommand(memoryCmd)
}
