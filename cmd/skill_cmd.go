package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/skill"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage reusable prompt skill macros",
	Long: `Manage reusable prompt skill macros stored in .cloop/skills/<name>.md.

Skills are named prompt fragments that can be referenced in task descriptions
and prompts using the {{skill:name}} syntax. When cloop builds the execution
prompt for a task it automatically expands all skill references.

Built-in skills (always available):
  tdd       Write tests first — test-driven development checklist
  secure    OWASP security checklist reminder
  minimal   No over-engineering principle

Subcommands:
  list              Show all available skills
  show <name>       Print the content of a skill
  add  <name>       Create or edit a skill (opens $EDITOR)
  delete <name>     Remove a user-defined skill`,
}

var skillListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all available skills",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		skills, err := skill.List(workDir)
		if err != nil {
			return err
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		builtinColor := color.New(color.Faint)
		nameColor := color.New(color.FgWhite, color.Bold)

		headerColor.Printf("%-20s  %-8s  %s\n", "NAME", "TYPE", "PREVIEW")
		fmt.Println(strings.Repeat("─", 72))

		for _, s := range skills {
			typeLabel := "user"
			if s.Builtin {
				typeLabel = "builtin"
			}

			// Build a single-line preview (first non-empty, non-header line).
			preview := ""
			for _, line := range strings.Split(s.Content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				preview = line
				break
			}
			if len(preview) > 48 {
				preview = preview[:48] + "..."
			}

			nameColor.Printf("%-20s", s.Name)
			if s.Builtin {
				builtinColor.Printf("  %-8s", typeLabel)
			} else {
				color.New(color.FgGreen).Printf("  %-8s", typeLabel)
			}
			builtinColor.Printf("  %s\n", preview)
		}

		fmt.Printf("\nUsage in task descriptions: {{skill:name}}\n")
		return nil
	},
}

var skillShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Print the content of a skill",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		s, err := skill.Get(workDir, args[0])
		if err != nil {
			return err
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		typeLabel := "builtin"
		if !s.Builtin {
			typeLabel = "user"
		}
		headerColor.Printf("Skill: %s [%s]\n\n", s.Name, typeLabel)
		fmt.Print(s.Content)
		if !strings.HasSuffix(s.Content, "\n") {
			fmt.Println()
		}
		return nil
	},
}

var skillAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Create or edit a skill (opens $EDITOR)",
	Long: `Create a new skill or edit an existing one. The skill content is opened
in $EDITOR (falls back to vi). The file is saved to .cloop/skills/<name>.md.

Example:
  cloop skill add my-style
  cloop skill add tdd   # override the built-in tdd skill`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		name := args[0]

		// Seed with existing content (user file or built-in).
		initial := ""
		if existing, err := skill.Get(workDir, name); err == nil {
			initial = existing.Content
		}

		// Write to a temp file for editing.
		tmp, err := os.CreateTemp("", "cloop-skill-*.md")
		if err != nil {
			return fmt.Errorf("creating temp file: %w", err)
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)

		if _, err := tmp.WriteString(initial); err != nil {
			tmp.Close()
			return fmt.Errorf("writing temp file: %w", err)
		}
		tmp.Close()

		// Open in editor.
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = os.Getenv("VISUAL")
		}
		if editor == "" {
			editor = "vi"
		}

		editorCmd := exec.Command(editor, tmpPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w", err)
		}

		// Read back the edited content.
		data, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("reading edited file: %w", err)
		}
		content := string(data)

		if strings.TrimSpace(content) == "" {
			fmt.Println("Empty content — skill not saved.")
			return nil
		}

		if err := skill.Save(workDir, name, content); err != nil {
			return err
		}

		path := filepath.Join(workDir, ".cloop", "skills", name+".md")
		color.New(color.FgGreen).Printf("Skill %q saved → %s\n", name, path)
		return nil
	},
}

var skillDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a user-defined skill",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		name := args[0]
		if err := skill.Delete(workDir, name); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Skill %q deleted.\n", name)
		return nil
	},
}

func init() {
	skillCmd.AddCommand(skillListCmd)
	skillCmd.AddCommand(skillShowCmd)
	skillCmd.AddCommand(skillAddCmd)
	skillCmd.AddCommand(skillDeleteCmd)
	rootCmd.AddCommand(skillCmd)
}
