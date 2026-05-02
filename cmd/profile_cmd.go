package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	profileProvider    string
	profileModel       string
	profileBaseURL     string
	profileAPIKey      string
	profileDescription string
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage named provider/model configuration profiles",
	Long: `Profiles let you maintain multiple named provider/model configurations
and switch between them instantly without editing config files.

Profiles are stored globally in ~/.cloop/profiles.yaml and work across projects.

Examples:
  cloop profile create dev --provider anthropic --model claude-opus-4-6
  cloop profile create local --provider ollama --model llama3.2
  cloop profile use dev
  cloop profile list
  cloop profile show dev
  cloop profile delete local`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles, err := profile.LoadProfiles()
		if err != nil {
			return err
		}
		active := profile.GetActive()

		if len(profiles) == 0 {
			fmt.Println("No profiles defined. Use 'cloop profile create <name>' to create one.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tPROVIDER\tMODEL\tDESCRIPTION")
		for _, p := range profiles {
			marker := "  "
			name := p.Name
			if p.Name == active {
				marker = "* "
				name = color.New(color.FgGreen, color.Bold).Sprint(p.Name)
			}
			fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\n", marker, name, p.Provider, p.Model, p.Description)
		}
		w.Flush()
		return nil
	},
}

var profileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create or overwrite a named profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if name == "" {
			return fmt.Errorf("profile name must not be empty")
		}

		p := profile.Profile{
			Name:        name,
			Provider:    profileProvider,
			Model:       profileModel,
			BaseURL:     profileBaseURL,
			APIKey:      profileAPIKey,
			Description: profileDescription,
		}

		if err := profile.Upsert(p); err != nil {
			return fmt.Errorf("saving profile: %w", err)
		}

		color.Green("✓ Profile %q saved", name)
		if p.Provider != "" {
			fmt.Printf("  Provider: %s\n", p.Provider)
		}
		if p.Model != "" {
			fmt.Printf("  Model:    %s\n", p.Model)
		}
		if p.BaseURL != "" {
			fmt.Printf("  Base URL: %s\n", p.BaseURL)
		}
		if p.Description != "" {
			fmt.Printf("  Desc:     %s\n", p.Description)
		}
		return nil
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the active profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// Verify the profile exists before setting it active.
		if _, err := profile.Get(name); err != nil {
			return err
		}

		if err := profile.SetActive(name); err != nil {
			return fmt.Errorf("setting active profile: %w", err)
		}
		color.Green("✓ Active profile set to %q", name)
		return nil
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Remove a named profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// Clear active profile if it was this one.
		if profile.GetActive() == name {
			if err := profile.SetActive(""); err != nil {
				return err
			}
		}

		if err := profile.Delete(name); err != nil {
			return fmt.Errorf("deleting profile: %w", err)
		}
		color.Green("✓ Profile %q deleted", name)
		return nil
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show details of a named profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		p, err := profile.Get(name)
		if err != nil {
			return err
		}
		active := profile.GetActive()

		activeLabel := ""
		if active == name {
			activeLabel = color.New(color.FgGreen).Sprint(" (active)")
		}
		fmt.Printf("Profile: %s%s\n", color.New(color.Bold).Sprint(p.Name), activeLabel)
		if p.Description != "" {
			fmt.Printf("  Description: %s\n", p.Description)
		}
		if p.Provider != "" {
			fmt.Printf("  Provider:    %s\n", p.Provider)
		}
		if p.Model != "" {
			fmt.Printf("  Model:       %s\n", p.Model)
		}
		if p.BaseURL != "" {
			fmt.Printf("  Base URL:    %s\n", p.BaseURL)
		}
		if p.APIKey != "" {
			masked := maskKey(p.APIKey)
			fmt.Printf("  API Key:     %s\n", masked)
		}
		return nil
	},
}

// maskKey masks all but the first 4 and last 4 characters of a key.
func maskKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}

func init() {
	profileCreateCmd.Flags().StringVar(&profileProvider, "provider", "", "Provider name (anthropic, openai, ollama, claudecode)")
	profileCreateCmd.Flags().StringVar(&profileModel, "model", "", "Model name")
	profileCreateCmd.Flags().StringVar(&profileBaseURL, "base-url", "", "Custom base URL for the provider API")
	profileCreateCmd.Flags().StringVar(&profileAPIKey, "api-key", "", "API key (stored in plain text in ~/.cloop/profiles.yaml)")
	profileCreateCmd.Flags().StringVar(&profileDescription, "description", "", "Human-readable description")

	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	profileCmd.AddCommand(profileShowCmd)

	rootCmd.AddCommand(profileCmd)
}
