package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/env"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage per-project environment variables",
	Long: `Store secrets and config values that are injected into task prompts and shell hooks.

Secret values (--secret) are stored base64-encoded in .cloop/env.yaml so they are
not in plain text, but you should still add .cloop/env.yaml to your .gitignore.

Placeholders in the form {{KEY}} inside task descriptions and prompts are
automatically replaced with the corresponding env variable value at runtime.`,
}

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all environment variables",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		vars, err := env.Load(workdir)
		if err != nil {
			return err
		}
		if len(vars) == 0 {
			color.New(color.Faint).Println("No environment variables set. Use 'cloop env set KEY value' to add one.")
			return nil
		}
		headerColor := color.New(color.Bold)
		secretColor := color.New(color.FgYellow)
		fmt.Printf("%-24s %-30s %s\n", headerColor.Sprint("KEY"), headerColor.Sprint("VALUE"), headerColor.Sprint("DESCRIPTION"))
		fmt.Println(strings.Repeat("─", 72))
		for _, v := range vars {
			val := env.DecodeValue(v)
			if v.Secret {
				val = secretColor.Sprint("****")
			}
			desc := v.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Printf("%-24s %-30s %s\n", v.Key, val, color.New(color.Faint).Sprint(desc))
		}
		return nil
	},
}

var envSetCmd = &cobra.Command{
	Use:   "set <KEY> <value>",
	Short: "Set an environment variable (upsert)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		key := args[0]
		value := args[1]

		isSecret, _ := cmd.Flags().GetBool("secret")
		description, _ := cmd.Flags().GetString("description")

		vars, err := env.Load(workdir)
		if err != nil {
			return err
		}

		v := env.Var{
			Key:         key,
			Value:       value,
			Description: description,
			Secret:      isSecret,
		}
		// Preserve secret flag from existing var if not specified.
		if existing, ok := env.Get(vars, key); ok && !cmd.Flags().Changed("secret") {
			v.Secret = existing.Secret
		}
		vars = env.Upsert(vars, v)
		if err := env.Save(workdir, vars); err != nil {
			return err
		}
		if isSecret {
			color.Green("✓ %s set (secret)", key)
		} else {
			color.Green("✓ %s set", key)
		}
		return nil
	},
}

var envGetCmd = &cobra.Command{
	Use:   "get <KEY>",
	Short: "Print the value of an environment variable",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		key := args[0]
		reveal, _ := cmd.Flags().GetBool("reveal")

		vars, err := env.Load(workdir)
		if err != nil {
			return err
		}
		v, ok := env.Get(vars, key)
		if !ok {
			return fmt.Errorf("env: key %q not found", key)
		}
		if v.Secret && !reveal {
			color.New(color.FgYellow).Printf("%s = ****  (use --reveal to show the value)\n", key)
			return nil
		}
		fmt.Printf("%s\n", env.DecodeValue(v))
		return nil
	},
}

var envDeleteCmd = &cobra.Command{
	Use:     "delete <KEY>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete an environment variable",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		key := args[0]

		vars, err := env.Load(workdir)
		if err != nil {
			return err
		}
		updated, ok := env.Delete(vars, key)
		if !ok {
			return fmt.Errorf("env: key %q not found", key)
		}
		if err := env.Save(workdir, updated); err != nil {
			return err
		}
		color.Green("✓ %s deleted", key)
		return nil
	},
}

var envExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print shell export statements for all env vars",
	Long: `Output 'export KEY=value' lines suitable for sourcing in a shell.
Secrets are skipped unless --include-secrets is specified.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		includeSecrets, _ := cmd.Flags().GetBool("include-secrets")

		vars, err := env.Load(workdir)
		if err != nil {
			return err
		}
		for _, v := range vars {
			if v.Secret && !includeSecrets {
				continue
			}
			// Shell-quote the value to handle spaces and special chars safely.
			val := env.DecodeValue(v)
			fmt.Printf("export %s=%s\n", v.Key, shellQuote(val))
		}
		return nil
	},
}

// shellQuote wraps v in single quotes, escaping any single quotes inside.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'"
}

func init() {
	envSetCmd.Flags().Bool("secret", false, "Mark the value as a secret (stored encoded, masked in list)")
	envSetCmd.Flags().String("description", "", "Optional description for the variable")

	envGetCmd.Flags().Bool("reveal", false, "Show the plain-text value of a secret variable")

	envExportCmd.Flags().Bool("include-secrets", false, "Include secret variables in the export output")

	envCmd.AddCommand(envListCmd)
	envCmd.AddCommand(envSetCmd)
	envCmd.AddCommand(envGetCmd)
	envCmd.AddCommand(envDeleteCmd)
	envCmd.AddCommand(envExportCmd)

	rootCmd.AddCommand(envCmd)
}
