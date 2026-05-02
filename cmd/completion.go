package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for cloop.

To load completions in the current session:

  Bash:
    source <(cloop completion bash)

  Zsh:
    source <(cloop completion zsh)

  Fish:
    cloop completion fish | source

  PowerShell:
    cloop completion powershell | Out-String | Invoke-Expression

To make completions permanent, see the per-shell installation instructions
below or run 'cloop completion <shell> --help'.`,
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s", args[0])
		}
	},
}

var completionBashCmd = &cobra.Command{
	Use:   "bash",
	Short: "Generate bash completion script",
	Long: `Generate the autocompletion script for bash.

To load completions in the current session:
  source <(cloop completion bash)

To load completions for every new session, add this to your ~/.bashrc or
~/.bash_profile:
  # cloop shell completion
  source <(cloop completion bash)

Or install to the system completions directory:
  # Linux:
  cloop completion bash > /etc/bash_completion.d/cloop
  # macOS (requires bash-completion@2 via brew):
  cloop completion bash > $(brew --prefix)/etc/bash_completion.d/cloop`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenBashCompletion(os.Stdout)
	},
}

var completionZshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "Generate zsh completion script",
	Long: `Generate the autocompletion script for zsh.

To load completions in the current session:
  source <(cloop completion zsh)

To load completions for every new session, add this to your ~/.zshrc:
  # cloop shell completion
  source <(cloop completion zsh)

Or install to a directory in your $fpath:
  cloop completion zsh > "${fpath[1]}/_cloop"

If you encounter "command not found: compdef", add this to the top of
~/.zshrc before the source line above:
  autoload -Uz compinit && compinit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenZshCompletion(os.Stdout)
	},
}

var completionFishCmd = &cobra.Command{
	Use:   "fish",
	Short: "Generate fish completion script",
	Long: `Generate the autocompletion script for fish.

To load completions in the current session:
  cloop completion fish | source

To load completions for every new session:
  cloop completion fish > ~/.config/fish/completions/cloop.fish`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenFishCompletion(os.Stdout, true)
	},
}

var completionPowerShellCmd = &cobra.Command{
	Use:   "powershell",
	Short: "Generate PowerShell completion script",
	Long: `Generate the autocompletion script for PowerShell.

To load completions in the current session:
  cloop completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add this to your PowerShell profile
(run '$PROFILE' to find its path):
  Invoke-Expression (&cloop completion powershell)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
	},
}

func init() {
	completionCmd.AddCommand(completionBashCmd)
	completionCmd.AddCommand(completionZshCmd)
	completionCmd.AddCommand(completionFishCmd)
	completionCmd.AddCommand(completionPowerShellCmd)
	rootCmd.AddCommand(completionCmd)

	// Suppress the default Cobra completion command to avoid duplication.
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
