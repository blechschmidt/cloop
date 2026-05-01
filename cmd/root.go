package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloop",
	Short: "AI product manager and autonomous feedback loop",
	Long: `cloop is a multi-provider AI product manager and feedback loop.

Define a project goal and cloop drives an AI provider through it autonomously.
Supports Anthropic (Claude API), OpenAI, Ollama (local), and Claude Code.

  cloop init "Build a REST API with user auth and CRUD endpoints"
  cloop init --provider anthropic "Add comprehensive tests"
  cloop init --provider ollama --model llama3.2 "Refactor this module"
  cloop init "Build a REST API with user auth and CRUD endpoints"
  cloop scope "Build a REST API"  # AI scope analysis before you start
  cloop run                       # feedback loop mode
  cloop run --pm                  # product manager mode (task decomposition)
  cloop report                    # generate project progress report
  cloop status
  cloop log`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
