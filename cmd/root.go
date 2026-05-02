package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// globalLogJSON is the global --log-json flag value for structured NDJSON output.
var globalLogJSON bool

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
  cloop run --pm --fallback anthropic,openai  # with provider fallback chain
  cloop report                    # generate project progress report
  cloop retro                     # AI sprint retrospective
  cloop backlog                   # AI-generated prioritized product backlog
  cloop task list --graph         # visual task dependency graph
  cloop milestone plan            # AI sprint/release planning
  cloop milestone forecast        # velocity-based completion forecast
  cloop compare "Explain REST vs GraphQL"   # benchmark across providers
  cloop compare --judge --providers anthropic,openai "Design a caching layer"
  cloop github sync                         # import GitHub issues as tasks
  cloop github push --done                  # export tasks + close done issues
  cloop github prs                          # PR list with CI status
  cloop chat                                # interactive conversational PM interface
  cloop insights                            # AI-powered project health & risk analysis
  cloop insights --quick                    # metrics only, no AI call
  cloop router set backend anthropic        # route backend tasks to Claude
  cloop router set frontend openai          # route frontend tasks to GPT-4o
  cloop router list                         # show routing table
  cloop standup                             # AI daily standup report
  cloop standup --post                      # post standup to Slack webhook
  cloop standup --save                      # save to .cloop/standup-DATE.md
  cloop prioritize                          # AI task reprioritization suggestions
  cloop prioritize --apply                  # apply priority changes
  cloop simulate "what if we cut scope by 30%?"        # AI what-if scenario analysis
  cloop simulate "what if the deadline moves up 2 weeks?" --apply
  cloop agent start                                     # autonomous background agent
  cloop agent start --interval 2m --provider anthropic  # agent with custom settings
  cloop agent status                                    # is it running?
  cloop agent logs --tail 30                            # recent activity
  cloop agent follow                                    # live log stream
  cloop agent stop                                      # stop the agent
  cloop review                                          # AI code review of uncommitted changes
  cloop review --staged                                 # review only staged changes
  cloop review --last                                   # review the last commit
  cloop review HEAD~3..HEAD                             # review a commit range
  cloop review --task 3                                 # review code in context of PM task 3
  cloop review --format md -o review.md                 # save review as markdown
  cloop ui                                              # web dashboard (localhost:8080)
  cloop ui --port 9090                                  # custom port
  cloop tui                                             # terminal UI dashboard
  cloop suggest                                         # AI brainstorms 5 feature ideas interactively
  cloop suggest --count 10                              # brainstorm 10 ideas
  cloop suggest --yes                                   # auto-accept all suggestions
  cloop suggest --dry-run                               # show ideas without adding tasks
  cloop changelog                                       # AI-generated CHANGELOG from task history
  cloop changelog --dry-run                             # print changelog to stdout
  cloop changelog --since 2024-01-01                   # only include work after a date
  cloop changelog --format json                         # emit JSON instead of markdown
  cloop bench --prompt "Explain how a B-tree works"              # benchmark across providers
  cloop bench --prompt "Write a Go HTTP handler" --providers anthropic,openai --runs 3
  cloop bench --prompt "Design a cache layer" --judge anthropic --output
  cloop status
  cloop log`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&globalLogJSON, "log-json", false, "Emit structured NDJSON log lines for key events (task_start, task_done, step, etc.) instead of colored text. Enables piping to Datadog, Splunk, or jq.")
}
