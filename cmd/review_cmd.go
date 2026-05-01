package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/review"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	reviewProvider string
	reviewModel    string
	reviewStaged   bool
	reviewLast     bool
	reviewCommit   string
	reviewFormat   string
	reviewOutput   string
	reviewTimeout  string
	reviewTaskID   int
	reviewQuick    bool
)

var reviewCmd = &cobra.Command{
	Use:   "review [commit-range]",
	Short: "AI-powered code review for git diffs",
	Long: `Review runs an AI code review on your git changes and returns
structured feedback: quality score, issues by severity, praise, and suggestions.

By default it reviews unstaged+staged changes (working tree diff).

Examples:
  cloop review                       # review all uncommitted changes
  cloop review --staged              # review only staged changes
  cloop review --last                # review the last commit
  cloop review HEAD~3..HEAD          # review a range of commits
  cloop review --task 3              # include PM task context in review
  cloop review --format md           # markdown output
  cloop review --format md -o review.md  # save markdown to file
  cloop review --quick               # diff stats only, no AI call
  cloop review --provider anthropic  # use a specific provider`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		s, _ := state.Load(workdir) // non-fatal; used for context

		// Get the diff.
		diff, source, err := getDiff(args, reviewStaged, reviewLast, reviewCommit)
		if err != nil {
			return err
		}
		if strings.TrimSpace(diff) == "" {
			return fmt.Errorf("diff is empty — no changes to review")
		}

		// Stats header.
		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		printDiffStats(diff, source, bold, dim)

		if reviewQuick {
			return nil
		}

		// Build provider.
		providerName := reviewProvider
		if providerName == "" {
			providerName = cfg.Provider
		}
		if providerName == "" && s != nil {
			providerName = s.Provider
		}
		if providerName == "" {
			providerName = autoSelectProvider()
		}

		model := reviewModel
		if model == "" && s != nil {
			model = s.Model
		}
		if model == "" {
			switch providerName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}

		provCfg := provider.ProviderConfig{
			Name:             providerName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 120 * time.Second
		if reviewTimeout != "" {
			timeout, err = time.ParseDuration(reviewTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		// Build optional task context.
		taskCtx := ""
		goal := ""
		if s != nil {
			goal = s.Goal
			if reviewTaskID > 0 && s.Plan != nil {
				for _, t := range s.Plan.Tasks {
					if t.ID == reviewTaskID {
						taskCtx = fmt.Sprintf("[Task %d] %s\n%s", t.ID, t.Title, t.Description)
						break
					}
				}
			}
		}

		dim.Printf("Running code review with %s...\n\n", prov.Name())

		ctx := context.Background()
		rev, err := review.Perform(ctx, prov, model, timeout, diff, taskCtx, goal)
		if err != nil {
			return fmt.Errorf("review failed: %w", err)
		}

		switch reviewFormat {
		case "md", "markdown":
			md := review.FormatMarkdown(rev, diff, source)
			if reviewOutput != "" {
				if err := os.WriteFile(reviewOutput, []byte(md), 0o644); err != nil {
					return fmt.Errorf("writing output: %w", err)
				}
				color.New(color.FgGreen).Printf("Review saved to %s\n", reviewOutput)
			} else {
				fmt.Print(md)
			}
		default:
			printReviewTerminal(rev, source)
		}

		return nil
	},
}

// getDiff returns the git diff as a string plus a human-readable source label.
func getDiff(args []string, staged, last bool, commit string) (string, string, error) {
	var gitArgs []string
	var source string

	switch {
	case len(args) > 0:
		// Explicit commit range like HEAD~3..HEAD
		gitArgs = []string{"diff", args[0]}
		source = args[0]
	case commit != "":
		gitArgs = []string{"show", commit}
		source = "commit " + commit
	case last:
		gitArgs = []string{"diff", "HEAD~1", "HEAD"}
		source = "last commit"
	case staged:
		gitArgs = []string{"diff", "--cached"}
		source = "staged changes"
	default:
		// All uncommitted changes (staged + unstaged).
		gitArgs = []string{"diff", "HEAD"}
		source = "uncommitted changes"
	}

	out, err := runGit(gitArgs...)
	if err != nil {
		// Fall back to diff without HEAD for new repos with no commits.
		if !staged && !last && commit == "" && len(args) == 0 {
			out2, err2 := runGit("diff")
			if err2 == nil && strings.TrimSpace(out2) != "" {
				return out2, source, nil
			}
		}
		return "", "", fmt.Errorf("git %s: %w", strings.Join(gitArgs, " "), err)
	}

	// If diff HEAD is empty but there are staged changes, include them.
	if strings.TrimSpace(out) == "" && !staged && !last && commit == "" && len(args) == 0 {
		staged2, _ := runGit("diff", "--cached")
		if strings.TrimSpace(staged2) != "" {
			return staged2, "staged changes", nil
		}
	}

	return out, source, nil
}

func runGit(args ...string) (string, error) {
	var buf bytes.Buffer
	var ebuf bytes.Buffer
	c := exec.Command("git", args...)
	c.Stdout = &buf
	c.Stderr = &ebuf
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(ebuf.String()))
	}
	return buf.String(), nil
}

func printDiffStats(diff, source string, bold, dim *color.Color) {
	lines := strings.Split(diff, "\n")
	added, removed, files := 0, 0, 0
	seen := map[string]bool{}
	for _, l := range lines {
		if strings.HasPrefix(l, "+++ b/") {
			f := strings.TrimPrefix(l, "+++ b/")
			if !seen[f] {
				seen[f] = true
				files++
			}
		} else if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			added++
		} else if strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---") {
			removed++
		}
	}

	bold.Printf("Code Review")
	dim.Printf(" — %s\n", source)
	dim.Printf("  %d file(s) changed · +%d lines · -%d lines\n\n", files, added, removed)
}

func printReviewTerminal(r *review.Review, source string) {
	header := color.New(color.FgCyan, color.Bold)
	critColor := color.New(color.FgRed, color.Bold)
	majorColor := color.New(color.FgYellow, color.Bold)
	minorColor := color.New(color.FgYellow)
	suggColor := color.New(color.FgBlue)
	successColor := color.New(color.FgGreen)
	boldColor := color.New(color.Bold)
	dimColor := color.New(color.Faint)

	// Score line.
	scoreColor := successColor
	if r.Score < 5 {
		scoreColor = critColor
	} else if r.Score < 7 {
		scoreColor = majorColor
	}
	boldColor.Printf("Quality Score: ")
	scoreColor.Printf("%.1f/10\n", r.Score)
	fmt.Printf("%s\n\n", r.Summary)

	// Issue counts.
	critical, major, minor, suggestion := r.Counts()
	if critical+major+minor+suggestion == 0 {
		successColor.Printf("No issues found.\n\n")
	} else {
		boldColor.Printf("Issues: ")
		if critical > 0 {
			critColor.Printf("%d critical  ", critical)
		}
		if major > 0 {
			majorColor.Printf("%d major  ", major)
		}
		if minor > 0 {
			minorColor.Printf("%d minor  ", minor)
		}
		if suggestion > 0 {
			suggColor.Printf("%d suggestions", suggestion)
		}
		fmt.Printf("\n\n")
	}

	// Print issues grouped by severity.
	if len(r.Issues) > 0 {
		header.Printf("Issues\n")
		dimColor.Printf("──────\n")
		for _, iss := range r.Issues {
			var col *color.Color
			var prefix string
			switch iss.Severity {
			case review.SeverityCritical:
				col = critColor
				prefix = "[CRITICAL]"
			case review.SeverityMajor:
				col = majorColor
				prefix = "[MAJOR]"
			case review.SeverityMinor:
				col = minorColor
				prefix = "[MINOR]"
			default:
				col = suggColor
				prefix = "[SUGGESTION]"
			}

			col.Printf("  %s ", prefix)
			boldColor.Printf("%s", iss.Title)
			if iss.File != "" {
				loc := iss.File
				if iss.Line > 0 {
					loc = fmt.Sprintf("%s:%d", iss.File, iss.Line)
				}
				dimColor.Printf(" (%s)", loc)
			}
			fmt.Printf("\n")
			if iss.Detail != "" {
				wrapped := wrapText(iss.Detail, 72)
				for _, line := range strings.Split(wrapped, "\n") {
					dimColor.Printf("    %s\n", line)
				}
			}
			if iss.Fix != "" {
				col.Printf("    Fix: ")
				fmt.Printf("%s\n", iss.Fix)
			}
			fmt.Printf("\n")
		}
	}

	// Praise.
	if len(r.Praise) > 0 {
		successColor.Printf("What's Good\n")
		dimColor.Printf("───────────\n")
		for _, p := range r.Praise {
			successColor.Printf("  + ")
			fmt.Printf("%s\n", p)
		}
		fmt.Printf("\n")
	}

	// Suggestions.
	if len(r.Suggestions) > 0 {
		header.Printf("Suggestions\n")
		dimColor.Printf("───────────\n")
		for _, s := range r.Suggestions {
			dimColor.Printf("  • ")
			fmt.Printf("%s\n", s)
		}
		fmt.Printf("\n")
	}

	// Test feedback.
	if r.TestFeedback != "" {
		boldColor.Printf("Test Coverage\n")
		dimColor.Printf("─────────────\n")
		fmt.Printf("  %s\n\n", r.TestFeedback)
	}

	// Security notes.
	if len(r.SecurityNotes) > 0 {
		critColor.Printf("Security Notes\n")
		dimColor.Printf("──────────────\n")
		for _, n := range r.SecurityNotes {
			critColor.Printf("  ! ")
			fmt.Printf("%s\n", n)
		}
		fmt.Printf("\n")
	}

	_ = source
}

// wrapText wraps text at approximately `width` characters, breaking at spaces.
func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	var sb strings.Builder
	col := 0
	for _, word := range strings.Fields(text) {
		if col+len(word)+1 > width && col > 0 {
			sb.WriteString("\n")
			col = 0
		}
		if col > 0 {
			sb.WriteString(" ")
			col++
		}
		sb.WriteString(word)
		col += len(word)
	}
	return sb.String()
}

func init() {
	reviewCmd.Flags().StringVar(&reviewProvider, "provider", "", "Provider to use for review")
	reviewCmd.Flags().StringVar(&reviewModel, "model", "", "Model to use for review")
	reviewCmd.Flags().BoolVar(&reviewStaged, "staged", false, "Review only staged changes")
	reviewCmd.Flags().BoolVar(&reviewLast, "last", false, "Review the last commit")
	reviewCmd.Flags().StringVar(&reviewCommit, "commit", "", "Review a specific commit (hash)")
	reviewCmd.Flags().StringVar(&reviewFormat, "format", "terminal", "Output format: terminal (default) or md")
	reviewCmd.Flags().StringVarP(&reviewOutput, "output", "o", "", "Write output to file (for --format md)")
	reviewCmd.Flags().StringVar(&reviewTimeout, "timeout", "", "Review timeout (e.g. 60s, 2m)")
	reviewCmd.Flags().IntVar(&reviewTaskID, "task", 0, "Include PM task context in review (task ID)")
	reviewCmd.Flags().BoolVar(&reviewQuick, "quick", false, "Show diff stats only, no AI call")
	rootCmd.AddCommand(reviewCmd)
}
