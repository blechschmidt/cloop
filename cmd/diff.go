package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

var (
	diffStat    bool
	diffSession bool
	diffNameOnly bool
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show changes in the working directory or since session start",
	Long: `Show git diff for the current project.

By default, shows all uncommitted changes (staged + unstaged) relative to HEAD.
Use --session to diff from when the cloop session was initialized (finds the
last git commit that existed before the session began).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		var gitArgs []string

		if diffSession {
			s, err := state.Load(workdir)
			if err != nil {
				return err
			}
			baseRef, err := commitBeforeTime(workdir, s.CreatedAt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not find session base commit (%v); falling back to HEAD diff\n", err)
				gitArgs = []string{"diff", "HEAD"}
			} else {
				gitArgs = []string{"diff", baseRef}
			}
		} else {
			// Default: all uncommitted changes vs HEAD
			gitArgs = []string{"diff", "HEAD"}
		}

		if diffStat {
			gitArgs = append(gitArgs, "--stat")
		} else if diffNameOnly {
			gitArgs = append(gitArgs, "--name-only")
		}

		gitCmd := exec.Command("git", gitArgs...)
		gitCmd.Dir = workdir
		gitCmd.Stdout = os.Stdout
		gitCmd.Stderr = os.Stderr

		if err := gitCmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// git diff exits 1 when differences exist — not an error.
				return nil
			}
			return fmt.Errorf("git diff: %w", err)
		}
		return nil
	},
}

// commitBeforeTime returns the SHA of the most recent git commit that existed
// strictly before t. Returns an error if no such commit is found.
func commitBeforeTime(workdir string, t time.Time) (string, error) {
	// Use --before which is exclusive (strictly before), so commits AT t are excluded.
	// Format: ISO 8601 timestamp.
	timeStr := t.UTC().Format(time.RFC3339)
	out, err := exec.Command(
		"git", "-C", workdir,
		"log", "--format=%H", "--before="+timeStr, "-n", "1",
	).Output()
	if err != nil {
		return "", fmt.Errorf("git log: %w", err)
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("no commit found before %s (session may have started before first commit)", timeStr)
	}
	return sha, nil
}

func init() {
	diffCmd.Flags().BoolVar(&diffStat, "stat", false, "Show diff statistics (files changed, insertions, deletions)")
	diffCmd.Flags().BoolVar(&diffNameOnly, "name-only", false, "Show only names of changed files")
	diffCmd.Flags().BoolVar(&diffSession, "session", false, "Diff from when the cloop session was initialized")
	rootCmd.AddCommand(diffCmd)
}
