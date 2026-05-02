package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/githubsync"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	gitsync "github.com/blechschmidt/cloop/pkg/sync"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ─── flags ────────────────────────────────────────────────────────────────────

var (
	syncRepo      string
	syncToken     string
	syncPush      bool
	syncPull      bool
	syncDryRun    bool
	syncForce     bool
	syncLabels    string
	syncCloseDone bool
	syncComment   bool

	// git-remote sync flags
	syncGitRemote string
	syncGitBranch string
)

// ─── root sync command ────────────────────────────────────────────────────────

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync PM tasks with external services or git remotes",
	Long: `Synchronize cloop PM tasks with external services or git remotes.

Subcommands:
  push      Commit and push .cloop state to a git remote branch
  pull      Fetch and merge remote state into the local plan
  auto      Pull then push (full bidirectional sync)
  github    Two-way sync with GitHub Issues`,
}

// ─── sync github ─────────────────────────────────────────────────────────────

var syncGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Two-way sync between PM tasks and GitHub Issues",
	Long: `Synchronize cloop PM tasks with GitHub Issues.

By default (no --push / --pull flags), both directions are executed:
  1. Pull: import open issues as pending tasks (skips already-linked issues).
  2. Push: create or update GitHub issues for every task, and optionally
     close issues for tasks that are done or skipped (--close-done).

Use --pull to only pull from GitHub, or --push to only push to GitHub.

The task↔issue mapping is persisted in .cloop/github-sync.json so that
subsequent runs are idempotent.

Token resolution order: --token flag > GITHUB_TOKEN env > config github.token
Repo resolution order:  --repo flag  > config github.repo > git remote origin

Examples:
  cloop sync github                          # bidirectional sync
  cloop sync github --pull                   # import issues only
  cloop sync github --push                   # export tasks only
  cloop sync github --push --close-done      # export + close done tasks
  cloop sync github --dry-run                # preview without writing
  cloop sync github --repo owner/name        # explicit repo
  cloop sync github --labels bug,feature     # filter by label (pull only)
  cloop sync github --force                  # overwrite linked task metadata`,
	RunE: runSyncGitHub,
}

func runSyncGitHub(cmd *cobra.Command, args []string) error {
	workDir, _ := os.Getwd()

	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	s, err := state.Load(workDir)
	if err != nil {
		return err
	}

	client, err := resolveSyncGitHub(cfg)
	if err != nil {
		return err
	}

	mapping, err := githubsync.LoadMapping(workDir)
	if err != nil {
		return fmt.Errorf("loading sync mapping: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	bold.Printf("GitHub sync — %s\n", cyan.Sprint("github.com/"+client.Repo))
	if syncDryRun {
		yellow.Println("(dry run — no changes will be written)")
	}
	fmt.Println()

	doPull := syncPull || (!syncPull && !syncPush)
	doPush := syncPush || (!syncPull && !syncPush)

	stateDirty := false
	mappingDirty := false

	// ── PULL ──────────────────────────────────────────────────────────────────
	if doPull {
		bold.Println("── Pull (GitHub → cloop) ──")

		var labelFilter []string
		if syncLabels != "" {
			labelFilter = strings.Split(syncLabels, ",")
		}

		// Ensure plan exists before pulling.
		if s.Plan == nil && !syncDryRun {
			s.Plan = pm.NewPlan(s.Goal)
			s.PMMode = true
		}

		pullResult, err := githubsync.Pull(workDir, client, s.Plan, mapping, labelFilter, syncForce)
		if err != nil {
			return fmt.Errorf("pull failed: %w", err)
		}

		if pullResult.Imported == 0 && pullResult.Updated == 0 && pullResult.Skipped == 0 {
			dim.Println("  No open issues found.")
		} else {
			if pullResult.Imported > 0 {
				green.Printf("  + %d issue(s) imported as new tasks\n", pullResult.Imported)
				stateDirty = true
				mappingDirty = true
			}
			if pullResult.Updated > 0 {
				yellow.Printf("  ~ %d task(s) updated from GitHub\n", pullResult.Updated)
				stateDirty = true
			}
			if pullResult.Skipped > 0 {
				dim.Printf("  - %d issue(s) already linked — skipped\n", pullResult.Skipped)
			}
		}
		fmt.Println()
	}

	// ── PUSH ──────────────────────────────────────────────────────────────────
	if doPush {
		bold.Println("── Push (cloop → GitHub) ──")

		if s.Plan == nil || len(s.Plan.Tasks) == 0 {
			dim.Println("  No PM tasks to push.")
		} else {
			defaultLabels := cfg.GitHub.Labels
			if len(defaultLabels) == 0 {
				defaultLabels = []string{"cloop"}
			}

			pushResult, err := githubsync.Push(workDir, client, s.Plan, mapping, defaultLabels, syncDryRun, syncCloseDone, syncComment)
			if err != nil {
				// Push returns partial results; print what we have before reporting error.
				red.Printf("  ! push error: %v\n", err)
			}

			if pushResult != nil {
				if pushResult.Created > 0 {
					action := "created"
					if syncDryRun {
						action = "would create"
					}
					green.Printf("  + %d issue(s) %s\n", pushResult.Created, action)
					if !syncDryRun {
						stateDirty = true
						mappingDirty = true
					}
				}
				if pushResult.Updated > 0 {
					action := "updated"
					if syncDryRun {
						action = "would update"
					}
					yellow.Printf("  ~ %d issue(s) %s\n", pushResult.Updated, action)
				}
				if pushResult.Closed > 0 {
					action := "closed"
					if syncDryRun {
						action = "would close"
					}
					dim.Printf("  x %d issue(s) %s\n", pushResult.Closed, action)
					if !syncDryRun {
						stateDirty = true
					}
				}
				if pushResult.Skipped > 0 {
					dim.Printf("  - %d issue(s) already in sync\n", pushResult.Skipped)
				}
				if pushResult.Created == 0 && pushResult.Updated == 0 && pushResult.Closed == 0 && pushResult.Skipped == 0 {
					dim.Println("  Nothing to push.")
				}
			}
		}
		fmt.Println()
	}

	// ── SAVE ──────────────────────────────────────────────────────────────────
	if syncDryRun {
		bold.Println("Dry run complete — no changes written.")
		return nil
	}

	if mappingDirty {
		if err := mapping.Save(workDir); err != nil {
			return fmt.Errorf("saving sync mapping: %w", err)
		}
		dim.Println("Saved .cloop/github-sync.json")
	}

	if stateDirty {
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}

	bold.Println("Sync complete.")
	return nil
}

// resolveSyncGitHub builds a Client from flags + env + config, resolving the
// token and repo with the same fallback chain used by github_cmd.go.
func resolveSyncGitHub(cfg *config.Config) (*gh.Client, error) {
	token := syncToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = cfg.GitHub.Token
	}

	repo := syncRepo
	if repo == "" {
		repo = cfg.GitHub.Repo
	}
	if repo == "" {
		detected, err := gh.DetectRepo()
		if err != nil {
			return nil, fmt.Errorf("no GitHub repo specified (use --repo owner/repo or set github.repo in config): %w", err)
		}
		repo = detected
	}
	if !strings.Contains(repo, "/") {
		return nil, fmt.Errorf("invalid repo format %q — expected owner/repo", repo)
	}
	return gh.New(token, repo), nil
}

// ─── sync push ───────────────────────────────────────────────────────────────

var syncPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push local state to a git remote branch",
	Long: `Commit .cloop/state.json and .cloop/plan-history/ to a dedicated git
remote branch (default "cloop-state") so teammates can pull your progress.

The commit message format is: cloop: sync state <RFC3339-timestamp>

Remote and branch default to config sync.remote / sync.branch, or
"origin" / "cloop-state" if not configured.

Examples:
  cloop sync push
  cloop sync push --remote origin --branch cloop-state`,
	RunE: runSyncGitPush,
}

var syncPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull and merge remote state into local plan",
	Long: `Fetch .cloop/state.json from the configured git remote branch and
three-way merge its plan with the local plan:

  • Local in_progress tasks are preserved (your active work is never overridden).
  • Remote done/failed/skipped status is accepted for shared tasks.
  • Pending tasks that only exist on the remote are unioned in.
  • Plan-history snapshots from the remote are copied locally.

Examples:
  cloop sync pull
  cloop sync pull --remote origin --branch cloop-state`,
	RunE: runSyncGitPull,
}

var syncAutoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Pull then push (full bidirectional sync)",
	Long: `Perform a full bidirectional sync: pull remote state first, then push
the merged local state back.  Equivalent to running 'cloop sync pull' followed
by 'cloop sync push'.

Examples:
  cloop sync auto`,
	RunE: runSyncGitAuto,
}

func resolveGitSyncConfig(cfg *config.Config) (remote, branch string) {
	remote = syncGitRemote
	if remote == "" {
		remote = cfg.Sync.Remote
	}
	if remote == "" {
		remote = gitsync.DefaultConfig().Remote
	}
	branch = syncGitBranch
	if branch == "" {
		branch = cfg.Sync.Branch
	}
	if branch == "" {
		branch = gitsync.DefaultConfig().Branch
	}
	return remote, branch
}

func runSyncGitPush(cmd *cobra.Command, args []string) error {
	workDir, _ := os.Getwd()
	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	remote, branch := resolveGitSyncConfig(cfg)

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	dim := color.New(color.Faint)
	bold.Printf("Pushing state to %s/%s …\n", remote, branch)

	if err := gitsync.Push(workDir, remote, branch); err != nil {
		return fmt.Errorf("sync push: %w", err)
	}
	green.Println("Push complete.")
	dim.Printf("Remote: %s  Branch: %s\n", remote, branch)
	return nil
}

func runSyncGitPull(cmd *cobra.Command, args []string) error {
	workDir, _ := os.Getwd()
	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	remote, branch := resolveGitSyncConfig(cfg)

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)
	bold.Printf("Pulling state from %s/%s …\n", remote, branch)

	merged, err := gitsync.Pull(workDir, remote, branch)
	if err != nil {
		return fmt.Errorf("sync pull: %w", err)
	}

	if merged == nil {
		dim.Println("No remote state found — nothing to merge.")
		return nil
	}

	// Apply merged plan to local state.
	s, err := state.Load(workDir)
	if err != nil {
		return fmt.Errorf("loading local state: %w", err)
	}

	if s.Plan == nil {
		yellow.Println("No local plan found; adopting remote plan entirely.")
		s.Plan = merged
		s.PMMode = true
	} else {
		origCount := len(s.Plan.Tasks)
		s.Plan = merged
		added := len(merged.Tasks) - origCount
		if added > 0 {
			green.Printf("+ %d task(s) imported from remote\n", added)
		} else {
			dim.Println("Plan up to date — no new tasks imported.")
		}
	}

	if err := s.Save(); err != nil {
		return fmt.Errorf("saving merged state: %w", err)
	}

	green.Println("Pull complete.")
	dim.Printf("Remote: %s  Branch: %s\n", remote, branch)
	return nil
}

func runSyncGitAuto(cmd *cobra.Command, args []string) error {
	if err := runSyncGitPull(cmd, args); err != nil {
		return err
	}
	return runSyncGitPush(cmd, args)
}

// ─── init ────────────────────────────────────────────────────────────────────

func init() {
	syncGitHubCmd.Flags().StringVar(&syncRepo, "repo", "", "GitHub repo in owner/repo format (overrides config and auto-detect)")
	syncGitHubCmd.Flags().StringVar(&syncToken, "token", "", "GitHub personal access token (overrides GITHUB_TOKEN env and config)")
	syncGitHubCmd.Flags().BoolVar(&syncPush, "push", false, "Only push tasks to GitHub (skip pull)")
	syncGitHubCmd.Flags().BoolVar(&syncPull, "pull", false, "Only pull issues from GitHub (skip push)")
	syncGitHubCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Preview changes without writing to GitHub or disk")
	syncGitHubCmd.Flags().BoolVar(&syncForce, "force", false, "Overwrite already-linked task metadata from GitHub (pull) or re-push all tasks (push)")
	syncGitHubCmd.Flags().StringVar(&syncLabels, "labels", "", "Filter issues by label(s) when pulling (comma-separated)")
	syncGitHubCmd.Flags().BoolVar(&syncCloseDone, "close-done", false, "Close GitHub issues for tasks that are done or skipped")
	syncGitHubCmd.Flags().BoolVar(&syncComment, "comment", true, "Add a completion comment when closing an issue")

	// git-remote sync flags (shared by push/pull/auto)
	for _, c := range []*cobra.Command{syncPushCmd, syncPullCmd, syncAutoCmd} {
		c.Flags().StringVar(&syncGitRemote, "remote", "", "Git remote name (overrides config sync.remote, default \"origin\")")
		c.Flags().StringVar(&syncGitBranch, "branch", "", "Git branch for state (overrides config sync.branch, default \"cloop-state\")")
	}

	syncCmd.AddCommand(syncGitHubCmd)
	syncCmd.AddCommand(syncPushCmd)
	syncCmd.AddCommand(syncPullCmd)
	syncCmd.AddCommand(syncAutoCmd)
	rootCmd.AddCommand(syncCmd)
}
