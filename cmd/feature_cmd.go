package cmd

// feature_cmd.go is `cloop feature`: parallel feature development in git
// worktrees, each with its own task list and run settings (Task 20341).
//
// A feature is a project of its own — `cloop run`, `cloop task add` and every
// other command work in its directory unchanged — so this command only covers
// what is specific to being a feature: creating one, listing a project's,
// removing one, and proposing one as a pull request.
//
// Every subcommand takes --json, which the dashboard uses when it dispatches
// the command through the project's executor. The payload is framed with
// pkg/clijson because the executor hands back stdout and stderr as one stream.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/featureops"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// featureErrorCode classifies a feature command failure for --json callers,
// so the dashboard can answer 409 for a name that is taken without parsing
// English.
func featureErrorCode(err error) string {
	var dirty *featureops.DirtyError
	switch {
	case errors.Is(err, featureops.ErrExists):
		return "exists"
	case errors.Is(err, featureops.ErrNested):
		return "nested"
	case errors.As(err, &dirty):
		return "dirty"
	case errors.Is(err, featureops.ErrNothingToPropose):
		return "nothing_to_propose"
	case errors.Is(err, featureops.ErrNoToken):
		return "no_token"
	case errors.Is(err, errFeatureRunning):
		return "running"
	case errors.Is(err, errNoSuchFeature):
		return "not_found"
	}
	return "failed"
}

var (
	errFeatureRunning = errors.New("the feature has a run in progress — stop it first")
	errNoSuchFeature  = errors.New("no such feature")
)

// featureJSONError is the --json shape of a failure.
type featureJSONError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Code  string `json:"code"`
	// Partial carries what was done before the failure, when something was —
	// a pull request whose branch was pushed but could not be opened.
	Partial any `json:"partial,omitempty"`
}

// featureFail reports err: as a framed JSON document when --json is set (and
// then still as the command's error, so the exit status says it failed).
func featureFail(cmd *cobra.Command, err error, partial any) error {
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		_ = clijson.Emit(cmd.OutOrStdout(), featureJSONError{
			OK: false, Error: err.Error(), Code: featureErrorCode(err), Partial: partial,
		})
	}
	return err
}

// featureProjectDir resolves the project a feature command operates on: the
// working directory, or — when that is itself a feature — its parent, so
// `cloop feature list` inside a feature lists its siblings.
func featureProjectDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determine working directory: %w", err)
	}
	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	if parent, _, ok := feature.ParentOf(cwd); ok {
		return parent, nil
	}
	return cwd, nil
}

// featureDirFor resolves a feature by slug within the current project, or —
// with no slug — the feature the working directory is.
func featureDirFor(args []string) (string, error) {
	if len(args) == 1 {
		project, err := featureProjectDir()
		if err != nil {
			return "", err
		}
		slug := strings.TrimSpace(args[0])
		if err := feature.ValidSlug(slug); err != nil {
			return "", err
		}
		dir := feature.Path(project, slug)
		if !feature.IsFeature(dir) {
			return "", fmt.Errorf("%w %q in %s", errNoSuchFeature, slug, project)
		}
		return dir, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if !feature.IsFeature(cwd) {
		return "", errors.New("name a feature, or run this inside one")
	}
	return cwd, nil
}

var featureCmd = &cobra.Command{
	Use:   "feature",
	Short: "Develop several features in parallel, each in its own git worktree",
	Long: `A feature is a git worktree of the project's repository on its own branch
(cloop/feature/<name>), with its own task list and its own run settings. Any
number of features run at the same time without touching each other's files,
and each can be proposed as a pull request into the branch it was cut from.

A feature lives at .cloop/features/<name> inside the project. It is a
project of its own: run it, add tasks to it and toggle its options from its
directory, or from the dashboard, which lists features under their project.`,
	Example: `  cloop feature new "Dark mode" --description "Add a dark theme and a toggle" --auto-evolve
  cloop feature new login --task "Add a login form" --task "Hash passwords"
  cloop feature list
  cd .cloop/features/dark-mode && cloop run
  cloop feature pr dark-mode
  cloop feature remove dark-mode --delete-branch`,
}

var featureNewCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Create a feature: a new worktree, branch and task list",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		cwd, _ = filepath.Abs(cwd)
		f := cmd.Flags()
		desc, _ := f.GetString("description")
		base, _ := f.GetString("base")
		slug, _ := f.GetString("slug")
		tasks, _ := f.GetStringArray("task")
		autoEvolve, _ := f.GetBool("auto-evolve")
		innovate, _ := f.GetBool("innovate")
		parallel, _ := f.GetBool("parallel")
		maxParallel, _ := f.GetInt("max-parallel")
		autoPR, _ := f.GetBool("auto-pr")
		createdBy, _ := f.GetString("created-by")

		// Shorter than the dashboard's 4-minute bound on this command, so a
		// slow checkout times out *here* — where the half-made feature is
		// rolled back — rather than being killed from outside mid-way.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		info, err := featureops.Create(ctx, featureops.CreateOptions{
			ProjectDir:  cwd,
			Name:        args[0],
			Slug:        slug,
			Description: desc,
			Base:        base,
			AutoEvolve:  autoEvolve,
			Innovate:    innovate,
			Parallel:    parallel,
			MaxParallel: maxParallel,
			Tasks:       tasks,
			AutoPR:      autoPR,
			CreatedBy:   createdBy,
		})
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		if asJSON, _ := f.GetBool("json"); asJSON {
			return clijson.Emit(cmd.OutOrStdout(), map[string]any{
				"ok":      true,
				"feature": featureView(info, nil),
			})
		}
		green := color.New(color.FgGreen)
		green.Printf("✓ feature %q created\n", info.Meta.Title)
		fmt.Printf("  Branch:    %s (from %s)\n", info.Meta.Branch, info.Meta.Base)
		fmt.Printf("  Worktree:  %s\n", info.Path)
		fmt.Printf("  Tasks:     %d\n", len(tasks))
		fmt.Printf("\nRun it with:  cd %s && cloop run\n", info.Path)
		return nil
	},
}

// featureListItem is one feature in `cloop feature list --json`.
type featureListItem struct {
	Slug        string                `json:"slug"`
	Title       string                `json:"title"`
	Description string                `json:"description,omitempty"`
	Branch      string                `json:"branch"`
	Base        string                `json:"base"`
	Path        string                `json:"path"`
	CreatedAt   time.Time             `json:"created_at"`
	AutoPR      bool                  `json:"auto_pr,omitempty"`
	PR          *feature.PR           `json:"pr,omitempty"`
	Status      string                `json:"status,omitempty"`
	Running     bool                  `json:"running"`
	Tasks       featureTaskCounts     `json:"tasks"`
	Git         *featureops.GitStatus `json:"git,omitempty"`
}

type featureTaskCounts struct {
	Total  int `json:"total"`
	Done   int `json:"done"`
	Failed int `json:"failed"`
}

// featureView renders a feature for output, reading its state for the task
// counts. git status is attached by the caller when it was asked for.
func featureView(info *feature.Info, git *featureops.GitStatus) featureListItem {
	m := info.Meta
	item := featureListItem{
		Slug: m.Slug, Title: m.Title, Description: m.Description,
		Branch: m.Branch, Base: m.Base, Path: info.Path,
		CreatedAt: m.CreatedAt, AutoPR: m.AutoPR, PR: m.PR, Git: git,
		Running: multiui.IsCloopRunningInDir(info.Path),
	}
	if st, err := state.LoadLite(info.Path); err == nil {
		item.Status = st.Status
		if st.Plan != nil {
			for _, t := range st.Plan.Tasks {
				item.Tasks.Total++
				switch t.Status {
				case pm.TaskDone:
					item.Tasks.Done++
				case pm.TaskFailed, pm.TaskTimedOut:
					item.Tasks.Failed++
				}
			}
		}
	}
	return item
}

var featureListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the project's features, their progress and pull requests",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		project, err := featureProjectDir()
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		infos, err := feature.List(project)
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		orphans, _ := feature.Orphans(project)
		noGit, _ := cmd.Flags().GetBool("no-git")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		items := make([]featureListItem, 0, len(infos))
		for i := range infos {
			var git *featureops.GitStatus
			if !noGit {
				st := featureops.Status(ctx, infos[i])
				git = &st
			}
			items = append(items, featureView(&infos[i], git))
		}

		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			return clijson.Emit(cmd.OutOrStdout(), map[string]any{
				"ok": true, "project": project, "features": items, "orphans": orphans,
			})
		}
		if len(items) == 0 {
			fmt.Println("No features. Create one with: cloop feature new <name>")
		}
		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)
		if len(items) > 0 {
			header.Printf("%-24s %-12s %-9s %-14s %s\n", "FEATURE", "STATUS", "TASKS", "BRANCH±", "PULL REQUEST")
		}
		for _, it := range items {
			status := it.Status
			if it.Running {
				status = "running"
			}
			if status == "" {
				status = "—"
			}
			pos := "—"
			if it.Git != nil && it.Git.Error == "" {
				pos = fmt.Sprintf("+%d -%d", it.Git.Ahead, it.Git.Behind)
				if it.Git.Dirty > 0 {
					pos += fmt.Sprintf(" *%d", it.Git.Dirty)
				}
			}
			pr := "—"
			if it.PR != nil {
				pr = fmt.Sprintf("#%d %s %s", it.PR.Number, it.PR.State, it.PR.URL)
			}
			fmt.Printf("%-24s %-12s %-9s %-14s %s\n", truncateFeature(it.Slug, 24), status,
				fmt.Sprintf("%d/%d", it.Tasks.Done, it.Tasks.Total), pos, pr)
		}
		for path, why := range orphans {
			dim.Printf("skipped %s: %s\n", path, why)
		}
		return nil
	},
}

func truncateFeature(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var featureRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a feature's worktree and task list (its branch is kept unless asked)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		project, err := featureProjectDir()
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		slug := strings.TrimSpace(args[0])
		if err := feature.ValidSlug(slug); err != nil {
			return featureFail(cmd, err, nil)
		}
		dir := feature.Path(project, slug)
		// Anywhere below the worktree, not just at its root: a parallel task
		// runs in the feature's own .cloop/worktrees, and removing the tree
		// would take that directory away mid-task too.
		if multiui.IsCloopRunningUnder(dir) {
			return featureFail(cmd, errFeatureRunning, nil)
		}
		deleteBranch, _ := cmd.Flags().GetBool("delete-branch")
		force, _ := cmd.Flags().GetBool("force")
		// Inside the dashboard's 3-minute bound, for the same reason as new.
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		res, err := featureops.Remove(ctx, featureops.RemoveOptions{
			ProjectDir: project, Slug: slug, DeleteBranch: deleteBranch, Force: force,
		})
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			return clijson.Emit(cmd.OutOrStdout(), map[string]any{"ok": true, "removed": res})
		}
		color.New(color.FgGreen).Printf("✓ feature %q removed\n", slug)
		switch {
		case res.BranchDeleted:
			fmt.Printf("  Branch %s deleted.\n", res.Branch)
		case res.BranchKept != "":
			color.Yellow("  Branch %s kept: %s", res.Branch, res.BranchKept)
		default:
			fmt.Printf("  Branch %s kept — delete it with: git branch -d %s\n", res.Branch, res.Branch)
		}
		return nil
	},
}

var featurePRCmd = &cobra.Command{
	Use:   "pr [name]",
	Short: "Push a feature's branch and open a pull request into its base branch",
	Long: `Push the feature's branch and open a GitHub pull request from it into the
branch the feature was cut from (usually main). Asked again while that pull
request is open, it pushes new commits — which updates the pull request — and
reports the existing one.

The token for GitHub's API is taken from, in order: --token, GITHUB_TOKEN,
GH_TOKEN, github.token in the feature's config, git's credential helpers for
the repository, the gh CLI, and last CLOOP_GITHUB_TOKEN — the hub's own, so a
project's credentials are always preferred to it. A token from the
environment or a config file is only sent to github.com, or to the host
--api-url names.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := featureDirFor(args)
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		f := cmd.Flags()
		opts := featureops.PROptions{FeatureDir: dir}
		opts.Title, _ = f.GetString("title")
		opts.Body, _ = f.GetString("body")
		opts.Base, _ = f.GetString("base")
		opts.Draft, _ = f.GetBool("draft")
		opts.Remote, _ = f.GetString("remote")
		opts.NoPush, _ = f.GetBool("no-push")
		opts.Token, _ = f.GetString("token")
		opts.Repo, _ = f.GetString("repo")
		opts.APIURL, _ = f.GetString("api-url")

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		res, err := featureops.OpenPR(ctx, opts)
		if err != nil {
			return featureFail(cmd, err, res)
		}
		if asJSON, _ := f.GetBool("json"); asJSON {
			return clijson.Emit(cmd.OutOrStdout(), map[string]any{"ok": true, "result": res})
		}
		verb := "opened"
		if res.Existing {
			verb = "already open"
		}
		color.New(color.FgGreen).Printf("✓ pull request #%d %s: %s\n", res.PR.Number, verb, res.PR.URL)
		fmt.Printf("  %s → %s, %d commit(s)\n", res.PR.Head, res.PR.Base, res.Ahead)
		if len(res.Dirty) > 0 {
			color.Yellow("  %d uncommitted change(s) are not part of it.", len(res.Dirty))
		}
		return nil
	},
}

var featurePRStatusCmd = &cobra.Command{
	Use:   "pr-status [name]",
	Short: "Refresh a feature's pull request state (open, closed, merged) from GitHub",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := featureDirFor(args)
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		token, _ := cmd.Flags().GetString("token")
		api, _ := cmd.Flags().GetString("api-url")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pr, err := featureops.RefreshPR(ctx, dir, token, api)
		if err != nil {
			return featureFail(cmd, err, nil)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			return clijson.Emit(cmd.OutOrStdout(), map[string]any{"ok": true, "pr": pr})
		}
		fmt.Printf("#%d %s %s\n", pr.Number, pr.State, pr.URL)
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{featureNewCmd, featureListCmd, featureRemoveCmd, featurePRCmd, featurePRStatusCmd} {
		c.Flags().Bool("json", false, "print a machine-readable result")
	}

	nf := featureNewCmd.Flags()
	nf.String("description", "", "what the feature should achieve — its goal (default: the name)")
	nf.String("base", "", "branch to cut the feature from and propose it into (default: the remote's default branch, else main/master)")
	nf.String("slug", "", "directory and branch name (default: derived from the name)")
	nf.StringArray("task", nil, "an initial task, in order (repeatable); without any, the first run decomposes the goal")
	nf.Bool("auto-evolve", false, "keep discovering new tasks once the plan is done")
	nf.Bool("innovate", false, "let evolution propose novel features, not just improvements")
	nf.Bool("parallel", false, "run independent tasks of this feature concurrently")
	nf.Int("max-parallel", 0, "cap concurrent tasks when --parallel is set (0 = unlimited)")
	nf.Bool("auto-pr", false, "have the dashboard open the pull request when the plan completes")
	nf.String("created-by", "", "who created the feature, for the record")

	featureListCmd.Flags().Bool("no-git", false, "skip the per-feature git status (faster)")

	featureRemoveCmd.Flags().Bool("delete-branch", false, "also delete the feature's branch if it is merged")
	featureRemoveCmd.Flags().Bool("force", false, "discard uncommitted changes (and with --delete-branch, delete an unmerged branch)")

	pf := featurePRCmd.Flags()
	pf.String("title", "", "pull request title (default: the feature's name)")
	pf.String("body", "", "pull request description (default: generated from the task list)")
	pf.String("base", "", "branch to propose into (default: the feature's base)")
	pf.Bool("draft", false, "open the pull request as a draft")
	pf.String("remote", "origin", "git remote to push to")
	pf.Bool("no-push", false, "do not push; the branch is already published")
	pf.String("token", "", "GitHub token for the API (see the precedence above)")
	pf.String("repo", "", "owner/name, when the remote does not name a GitHub repository")
	pf.String("api-url", "", "GitHub API base URL (default: derived from the remote; also "+featureops.EnvAPIURL+")")

	featurePRStatusCmd.Flags().String("token", "", "GitHub token for the API")
	featurePRStatusCmd.Flags().String("api-url", "", "GitHub API base URL")

	featureCmd.AddCommand(featureNewCmd, featureListCmd, featureRemoveCmd, featurePRCmd, featurePRStatusCmd)
	rootCmd.AddCommand(featureCmd)
}
