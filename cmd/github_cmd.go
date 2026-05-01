package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ─── flags ─────────────────────────────────────────────────────────────────

var (
	ghRepo    string
	ghToken   string
	ghLabels  string
	ghDryRun  bool
	ghState   string
	ghForce   bool
	ghComment bool
	ghFull    bool
)

// ─── helpers ────────────────────────────────────────────────────────────────

// resolveGitHub builds a Client from flags + config + env, and validates
// the repo string. Returns an error when neither flag nor config nor git
// remote can supply a repo.
func resolveGitHub(cfg *config.Config) (*gh.Client, error) {
	token := ghToken
	if token == "" {
		token = cfg.GitHub.Token
	}
	repo := ghRepo
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

// ─── root github command ─────────────────────────────────────────────────────

var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "Sync tasks with GitHub Issues and pull requests",
	Long: `Integrate cloop PM tasks with GitHub Issues and pull requests.

Pull open issues into your task plan, push tasks back as issues, and
monitor PR CI status — all from the command line.

Examples:
  cloop github sync                                 # import open issues as tasks
  cloop github sync --repo owner/repo               # specify repo
  cloop github sync --labels bug,enhancement        # filter by label
  cloop github push                                 # create issues for unlinked tasks
  cloop github push --dry-run                       # preview what would be created
  cloop github push --done                          # also close issues for done tasks
  cloop github prs                                  # list open PRs with CI status
  cloop github prs --state all                      # include closed PRs
  cloop github link 3 42                            # link task #3 to issue #42
  cloop github unlink 3                             # remove task #3's issue link
  cloop github status                               # show sync overview`,
}

// ─── sync ────────────────────────────────────────────────────────────────────

var githubSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Import GitHub issues as PM tasks",
	Long: `Fetch open issues from GitHub and create PM tasks for those not yet linked.

Existing tasks that are already linked to a GitHub issue are skipped.
Use --force to update linked tasks' titles and descriptions from GitHub.

Requires PM mode to be initialized (cloop init --pm or cloop run --pm).`,
	RunE: runGitHubSync,
}

func runGitHubSync(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}

	client, err := resolveGitHub(cfg)
	if err != nil {
		return err
	}

	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	bold.Printf("Syncing issues from github.com/%s ...\n\n", client.Repo)

	var labelFilter []string
	if ghLabels != "" {
		labelFilter = strings.Split(ghLabels, ",")
	}

	issues, err := client.ListIssues("open", labelFilter)
	if err != nil {
		return fmt.Errorf("fetching issues: %w", err)
	}

	if len(issues) == 0 {
		dim.Println("No open issues found.")
		return nil
	}

	// Build index of already-linked issue numbers
	linked := map[int]bool{}
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if t.GitHubIssue > 0 {
				linked[t.GitHubIssue] = true
			}
		}
	}

	imported := 0
	updated := 0
	skipped := 0

	for _, issue := range issues {
		icon := cyan.Sprint("#" + fmt.Sprintf("%d", issue.Number))
		if linked[issue.Number] {
			if ghForce && s.Plan != nil {
				// Update existing linked task
				for _, t := range s.Plan.Tasks {
					if t.GitHubIssue == issue.Number {
						t.Title = issue.Title
						if issue.Body != "" {
							t.Description = issue.Body
						}
						updated++
						yellow.Printf("  ~ %s  updated: %s\n", icon, issue.Title)
						break
					}
				}
			} else {
				skipped++
				dim.Printf("  - %s  already linked — skipped\n", icon)
			}
			continue
		}

		// Determine priority from labels
		priority := nextPriority(s.Plan)
		role := roleFromLabels(issue.Labels)

		newTask := &pm.Task{
			ID:          nextTaskID(s.Plan),
			Title:       issue.Title,
			Description: buildTaskDescription(issue),
			Priority:    priority,
			Status:      pm.TaskPending,
			Role:        role,
			GitHubIssue: issue.Number,
		}

		if ghDryRun {
			green.Printf("  + %s  would import: %s\n", icon, issue.Title)
			imported++
			continue
		}

		// Ensure plan exists
		if s.Plan == nil {
			s.Plan = pm.NewPlan(s.Goal)
			s.PMMode = true
		}
		s.Plan.Tasks = append(s.Plan.Tasks, newTask)
		linked[issue.Number] = true
		imported++

		green.Printf("  + %s  imported as task #%d: %s\n", icon, newTask.ID, issue.Title)
	}

	fmt.Println()
	if ghDryRun {
		bold.Printf("Dry run: %d would be imported, %d skipped\n", imported, skipped)
		return nil
	}

	if imported > 0 || updated > 0 {
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}

	parts := []string{}
	if imported > 0 {
		parts = append(parts, fmt.Sprintf("%d imported", imported))
	}
	if updated > 0 {
		parts = append(parts, fmt.Sprintf("%d updated", updated))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}
	bold.Printf("Sync complete: %s\n", strings.Join(parts, ", "))
	if imported > 0 {
		dim.Println("Run 'cloop run --pm' to execute the imported tasks.")
	}
	return nil
}

// ─── push ────────────────────────────────────────────────────────────────────

var githubPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Create GitHub issues for unlinked PM tasks",
	Long: `For each PM task that doesn't have a linked GitHub issue, create one.

With --done, also close issues linked to tasks that are done or skipped,
adding a completion comment with the task result.

Use --dry-run to preview changes without writing to GitHub.`,
	RunE: runGitHubPush,
}

var ghPushDone bool

func runGitHubPush(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}

	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		return fmt.Errorf("no PM tasks found — run 'cloop init --pm' or 'cloop run --pm' first")
	}

	client, err := resolveGitHub(cfg)
	if err != nil {
		return err
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed)

	bold.Printf("Pushing tasks to github.com/%s ...\n\n", client.Repo)

	// Build labels from config + any custom ones
	defaultLabels := cfg.GitHub.Labels
	if len(defaultLabels) == 0 {
		defaultLabels = []string{"cloop"}
	}

	created := 0
	closed := 0
	skipped := 0

	for _, t := range s.Plan.Tasks {
		switch {
		case t.GitHubIssue == 0:
			// No linked issue — create one
			body := buildIssueBody(t, s.Goal)
			if ghDryRun {
				green.Printf("  + task #%d  would create issue: %s\n", t.ID, t.Title)
				created++
				continue
			}
			issue, err := client.CreateIssue(t.Title, body, defaultLabels)
			if err != nil {
				red.Printf("  ! task #%d  error creating issue: %v\n", t.ID, err)
				continue
			}
			t.GitHubIssue = issue.Number
			created++
			green.Printf("  + task #%d  created issue #%d: %s\n", t.ID, issue.Number, issue.HTMLURL)

		case ghPushDone && (t.Status == pm.TaskDone || t.Status == pm.TaskSkipped):
			// Linked and done — close the issue
			issue, err := client.GetIssue(t.GitHubIssue)
			if err != nil {
				red.Printf("  ! task #%d  error fetching issue #%d: %v\n", t.ID, t.GitHubIssue, err)
				continue
			}
			if issue.State == "closed" {
				dim.Printf("  - task #%d  issue #%d already closed\n", t.ID, t.GitHubIssue)
				skipped++
				continue
			}
			if ghDryRun {
				yellow.Printf("  ~ task #%d  would close issue #%d: %s\n", t.ID, t.GitHubIssue, t.Title)
				closed++
				continue
			}
			if ghComment && t.Result != "" {
				comment := fmt.Sprintf("**Task completed by cloop**\n\n%s", truncate(t.Result, 1000))
				_ = client.AddComment(t.GitHubIssue, comment)
			}
			if err := client.CloseIssue(t.GitHubIssue); err != nil {
				red.Printf("  ! task #%d  error closing issue #%d: %v\n", t.ID, t.GitHubIssue, err)
				continue
			}
			closed++
			yellow.Printf("  ~ task #%d  closed issue #%d: %s\n", t.ID, t.GitHubIssue, t.Title)

		default:
			dim.Printf("  - task #%d  issue #%d linked — skipped\n", t.ID, t.GitHubIssue)
			skipped++
		}
	}

	fmt.Println()
	if ghDryRun {
		bold.Printf("Dry run: %d would create, %d would close, %d skipped\n", created, closed, skipped)
		return nil
	}

	if created > 0 || closed > 0 {
		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}

	parts := []string{}
	if created > 0 {
		parts = append(parts, fmt.Sprintf("%d created", created))
	}
	if closed > 0 {
		parts = append(parts, fmt.Sprintf("%d closed", closed))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}
	bold.Printf("Push complete: %s\n", strings.Join(parts, ", "))
	return nil
}

// ─── prs ─────────────────────────────────────────────────────────────────────

var githubPRsCmd = &cobra.Command{
	Use:   "prs",
	Short: "List pull requests with CI status",
	Long: `Display open pull requests for the repository, including CI check status.

Examples:
  cloop github prs                 # open PRs
  cloop github prs --state all     # include closed PRs
  cloop github prs --full          # show PR body preview`,
	RunE: runGitHubPRs,
}

func runGitHubPRs(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}

	client, err := resolveGitHub(cfg)
	if err != nil {
		return err
	}

	prState := ghState
	if prState == "" {
		prState = "open"
	}

	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	dim := color.New(color.Faint)

	bold.Printf("Pull requests — github.com/%s  (%s)\n\n", client.Repo, prState)

	prs, err := client.ListPRs(prState)
	if err != nil {
		return fmt.Errorf("fetching PRs: %w", err)
	}

	if len(prs) == 0 {
		dim.Println("No pull requests found.")
		return nil
	}

	// Try to load state for task linkage
	s, _ := state.Load(workdir)

	for _, pr := range prs {
		// Status indicator
		var stateStr string
		switch pr.State {
		case "open":
			if pr.Draft {
				stateStr = dim.Sprint("[draft]")
			} else {
				stateStr = green.Sprint("[open] ")
			}
		case "closed":
			stateStr = red.Sprint("[closed]")
		default:
			stateStr = dim.Sprint("[" + pr.State + "]")
		}

		prNum := cyan.Sprintf("#%d", pr.Number)
		age := formatAge(pr.UpdatedAt)

		fmt.Printf("  %s %s  %s\n", stateStr, prNum, bold.Sprint(pr.Title))
		fmt.Printf("         %s → %s  by %s  %s\n",
			dim.Sprint(pr.Head.Ref),
			dim.Sprint(pr.Base.Ref),
			pr.User.Login,
			dim.Sprint(age),
		)

		// Fetch check runs for the head SHA
		if pr.Head.SHA != "" {
			checks, err := client.ListCheckRuns(pr.Head.SHA)
			if err == nil && len(checks) > 0 {
				summary := gh.CheckRunSummary(checks)
				allPass := true
				anyFail := false
				for _, c := range checks {
					if c.Conclusion == "failure" || c.Conclusion == "timed_out" {
						anyFail = true
					}
					if c.Conclusion != "success" {
						allPass = false
					}
				}
				ciStr := dim.Sprint(summary)
				if allPass {
					ciStr = green.Sprint("CI: " + summary)
				} else if anyFail {
					ciStr = red.Sprint("CI: " + summary)
				} else {
					ciStr = yellow.Sprint("CI: " + summary)
				}
				fmt.Printf("         %s\n", ciStr)
			}
		}

		// Check if this PR is linked to a task
		if s != nil && s.Plan != nil && pr.Body != "" {
			for _, t := range s.Plan.Tasks {
				if t.GitHubIssue > 0 && strings.Contains(pr.Body, fmt.Sprintf("#%d", t.GitHubIssue)) {
					fmt.Printf("         %s\n", dim.Sprintf("linked to task #%d: %s", t.ID, t.Title))
				}
			}
		}

		if ghFull && pr.Body != "" {
			preview := truncate(pr.Body, 200)
			for _, line := range strings.Split(preview, "\n") {
				fmt.Printf("         %s\n", dim.Sprint(line))
			}
		}

		fmt.Printf("         %s\n\n", dim.Sprint(pr.HTMLURL))
	}

	bold.Printf("%d pull request(s) listed.\n", len(prs))
	return nil
}

// ─── link ────────────────────────────────────────────────────────────────────

var githubLinkCmd = &cobra.Command{
	Use:   "link <task-id> <issue-number>",
	Short: "Link a PM task to a GitHub issue",
	Args:  cobra.ExactArgs(2),
	RunE:  runGitHubLink,
}

func runGitHubLink(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}
	if s.Plan == nil {
		return fmt.Errorf("no PM plan — run 'cloop run --pm' first")
	}

	taskID := 0
	issueNum := 0
	if _, err := fmt.Sscanf(args[0], "%d", &taskID); err != nil {
		return fmt.Errorf("invalid task id: %s", args[0])
	}
	if _, err := fmt.Sscanf(args[1], "%d", &issueNum); err != nil {
		return fmt.Errorf("invalid issue number: %s", args[1])
	}

	var target *pm.Task
	for _, t := range s.Plan.Tasks {
		if t.ID == taskID {
			target = t
			break
		}
	}
	if target == nil {
		return fmt.Errorf("task #%d not found", taskID)
	}

	target.GitHubIssue = issueNum
	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	bold := color.New(color.Bold)
	bold.Printf("Task #%d linked to GitHub issue #%d\n", taskID, issueNum)
	return nil
}

// ─── unlink ───────────────────────────────────────────────────────────────────

var githubUnlinkCmd = &cobra.Command{
	Use:   "unlink <task-id>",
	Short: "Remove a PM task's GitHub issue link",
	Args:  cobra.ExactArgs(1),
	RunE:  runGitHubUnlink,
}

func runGitHubUnlink(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}
	if s.Plan == nil {
		return fmt.Errorf("no PM plan — run 'cloop run --pm' first")
	}

	taskID := 0
	if _, err := fmt.Sscanf(args[0], "%d", &taskID); err != nil {
		return fmt.Errorf("invalid task id: %s", args[0])
	}

	var target *pm.Task
	for _, t := range s.Plan.Tasks {
		if t.ID == taskID {
			target = t
			break
		}
	}
	if target == nil {
		return fmt.Errorf("task #%d not found", taskID)
	}

	prev := target.GitHubIssue
	target.GitHubIssue = 0
	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	bold := color.New(color.Bold)
	if prev > 0 {
		bold.Printf("Task #%d unlinked from GitHub issue #%d\n", taskID, prev)
	} else {
		bold.Printf("Task #%d had no GitHub link\n", taskID)
	}
	return nil
}

// ─── status ───────────────────────────────────────────────────────────────────

var githubStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show GitHub sync overview",
	RunE:  runGitHubStatus,
}

func runGitHubStatus(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()
	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}

	client, err := resolveGitHub(cfg)
	if err != nil {
		return err
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan)

	bold.Printf("GitHub sync status — %s\n\n", cyan.Sprint("github.com/"+client.Repo))

	token := cfg.GitHub.Token
	if token == "" {
		dim.Println("Token: not configured (read-only, public repos only)")
	} else {
		dim.Printf("Token: configured (%s...)\n", token[:min(8, len(token))])
	}
	fmt.Println()

	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		dim.Println("No PM plan tasks.")
		return nil
	}

	linked := 0
	unlinked := 0
	bold.Println("Task linkage:")
	for _, t := range s.Plan.Tasks {
		status := statusMarker(t.Status)
		if t.GitHubIssue > 0 {
			linked++
			fmt.Printf("  %s task #%d  ── #%s  %s\n",
				status, t.ID,
				cyan.Sprintf("%d", t.GitHubIssue),
				t.Title,
			)
		} else {
			unlinked++
			fmt.Printf("  %s task #%d  ── %s  %s\n",
				status, t.ID,
				dim.Sprint("no issue"),
				t.Title,
			)
		}
	}
	fmt.Println()
	green.Printf("  %d linked  /  %d unlinked  /  %d total\n", linked, unlinked, len(s.Plan.Tasks))
	fmt.Println()
	dim.Println("Use 'cloop github sync' to import issues, 'cloop github push' to export tasks.")
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func nextTaskID(plan *pm.Plan) int {
	if plan == nil {
		return 1
	}
	max := 0
	for _, t := range plan.Tasks {
		if t.ID > max {
			max = t.ID
		}
	}
	return max + 1
}

func nextPriority(plan *pm.Plan) int {
	if plan == nil {
		return 1
	}
	max := 0
	for _, t := range plan.Tasks {
		if t.Priority > max {
			max = t.Priority
		}
	}
	return max + 1
}

func roleFromLabels(labels []gh.Label) pm.AgentRole {
	for _, l := range labels {
		switch strings.ToLower(l.Name) {
		case "backend", "api", "server":
			return pm.RoleBackend
		case "frontend", "ui", "ux":
			return pm.RoleFrontend
		case "test", "testing", "tests":
			return pm.RoleTesting
		case "security", "auth":
			return pm.RoleSecurity
		case "devops", "ci", "cd", "infra":
			return pm.RoleDevOps
		case "database", "data", "db":
			return pm.RoleData
		case "docs", "documentation":
			return pm.RoleDocs
		case "review", "refactor", "cleanup":
			return pm.RoleReview
		}
	}
	return ""
}

func buildTaskDescription(issue gh.Issue) string {
	var b strings.Builder
	if issue.Body != "" {
		b.WriteString(issue.Body)
		b.WriteString("\n\n")
	}
	if issue.LabelNames() != "" {
		b.WriteString("Labels: " + issue.LabelNames() + "\n")
	}
	b.WriteString(fmt.Sprintf("Source: %s", issue.HTMLURL))
	return b.String()
}

func buildIssueBody(t *pm.Task, goal string) string {
	var b strings.Builder
	if t.Description != "" {
		b.WriteString(t.Description)
		b.WriteString("\n\n")
	}
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*Created by [cloop](https://github.com/blechschmidt/cloop) — task #%d*\n", t.ID))
	if goal != "" {
		b.WriteString(fmt.Sprintf("*Goal: %s*\n", truncate(goal, 120)))
	}
	if t.Role != "" {
		b.WriteString(fmt.Sprintf("*Role: %s*\n", t.Role))
	}
	return b.String()
}

func formatAge(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func statusMarker(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return color.GreenString("[x]")
	case pm.TaskSkipped:
		return color.YellowString("[-]")
	case pm.TaskFailed:
		return color.RedString("[!]")
	case pm.TaskInProgress:
		return color.CyanString("[~]")
	default:
		return color.New(color.Faint).Sprint("[ ]")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── init ────────────────────────────────────────────────────────────────────

func init() {
	// Shared flags for commands that need a repo / token
	for _, c := range []*cobra.Command{
		githubSyncCmd,
		githubPushCmd,
		githubPRsCmd,
		githubStatusCmd,
	} {
		c.Flags().StringVar(&ghRepo, "repo", "", "GitHub repo in owner/repo format (overrides config and auto-detect)")
		c.Flags().StringVar(&ghToken, "token", "", "GitHub personal access token (overrides config and GITHUB_TOKEN env)")
	}

	// sync flags
	githubSyncCmd.Flags().StringVar(&ghLabels, "labels", "", "Filter issues by label (comma-separated)")
	githubSyncCmd.Flags().BoolVar(&ghDryRun, "dry-run", false, "Preview what would be imported without saving")
	githubSyncCmd.Flags().BoolVar(&ghForce, "force", false, "Update already-linked tasks from GitHub")

	// push flags
	githubPushCmd.Flags().BoolVar(&ghDryRun, "dry-run", false, "Preview what would be created/closed without writing to GitHub")
	githubPushCmd.Flags().BoolVar(&ghPushDone, "done", false, "Close linked issues for done/skipped tasks")
	githubPushCmd.Flags().BoolVar(&ghComment, "comment", true, "Add completion comment when closing issues")

	// prs flags
	githubPRsCmd.Flags().StringVar(&ghState, "state", "open", "PR state: open, closed, all")
	githubPRsCmd.Flags().BoolVar(&ghFull, "full", false, "Show PR body preview")

	// Assemble command tree
	githubCmd.AddCommand(githubSyncCmd)
	githubCmd.AddCommand(githubPushCmd)
	githubCmd.AddCommand(githubPRsCmd)
	githubCmd.AddCommand(githubLinkCmd)
	githubCmd.AddCommand(githubUnlinkCmd)
	githubCmd.AddCommand(githubStatusCmd)

	rootCmd.AddCommand(githubCmd)
}
