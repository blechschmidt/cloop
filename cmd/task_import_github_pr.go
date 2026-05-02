package cmd

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	gh "github.com/blechschmidt/cloop/pkg/github"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	importPRRepo  string
	importPRToken string
)

var taskImportGitHubPRCmd = &cobra.Command{
	Use:   "import-github-pr",
	Short: "Create tasks from open GitHub pull requests",
	Long: `Fetch open pull requests from a GitHub repository and create cloop tasks.

Presents a selection menu showing PR title, author, number, and labels.
Each selected PR becomes a task with:
  - Title from the PR title
  - Description summarising the PR body and changed files
  - Tag "github-pr"
  - ExternalURL set to the PR URL
  - DependsOn links to any referenced issue tasks already in the plan

Examples:
  cloop task import-github-pr
  cloop task import-github-pr --repo owner/repo
  cloop task import-github-pr --repo owner/repo --token ghp_xxx`,
	RunE: runTaskImportGitHubPR,
}

func runTaskImportGitHubPR(cmd *cobra.Command, args []string) error {
	workdir, _ := os.Getwd()

	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}
	s, err := state.Load(workdir)
	if err != nil {
		return err
	}

	// Resolve token: flag > config > env
	token := importPRToken
	if token == "" {
		token = cfg.GitHub.Token
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	// Resolve repo: flag > config > git remote auto-detect
	repo := importPRRepo
	if repo == "" {
		repo = cfg.GitHub.Repo
	}
	if repo == "" {
		detected, err := gh.DetectRepo()
		if err != nil {
			return fmt.Errorf("no GitHub repo specified (use --repo owner/repo or set github.repo in config): %w", err)
		}
		repo = detected
	}
	if !strings.Contains(repo, "/") {
		return fmt.Errorf("invalid repo format %q — expected owner/repo", repo)
	}

	client := gh.New(token, repo)

	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	dim := color.New(color.Faint)
	yellow := color.New(color.FgYellow)

	bold.Printf("Fetching open pull requests from github.com/%s ...\n\n", repo)

	prs, err := client.ListPRs("open")
	if err != nil {
		return fmt.Errorf("fetching pull requests: %w", err)
	}

	if len(prs) == 0 {
		dim.Println("No open pull requests found.")
		return nil
	}

	// Build set of already-imported PR URLs to skip duplicates
	alreadyImported := map[string]bool{}
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			if t.ExternalURL != "" {
				alreadyImported[t.ExternalURL] = true
			}
		}
	}

	// Display selection menu
	fmt.Printf("%-5s %-7s %-20s %-25s %s\n",
		"#", "PR", "Author", "Labels", "Title")
	fmt.Println(strings.Repeat("─", 90))

	available := make([]gh.PR, 0, len(prs))
	for _, pr := range prs {
		if alreadyImported[pr.HTMLURL] {
			dim.Printf("  [already imported] #%-4d %s\n", pr.Number, pr.Title)
			continue
		}
		idx := len(available) + 1
		available = append(available, pr)
		labels := pr.LabelNames()
		if labels == "" {
			labels = dim.Sprint("(none)")
		}
		draft := ""
		if pr.Draft {
			draft = dim.Sprint(" [draft]")
		}
		fmt.Printf("%-5d %-7s %-20s %-25s %s%s\n",
			idx,
			cyan.Sprintf("#%d", pr.Number),
			truncatePR(pr.User.Login, 18),
			truncatePR(labels, 23),
			pr.Title,
			draft,
		)
	}

	if len(available) == 0 {
		fmt.Println()
		dim.Println("All open PRs have already been imported.")
		return nil
	}

	fmt.Println()
	fmt.Printf("Enter PR numbers to import (e.g. 1,3 or 1-3 or 'all'), or press Enter to cancel: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		dim.Println("Cancelled.")
		return nil
	}

	selected, err := parsePRSelection(input, len(available))
	if err != nil {
		return fmt.Errorf("invalid selection: %w", err)
	}
	if len(selected) == 0 {
		dim.Println("No PRs selected.")
		return nil
	}

	// Ensure plan exists
	if s.Plan == nil {
		s.Plan = pm.NewPlan(s.Goal)
		s.PMMode = true
	}

	// Build index: GitHub issue number → task ID (for dependency links)
	issueToTaskID := map[int]int{}
	for _, t := range s.Plan.Tasks {
		if t.GitHubIssue > 0 {
			issueToTaskID[t.GitHubIssue] = t.ID
		}
	}

	imported := 0
	for _, idx := range selected {
		pr := available[idx-1]

		bold.Printf("\nImporting PR #%d: %s\n", pr.Number, pr.Title)

		// Fetch changed files
		files, err := client.GetPRFiles(pr.Number)
		if err != nil {
			yellow.Printf("  Warning: could not fetch changed files: %v\n", err)
		}

		// Build description
		desc := buildPRTaskDescription(pr, files)

		// Detect referenced issue numbers in PR body
		deps := findReferencedIssueTasks(pr.Body, issueToTaskID)

		newTask := &pm.Task{
			ID:          nextTaskIDFromPlan(s.Plan),
			Title:       pr.Title,
			Description: desc,
			Priority:    nextPriorityFromPlan(s.Plan),
			Status:      pm.TaskPending,
			Tags:        []string{"github-pr"},
			ExternalURL: pr.HTMLURL,
			DependsOn:   deps,
			Role:        roleFromLabels(pr.Labels),
		}

		s.Plan.Tasks = append(s.Plan.Tasks, newTask)
		// Update index for subsequent tasks in this batch
		issueToTaskID[pr.Number] = newTask.ID

		green.Printf("  + Created task #%d: %s\n", newTask.ID, newTask.Title)
		if len(deps) > 0 {
			depStrs := make([]string, len(deps))
			for i, d := range deps {
				depStrs[i] = fmt.Sprintf("#%d", d)
			}
			dim.Printf("    Depends on tasks: %s\n", strings.Join(depStrs, ", "))
		}
		dim.Printf("    URL: %s\n", pr.HTMLURL)
		imported++
	}

	if imported == 0 {
		return nil
	}

	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Println()
	bold.Printf("Imported %d task(s) from GitHub PRs.\n", imported)
	dim.Println("Run 'cloop run --pm' to execute the imported tasks.")
	return nil
}

// buildPRTaskDescription assembles a task description from PR body and changed files.
func buildPRTaskDescription(pr gh.PR, files []gh.PRFile) string {
	var b strings.Builder

	if pr.Body != "" {
		body := strings.TrimSpace(pr.Body)
		if len(body) > 800 {
			body = body[:800] + "…"
		}
		b.WriteString(body)
		b.WriteString("\n\n")
	}

	if len(files) > 0 {
		b.WriteString("**Changed files:**\n")
		shown := files
		if len(shown) > 20 {
			shown = shown[:20]
		}
		for _, f := range shown {
			b.WriteString(fmt.Sprintf("- %s (%s)\n", f.Filename, f.Status))
		}
		if len(files) > 20 {
			b.WriteString(fmt.Sprintf("- … and %d more file(s)\n", len(files)-20))
		}
		b.WriteString("\n")
	}

	if pr.LabelNames() != "" {
		b.WriteString("Labels: " + pr.LabelNames() + "\n")
	}
	b.WriteString(fmt.Sprintf("Branch: %s → %s\n", pr.Head.Ref, pr.Base.Ref))
	b.WriteString(fmt.Sprintf("Author: %s\n", pr.User.Login))
	b.WriteString(fmt.Sprintf("PR URL: %s", pr.HTMLURL))
	return b.String()
}

// findReferencedIssueTasks scans a PR body for "closes/fixes/resolves #NNN" and
// "referenced in #NNN" patterns, returning task IDs for any matching linked issues.
var issueRefRe = regexp.MustCompile(`(?i)(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|ref(?:erence[sd]?)?)?\s*#(\d+)`)

func findReferencedIssueTasks(body string, issueToTaskID map[int]int) []int {
	if body == "" || len(issueToTaskID) == 0 {
		return nil
	}
	seen := map[int]bool{}
	var deps []int
	for _, match := range issueRefRe.FindAllStringSubmatch(body, -1) {
		num, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		if taskID, ok := issueToTaskID[num]; ok && !seen[taskID] {
			seen[taskID] = true
			deps = append(deps, taskID)
		}
	}
	return deps
}

// parsePRSelection parses user input like "1,3", "1-3", "all" into 1-based indices.
func parsePRSelection(input string, total int) ([]int, error) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "all" {
		indices := make([]int, total)
		for i := range indices {
			indices[i] = i + 1
		}
		return indices, nil
	}

	seen := map[int]bool{}
	var result []int

	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if lo < 1 || hi > total || lo > hi {
				return nil, fmt.Errorf("range %d-%d out of bounds (1-%d)", lo, hi, total)
			}
			for i := lo; i <= hi; i++ {
				if !seen[i] {
					seen[i] = true
					result = append(result, i)
				}
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid number %q", part)
			}
			if n < 1 || n > total {
				return nil, fmt.Errorf("number %d out of bounds (1-%d)", n, total)
			}
			if !seen[n] {
				seen[n] = true
				result = append(result, n)
			}
		}
	}
	return result, nil
}

func nextTaskIDFromPlan(plan *pm.Plan) int {
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

func nextPriorityFromPlan(plan *pm.Plan) int {
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

func truncatePR(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func init() {
	taskImportGitHubPRCmd.Flags().StringVar(&importPRRepo, "repo", "", "GitHub repo in owner/repo format (overrides config and auto-detect)")
	taskImportGitHubPRCmd.Flags().StringVar(&importPRToken, "token", "", "GitHub personal access token (overrides config and GITHUB_TOKEN env)")
	taskCmd.AddCommand(taskImportGitHubPRCmd)
}
