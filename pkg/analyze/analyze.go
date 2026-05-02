// Package analyze implements AI-powered codebase bootstrapping for cloop.
// It scans an existing project directory, collects contextual signals
// (git history, README, directory layout, TODOs, manifest files), and
// asks the configured AI provider to propose a 5-10 task cloop plan.
package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// ProposedTask is a single task returned by the AI analysis.
type ProposedTask struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Priority         int      `json:"priority"`
	Role             string   `json:"role"`
	EstimatedMinutes int      `json:"estimated_minutes"`
	Tags             []string `json:"tags"`
}

// Proposal is the AI's full plan proposal for an analysed project.
type Proposal struct {
	Goal  string         `json:"goal"`
	Tasks []ProposedTask `json:"tasks"`
}

// Context holds the raw signals collected from the target directory.
type Context struct {
	GitLog    string
	Readme    string
	Changelog string
	DirTree   string
	Todos     string
	Manifest  string // content of go.mod / package.json / Cargo.toml (first found)
}

// Collect gathers project signals from dir.
func Collect(dir string) (*Context, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving directory: %w", err)
	}

	ctx := &Context{}

	// Git log
	if out, err := runCmd(abs, "git", "log", "--oneline", "-20"); err == nil {
		ctx.GitLog = strings.TrimSpace(out)
	}

	// README
	ctx.Readme = readFirstExisting(abs, "README.md", "README.txt", "README")

	// CHANGELOG
	ctx.Changelog = readFirstExisting(abs, "CHANGELOG.md", "CHANGELOG.txt", "CHANGELOG")
	if ctx.Changelog != "" && len(ctx.Changelog) > 3000 {
		ctx.Changelog = ctx.Changelog[:3000] + "\n... (truncated)"
	}

	// Directory tree (top 2 levels)
	ctx.DirTree = buildDirTree(abs, 2)

	// TODO/FIXME comments
	if out, err := runCmd(abs, "grep", "-rn", "--include=*.go", "--include=*.ts", "--include=*.js",
		"--include=*.py", "--include=*.rs", "--include=*.java",
		"-e", "TODO", "-e", "FIXME", "--max-count=5", "."); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		// Cap at 30 lines
		if len(lines) > 30 {
			lines = lines[:30]
		}
		ctx.Todos = strings.Join(lines, "\n")
	}

	// Build manifest
	for _, name := range []string{"go.mod", "package.json", "Cargo.toml", "pyproject.toml", "pom.xml"} {
		content := readFirstExisting(abs, name)
		if content != "" {
			if len(content) > 2000 {
				content = content[:2000] + "\n... (truncated)"
			}
			ctx.Manifest = fmt.Sprintf("=== %s ===\n%s", name, content)
			break
		}
	}

	return ctx, nil
}

// BuildPrompt constructs the AI prompt from a collected Context.
func BuildPrompt(ctx *Context, goal string) string {
	var b strings.Builder

	b.WriteString("You are an AI product manager performing codebase bootstrapping.\n")
	b.WriteString("Analyse the project signals below and propose a focused 5-10 task cloop plan.\n\n")

	if goal != "" {
		b.WriteString("## USER-SUPPLIED GOAL\n")
		b.WriteString(goal)
		b.WriteString("\n\n")
	}

	if ctx.GitLog != "" {
		b.WriteString("## RECENT GIT HISTORY (last 20 commits)\n")
		b.WriteString(ctx.GitLog)
		b.WriteString("\n\n")
	}

	if ctx.Readme != "" {
		readme := ctx.Readme
		if len(readme) > 3000 {
			readme = readme[:3000] + "\n... (truncated)"
		}
		b.WriteString("## README\n")
		b.WriteString(readme)
		b.WriteString("\n\n")
	}

	if ctx.Changelog != "" {
		b.WriteString("## CHANGELOG (recent)\n")
		b.WriteString(ctx.Changelog)
		b.WriteString("\n\n")
	}

	if ctx.DirTree != "" {
		b.WriteString("## DIRECTORY STRUCTURE (top 2 levels)\n")
		b.WriteString(ctx.DirTree)
		b.WriteString("\n\n")
	}

	if ctx.Manifest != "" {
		b.WriteString("## BUILD MANIFEST\n")
		b.WriteString(ctx.Manifest)
		b.WriteString("\n\n")
	}

	if ctx.Todos != "" {
		b.WriteString("## OPEN TODO/FIXME COMMENTS\n")
		b.WriteString(ctx.Todos)
		b.WriteString("\n\n")
	}

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Based on the project signals above, produce a JSON object with two fields:\n")
	b.WriteString("- goal: a concise one-sentence summary of what the project is and what the plan aims to achieve\n")
	b.WriteString("- tasks: array of 5-10 task objects, each with:\n")
	b.WriteString("    - title: short imperative title (max 80 chars)\n")
	b.WriteString("    - description: 1-3 sentences explaining what to do and why\n")
	b.WriteString("    - priority: integer 1-10, where 1 is highest priority\n")
	b.WriteString("    - role: one of backend, frontend, testing, security, devops, data, docs, review\n")
	b.WriteString("    - estimated_minutes: realistic integer estimate\n")
	b.WriteString("    - tags: array of 1-3 lowercase tags\n\n")
	b.WriteString("Order tasks by priority (most important first).\n")
	b.WriteString("Focus on concrete, actionable improvements visible from the project signals.\n")
	b.WriteString("Do NOT invent features unrelated to what the project already does.\n\n")
	b.WriteString("Output ONLY valid JSON with no explanation, no markdown code fences, no extra text.\n\n")
	b.WriteString(`Example: {"goal":"Harden and expand the REST API","tasks":[{"title":"Add request validation middleware","description":"Validate all incoming request bodies against JSON schemas before they reach handlers. Return structured 400 errors.","priority":1,"role":"backend","estimated_minutes":90,"tags":["validation","api","security"]}]}`)

	return b.String()
}

// ParseProposal extracts the Proposal from an AI response string.
func ParseProposal(response string) (*Proposal, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in AI response")
	}

	var p Proposal
	if err := json.Unmarshal([]byte(response[start:end+1]), &p); err != nil {
		return nil, fmt.Errorf("parsing proposal: %w", err)
	}
	if p.Goal == "" {
		return nil, fmt.Errorf("AI returned empty goal")
	}
	if len(p.Tasks) == 0 {
		return nil, fmt.Errorf("AI returned no tasks")
	}

	// Clamp priorities
	for i := range p.Tasks {
		if p.Tasks[i].Priority < 1 {
			p.Tasks[i].Priority = 1
		}
		if p.Tasks[i].Priority > 10 {
			p.Tasks[i].Priority = 10
		}
		if p.Tasks[i].EstimatedMinutes < 0 {
			p.Tasks[i].EstimatedMinutes = 0
		}
	}

	return &p, nil
}

// Analyze runs the full analysis pipeline: collect → prompt → call AI → parse.
func Analyze(ctx context.Context, p provider.Provider, opts provider.Options, dir, goal string) (*Proposal, error) {
	collected, err := Collect(dir)
	if err != nil {
		return nil, fmt.Errorf("analyze: collect: %w", err)
	}

	prompt := BuildPrompt(collected, goal)
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("analyze: provider: %w", err)
	}

	proposal, err := ParseProposal(result.Output)
	if err != nil {
		return nil, fmt.Errorf("analyze: parse: %w", err)
	}

	return proposal, nil
}

// ProposalToPlan converts a Proposal into a pm.Plan ready to persist.
func ProposalToPlan(proposal *Proposal) *pm.Plan {
	plan := pm.NewPlan(proposal.Goal)
	for i, pt := range proposal.Tasks {
		task := &pm.Task{
			ID:               i + 1,
			Title:            pt.Title,
			Description:      pt.Description,
			Priority:         pt.Priority,
			Role:             pm.AgentRole(pt.Role),
			Tags:             pt.Tags,
			EstimatedMinutes: pt.EstimatedMinutes,
			Status:           pm.TaskPending,
		}
		plan.Tasks = append(plan.Tasks, task)
	}
	return plan
}

// --- helpers ---

func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

func readFirstExisting(dir string, names ...string) string {
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			return string(data)
		}
	}
	return ""
}

// buildDirTree produces a simple indented tree of dir up to maxDepth levels.
func buildDirTree(dir string, maxDepth int) string {
	var b strings.Builder
	walkDir(&b, dir, dir, 0, maxDepth)
	return strings.TrimRight(b.String(), "\n")
}

func walkDir(b *strings.Builder, root, current string, depth, maxDepth int) {
	if depth > maxDepth {
		return
	}

	entries, err := os.ReadDir(current)
	if err != nil {
		return
	}

	for _, e := range entries {
		// Skip hidden dirs/files and common noise
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if name == "node_modules" || name == "vendor" || name == "dist" || name == "target" || name == "__pycache__" {
			continue
		}

		indent := strings.Repeat("  ", depth)
		if e.IsDir() {
			fmt.Fprintf(b, "%s%s/\n", indent, name)
			if depth < maxDepth {
				walkDir(b, root, filepath.Join(current, name), depth+1, maxDepth)
			}
		} else {
			fmt.Fprintf(b, "%s%s\n", indent, name)
		}
	}
}
