// Package onboard implements AI-generated contributor onboarding guide generation.
// It collects project context from state, file tree, integrations, providers,
// and knowledge base, then asks the AI to produce a structured Markdown
// ONBOARDING.md guide for new contributors.
package onboard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/analyze"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/integrations"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/profile"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Input holds all data collected to build the onboarding prompt.
type Input struct {
	Goal             string
	Instructions     string
	CompletedTasks   []*pm.Task
	PendingTasks     []*pm.Task
	DirTree          string
	GitLog           string
	Readme           string
	Manifest         string
	Integrations     []integrations.IntegrationStatus
	ProviderName     string
	ProviderModel    string
	Profiles         []profile.Profile
	KBEntries        []*kb.Entry
}

// Collect gathers all context needed to generate the onboarding guide.
func Collect(workDir string, s *state.ProjectState, cfg *config.Config, providerName, model string) (*Input, error) {
	inp := &Input{
		Goal:          s.Goal,
		Instructions:  s.Instructions,
		ProviderName:  providerName,
		ProviderModel: model,
	}

	// Tasks from plan
	if s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone, pm.TaskSkipped:
				inp.CompletedTasks = append(inp.CompletedTasks, t)
			case pm.TaskPending, pm.TaskInProgress:
				inp.PendingTasks = append(inp.PendingTasks, t)
			}
		}
	}

	// File tree and git log via analyze.Collect
	ac, err := analyze.Collect(workDir)
	if err == nil {
		inp.DirTree = ac.DirTree
		inp.GitLog = ac.GitLog
		inp.Readme = ac.Readme
		inp.Manifest = ac.Manifest
	}

	// Integrations (no health check, just status)
	inp.Integrations = integrations.Check(context.Background(), workDir, cfg)

	// Named profiles
	profs, _ := profile.LoadProfiles()
	inp.Profiles = profs

	// Knowledge base entries
	kbStore, kbErr := kb.Load(workDir)
	if kbErr == nil {
		inp.KBEntries = kbStore.Entries
	}

	return inp, nil
}

// BuildPrompt constructs the AI prompt requesting the onboarding guide.
func BuildPrompt(inp *Input) string {
	var b strings.Builder

	b.WriteString("You are a senior developer writing a contributor onboarding guide for a software project.\n")
	b.WriteString("Based on the project context below, write a comprehensive ONBOARDING.md in GitHub-flavored Markdown.\n\n")

	b.WriteString("## PROJECT GOAL\n")
	b.WriteString(inp.Goal + "\n\n")

	if inp.Instructions != "" {
		b.WriteString("## CONSTRAINTS / INSTRUCTIONS\n")
		b.WriteString(inp.Instructions + "\n\n")
	}

	// Provider / model
	b.WriteString("## CONFIGURED AI PROVIDER\n")
	b.WriteString(fmt.Sprintf("Provider: %s", inp.ProviderName))
	if inp.ProviderModel != "" {
		b.WriteString(fmt.Sprintf(", Model: %s", inp.ProviderModel))
	}
	b.WriteString("\n\n")

	// Named profiles
	if len(inp.Profiles) > 0 {
		b.WriteString("## NAMED PROFILES\n")
		for _, p := range inp.Profiles {
			line := fmt.Sprintf("- **%s**: provider=%s", p.Name, p.Provider)
			if p.Model != "" {
				line += fmt.Sprintf(", model=%s", p.Model)
			}
			if p.Description != "" {
				line += fmt.Sprintf(" — %s", p.Description)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	// Manifest (go.mod / package.json etc.)
	if inp.Manifest != "" {
		b.WriteString("## PROJECT MANIFEST\n")
		manifest := inp.Manifest
		if len(manifest) > 1000 {
			manifest = manifest[:1000] + "\n... (truncated)"
		}
		b.WriteString("```\n" + manifest + "\n```\n\n")
	}

	// README excerpt
	if inp.Readme != "" {
		readme := inp.Readme
		if len(readme) > 2000 {
			readme = readme[:2000] + "\n... (truncated)"
		}
		b.WriteString("## README EXCERPT\n")
		b.WriteString(readme + "\n\n")
	}

	// Directory tree
	if inp.DirTree != "" {
		b.WriteString("## DIRECTORY STRUCTURE\n")
		b.WriteString("```\n" + inp.DirTree + "\n```\n\n")
	}

	// Git log
	if inp.GitLog != "" {
		b.WriteString("## RECENT GIT HISTORY\n")
		b.WriteString("```\n" + inp.GitLog + "\n```\n\n")
	}

	// Completed tasks
	if len(inp.CompletedTasks) > 0 {
		b.WriteString("## COMPLETED WORK (task history)\n")
		// Show at most 30 to keep prompt manageable
		tasks := inp.CompletedTasks
		if len(tasks) > 30 {
			tasks = tasks[len(tasks)-30:]
		}
		for _, t := range tasks {
			b.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf("  %s\n", t.Description))
			}
		}
		b.WriteString("\n")
	}

	// Pending tasks
	if len(inp.PendingTasks) > 0 {
		b.WriteString("## PENDING / IN-PROGRESS TASKS\n")
		for _, t := range inp.PendingTasks {
			b.WriteString(fmt.Sprintf("- Task %d: %s\n", t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	// Integrations
	configured := filterConfigured(inp.Integrations)
	if len(configured) > 0 {
		b.WriteString("## ACTIVE INTEGRATIONS\n")
		for _, s := range configured {
			status := "configured"
			if s.Healthy {
				status = "healthy"
			}
			b.WriteString(fmt.Sprintf("- **%s**: %s", s.Name, status))
			if s.Detail != "" {
				b.WriteString(fmt.Sprintf(" (%s)", s.Detail))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Knowledge base
	if len(inp.KBEntries) > 0 {
		b.WriteString("## PROJECT KNOWLEDGE BASE\n")
		for _, e := range inp.KBEntries {
			b.WriteString(fmt.Sprintf("### %s\n", e.Title))
			content := e.Content
			if len(content) > 400 {
				content = content[:400] + "…"
			}
			b.WriteString(content + "\n\n")
		}
	}

	b.WriteString("---\n\n")
	b.WriteString("## YOUR TASK\n\n")
	b.WriteString("Write a complete ONBOARDING.md for new contributors to this project.\n\n")
	b.WriteString("The guide MUST include all of the following sections (use these exact headings):\n\n")
	b.WriteString("1. **Project Purpose** — what this project does and why it exists\n")
	b.WriteString("2. **Architecture Overview** — major packages/modules, how they interact, key design decisions\n")
	b.WriteString("3. **Prerequisites** — runtime versions, tools, accounts, or credentials needed\n")
	b.WriteString("4. **Getting Started** — step-by-step setup: clone, install deps, build, run\n")
	b.WriteString("5. **Running Tests** — how to run the test suite; any test categories or tags\n")
	b.WriteString("6. **Key Commands** — the most important CLI commands a contributor needs to know\n")
	b.WriteString("7. **Contribution Workflow** — branching strategy, commit conventions, PR process\n")
	b.WriteString("8. **Active Integrations** — external services in use and how to configure them\n")
	b.WriteString("9. **Provider Configuration** — how to set up and switch AI providers/models\n")
	b.WriteString("10. **Project Roadmap** — summary of completed work and what is planned next\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Be concrete and specific — use real file paths, command names, and config keys from the context above\n")
	b.WriteString("- Use code blocks for all commands and file snippets\n")
	b.WriteString("- Keep the tone friendly and welcoming for new contributors\n")
	b.WriteString("- Do NOT include a YAML front matter block\n")
	b.WriteString("- Start directly with the `# Onboarding Guide` heading\n")
	b.WriteString(fmt.Sprintf("- Use today's date (%s) where a date is needed\n", time.Now().Format("2006-01-02")))

	return b.String()
}

// Generate calls the AI provider with the prompt and returns the raw Markdown output.
func Generate(ctx context.Context, p provider.Provider, model string, timeout time.Duration, inp *Input) (string, error) {
	prompt := BuildPrompt(inp)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("onboard: %w", err)
	}
	return result.Output, nil
}

// filterConfigured returns only integrations that are configured.
func filterConfigured(statuses []integrations.IntegrationStatus) []integrations.IntegrationStatus {
	var out []integrations.IntegrationStatus
	for _, s := range statuses {
		if s.Configured {
			out = append(out, s)
		}
	}
	return out
}
