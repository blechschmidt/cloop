// Package naming provides AI-powered batch title normalization for cloop tasks.
// It rewrites task titles to follow a consistent verb-object imperative format
// such as "Implement X", "Fix Y", "Add Z", "Refactor W".
package naming

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// NormalizationPrompt builds a prompt asking the AI to rewrite all task titles
// to follow a consistent verb-object imperative format.
func NormalizationPrompt(tasks []*pm.Task) string {
	var sb strings.Builder

	sb.WriteString("You are a technical writing assistant. Your job is to normalize task titles to follow a consistent verb-object imperative format.\n\n")
	sb.WriteString("Rules for normalized titles:\n")
	sb.WriteString("- Start with a strong action verb in imperative form (Implement, Add, Fix, Refactor, Update, Remove, Create, Integrate, Enable, Migrate, Document, Test, Optimize, Expose, Support)\n")
	sb.WriteString("- Follow the verb with a concise object phrase describing what is being acted upon\n")
	sb.WriteString("- Keep titles concise: 3-8 words is ideal\n")
	sb.WriteString("- Do not include articles (a, an, the) unless required for clarity\n")
	sb.WriteString("- Preserve technical names, acronyms, and proper nouns exactly as given\n")
	sb.WriteString("- Do not change the meaning of a title — only normalize its grammatical form\n\n")

	sb.WriteString("Examples:\n")
	sb.WriteString("  Bad: \"Task for implementing user login\"     → Good: \"Implement user login\"\n")
	sb.WriteString("  Bad: \"The database should be migrated\"      → Good: \"Migrate database\"\n")
	sb.WriteString("  Bad: \"Add support for Markdown\"             → Good: \"Add Markdown support\" (already good)\n")
	sb.WriteString("  Bad: \"Fixing the broken OAuth flow\"         → Good: \"Fix OAuth flow\"\n")
	sb.WriteString("  Bad: \"A refactor of auth middleware\"        → Good: \"Refactor auth middleware\"\n\n")

	sb.WriteString("Here are the task titles to normalize:\n\n")
	for _, t := range tasks {
		fmt.Fprintf(&sb, "  ID %d: %q\n", t.ID, t.Title)
	}

	sb.WriteString("\nReturn ONLY a valid JSON object mapping task ID (as a number) to the suggested normalized title.\n")
	sb.WriteString("If a title is already well-formed, you may keep it unchanged.\n")
	sb.WriteString("Do not include any explanation, markdown fences, or additional text.\n\n")
	sb.WriteString("Example response format:\n")
	sb.WriteString(`{"1": "Implement user login", "2": "Fix OAuth flow", "3": "Add Markdown support"}`)
	sb.WriteString("\n")

	return sb.String()
}

// ParseResponse parses the AI's JSON response into a map of task ID → normalized title.
// It handles responses that may be wrapped in markdown code fences.
func ParseResponse(raw string) (map[int]string, error) {
	raw = strings.TrimSpace(raw)

	// Strip markdown code fences if present.
	if idx := strings.Index(raw, "```"); idx != -1 {
		// Find content between fences.
		start := strings.Index(raw, "\n")
		if start == -1 {
			start = idx + 3
		} else {
			start++
		}
		end := strings.LastIndex(raw, "```")
		if end > start {
			raw = strings.TrimSpace(raw[start:end])
		}
	}

	// Extract the first JSON object if there's surrounding text.
	re := regexp.MustCompile(`\{[^{}]*\}`)
	if m := re.FindString(raw); m != "" {
		raw = m
	}

	// Unmarshal as map[string]string first (JSON keys are always strings).
	var strMap map[string]string
	if err := json.Unmarshal([]byte(raw), &strMap); err != nil {
		return nil, fmt.Errorf("parsing AI response as JSON: %w (raw: %q)", err, raw)
	}

	result := make(map[int]string, len(strMap))
	for k, v := range strMap {
		var id int
		if _, err := fmt.Sscanf(k, "%d", &id); err != nil {
			return nil, fmt.Errorf("invalid task ID key %q in response", k)
		}
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("empty title for task ID %d", id)
		}
		result[id] = v
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("AI returned an empty mapping")
	}

	return result, nil
}
