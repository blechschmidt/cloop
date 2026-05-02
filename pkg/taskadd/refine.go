package taskadd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
)

// editableFields lists the fields that can be refined, in display order.
var editableFields = []string{
	"title",
	"description",
	"priority",
	"role",
	"estimated_minutes",
	"tags",
	"depends_on",
}

// PrintSpec pretty-prints a TaskSpec to stdout.
func PrintSpec(spec *TaskSpec, existingPlan *pm.Plan) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	bold.Println("── Proposed Task ──────────────────────────────────────")
	yellow.Printf("  [1] title             %s\n", spec.Title)
	fmt.Printf("  [2] description       ")
	dim.Printf("%s\n", spec.Description)
	fmt.Printf("  [3] priority          %d\n", spec.Priority)
	if spec.Role != "" {
		fmt.Printf("  [4] role              %s\n", spec.Role)
	} else {
		dim.Printf("  [4] role              (none)\n")
	}
	if spec.EstimatedMinutes > 0 {
		fmt.Printf("  [5] estimated_minutes %d\n", spec.EstimatedMinutes)
	} else {
		dim.Printf("  [5] estimated_minutes (none)\n")
	}
	if len(spec.Tags) > 0 {
		fmt.Printf("  [6] tags              %s\n", strings.Join(spec.Tags, ", "))
	} else {
		dim.Printf("  [6] tags              (none)\n")
	}
	if len(spec.SuggestedDependsOn) > 0 {
		deps := make([]string, 0, len(spec.SuggestedDependsOn))
		for _, id := range spec.SuggestedDependsOn {
			deps = append(deps, fmt.Sprintf("#%d", id))
		}
		fmt.Printf("  [7] depends_on        %s\n", strings.Join(deps, ", "))
	} else {
		dim.Printf("  [7] depends_on        (none)\n")
	}
	if spec.Rationale != "" {
		fmt.Printf("\n  rationale: ")
		dim.Printf("%s\n", spec.Rationale)
	}
	fmt.Println()
	_ = existingPlan // reserved for future dep resolution display
	cyan.Printf("  [a]ccept  [e]dit <1-7 or name>  [r]egenerate  [q]uit\n")
	fmt.Println()
}

// RefineFieldPrompt returns a prompt asking the AI to update a single field.
func RefineFieldPrompt(spec *TaskSpec, field, guidance string, existingPlan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are an AI product manager. Update ONLY the \"")
	b.WriteString(field)
	b.WriteString("\" field of the following task based on the user's guidance. Keep all other fields unchanged.\n\n")

	b.WriteString("## CURRENT TASK\n")
	if raw, err := json.Marshal(spec); err == nil {
		b.Write(raw)
		b.WriteString("\n\n")
	}

	if existingPlan != nil && len(existingPlan.Tasks) > 0 {
		b.WriteString("## PLAN CONTEXT\n")
		b.WriteString(fmt.Sprintf("Goal: %s\n", existingPlan.Goal))
		for _, t := range existingPlan.Tasks {
			b.WriteString(fmt.Sprintf("  #%d [P%d] %s — %s\n", t.ID, t.Priority, t.Title, t.Status))
		}
		b.WriteString("\n")
	}

	b.WriteString("## USER GUIDANCE FOR \"")
	b.WriteString(field)
	b.WriteString("\"\n")
	b.WriteString(guidance)
	b.WriteString("\n\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Return ONLY a JSON object containing just the updated \"")
	b.WriteString(field)
	b.WriteString("\" field.\n")

	switch field {
	case "priority":
		b.WriteString("Example: {\"priority\": 3}\n")
	case "tags":
		b.WriteString("Example: {\"tags\": [\"auth\", \"api\"]}\n")
	case "depends_on", "suggested_depends_on":
		b.WriteString("Example: {\"suggested_depends_on\": [1, 2]}\n")
	case "estimated_minutes":
		b.WriteString("Example: {\"estimated_minutes\": 90}\n")
	case "role":
		b.WriteString("Example: {\"role\": \"backend\"}\n")
		b.WriteString("Valid roles: backend, frontend, testing, security, devops, data, docs, review, or empty string.\n")
	case "title":
		b.WriteString("Example: {\"title\": \"Implement JWT authentication\"}\n")
	case "description":
		b.WriteString("Example: {\"description\": \"Replace session auth with JWT tokens.\"}\n")
	}

	b.WriteString("Output ONLY valid JSON with no explanation, no markdown code fences, no extra text.\n")

	return b.String()
}

// applyFieldUpdate merges a single-field AI response into the spec.
func applyFieldUpdate(spec *TaskSpec, field, aiResponse string) error {
	start := strings.Index(aiResponse, "{")
	end := strings.LastIndex(aiResponse, "}")
	if start == -1 || end == -1 || end <= start {
		return fmt.Errorf("no JSON object found in AI response")
	}
	jsonStr := aiResponse[start : end+1]

	var patch map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &patch); err != nil {
		return fmt.Errorf("parsing field patch: %w", err)
	}

	// Normalise the key — AI may return "depends_on" or "suggested_depends_on"
	val, ok := patch[field]
	if !ok {
		// Try alternate key for depends_on
		if field == "depends_on" {
			val, ok = patch["suggested_depends_on"]
		}
		if !ok {
			return fmt.Errorf("AI response missing field %q", field)
		}
	}

	switch field {
	case "title":
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return err
		}
		if s == "" {
			return fmt.Errorf("title cannot be empty")
		}
		spec.Title = s
	case "description":
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return err
		}
		spec.Description = s
	case "priority":
		var n int
		if err := json.Unmarshal(val, &n); err != nil {
			return err
		}
		if n < 1 {
			n = 1
		}
		if n > 10 {
			n = 10
		}
		spec.Priority = n
	case "role":
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return err
		}
		spec.Role = s
	case "estimated_minutes":
		var n int
		if err := json.Unmarshal(val, &n); err != nil {
			return err
		}
		if n < 0 {
			n = 0
		}
		spec.EstimatedMinutes = n
	case "tags":
		var tags []string
		if err := json.Unmarshal(val, &tags); err != nil {
			return err
		}
		spec.Tags = tags
	case "depends_on":
		var ids []int
		if err := json.Unmarshal(val, &ids); err != nil {
			return err
		}
		spec.SuggestedDependsOn = ids
	}

	return nil
}

// resolveField maps a user input (number 1-7 or field name) to a canonical field name.
func resolveField(input string) (string, error) {
	input = strings.TrimSpace(strings.ToLower(input))
	if n, err := strconv.Atoi(input); err == nil {
		if n >= 1 && n <= len(editableFields) {
			return editableFields[n-1], nil
		}
		return "", fmt.Errorf("field number must be 1-%d", len(editableFields))
	}
	for _, f := range editableFields {
		if f == input {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown field %q — use 1-7 or a field name", input)
}

// Refine runs the interactive refinement REPL.
// It returns the (possibly modified) spec, whether the user accepted, and any error.
// Pass a nil scanner to use os.Stdin via bufio.
func Refine(
	ctx context.Context,
	p provider.Provider,
	opts provider.Options,
	description string,
	spec *TaskSpec,
	existingPlan *pm.Plan,
	scanner *bufio.Scanner,
) (*TaskSpec, bool, error) {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)
	dim := color.New(color.Faint)

	for {
		PrintSpec(spec, existingPlan)

		fmt.Printf("  > ")
		if !scanner.Scan() {
			// EOF — treat as quit
			return spec, false, nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "a", "accept":
			green.Println("  Task accepted.")
			return spec, true, nil

		case "q", "quit":
			fmt.Println("  Cancelled.")
			return spec, false, nil

		case "r", "regen", "regenerate":
			cyan.Println("  Regenerating task...")
			newSpec, err := Enrich(ctx, p, opts, description, existingPlan)
			if err != nil {
				red.Printf("  Regenerate failed: %v\n\n", err)
				continue
			}
			spec = newSpec
			green.Println("  Regenerated.")

		case "e", "edit":
			var fieldInput string
			if len(parts) > 1 {
				fieldInput = strings.TrimSpace(parts[1])
			} else {
				fmt.Printf("  Field [1-7 or name]: ")
				if !scanner.Scan() {
					return spec, false, nil
				}
				fieldInput = strings.TrimSpace(scanner.Text())
			}

			field, err := resolveField(fieldInput)
			if err != nil {
				red.Printf("  %v\n\n", err)
				continue
			}

			fmt.Printf("  Guidance for %q (what you want): ", field)
			if !scanner.Scan() {
				return spec, false, nil
			}
			guidance := strings.TrimSpace(scanner.Text())
			if guidance == "" {
				dim.Println("  (no guidance provided, skipping)")
				continue
			}

			cyan.Printf("  Refining %q...\n", field)
			prompt := RefineFieldPrompt(spec, field, guidance, existingPlan)
			result, err := p.Complete(ctx, prompt, opts)
			if err != nil {
				red.Printf("  AI call failed: %v\n\n", err)
				continue
			}

			if err := applyFieldUpdate(spec, field, result.Output); err != nil {
				red.Printf("  Could not apply update: %v\n\n", err)
				continue
			}
			green.Printf("  Updated %q.\n", field)

		default:
			red.Printf("  Unknown command %q — use [a]ccept, [e]dit, [r]egenerate, or [q]uit\n\n", cmd)
		}
	}
}
