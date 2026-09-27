package suggest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Planning a request (Task 20342). Given something the user wants done, the
// same machinery that brainstorms ideas breaks it into the tasks of a plan
// instead: ordered, each self-contained, and each naming the earlier tasks it
// needs. The result travels in the same Result shape, so everything that
// reviews ideas reviews a plan too; Result.Request is what tells them apart.

const (
	// DefaultCount is how many ideas a brainstorm produces when not told.
	// A plan has no default: left unset, it is as long as the request needs.
	DefaultCount = 5
	// MaxCount caps one generation: the ideas a hub will brainstorm at once,
	// and the tasks any plan may have.
	MaxCount = 20
	// MaxRequestRunes bounds a request to plan. It is generous for a page of
	// prose, and it keeps the request — which reaches the executor as a
	// command-line argument — far below the kernel's per-argument limit.
	MaxRequestRunes = 8000
)

// CleanRequest trims a request to plan and checks that it can be handed to
// the planner. The request travels to the executor as an argument, and argv
// cannot carry a NUL byte, so one is refused here with a reason rather than
// failing later as an opaque exec error.
func CleanRequest(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("the request contains a NUL character")
	}
	if n := utf8.RuneCountInString(s); n > MaxRequestRunes {
		return "", fmt.Errorf("the request is %d characters long; the limit is %d", n, MaxRequestRunes)
	}
	return s, nil
}

// BuildPlanPrompt constructs the prompt that breaks request into a plan of
// tasks. count > 0 asks for exactly that many; 0 leaves the number to the
// request — as many tasks as it genuinely needs, up to MaxCount.
func BuildPlanPrompt(goal, instructions, fileTree, recentLog, memCtx, existingTasks, request string, count int) string {
	var b strings.Builder
	b.WriteString("You are a senior software architect turning a request into an executable plan.\n")
	b.WriteString("Break the request below into concrete tasks that AI coding agents will carry out one after another.\n\n")

	fmt.Fprintf(&b, "## PROJECT GOAL\n%s\n\n", goal)
	if instructions != "" {
		fmt.Fprintf(&b, "## CONSTRAINTS\n%s\n\n", instructions)
	}
	if existingTasks != "" {
		fmt.Fprintf(&b, "## EXISTING TASKS (do NOT plan work these already cover)\n%s\n\n", existingTasks)
	}
	if fileTree != "" {
		fmt.Fprintf(&b, "## PROJECT STRUCTURE\n```\n%s\n```\n\n", fileTree)
	}
	if recentLog != "" {
		fmt.Fprintf(&b, "## RECENT ACTIVITY\n%s\n\n", recentLog)
	}
	if memCtx != "" {
		fmt.Fprintf(&b, "## PROJECT MEMORY\n%s\n\n", memCtx)
	}
	fmt.Fprintf(&b, "## REQUEST\n%s\n\n", request)

	b.WriteString("## TASK\n")
	if count > 0 {
		fmt.Fprintf(&b, "Break the request into exactly %d tasks.\n\n", count)
	} else {
		fmt.Fprintf(&b, "Break the request into as many tasks as it genuinely needs and no more — "+
			"a small request may be a single task, and none may take more than %d. "+
			"Do not pad the plan, and do not split work one agent would naturally do in one go.\n\n", MaxCount)
	}
	b.WriteString("Requirements for each task:\n")
	b.WriteString("- Together the tasks must accomplish the whole request, and nothing beyond it\n")
	b.WriteString("- Each must be concrete and implementable by an AI agent in one session\n")
	b.WriteString("- Each description must stand on its own: the agent doing a task sees that task, not the request\n")
	b.WriteString("- List the tasks in the order they should be done\n")
	b.WriteString("- depends_on lists the ids of EARLIER tasks in this plan that must be finished first; [] if none\n\n")
	b.WriteString("For category, choose from: feature, ux, performance, security, dx, integration, docs\n")
	b.WriteString("For effort, choose from: xs (<1h), s (1-4h), m (4-16h), l (1-5d), xl (>1wk)\n\n")
	b.WriteString("Output ONLY valid JSON, no explanation, no markdown:\n")
	b.WriteString(`{"summary":"one sentence overview of the plan","suggestions":[`)
	b.WriteString(`{"id":1,"title":"short title","description":"what to do and how","rationale":"why the plan needs it","category":"feature","effort":"m","depends_on":[]},`)
	b.WriteString(`{"id":2,"title":"...","description":"...","rationale":"...","category":"feature","effort":"s","depends_on":[1]}`)
	b.WriteString(`]}`)
	return b.String()
}

// GeneratePlan calls the provider to break request into a plan: count tasks,
// or as many as the request needs when count is 0. The result is normalized
// (see NormalizePlan) and carries the request, which marks it as a plan.
func GeneratePlan(ctx context.Context, p provider.Provider, prompt string, opts provider.Options, request string, count int) (*Result, error) {
	r, err := Generate(ctx, p, prompt, opts)
	if err != nil {
		return nil, err
	}
	NormalizePlan(r, count)
	r.Request = request
	return r, nil
}

// NormalizePlan makes a generated plan safe to act on, whatever the model
// wrote. Tasks without a title are dropped and at most limit are kept
// (MaxCount when limit is 0 or larger). The rest are renumbered 1..N in the
// order given, and every DependsOn is translated to the new numbers and kept
// only where it names an earlier task — so each edge points backwards and
// the dependencies cannot form a cycle, by construction.
//
// Idempotent: normalizing a normalized plan changes nothing, which lets the
// hub re-check what a device's cloop sent it without disturbing it.
func NormalizePlan(r *Result, limit int) {
	if r == nil {
		return
	}
	if limit <= 0 || limit > MaxCount {
		limit = MaxCount
	}
	// An ID the model gave to two tasks names neither, so nothing may depend
	// on it.
	uses := make(map[int]int, len(r.Suggestions))
	for _, s := range r.Suggestions {
		if s != nil {
			uses[s.ID]++
		}
	}
	kept := make([]*Suggestion, 0, len(r.Suggestions))
	renumber := make(map[int]int, len(r.Suggestions))
	for _, s := range r.Suggestions {
		if s == nil || strings.TrimSpace(s.Title) == "" {
			continue
		}
		if len(kept) == limit {
			break
		}
		if uses[s.ID] == 1 {
			renumber[s.ID] = len(kept) + 1
		}
		kept = append(kept, s)
	}
	for i, s := range kept {
		id := i + 1
		var deps []int
		for _, d := range s.DependsOn {
			if n, ok := renumber[d]; ok && n < id && !containsInt(deps, n) {
				deps = append(deps, n)
			}
		}
		sort.Ints(deps)
		s.ID, s.Title, s.DependsOn = id, strings.TrimSpace(s.Title), deps
	}
	r.Suggestions = kept
}

// NormalizeIdeas is NormalizePlan for a brainstorm: untitled ideas are
// dropped, at most limit are kept when limit > 0, and the rest are numbered
// 1..N. Ideas are independent, so any dependencies are discarded. Unique IDs
// are what lets the dashboard accept one idea by naming it.
func NormalizeIdeas(r *Result, limit int) {
	if r == nil {
		return
	}
	kept := make([]*Suggestion, 0, len(r.Suggestions))
	for _, s := range r.Suggestions {
		if s == nil || strings.TrimSpace(s.Title) == "" {
			continue
		}
		if limit > 0 && len(kept) == limit {
			break
		}
		s.ID, s.Title, s.DependsOn = len(kept)+1, strings.TrimSpace(s.Title), nil
		kept = append(kept, s)
	}
	r.Suggestions = kept
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
