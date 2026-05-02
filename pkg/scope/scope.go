// Package scope detects and reports scope creep across plan evolution.
package scope

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Report holds the full scope creep analysis result.
type Report struct {
	BaselineVersion   int
	CurrentVersion    int
	BaselineTimestamp time.Time
	CurrentTimestamp  time.Time
	BaselineGoal      string
	CurrentGoal       string
	GoalDrifted       bool

	TasksAdded         []*pm.Task
	TasksRemoved       []*pm.Task
	PriorityEscalated  []PriorityChange
	PriorityDeescalated []PriorityChange

	BaselineTaskCount int
	CurrentTaskCount  int

	// ScopeCreepScore is 0–100. Higher means more scope has been added.
	ScopeCreepScore int

	// Narrative is the AI-generated assessment.
	Narrative string
}

// PriorityChange records a task whose priority changed between snapshots.
type PriorityChange struct {
	TaskID    int
	TaskTitle string
	OldPriority int
	NewPriority int
}

// Analyze compares a baseline snapshot against the current plan and returns a
// scope creep Report. workDir is the project root. baselineVersion is the
// version number to use as the baseline (0 = first snapshot). If no snapshots
// exist an error is returned.
func Analyze(workDir string, baselineVersion int) (*Report, error) {
	metas, err := pm.ListSnapshots(workDir)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	if len(metas) == 0 {
		return nil, fmt.Errorf("no plan snapshots found — run 'cloop run --pm' first")
	}

	// Resolve baseline snapshot.
	var baseSnap *pm.Snapshot
	if baselineVersion == 0 {
		// Default: first (oldest) snapshot.
		baseSnap, err = pm.LoadSnapshot(workDir, metas[0].Version)
	} else {
		baseSnap, err = pm.LoadSnapshot(workDir, baselineVersion)
	}
	if err != nil {
		return nil, fmt.Errorf("loading baseline snapshot: %w", err)
	}

	// Current = latest snapshot.
	curSnap, err := pm.LoadSnapshot(workDir, metas[len(metas)-1].Version)
	if err != nil {
		return nil, fmt.Errorf("loading current snapshot: %w", err)
	}

	if baseSnap.Version == curSnap.Version {
		return nil, fmt.Errorf("baseline (v%d) and current (v%d) are the same snapshot — no diff to report",
			baseSnap.Version, curSnap.Version)
	}

	return computeReport(baseSnap, curSnap), nil
}

// computeReport builds a Report from two snapshots without AI narration.
func computeReport(base, cur *pm.Snapshot) *Report {
	r := &Report{
		BaselineVersion:   base.Version,
		CurrentVersion:    cur.Version,
		BaselineTimestamp: base.Timestamp,
		CurrentTimestamp:  cur.Timestamp,
		BaselineGoal:      base.Plan.Goal,
		CurrentGoal:       cur.Plan.Goal,
		BaselineTaskCount: len(base.Plan.Tasks),
		CurrentTaskCount:  len(cur.Plan.Tasks),
	}

	// Detect goal drift (case-insensitive trim comparison).
	r.GoalDrifted = strings.TrimSpace(strings.ToLower(base.Plan.Goal)) !=
		strings.TrimSpace(strings.ToLower(cur.Plan.Goal))

	// Index tasks by ID.
	baseByID := make(map[int]*pm.Task, len(base.Plan.Tasks))
	for _, t := range base.Plan.Tasks {
		baseByID[t.ID] = t
	}
	curByID := make(map[int]*pm.Task, len(cur.Plan.Tasks))
	for _, t := range cur.Plan.Tasks {
		curByID[t.ID] = t
	}

	// Tasks added (in cur but not in base).
	for _, t := range cur.Plan.Tasks {
		if _, exists := baseByID[t.ID]; !exists {
			r.TasksAdded = append(r.TasksAdded, t)
		}
	}

	// Tasks removed (in base but not in cur).
	for _, t := range base.Plan.Tasks {
		if _, exists := curByID[t.ID]; !exists {
			r.TasksRemoved = append(r.TasksRemoved, t)
		}
	}

	// Priority changes for tasks present in both.
	for _, ct := range cur.Plan.Tasks {
		bt, exists := baseByID[ct.ID]
		if !exists {
			continue
		}
		if bt.Priority == ct.Priority {
			continue
		}
		pc := PriorityChange{
			TaskID:      ct.ID,
			TaskTitle:   ct.Title,
			OldPriority: bt.Priority,
			NewPriority: ct.Priority,
		}
		// Lower priority number = higher urgency. Escalation = number dropped.
		if ct.Priority < bt.Priority {
			r.PriorityEscalated = append(r.PriorityEscalated, pc)
		} else {
			r.PriorityDeescalated = append(r.PriorityDeescalated, pc)
		}
	}

	r.ScopeCreepScore = computeScore(r)
	return r
}

// computeScore produces a 0–100 scope creep score.
//
//   - Up to 50 pts: task expansion ratio (added tasks vs. baseline count).
//   - Up to 20 pts: priority escalations ratio.
//   - 10 pts: goal text drifted.
//   - Up to 20 pts: net task growth beyond removed tasks.
func computeScore(r *Report) int {
	base := float64(max1(r.BaselineTaskCount))

	// Net added (added minus removed is unbounded; cap contribution).
	netAdded := float64(len(r.TasksAdded) - len(r.TasksRemoved))
	expansionPts := clamp(netAdded/base*50, 0, 50)

	// Raw additions regardless of removals.
	addedPts := clamp(float64(len(r.TasksAdded))/base*20, 0, 20)

	// Priority escalations.
	escalationPts := clamp(float64(len(r.PriorityEscalated))/base*20, 0, 20)

	// Goal drift.
	driftPts := 0.0
	if r.GoalDrifted {
		driftPts = 10
	}

	score := expansionPts + addedPts + escalationPts + driftPts
	return int(math.Round(clamp(score, 0, 100)))
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// NarratePrompt returns the AI prompt for scope creep narration.
func NarratePrompt(r *Report) string {
	var b strings.Builder
	b.WriteString("You are an expert AI project manager. Analyze the following scope creep report and provide a concise assessment.\n\n")

	b.WriteString("## SCOPE CREEP REPORT\n")
	fmt.Fprintf(&b, "Baseline: v%d (%s, %d tasks)\n",
		r.BaselineVersion, r.BaselineTimestamp.Format("2006-01-02 15:04"), r.BaselineTaskCount)
	fmt.Fprintf(&b, "Current:  v%d (%s, %d tasks)\n",
		r.CurrentVersion, r.CurrentTimestamp.Format("2006-01-02 15:04"), r.CurrentTaskCount)
	fmt.Fprintf(&b, "Scope Creep Score: %d/100\n\n", r.ScopeCreepScore)

	if r.GoalDrifted {
		fmt.Fprintf(&b, "### Goal Drift\nOriginal goal: %s\nCurrent goal:  %s\n\n",
			r.BaselineGoal, r.CurrentGoal)
	}

	if len(r.TasksAdded) > 0 {
		b.WriteString("### Tasks Added Since Baseline\n")
		for _, t := range r.TasksAdded {
			fmt.Fprintf(&b, "- [%d] %s (priority %d)\n", t.ID, t.Title, t.Priority)
		}
		b.WriteString("\n")
	}

	if len(r.TasksRemoved) > 0 {
		b.WriteString("### Tasks Removed Since Baseline\n")
		for _, t := range r.TasksRemoved {
			fmt.Fprintf(&b, "- [%d] %s\n", t.ID, t.Title)
		}
		b.WriteString("\n")
	}

	if len(r.PriorityEscalated) > 0 {
		b.WriteString("### Priority Escalations (higher urgency)\n")
		for _, pc := range r.PriorityEscalated {
			fmt.Fprintf(&b, "- [%d] %s: priority %d → %d\n",
				pc.TaskID, pc.TaskTitle, pc.OldPriority, pc.NewPriority)
		}
		b.WriteString("\n")
	}

	if len(r.PriorityDeescalated) > 0 {
		b.WriteString("### Priority De-escalations (lower urgency)\n")
		for _, pc := range r.PriorityDeescalated {
			fmt.Fprintf(&b, "- [%d] %s: priority %d → %d\n",
				pc.TaskID, pc.TaskTitle, pc.OldPriority, pc.NewPriority)
		}
		b.WriteString("\n")
	}

	b.WriteString("## YOUR TASK\n")
	b.WriteString("In 3–5 sentences, assess:\n")
	b.WriteString("1. Whether the scope changes are JUSTIFIED (feature evolution, discovered requirements) or PROBLEMATIC DRIFT (unfocused expansion, loss of direction).\n")
	b.WriteString("2. Whether the scope creep score reflects the risk level accurately.\n")
	b.WriteString("3. One concrete recommendation for the team.\n")
	b.WriteString("Be direct and specific. Do not repeat the raw numbers — interpret them.\n")

	return b.String()
}

// Narrate calls the AI provider to generate a scope creep narrative and attaches
// it to the report. It mutates r.Narrative in place.
func Narrate(ctx context.Context, prov provider.Provider, model string, r *Report) error {
	prompt := NarratePrompt(r)
	result, err := prov.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 90 * time.Second,
	})
	if err != nil {
		return err
	}
	r.Narrative = strings.TrimSpace(result.Output)
	return nil
}
