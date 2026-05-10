package taskreplay

import (
	"context"
	"errors"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// SuiteOptions controls a batch replay (cloop task replay-suite).
type SuiteOptions struct {
	Options
	// Tags, when non-empty, restricts the replay set to tasks matching ANY of
	// the given tags (matches pm.TaskMatchesTags semantics).
	Tags []string
	// IncludeFailed re-runs failed tasks too. Default is done-only.
	IncludeFailed bool
	// MaxTasks limits how many tasks are replayed (0 = unlimited).
	MaxTasks int
}

// SuiteSummary aggregates a SuiteRun's results.
type SuiteSummary struct {
	TotalTasks       int
	Replayed         int
	Skipped          int
	Failed           int
	AverageJaccard   float64
	AverageEquiv     float64
	HighEquivCount   int // equivalence_score >= 8
	LowEquivCount    int // equivalence_score in [1,4]
	Results          []*Result
}

// RunSuite replays every replayable task in the project that matches the
// suite filter. Each task replay is persisted via the same path as
// ReplayTask. The summary is computed in memory and returned to the caller.
//
// Errors from individual tasks are recorded in result.Err and do not abort
// the suite; only catastrophic failures (state load, etc.) bubble up.
func RunSuite(ctx context.Context, workDir string, opts SuiteOptions) (*SuiteSummary, error) {
	if opts.Target == nil {
		return nil, ErrNoTargetProvider
	}
	s, err := state.Load(workDir)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		return nil, errors.New("no plan found")
	}

	tasks := selectReplayableTasks(s.Plan.Tasks, opts)
	summary := &SuiteSummary{TotalTasks: len(tasks)}

	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		res, err := ReplayTask(ctx, workDir, t.ID, opts.Options)
		if err != nil {
			summary.Skipped++
			// Skip but keep going — some tasks may not be replayable.
			continue
		}
		summary.Results = append(summary.Results, res)
		if res.Err != "" {
			summary.Failed++
			continue
		}
		summary.Replayed++
	}

	if summary.Replayed > 0 {
		var jSum, eSum float64
		var eN int
		for _, r := range summary.Results {
			if r.Err != "" {
				continue
			}
			jSum += r.SimilarityScore
			if r.EquivalenceScore > 0 {
				eSum += float64(r.EquivalenceScore)
				eN++
				if r.EquivalenceScore >= 8 {
					summary.HighEquivCount++
				}
				if r.EquivalenceScore >= 1 && r.EquivalenceScore <= 4 {
					summary.LowEquivCount++
				}
			}
		}
		summary.AverageJaccard = jSum / float64(summary.Replayed)
		if eN > 0 {
			summary.AverageEquiv = eSum / float64(eN)
		}
	}

	return summary, nil
}

func selectReplayableTasks(tasks []*pm.Task, opts SuiteOptions) []*pm.Task {
	out := make([]*pm.Task, 0, len(tasks))
	for _, t := range tasks {
		if !isReplayable(t) {
			continue
		}
		// Only include failed/timed_out when opts.IncludeFailed is set.
		if !opts.IncludeFailed {
			if t.Status == pm.TaskFailed || t.Status == pm.TaskSkipped || t.Status == pm.TaskTimedOut {
				continue
			}
		}
		if len(opts.Tags) > 0 && !pm.TaskMatchesTags(t, opts.Tags) {
			continue
		}
		out = append(out, t)
		if opts.MaxTasks > 0 && len(out) >= opts.MaxTasks {
			break
		}
	}
	return out
}
