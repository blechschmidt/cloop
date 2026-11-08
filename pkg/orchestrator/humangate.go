package orchestrator

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// stopAtReviewGate ends the run at the human review gate it reached (Task
// 20477): every task ahead of the gate has finished, so the run pauses for a
// person to look at what they produced, and records which gate it waits at.
//
// The run ends rather than waits in place. A review takes as long as the
// reviewer does, and a run kept alive meanwhile would hold its executor, its
// leases and its credentials for hours with nothing to do. Approving the gate
// and pressing Run (the dashboard's "Approve & continue" does both) starts the
// next run, which records the gate as passed and carries on; pressing Run
// without approving runs whatever was put ahead of the gate meanwhile, and
// stops at it again.
//
// The pause is stored before it is announced, like every other pause, so a
// run whose write fails says so instead of announcing a stop the database
// does not record.
func (o *Orchestrator) stopAtReviewGate(s *state.ProjectState, g *pm.Task) error {
	detail := fmt.Sprintf("waiting for human review at gate #%d: %s", g.ID, g.Title)
	s.SetPaused(pausereason.NewForTask(pausereason.CodeApproval, detail, g.ID))
	if err := o.persist(s, fmt.Sprintf("the pause at review gate #%d", g.ID)); err != nil {
		return err
	}

	held := 0
	for _, t := range s.Plan.Tasks {
		if t.Status == pm.TaskPending && t.IsWork() && pm.HeldBy(g, t) {
			held++
		}
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventReviewGate,
		TaskID:    g.ID,
		TaskTitle: g.Title,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("Run stopped at review gate #%d (%s): %d task(s) wait behind it", g.ID, g.Title, held),
	}, map[string]any{"action": "reached", "held": held})
	o.log.Info(logger.EventReviewGate, g.ID, g.Title, map[string]interface{}{
		"action": "reached",
		"held":   held,
	})

	if !o.log.IsJSON() {
		banner := color.New(color.FgYellow, color.Bold)
		banner.Printf("\n⏸ Review gate #%d: %s\n", g.ID, g.Title)
		if g.Description != "" {
			color.New(color.Faint).Printf("   %s\n", truncate(g.Description, 300))
		}
		fmt.Printf("   Every task ahead of it has finished; %d task(s) wait behind it.\n", held)
		fmt.Printf("   Review the work, change or add tasks ahead of the gate if needed, then\n")
		fmt.Printf("   approve it with `cloop task gate approve %d` (or in the dashboard) and run again.\n\n", g.ID)
	}
	title := fmt.Sprintf("cloop: review gate #%d is waiting", g.ID)
	body := fmt.Sprintf("%s\nGoal: %s\n%d task(s) wait behind the gate until it is approved.", g.Title, s.Goal, held)
	if o.config.Notify {
		notify.Send(title, body)
	}
	o.notifyWebhooks(title, body)
	return nil
}
