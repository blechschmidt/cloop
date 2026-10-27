package orchestrator

// attachments.go gives every attempt at a task an outbox, and attaches to the
// task what the agent leaves in it (Task 20428). See pkg/attachments for the
// store and the rules a file has to pass.
//
// The outbox is the agent's whole interface to the feature: a directory, named
// in its prompt and in $CLOOP_TASK_ATTACHMENTS, that it copies files into. A
// command would have been the other choice, and the worse one here — the
// `cloop` on an agent's PATH is not necessarily this build (on the hub's own
// host it is a different, older binary), while a directory works with
// whatever tool produced the file. When the attempt ends the orchestrator,
// which is this build, empties the outbox into the store.

import (
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/provider/copilot"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// orphanAttachmentAge is how old a file in the store no row names must be
// before a run's start sweeps it away: older than any attach in flight.
const orphanAttachmentAge = time.Hour

// taskOutbox is one attempt's outbox.
type taskOutbox struct {
	taskID int
	dir    string // absolute
}

// runsTools reports whether p's agent works in the project directory with
// tools of its own, and so can put a file in an outbox: an agent harness,
// claudecode's or copilot's. HTTP providers return text and nothing else;
// telling their model about a directory would only cost prompt. A fallback
// chain is named for its providers in order ("claudecode→anthropic"), and runs
// its first unless that fails.
func runsTools(p provider.Provider) bool {
	if p == nil {
		return false
	}
	name := p.Name()
	return strings.HasPrefix(name, claudecode.ProviderName) || strings.HasPrefix(name, copilot.ProviderName)
}

// openOutbox prepares the outbox of an attempt at task by p's agent, or
// returns nil when there is none to offer: an agent with no tools, or a store
// that cannot be created — the attempt then runs without attachments rather
// than not at all.
func (o *Orchestrator) openOutbox(task *pm.Task, p provider.Provider) *taskOutbox {
	if task == nil || !runsTools(p) {
		return nil
	}
	dir, err := attachments.PrepareOutbox(state.DBPath(o.config.WorkDir), task.ID)
	if err != nil {
		color.New(color.Faint).Printf("  attachments unavailable for task %d: %v\n", task.ID, err)
		return nil
	}
	return &taskOutbox{taskID: task.ID, dir: dir}
}

// env is what the agent's process is told about the outbox.
func (b *taskOutbox) env() []string {
	if b == nil {
		return nil
	}
	return attachments.Env(b.taskID, b.dir)
}

// promptSection is what the task's prompt says about the outbox.
func (b *taskOutbox) promptSection() string {
	if b == nil {
		return ""
	}
	return attachments.PromptSection(b.taskID, b.dir)
}

// agentEnv is the environment an agent's process gets for an attempt beyond
// the run's own: the review gate's push hold and the task's outbox.
func agentEnv(g *gateRun, b *taskOutbox) []string {
	env := g.env()
	if extra := b.env(); len(extra) > 0 {
		env = append(append([]string(nil), env...), extra...)
	}
	return env
}

// collectAttachments attaches what is in the task's outbox, records it in the
// project's journal and counts it on the task, under the task's run id —
// which, before beginTaskExecution, is still the run that made the files.
// final says the attempt is over, so its outbox goes too once it is empty.
//
// Best effort: a file that could not be attached is named in the journal, and
// a failure of the store itself is printed — neither is a reason to fail work
// the agent has done.
func (o *Orchestrator) collectAttachments(task *pm.Task, final bool) {
	if task == nil || task.ID <= 0 {
		return
	}
	dbPath := state.DBPath(o.config.WorkDir)
	if final {
		defer attachments.CloseOutbox(dbPath, task.ID)
	}
	if entries, err := os.ReadDir(attachments.OutboxDir(dbPath, task.ID)); err != nil || len(entries) == 0 {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		color.New(color.Faint).Printf("  attachments of task %d not collected: %v\n", task.ID, err)
		return
	}
	defer db.Close()
	rep, err := attachments.Ingest(db, dbPath, task.ID, attachments.IngestOptions{
		RunID: task.RunID,
		// The run's leased credentials, as the provider's redaction removes
		// them from the transcript: an agent that wrote its debug log into
		// the outbox wrote whatever its tools printed.
		Scrub: redact.NewLive(os.Environ()).Current(),
	})
	if err != nil {
		color.New(color.Faint).Printf("  attachments of task %d: %v\n", task.ID, err)
	}
	if rep.Empty() {
		return
	}
	task.AttachmentCount += len(rep.Added)
	summary := attachments.Summary(task.ID, rep)
	color.New(color.FgCyan).Printf("  📎 %s\n", summary)

	added := make([]map[string]any, 0, len(rep.Added))
	for _, a := range rep.Added {
		added = append(added, map[string]any{
			"id": a.ID, "name": a.Name, "size": a.Size, "media_type": a.MediaType, "sha256": a.SHA256,
		})
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskAttachments,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message:   summary,
	}, map[string]any{"added": added, "refused": rep.Refused, "run_id": task.RunID})
}

// drainOutboxes attaches what every outbox still holds when the run loop
// ends, and removes the outboxes of tasks the plan no longer has.
func (o *Orchestrator) drainOutboxes() {
	dbPath := state.DBPath(o.config.WorkDir)
	for _, id := range attachments.Outboxes(dbPath) {
		var task *pm.Task
		if o.state != nil && o.state.Plan != nil {
			task = o.state.Plan.TaskByID(id)
		}
		if task == nil {
			attachments.RemoveOutbox(dbPath, id)
			continue
		}
		o.collectAttachments(task, true)
	}
}

// sweepAttachments removes what the store holds that no row names: the files
// of attachments a build without this feature deleted with their task, and
// copies an attach abandoned when its process died.
func (o *Orchestrator) sweepAttachments() {
	dbPath := state.DBPath(o.config.WorkDir)
	if _, err := os.Lstat(attachments.StoreDir(dbPath)); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return
	}
	defer db.Close()
	if n, err := attachments.Sweep(db, dbPath, orphanAttachmentAge); err == nil && n > 0 {
		color.New(color.Faint).Printf("Removed %d attachment %s no task names any more\n", n, pluralWord(n, "file", "files"))
	} else if err != nil {
		color.New(color.Faint).Printf("attachment sweep: %v (ignored)\n", err)
	}
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
