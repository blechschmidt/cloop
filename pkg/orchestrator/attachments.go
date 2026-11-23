package orchestrator

// attachments.go gives every attempt at a task an outbox, and attaches to the
// task what the agent leaves in it (Task 20428); and an inbox, holding copies
// of the files a person attached to the task for its agent (Task 20511). See
// pkg/attachments for the store and the rules a file has to pass.
//
// The outbox is the agent's whole interface to the feature: a directory, named
// in its prompt and in $CLOOP_TASK_ATTACHMENTS, that it copies files into. A
// command would have been the other choice, and the worse one here — the
// `cloop` on an agent's PATH is not necessarily this build (on the hub's own
// host it is a different, older binary), while a directory works with
// whatever tool produced the file. When the attempt ends the orchestrator,
// which is this build, empties the outbox into the store.
//
// The inbox is the same idea the other way round: a directory, named in the
// prompt and in $CLOOP_TASK_INPUTS, that the orchestrator fills with the
// task's input files before the agent starts and removes when the attempt
// ends. An agent without tools of its own is given the text among them in its
// prompt instead.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
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

// taskOutbox is what one attempt at a task is given to exchange files with
// people: its outbox, and its input files — in an inbox, or as text in its
// prompt. Every part is optional; a nil *taskOutbox is an attempt given none.
type taskOutbox struct {
	taskID int
	dir    string // the outbox, absolute; "" for an agent without tools
	// inbox is where the task's input files were copied; nil when it has none
	// or the agent cannot open files.
	inbox *attachments.Inbox
	// inline is the prompt section carrying the input files' text, for an
	// agent without tools.
	inline string
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

// openOutbox prepares the outbox of an attempt at task by p's agent and gives
// the attempt the task's input files, or returns nil when there is nothing to
// offer: an agent with no tools and a task without input files, or a store
// that cannot be created — the attempt then runs without attachments rather
// than not at all.
func (o *Orchestrator) openOutbox(ctx context.Context, task *pm.Task, p provider.Provider) *taskOutbox {
	if task == nil {
		return nil
	}
	dbPath := state.DBPath(o.config.WorkDir)
	b := &taskOutbox{taskID: task.ID}
	ref := attachments.TaskRef{ID: task.ID, Title: task.Title}
	src := o.inputSource()
	if !runsTools(p) {
		// An agent that returns text cannot open a directory: the text of
		// the task's input files goes into its prompt.
		fetchCtx, cancel := context.WithTimeout(ctx, inputFetchBudget)
		b.inline = attachments.InlineInputs(fetchCtx, ref, src)
		cancel()
		if b.inline == "" {
			return nil
		}
		return b
	}
	if dir, err := attachments.PrepareOutbox(dbPath, task.ID); err != nil {
		color.New(color.Faint).Printf("  attachments unavailable for task %d: %v\n", task.ID, err)
	} else {
		b.dir = dir
	}
	// Fetching from the hub can take a while: bounded, and stopped by an
	// abort from the dashboard like the rest of the attempt — the kill
	// poller fires this cancel, and fires again once the attempt's own is
	// registered, after this returns.
	fetchCtx, cancel := context.WithTimeout(ctx, inputFetchBudget)
	o.watchdog.Register(task.ID, cancel)
	inbox, err := attachments.PrepareInbox(fetchCtx, dbPath, ref, src)
	o.watchdog.Unregister(task.ID)
	cancel()
	switch {
	case err != nil:
		// The store itself failed: the agent is told the files exist and
		// that it does not have them, rather than nothing at all.
		color.New(color.FgYellow).Printf("  input files of task %d unavailable: %v\n", task.ID, err)
		inbox = &attachments.Inbox{TaskID: task.ID, ListError: err.Error()}
	case inbox != nil && inbox.ListError != "":
		color.New(color.FgYellow).Printf("  input files of task %d could not be listed: %s\n", task.ID, inbox.ListError)
	case inbox != nil:
		note := ""
		if n := len(inbox.Files) - inbox.Placed(); n > 0 {
			note = fmt.Sprintf(" (%d could not be given: see the prompt)", n)
		}
		color.New(color.FgCyan).Printf("  📥 %d input %s for task %d (%s) in %s%s\n", inbox.Placed(),
			pluralWord(inbox.Placed(), "file", "files"), task.ID, attachments.HumanBytes(inbox.Bytes()), inbox.Dir, note)
	}
	b.inbox = inbox
	if b.dir == "" && b.inbox.Empty() {
		return nil
	}
	return b
}

// inputSource is where this run reads its tasks' input files from: the hub,
// for a run seeded into a sandbox that was given a session to ask it with,
// otherwise the store beside the project's database.
func (o *Orchestrator) inputSource() attachments.InputSource {
	client, err := knowledgerun.InputsFromEnv(os.Getenv)
	if errors.Is(err, knowledgerun.ErrNotConfigured) {
		return attachments.LocalInputs(state.DBPath(o.config.WorkDir))
	}
	if err != nil {
		return failedInputs{err: fmt.Errorf("this run's session for them is not usable: %w", err)}
	}
	return hubInputs{client: client}
}

// env is what the agent's process is told: where the outbox and the input
// files are.
func (b *taskOutbox) env() []string {
	if b == nil {
		return nil
	}
	var env []string
	if b.dir != "" {
		env = append(env, attachments.Env(b.taskID, b.dir)...)
	}
	return append(env, attachments.InboxEnv(b.inbox)...)
}

// promptSection is what the task's prompt says about the input files and the
// outbox.
func (b *taskOutbox) promptSection() string {
	if b == nil {
		return ""
	}
	section := b.inline + attachments.InboxPromptSection(b.inbox)
	if b.dir != "" {
		section += attachments.PromptSection(b.taskID, b.dir)
	}
	return section
}

// inputFetchBudget bounds how long one attempt spends getting its task's input
// files before it starts without the rest.
var inputFetchBudget = 15 * time.Minute

// hubInputs reads a seeded run's input files from the hub, with the run's
// session (knowledgerun, inputs.go).
type hubInputs struct{ client *knowledgerun.Client }

// hubInputAttempts is how often a request for input files is made before the
// attempt is told they could not be fetched: a hub that is restarting, or a
// session that is momentarily over its rate, answers a later one.
var hubInputAttempts = []time.Duration{0, time.Second, 3 * time.Second, 6 * time.Second}

func (h hubInputs) Inputs(ctx context.Context, task attachments.TaskRef) ([]attachments.Input, error) {
	var resp *knowledgerun.InputsResponse
	err := retryHub(ctx, func() error {
		var err error
		resp, err = h.client.Inputs(ctx, knowledgerun.InputsRequest{Task: task.ID,
			TitleSHA256: knowledgerun.TitleDigest(task.Title)})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("asking the hub for them failed: %s", hubErrText(err))
	}
	if resp.Mismatch != "" {
		return nil, errors.New(resp.Mismatch)
	}
	out := make([]attachments.Input, 0, len(resp.Files))
	for _, f := range resp.Files {
		out = append(out, attachments.Input{ID: f.ID, Name: f.Name, Size: f.Size, SHA256: f.SHA256,
			MediaType: f.MediaType, Note: f.Note})
	}
	return out, nil
}

func (h hubInputs) Open(ctx context.Context, task attachments.TaskRef, in attachments.Input) (io.ReadCloser, error) {
	var body io.ReadCloser
	err := retryHub(ctx, func() error {
		var err error
		body, err = h.client.OpenInputFile(ctx, knowledgerun.InputFileRequest{Task: task.ID,
			TitleSHA256: knowledgerun.TitleDigest(task.Title), ID: in.ID}, in.Size)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("fetching it from the hub failed: %s", hubErrText(err))
	}
	return body, nil
}

// hubErrText says what went wrong asking the hub, without the knowledge
// search's name the shared client gives its errors: these are input files.
func hubErrText(err error) string {
	var api *knowledgerun.APIError
	if errors.As(err, &api) {
		if api.Message == "" {
			return fmt.Sprintf("the hub answered %d", api.Status)
		}
		return fmt.Sprintf("the hub answered %d: %s", api.Status, api.Message)
	}
	return strings.TrimPrefix(err.Error(), "knowledge search: ")
}

// retryHub runs call until it succeeds, fails for a reason another try will
// not change, or hubInputAttempts are spent.
func retryHub(ctx context.Context, call func() error) error {
	var err error
	for _, wait := range hubInputAttempts {
		if wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if err = call(); err == nil {
			return nil
		}
		var api *knowledgerun.APIError
		if errors.As(err, &api) && api.Status != http.StatusTooManyRequests && api.Status < 500 {
			return err
		}
	}
	return err
}

// failedInputs is the source of a run whose way to its input files is broken:
// every attempt is told so.
type failedInputs struct{ err error }

func (f failedInputs) Inputs(context.Context, attachments.TaskRef) ([]attachments.Input, error) {
	return nil, f.err
}

func (f failedInputs) Open(context.Context, attachments.TaskRef, attachments.Input) (io.ReadCloser, error) {
	return nil, f.err
}

// agentEnv is the environment an agent's process gets for an attempt beyond
// the run's own: the review gate's push hold and the task's outbox.
//
// It also takes back the variables a seeded run exchanges its tasks' files
// with the hub by (Tasks 20511, 20513), which are the orchestrator's to use:
// the agent finds its input files in its inbox and puts its own in its outbox,
// and a cloop the agent starts — a test of its own project — must neither
// fetch this run's tasks' input files nor send its files to this run's hub.
// (The agent can still learn the session's token where it is given the same
// session for a knowledge search, and the hub holds every request it makes to
// the same bounds as the run's own.)
func agentEnv(g *gateRun, b *taskOutbox) []string {
	env := append([]string(nil), g.env()...)
	env = append(env, b.env()...)
	if os.Getenv(knowledgerun.EnvResultsToken) != "" {
		env = append(env, knowledgerun.EnvResultsURL+"=", knowledgerun.EnvResultsToken+"=")
	}
	if os.Getenv(knowledgerun.EnvInputsToken) != "" {
		env = append(env, knowledgerun.EnvInputsURL+"=", knowledgerun.EnvInputsToken+"=")
	}
	if len(env) == 0 {
		return nil
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
		// The attempt's copies of the task's input files go with it: the
		// next attempt is given fresh ones.
		defer attachments.CloseInbox(dbPath, task.ID)
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
	// On to the hub, for a run seeded into its sandbox (Task 20513).
	o.results.enqueue(task, rep.Added)
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
// ends, and removes the outboxes of tasks the plan no longer has and every
// inbox: no attempt is running any more.
func (o *Orchestrator) drainOutboxes() {
	dbPath := state.DBPath(o.config.WorkDir)
	defer attachments.RemoveInboxes(dbPath)
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
