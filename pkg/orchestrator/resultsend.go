package orchestrator

// resultsend.go sends the files a seeded run attaches to the hub as each
// attempt ends (Task 20513).
//
// A run whose project was seeded into its sandbox — on an edge device, in a
// Kubernetes Pod — attaches files in its own copy of the project
// (attachments.go). Its result, read back once the run is over, brings home
// only as many of them as fit beside the run's history in one transport frame;
// a set of screenshots or a data export does not fit, and on a Pod or an
// executor pool's runner the workspace it was left in is gone with the run.
// So a run dispatched with a session for it
// (knowledgerun.EnvResultsURL, EnvResultsToken) sends each file to the hub as
// soon as it is attached, and marks it sent in its own store, so its result
// describes the file without carrying it.
//
// Sending is in the background, one file at a time, so the next task does not
// wait for the last one's report to cross a slow link. A send the hub could
// not take for a reason that passes — unreachable, busy, restarting — is tried
// again, and what is still waiting when the run loop ends is sent before the
// run exits, for a while: the result, read after the exit, carries whatever
// was not.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// How long the end of the run waits for files still being sent: long enough
// for a few large files over a slow link when the run ends of its own accord,
// short when it was stopped, so a stop stays prompt.
var (
	resultFlushBudget        = 5 * time.Minute
	resultFlushBudgetStopped = 30 * time.Second
)

// resultRetryWaits are the pauses before each further try of a send that
// failed for a reason that may pass.
var resultRetryWaits = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}

// resultSender sends one run's attached files to the hub. A nil sender is a
// run with nowhere to send them: every method does nothing.
type resultSender struct {
	client *knowledgerun.Client
	dbPath string
	// sentTasks are the tasks the run was sent, by id, with the title each
	// had then. A file of any other task — one the run created, or one it
	// retitled — is sent as such, and the hub holds it for the run's result
	// to place rather than attach it to the hub's task of that id.
	sentTasks map[int]string
	// logf prints one line of the run's output.
	logf func(c *color.Color, format string, args ...any)

	mu    sync.Mutex
	queue []resultItem
	// inflight counts the files being sent now, taken off the queue.
	inflight int
	running  bool
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	// ctx ends the sends in flight when the run is finished with them.
	ctx    context.Context
	cancel context.CancelFunc
}

// resultItem is one file waiting to be sent.
type resultItem struct {
	row       statedb.AttachmentRow
	title     string
	tries     int
	notBefore time.Time
}

// newResultSender returns the sender for a run dispatched with a session to
// send its files with, or nil — for every run whose files land in the
// project's own store. A session that is set but unusable is said once.
func newResultSender(getenv func(string) string, dbPath string, plan *pm.Plan) *resultSender {
	client, err := knowledgerun.ResultsFromEnv(getenv)
	if errors.Is(err, knowledgerun.ErrNotConfigured) {
		return nil
	}
	if err != nil {
		color.New(color.FgYellow).Printf("  The files this run's tasks attach will not be sent to the hub as they are "+
			"made: %v. They come back with the run's result, as far as it has room.\n", err)
		return nil
	}
	s := &resultSender{client: client, dbPath: dbPath, sentTasks: map[int]string{},
		logf: func(c *color.Color, format string, args ...any) { c.Printf(format, args...) }}
	if plan != nil {
		for _, t := range plan.Tasks {
			if t != nil {
				s.sentTasks[t.ID] = strings.TrimSpace(t.Title)
			}
		}
	}
	return s
}

// start runs the sender's worker, if it is not running.
func (s *resultSender) start() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.wake = make(chan struct{}, 1)
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.work(s.ctx, s.wake, s.stop, s.done)
}

// enqueue adds the files an ingest attached to task to what is sent.
func (s *resultSender) enqueue(task *pm.Task, rows []statedb.AttachmentRow) {
	if s == nil || task == nil || len(rows) == 0 {
		return
	}
	s.mu.Lock()
	for _, row := range rows {
		s.queue = append(s.queue, resultItem{row: row, title: strings.TrimSpace(task.Title)})
	}
	wake := s.wake
	s.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// pending reports how many files are still to be sent, counting the one being
// sent now.
func (s *resultSender) pending() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) + s.inflight
}

// finish waits, for at most the flush budget, for every file still waiting to
// be sent, and stops the worker. stopped says the run was stopped, which
// shortens the wait.
func (s *resultSender) finish(stopped bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	wake, stop, done, cancel := s.wake, s.stop, s.done, s.cancel
	s.mu.Unlock()
	budget := resultFlushBudget
	if stopped {
		budget = resultFlushBudgetStopped
	}
	if n := s.pending(); n > 0 {
		s.logf(color.New(color.Faint), "  Sending %d attached %s to the hub before the run ends…\n", n,
			pluralWord(n, "file", "files"))
	}
	// What waits for a retry is due now: the run is ending.
	s.mu.Lock()
	for i := range s.queue {
		s.queue[i].notBefore = time.Time{}
	}
	s.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
	deadline := time.Now().Add(budget)
	for s.pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	close(stop)
	cancel()
	<-done
	s.mu.Lock()
	left := len(s.queue)
	s.queue = nil
	s.running = false
	s.mu.Unlock()
	if left > 0 {
		s.logf(color.New(color.FgYellow), "  %d attached %s could not be sent to the hub in time; the run's "+
			"result brings back what it has room for.\n", left, pluralWord(left, "file was", "files were"))
	}
}

// work sends what is queued, one file at a time, until stop is closed.
func (s *resultSender) work(ctx context.Context, wake <-chan struct{}, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer func() {
		if r := recover(); r != nil {
			s.logf(color.New(color.FgYellow), "  sending attached files to the hub stopped: %v\n", r)
		}
	}()
	for {
		it, wait, ok := s.next()
		if !ok {
			select {
			case <-stop:
				return
			case <-wake:
			case <-time.After(wait):
			}
			continue
		}
		s.send(ctx, it)
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
		select {
		case <-stop:
			return
		default:
		}
	}
}

// next takes the first file that is due, or says how long until one is.
func (s *resultSender) next() (resultItem, time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	wait := time.Hour
	for i, it := range s.queue {
		if !it.notBefore.After(now) {
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			s.inflight++
			return it, 0, true
		}
		wait = min(wait, it.notBefore.Sub(now))
	}
	return resultItem{}, wait, false
}

// send sends one file, and puts it back in the queue when it failed for a
// reason that may pass.
func (s *resultSender) send(ctx context.Context, it resultItem) {
	row := it.row
	f, _, err := attachments.Open(s.dbPath, row)
	if err != nil {
		// Deleted with its task, or not a plain file any more: nothing to
		// send, and nothing the result could carry either.
		s.logf(color.New(color.Faint), "  📎 %s of task %d not sent to the hub: %v\n", row.Name, row.TaskID, err)
		return
	}
	title, sent := s.sentTasks[row.TaskID]
	u := knowledgerun.ResultUpload{
		ID: row.ID, Task: row.TaskID, TitleSHA256: knowledgerun.TitleDigest(it.title), Name: row.Name,
		Size: row.Size, SHA256: row.SHA256, CreatedAt: row.CreatedAt,
		Created: !sent || title != it.title,
	}
	resp, err := s.client.SendResult(ctx, u, f)
	f.Close()
	if err == nil {
		if merr := attachments.MarkSent(s.dbPath, row.ID); merr != nil {
			// The hub has it; the result will describe it as left here as
			// well, and the hub records it once all the same.
			s.logf(color.New(color.Faint), "  could not record that %s was sent: %v\n", row.Name, merr)
		}
		where := "held until the run ends, for its result to say which task it belongs to"
		if resp.Outcome == knowledgerun.ResultAttached {
			where = fmt.Sprintf("attached to task #%d", resp.Task)
		}
		s.logf(color.New(color.FgCyan), "  📤 %s (%s) of task %d is on the hub: %s\n", row.Name,
			attachments.HumanBytes(row.Size), row.TaskID, where)
		return
	}
	if ctx.Err() != nil {
		s.requeue(it, false)
		return
	}
	if knowledgerun.Retryable(err) && it.tries < len(resultRetryWaits) {
		s.requeue(it, true)
		return
	}
	s.logf(color.New(color.FgYellow), "  📎 %s of task %d was not sent to the hub: %s. It comes back with the "+
		"run's result if there is room.\n", row.Name, row.TaskID, hubErrText(err))
}

// requeue puts a file back for another try, after the wait its tries call for
// when counted is set.
func (s *resultSender) requeue(it resultItem, counted bool) {
	if counted {
		it.notBefore = time.Now().Add(resultRetryWaits[min(it.tries, len(resultRetryWaits)-1)])
		it.tries++
	}
	s.mu.Lock()
	s.queue = append(s.queue, it)
	s.mu.Unlock()
}

// finishResults is the deferred end of the run loop's sending: every file
// still waiting is sent, for a while.
func (o *Orchestrator) finishResults(ctx context.Context) {
	o.results.finish(ctx.Err() != nil)
}

// resultsEnv is read from the process environment; a variable so a test can
// give a run a session without setting the process's.
var resultsEnv = os.Getenv
