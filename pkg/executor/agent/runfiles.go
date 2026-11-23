package agent

// runfiles.go sends the hub the files a finished seeded run attached and did
// not send itself (Task 20515).
//
// The hub dispatches every seeded run that has a network with a run session
// for its files (knowledgerun.EnvResultsURL, EnvResultsToken), and the run
// sends each one as the attempt that made it ends. What it did not send — its
// `cloop` is a container image's, built before it could; the hub was
// restarting when it tried — came home only inside the run's result, as far
// as one transport frame had room for it, and the rest was recorded on the hub
// without its bytes, "left in the executor's workspace". A run on this device
// left four of its thirteen files there.
//
// This agent holds the same session — the hub put it in the workload's
// environment — and outlives the run, so once the workload has exited it sends
// what the run did not (projectseed.SendAttachments): the same endpoint, the
// same checks on the hub, under the id the run gave each file, and each file
// the hub took marked in the run's store, so the result describes it rather
// than carrying it.
//
// It happens before the workload is marked finished, and that ordering is the
// point: until then a reconnect's flushAll, the heartbeat and every status
// question treat the workload as running, so nothing can report its end — or
// read its result back — while its files are still on their way. The hub's own
// view is the same: the run is live, so its session is still open.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
)

// runFilesBudget bounds how long a finished run's files may take to reach the
// hub before its outcome is reported. What is not sent by then comes back in
// the run's result, as far as it has room. A variable so tests need not wait.
var runFilesBudget = 3 * time.Minute

// runSession is the session a seeded run was dispatched with to send the hub
// the files it attaches.
type runSession struct {
	url, token string
}

// recordRunSession remembers the session the hub put in env for the run's
// files, if it put one there.
func (w *workload) recordRunSession(env []string) {
	url := readOnlyEnvValue(env, knowledgerun.EnvResultsURL)
	token := readOnlyEnvValue(env, knowledgerun.EnvResultsToken)
	if url == "" || token == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = &runSession{url: url, token: token}
}

// runFiles reports what sendRunFiles needs: the seed the workload was started
// with, the directory it ran in, and the session to send with — or false when
// there is nothing to do.
func (w *workload) runFiles() (seed []byte, dir string, sess runSession, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.seed) == 0 || w.results == nil || w.workDir == "" {
		return nil, "", runSession{}, false
	}
	return w.seed, w.workDir, *w.results, true
}

// setStopFiles records how to end the sending of the run's files early, or
// clears it, and reports whether a stop came before it could: then there is
// nothing to send.
func (w *workload) setStopFiles(cancel context.CancelFunc) (stopped bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopFiles = cancel
	return w.filesStopped
}

// stopRunFiles ends the sending of the run's files, going on or still to
// come: the run was stopped, and its outcome should not wait for them.
func (w *workload) stopRunFiles() {
	w.mu.Lock()
	w.filesStopped = true
	cancel := w.stopFiles
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// sendRunFiles sends the hub, over the run's session, every file the finished
// run attached and did not send, and says in the run's transcript and in this
// agent's log what became of each. Never fatal: a file not sent comes back in
// the run's result, as far as it has room.
func (a *Agent) sendRunFiles(wl *workload) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic sending the files of %s: %v", wl.handleID, r)
		}
	}()
	seed, dir, sess, ok := wl.runFiles()
	if !ok {
		return
	}
	redactor := wl.redactor()
	emit := func(text string) {
		wl.buf.Append(redactor.String(text))
		if s := a.currentSession(); s != nil {
			a.flush(context.Background(), s, wl)
		}
	}
	client, err := knowledgerun.New(sess.url, sess.token)
	if err != nil {
		a.cfg.logf("workload %s: the run's attached files cannot be sent to the hub: %s", wl.handleID,
			redactor.String(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), runFilesBudget)
	defer cancel()
	if wl.setStopFiles(cancel) {
		// Stopped already, between the exit and here.
		cancel()
	}
	defer wl.setStopFiles(nil)
	started := a.cfg.now()
	rep, err := projectseed.SendAttachments(ctx, dir, seed, client, redactor.String)
	if err != nil {
		a.cfg.logf("workload %s: could not tell which of the run's attached files to send to the hub: %s",
			wl.handleID, redactor.String(err.Error()))
		return
	}
	if rep.Found == 0 {
		return
	}
	var b strings.Builder
	for _, f := range rep.Sent {
		where := "held until the run's result says which task it belongs to"
		if f.Outcome == knowledgerun.ResultAttached {
			where = fmt.Sprintf("attached to task #%d", f.HubTask)
		}
		fmt.Fprintf(&b, "  📤 %s (%s) of task %d is on the hub: %s\n", f.Name, attachments.HumanBytes(f.Size),
			f.Task, where)
	}
	for _, why := range rep.NotSent {
		fmt.Fprintf(&b, "  📎 not sent to the hub: %s\n", why)
	}
	if rep.Stopped != "" {
		fmt.Fprintf(&b, "  The rest were not tried: %s.\n", rep.Stopped)
	}
	if len(rep.NotSent) > 0 || rep.Stopped != "" {
		b.WriteString("  What was not sent comes back with the run's result, as far as it has room.\n")
	}
	emit(fmt.Sprintf("cloop agent: %d of the files this run attached had not reached the hub; %d sent now.\n%s",
		rep.Found, len(rep.Sent), b.String()))
	a.cfg.logf("workload %s: sent %d of the run's attached files to the hub in %s (%d not sent)%s", wl.handleID,
		len(rep.Sent), a.cfg.now().Sub(started).Round(time.Millisecond), len(rep.NotSent),
		map[bool]string{true: "; " + rep.Stopped, false: ""}[rep.Stopped != ""])
}
