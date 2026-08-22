package agent

// session.go is one connection's worth of agent behaviour: handshake, resume,
// the frame loop, and the workload lifecycle underneath it.
//
// The ordering in runOnce is load-bearing. Resume offers go out in the hello,
// the control plane's answer comes back in the welcome, and only then does
// output start flowing again — so a reconnect never replays bytes the control
// plane already has, and never skips bytes it does not.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// deviceSession is the agent's view of one live connection.
type deviceSession struct {
	conn remote.Conn
	// version is what the handshake settled on. Every frame this session
	// sends is stamped with it rather than with this build's maximum, so a
	// newer agent talking to an older control plane does not emit envelopes
	// the peer rejects as out of range.
	version int
	// writeMu serialises frame writes: the heartbeat ticker, the frame loop,
	// and every workload's output pump all write to the same connection.
	writeMu sync.Mutex
	closed  chan struct{}
	once    sync.Once
}

// frame builds a frame at the version this session negotiated. Before the
// welcome arrives version is 0, which NewFrameAt clamps to this build's
// maximum — correct for the hello, which is the frame that advertises it.
func (s *deviceSession) frame(t remote.FrameType, id, handle string, payload any) (remote.Frame, error) {
	return remote.NewFrameAt(s.version, t, id, handle, payload)
}

func (s *deviceSession) write(ctx context.Context, f remote.Frame) error {
	select {
	case <-s.closed:
		return fmt.Errorf("%w: session closed", remote.ErrSessionClosed)
	default:
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteFrame(ctx, f)
}

func (s *deviceSession) close(reason string) {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close(reason)
	})
}

// runOnce establishes one session and serves it until it ends.
func (a *Agent) runOnce(ctx context.Context) error {
	token, isEnrollment := a.authToken()
	conn, err := a.dial(ctx, token)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", a.cfg.Server, err)
	}
	sess := &deviceSession{conn: conn, closed: make(chan struct{})}
	defer sess.close("session ended")

	welcome, err := a.handshake(ctx, sess, isEnrollment)
	if err != nil {
		return err
	}
	sess.version = welcome.ProtocolVersion

	a.mu.Lock()
	a.connected = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.sess == sess {
			a.sess = nil
		}
		a.mu.Unlock()
	}()

	// Rewind every resumed handle to the offset the control plane asked for,
	// and only then publish the session.
	//
	// The order is load-bearing. pumpOutput flushes to whatever
	// currentSession() returns, using the workload's existing sentOffset —
	// which, after a link dropped mid-write, is ahead of what the control
	// plane actually received (a write into a half-open socket "succeeds").
	// Publishing the session first would let a chatty workload flush at that
	// stale offset before the rewind lands: the control plane would record a
	// phantom gap, then discard the correctly-rewound resend as duplicate,
	// silently losing the bytes in between and reordering the log.
	a.applyResume(ctx, sess, welcome)

	a.mu.Lock()
	a.sess = sess
	a.mu.Unlock()

	// Flush again now that output can actually reach the wire: anything a
	// workload produced during the rewind above was buffered, not sent.
	a.flushAll(ctx, sess)

	hbCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go a.heartbeatLoop(hbCtx, sess)

	return a.frameLoop(ctx, sess)
}

// authToken returns the credential to authenticate with, preferring a stored
// long-lived credential over the one-shot enrollment token.
func (a *Agent) authToken() (token string, isEnrollment bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cred.Valid() {
		return a.cred.Credential, false
	}
	return strings.TrimSpace(a.cfg.Token), true
}

// dial lives in transport.go, alongside the pinning and plaintext policy it
// applies.

// handshake sends hello and processes welcome.
func (a *Agent) handshake(ctx context.Context, sess *deviceSession, isEnrollment bool) (remote.WelcomePayload, error) {
	hsCtx, cancel := context.WithTimeout(ctx, remote.HeartbeatInterval)
	defer cancel()

	a.mu.Lock()
	agentID := a.cred.AgentID
	name := a.cred.Name
	a.mu.Unlock()
	if isEnrollment {
		// Enrolling for the first time: we have no identity to claim yet, and
		// the control plane assigns one.
		agentID = ""
	}

	hello, err := remote.NewFrame(remote.TypeHello, "hello", "", remote.HelloPayload{
		ProtocolVersion: remote.ProtocolVersion,
		AgentID:         agentID,
		Name:            name,
		AgentVersion:    AgentVersion,
		Capabilities:    a.Capabilities(),
		Resume:          a.resumeOffers(),
	})
	if err != nil {
		return remote.WelcomePayload{}, err
	}
	if err := sess.write(hsCtx, hello); err != nil {
		return remote.WelcomePayload{}, fmt.Errorf("send hello: %w", err)
	}

	frame, err := sess.conn.ReadFrame(hsCtx)
	if err != nil {
		return remote.WelcomePayload{}, fmt.Errorf("read welcome: %w", err)
	}
	if frame.Type == remote.TypeError {
		payload, _ := remote.DecodeError(frame)
		err := fmt.Errorf("control plane rejected the handshake: %s (%s)", payload.Message, payload.Code)
		// Unauthorized and version-unsupported are permanent for this
		// credential and this build: reconnecting cannot fix either, so stop
		// rather than hammer the control plane forever.
		if payload.Code == remote.CodeUnauthorized || payload.Code == remote.CodeVersionUnsupported {
			return remote.WelcomePayload{}, fmt.Errorf("%w: %v", errDoNotReconnect, err)
		}
		return remote.WelcomePayload{}, err
	}
	if frame.Type != remote.TypeWelcome {
		return remote.WelcomePayload{}, fmt.Errorf("%w: expected welcome, got %s", remote.ErrProtocol, frame.Type)
	}
	welcome, err := remote.DecodeWelcome(frame)
	if err != nil {
		return remote.WelcomePayload{}, err
	}

	if welcome.Credential != "" {
		if err := a.persistCredential(welcome); err != nil {
			// A credential we cannot persist is worse than useless: the
			// enrollment token is now spent, so a restart would leave the
			// device unable to authenticate at all. Fail loudly now, while
			// the operator is still watching the enroll command.
			return remote.WelcomePayload{}, fmt.Errorf(
				"enrolled as %s but could not save the credential to %s: %w\n"+
					"The enrollment token is now spent; mint a new one after fixing this",
				welcome.ExecutorID, a.cfg.CredentialPath, err)
		}
		a.cfg.logf("enrolled as %s; credential saved to %s", welcome.ExecutorID, a.cfg.CredentialPath)
	}
	a.cfg.logf("connected to %s as %s (protocol v%d)", a.cfg.Server, welcome.ExecutorID, welcome.ProtocolVersion)
	return welcome, nil
}

// persistCredential stores a newly issued credential.
func (a *Agent) persistCredential(w remote.WelcomePayload) error {
	a.mu.Lock()
	cred := Credential{
		Server:      a.cfg.Server,
		AgentID:     w.ExecutorID,
		Name:        a.cred.Name,
		Credential:  w.Credential,
		WorkDirRoot: a.root,
		Pin:         a.cfg.Pin,
		EnrolledAt:  a.cfg.now(),
	}
	a.cred = cred
	a.mu.Unlock()
	if err := SaveCredential(a.cfg.CredentialPath, cred); err != nil {
		return err
	}
	a.retireTokenFile()
	return nil
}

// retireTokenFile deletes the spent enrollment token.
//
// Ordering is deliberate: this runs only after the durable credential is
// safely on disk. Deleting first would turn a failed credential write into an
// unrecoverable device — the token spent on the control plane, and the only
// copy of it gone from the device too.
//
// Failure is logged, not returned. The token is already single-use and already
// redeemed, so a file that cannot be removed is untidy rather than dangerous,
// and it is not worth failing an otherwise successful enrollment over.
func (a *Agent) retireTokenFile() {
	path := strings.TrimSpace(a.cfg.TokenFile)
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.cfg.logf("note: could not remove the spent enrollment file %s: %v", path, err)
		}
		return
	}
	a.cfg.logf("removed the spent enrollment file %s", path)
}

// resumeOffers lists workloads still running, with how much output each has
// produced, so the control plane can say where to restart each stream.
func (a *Agent) resumeOffers() []remote.ResumeHandle {
	// Snapshot the map under a.mu, then read each workload's own fields with
	// it released: workload.local takes wl.mu, and holding a.mu across that
	// would order the two locks the opposite way from handleStart.
	a.mu.Lock()
	workloads := make([]*workload, 0, len(a.workloads))
	for _, w := range a.workloads {
		workloads = append(workloads, w)
	}
	a.mu.Unlock()

	out := make([]remote.ResumeHandle, 0, len(workloads))
	for _, w := range workloads {
		_, startedAt := w.local()
		out = append(out, remote.ResumeHandle{
			HandleID:  w.handleID,
			StartedAt: startedAt,
			LogOffset: w.buf.Total(),
		})
	}
	return out
}

// applyResume restarts the streams the control plane still wants and abandons
// the ones it has forgotten.
func (a *Agent) applyResume(ctx context.Context, sess *deviceSession, w remote.WelcomePayload) {
	accepted := make(map[string]int64, len(w.ResumeAccepted))
	for _, ack := range w.ResumeAccepted {
		accepted[ack.HandleID] = ack.FromOffset
	}

	a.mu.Lock()
	current := make([]*workload, 0, len(a.workloads))
	for _, wl := range a.workloads {
		current = append(current, wl)
	}
	a.mu.Unlock()

	for _, wl := range current {
		from, ok := accepted[wl.handleID]
		if !ok {
			// The control plane no longer tracks this workload. Streaming its
			// output would waste the device's uplink on data nobody will
			// read; the process is left alone and simply stops being
			// reported, and the heartbeat's handle list will drop it.
			a.cfg.logf("control plane no longer tracks %s; abandoning its stream", wl.handleID)
			a.forget(wl.handleID)
			continue
		}
		wl.sendMu.Lock()
		wl.sentOffset = from
		wl.sendMu.Unlock()
		a.flush(ctx, sess, wl)
	}
}

// heartbeatLoop beats at the protocol interval with jitter.
//
// Jitter is applied per beat rather than once at startup: a fleet that all
// reconnected after a control-plane restart would otherwise stay phase-locked
// forever, delivering every device's heartbeat in the same millisecond.
func (a *Agent) heartbeatLoop(ctx context.Context, sess *deviceSession) {
	for {
		delay := jitteredInterval(remote.HeartbeatInterval)
		select {
		case <-ctx.Done():
			return
		case <-sess.closed:
			return
		case <-time.After(delay):
		}

		a.mu.Lock()
		a.hbSeq++
		seq := a.hbSeq
		active := make([]string, 0, len(a.workloads))
		for id := range a.workloads {
			active = append(active, id)
		}
		a.mu.Unlock()

		frame, err := sess.frame(remote.TypeHeartbeat, fmt.Sprintf("hb-%d", seq), "",
			remote.HeartbeatPayload{Seq: seq, ActiveHandles: active})
		if err != nil {
			continue
		}
		if err := sess.write(ctx, frame); err != nil {
			// The link is gone. Closing here rather than just returning wakes
			// the frame loop immediately instead of leaving it blocked on a
			// read that will not fail until TCP notices, minutes later.
			sess.close("heartbeat write failed")
			return
		}
	}
}

func jitteredInterval(base time.Duration) time.Duration {
	d := time.Duration(float64(base) * (1 + (rand64()-0.5)*2*remote.JitterFraction))
	if d <= 0 {
		return base
	}
	return d
}

// frameLoop reads and dispatches until the connection ends.
func (a *Agent) frameLoop(ctx context.Context, sess *deviceSession) error {
	for {
		frame, err := sess.conn.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return context.Canceled
			}
			return err
		}
		switch frame.Type {
		case remote.TypeStart:
			// Started in its own goroutine: launching a workload touches the
			// filesystem and forks a process, and blocking the frame loop on
			// it would stall heartbeat acks and every other handle's control
			// traffic behind one slow spawn.
			go a.handleStart(ctx, sess, frame)

		case remote.TypeSignal:
			a.handleSignal(ctx, sess, frame)

		case remote.TypeStatusReq:
			a.handleStatusReq(ctx, sess, frame)

		case remote.TypeLogAck:
			a.handleLogAck(frame)

		case remote.TypeRevoke:
			// Its own goroutine, like start: a scrub unlinks files and may
			// signal a workload, and blocking the frame loop on it would
			// stall heartbeat acks and every other handle's control traffic.
			go a.handleRevoke(ctx, sess, frame)

		case remote.TypeHeartbeatAck:
			// Liveness confirmed; nothing to do. Its value is in arriving.

		case remote.TypeBye:
			bye, _ := remote.DecodeBye(frame)
			if !bye.Reconnect {
				return fmt.Errorf("%w: %s", errDoNotReconnect, bye.Reason)
			}
			return fmt.Errorf("control plane closed the session: %s", bye.Reason)

		case remote.TypeError:
			payload, _ := remote.DecodeError(frame)
			a.cfg.logf("control plane error [%s]: %s", payload.Code, payload.Message)

		default:
			a.cfg.logf("ignoring unexpected frame type %q", frame.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// Workload lifecycle
// ---------------------------------------------------------------------------

// handleStart launches a workload and answers with a started frame.
func (a *Agent) handleStart(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	defer func() {
		if r := recover(); r != nil {
			a.replyError(ctx, sess, frame.ID, remote.CodeStartFailed, fmt.Sprintf("panic: %v", r))
		}
	}()

	payload, err := remote.DecodeStart(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	handleID := payload.HandleID
	if handleID == "" {
		handleID = frame.Handle
	}

	// A repeated start for a handle we already run is a duplicate caused by a
	// lost response, not a request for a second copy. Re-answering with the
	// existing handle is what makes start idempotent across a reconnect.
	if existing, ok := a.workload(handleID); ok {
		st := existing.snapshot()
		_, startedAt := existing.local()
		a.reply(ctx, sess, remote.TypeStarted, frame.ID, handleID, remote.StartedPayload{
			HandleID:  handleID,
			PID:       st.PID,
			StartedAt: startedAt,
		})
		return
	}

	// Reserve the slot atomically. Start frames are dispatched on their own
	// goroutines, so a check followed by a later insert would let several
	// concurrent starts all observe room and blow past the ceiling.
	wl := &workload{
		handleID: handleID,
		buf:      newRetainBuffer(a.cfg.RetainBytes),
		status: executor.Status{
			HandleID: handleID,
			State:    executor.StatePending,
		},
	}
	if !a.reserve(wl) {
		a.replyError(ctx, sess, frame.ID, remote.CodeBusy,
			fmt.Sprintf("agent is at its concurrency ceiling of %d", a.cfg.MaxConcurrent))
		return
	}

	spec := payload.Spec
	// Index the lease material before anything can run with it. A revoke that
	// arrives between here and the launch finds the binding and scrubs it;
	// binding afterwards would leave a window in which the credential is live
	// on the device and invisible to revocation.
	a.vault.bind(handleID, spec.Secrets)

	workDir, err := a.resolveWorkDir(spec.WorkDir)
	if err != nil {
		a.forget(handleID)
		a.replyError(ctx, sess, frame.ID, remote.CodeForbiddenPath, err.Error())
		return
	}
	spec.WorkDir = workDir

	// The tree has to be in place before the harness is, and only this device
	// can put it there. A failure here fails the start rather than launching
	// anyway: a harness started against an empty directory produces a run that
	// looks healthy, streams a plausible transcript, and operated on no code —
	// which is the exact outcome the workspace contract exists to remove.
	if err := a.prepareWorkspace(ctx, wl, spec, payload.GitCredential()); err != nil {
		a.forget(handleID)
		a.reply(ctx, sess, remote.TypeStarted, frame.ID, handleID, remote.StartedPayload{
			HandleID: handleID,
			Error:    err.Error(),
		})
		return
	}
	// Remember how to give the work back, before the Spec is rewritten below
	// and before the harness is allowed to touch the tree. Both orderings are
	// load-bearing: provisionedWorkspace is about to replace the git workspace
	// with a bind one, which has no Repo to push to, and the base commit read
	// after the harness ran would be whatever HEAD the harness left behind.
	if plan, err := a.planWriteBack(ctx, spec, payload.GitCredential()); err != nil {
		a.forget(handleID)
		a.reply(ctx, sess, remote.TypeStarted, frame.ID, handleID, remote.StartedPayload{
			HandleID: handleID,
			Error:    err.Error(),
		})
		return
	} else if plan != nil {
		wl.mu.Lock()
		wl.plan = plan
		wl.mu.Unlock()
	}

	// The fetch is this device's job and it is done; the harness runs through
	// an inner driver that shares this filesystem, so what it is handed must
	// say the tree is already in place. See provisionedWorkspace.
	spec.Workspace = provisionedWorkspace(spec.Workspace)

	handle, err := a.local.Start(context.WithoutCancel(ctx), spec)
	if err != nil {
		// Release the reservation: nothing is running, and holding the slot
		// would leak capacity on every failed start.
		a.forget(handleID)
		a.reply(ctx, sess, remote.TypeStarted, frame.ID, handleID, remote.StartedPayload{
			HandleID: handleID,
			Error:    err.Error(),
		})
		return
	}

	wl.mu.Lock()
	wl.localID = handle.ID
	wl.startedAt = handle.StartedAt
	wl.status = executor.Status{
		HandleID:  handleID,
		State:     executor.StateRunning,
		PID:       handle.PID,
		StartedAt: handle.StartedAt,
	}
	wl.mu.Unlock()

	a.reply(ctx, sess, remote.TypeStarted, frame.ID, handleID, remote.StartedPayload{
		HandleID:  handleID,
		PID:       handle.PID,
		StartedAt: handle.StartedAt,
	})

	go a.pumpOutput(wl)
}

// drainGrace bounds how long the output pump keeps reading after the workload
// itself has terminated.
//
// Stream closure normally means "the process exited", but not always: a
// workload that spawns a background child leaves that child holding the
// inherited stdout pipe, so EOF can arrive minutes after the process cloop
// started is gone — or never. Since the terminal status is withheld until the
// pump finishes (see workload.draining), an unbounded wait here would leave
// the control plane believing a dead workload is still running. Two seconds is
// far more than a dying process needs to flush, and far less than a stuck
// grandchild would cost.
const drainGrace = 2 * time.Second

// drainOutput forwards output until the stream closes, or until the workload
// has been terminal for drainGrace.
func (a *Agent) drainOutput(ctx context.Context, wl *workload, localID string, lines <-chan executor.LogLine) {
	poll := time.NewTicker(200 * time.Millisecond)
	defer poll.Stop()

	graceTimer := time.NewTimer(time.Hour) // armed for real once the process exits
	defer graceTimer.Stop()
	if !graceTimer.Stop() {
		<-graceTimer.C
	}
	armed := false

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			if line.Text == "" {
				continue
			}
			wl.buf.Append(line.Text)
			if sess := a.currentSession(); sess != nil {
				a.flush(ctx, sess, wl)
			}
		case <-poll.C:
			if armed {
				continue
			}
			if st, err := a.local.Status(ctx, localID); err == nil && st.State.Terminal() {
				armed = true
				graceTimer.Reset(drainGrace)
			}
		case <-graceTimer.C:
			a.cfg.logf("workload %s exited but its output stream is still open after %s; "+
				"reporting its status now (a background child may hold the pipe)",
				wl.handleID, drainGrace)
			return
		}
	}
}

// pumpOutput forwards a workload's output and reports its terminal status.
//
// It deliberately does not take the session as a parameter: the session it
// started under may be replaced by a reconnect halfway through, and output
// must follow the *current* session rather than a dead one.
func (a *Agent) pumpOutput(wl *workload) {
	defer func() {
		if r := recover(); r != nil {
			a.cfg.logf("panic pumping output for %s: %v", wl.handleID, r)
		}
	}()

	// Detached from any request context: the workload outlives the frame that
	// started it, and cancelling this stream on a reconnect would silently
	// truncate the log.
	ctx := context.Background()
	localID, _ := wl.local()
	lines, err := a.local.Stream(ctx, localID)
	if err != nil {
		a.cfg.logf("stream %s: %v", wl.handleID, err)
	} else {
		a.drainOutput(ctx, wl, localID, lines)
	}

	// The stream is closed, so the workload has terminated and its exit code
	// is available.
	status, statusErr := a.local.Status(ctx, localID)
	if statusErr != nil {
		status = executor.Status{State: executor.StateFailed, Error: statusErr.Error()}
	}
	status.HandleID = wl.handleID
	wl.mu.Lock()
	wl.status = status
	wl.finished = true
	wl.mu.Unlock()

	// Flush before reporting terminal status: the control plane closes the
	// log stream when the terminal status arrives, so any output sent after
	// it would be discarded.
	//
	// If there is no session the workload is NOT forgotten. Its outcome has
	// nowhere to go right now, and dropping it here would lose the exit code
	// and the log tail — the control plane would later see the handle vanish
	// from a heartbeat and mis-resolve a clean exit as a failure. Keeping it
	// lets the next session deliver the truth.
	// The work product comes back before the terminal status does. The status
	// frame closes the hub's log stream and executor.Run reads the status the
	// instant that stream closes, so a result sent afterwards would land on a
	// handle whose consumer had already returned empty-handed.
	if sess := a.currentSession(); sess != nil {
		a.flush(ctx, sess, wl)
		a.performWriteBack(ctx, wl, sess)
	}

	// Re-read the session: producing a write-back can take minutes, and the
	// link the workload started on may be gone by now.
	if sess := a.currentSession(); sess != nil {
		a.flush(ctx, sess, wl)
		a.deliverFinal(ctx, sess, wl)
	}
}

// deliverFinal reports a finished workload's terminal status and releases its
// slot. Idempotent: only the first delivery is sent, so a reconnect that races
// the output pump cannot report the same exit twice.
func (a *Agent) deliverFinal(ctx context.Context, sess *deviceSession, wl *workload) {
	wl.mu.Lock()
	done, already, status := wl.finished, wl.reported, wl.status
	if done && !already {
		wl.reported = true
	}
	wl.mu.Unlock()
	if !done || already {
		return
	}
	a.reply(ctx, sess, remote.TypeStatus, "", wl.handleID, remote.StatusPayload{
		Status: status,
		// Now accurate: the pump has drained, so this really is the total.
		FinalOffset: wl.buf.Total(),
	})
	a.forget(wl.handleID)
}

// flushAll pushes any retained output for every workload onto sess and
// delivers the outcome of anything that finished while the link was down.
func (a *Agent) flushAll(ctx context.Context, sess *deviceSession) {
	a.mu.Lock()
	workloads := make([]*workload, 0, len(a.workloads))
	for _, w := range a.workloads {
		workloads = append(workloads, w)
	}
	a.mu.Unlock()

	for _, wl := range workloads {
		a.flush(ctx, sess, wl)
		// A workload that finished while the link was down still owes its work
		// product. performWriteBack is a no-op once the result has been
		// delivered, so a reconnect that races the output pump cannot commit
		// the tree twice; what it does cover is the case the pump could not —
		// the harness exited, there was no session to report on, and the plan
		// has been waiting here since.
		a.performWriteBack(ctx, wl, sess)
		a.deliverFinal(ctx, sess, wl)
	}
}

// flush sends everything retained above the workload's sent offset.
func (a *Agent) flush(ctx context.Context, sess *deviceSession, wl *workload) {
	wl.sendMu.Lock()
	defer wl.sendMu.Unlock()

	for {
		data, at := wl.buf.Slice(wl.sentOffset)
		if len(data) == 0 {
			wl.sentOffset = at
			return
		}
		chunk := data
		if len(chunk) > remote.MaxLogChunkBytes {
			chunk = chunk[:remote.MaxLogChunkBytes]
		}
		frame, err := sess.frame(remote.TypeLogChunk, "", wl.handleID, remote.LogChunkPayload{
			Stream: executor.StreamCombined,
			// `at`, not wl.sentOffset: eviction may have advanced the start
			// of the retained window past what we asked for, and mislabelling
			// the bytes would corrupt the control plane's offset accounting.
			Offset: at,
			Text:   string(chunk),
			Time:   a.cfg.now(),
		})
		if err != nil {
			return
		}
		if err := sess.write(ctx, frame); err != nil {
			// Leave sentOffset where it is; the bytes stay retained and go
			// out after the next reconnect resumes this handle.
			return
		}
		wl.sentOffset = at + int64(len(chunk))
	}
}

// handleSignal delivers a signal and answers with the resulting status.
func (a *Agent) handleSignal(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeSignal(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	wl, ok := a.workload(frame.Handle)
	if !ok {
		a.replyError(ctx, sess, frame.ID, remote.CodeUnknownHandle,
			fmt.Sprintf("no workload %s on this agent", frame.Handle))
		return
	}
	localID, _ := wl.local()
	if localID == "" && wl.cancelProvisioning() {
		// The workload is still fetching its source tree, so there is no
		// process to signal — but the fetch is what the stop is actually
		// aimed at, and it can run for minutes. Cancelling it makes the start
		// fail a moment later with the device's reason, which is the honest
		// outcome: the run never began.
		a.cfg.logf("signal %s arrived during workspace provisioning; cancelling the fetch", frame.Handle)
		a.reply(ctx, sess, remote.TypeStatus, frame.ID, frame.Handle, remote.StatusPayload{
			Status: wl.snapshot(),
		})
		return
	}
	if err := a.local.Signal(ctx, localID, payload.Signal); err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}
	status, err := a.local.Status(ctx, localID)
	if err != nil {
		status = wl.snapshot()
	}
	status.HandleID = frame.Handle
	a.reply(ctx, sess, remote.TypeStatus, frame.ID, frame.Handle, remote.StatusPayload{
		Status: wl.draining(status),
	})
}

// handleStatusReq answers a status request.
func (a *Agent) handleStatusReq(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	wl, ok := a.workload(frame.Handle)
	if !ok {
		a.replyError(ctx, sess, frame.ID, remote.CodeUnknownHandle,
			fmt.Sprintf("no workload %s on this agent", frame.Handle))
		return
	}
	localID, _ := wl.local()
	status, err := a.local.Status(ctx, localID)
	if err != nil {
		status = wl.snapshot()
	}
	status.HandleID = frame.Handle
	a.reply(ctx, sess, remote.TypeStatus, frame.ID, frame.Handle, remote.StatusPayload{
		Status: wl.draining(status),
	})
}

// handleLogAck releases retained output the control plane has confirmed.
func (a *Agent) handleLogAck(frame remote.Frame) {
	payload, err := remote.DecodeLogAck(frame)
	if err != nil {
		return
	}
	if wl, ok := a.workload(frame.Handle); ok {
		wl.buf.Ack(payload.Offset)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveWorkDir maps a control-plane-supplied path onto a real directory
// beneath this agent's root, creating it if needed.
//
// This is the agent's primary security boundary. The control plane is the
// party that could be compromised, and a workload's WorkDir is attacker-
// controlled input from the device's point of view — "/etc" or
// "../../root/.ssh" must not be honoured. Confinement is enforced here, on the
// device, because only the device knows its own filesystem.
//
// Relative paths are resolved beneath the root, which is also what makes the
// common case work: a control plane says "run in myproject" and the agent
// provisions <root>/myproject without either side hardcoding device paths.
func (a *Agent) resolveWorkDir(requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return a.root, nil
	}

	candidate := requested
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(a.root, candidate)
	}
	candidate = filepath.Clean(candidate)

	if err := containedIn(a.root, candidate); err != nil {
		return "", err
	}
	if err := os.MkdirAll(candidate, 0o700); err != nil {
		return "", fmt.Errorf("agent: create workdir %s: %w", candidate, err)
	}
	// Re-check after creation with symlinks resolved. The pre-creation check
	// compares lexical paths, which a symlink planted inside the root would
	// defeat: <root>/escape → /etc is lexically contained but resolves out.
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("agent: resolve workdir %s: %w", candidate, err)
	}
	if err := containedIn(a.root, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// containedIn reports whether path is the root or lies beneath it.
func containedIn(root, path string) error {
	if path == root {
		return nil
	}
	// The separator suffix is what stops "/srv/cloop-evil" from passing a
	// naive prefix test against root "/srv/cloop".
	if strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return nil
	}
	return fmt.Errorf("%w: %s is outside this agent's root %s", remote.ErrPathOutsideRoot, path, root)
}

func (a *Agent) currentSession() *deviceSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

func (a *Agent) workload(handleID string) (*workload, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	wl, ok := a.workloads[handleID]
	return wl, ok
}

// reserve inserts wl if the agent has room, returning false when it is at its
// concurrency ceiling. Check and insert happen under one lock so concurrent
// start frames cannot both see space that only exists for one of them.
func (a *Agent) reserve(wl *workload) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.MaxConcurrent > 0 && len(a.workloads) >= a.cfg.MaxConcurrent {
		return false
	}
	a.workloads[wl.handleID] = wl
	return true
}

func (a *Agent) forget(handleID string) {
	a.mu.Lock()
	wl := a.workloads[handleID]
	delete(a.workloads, handleID)
	a.mu.Unlock()
	if wl != nil {
		// A workload dropped while its tree was still being fetched has nothing
		// left to fetch for: the control plane has stopped tracking it, or the
		// start already failed. Continuing would spend the device's uplink on a
		// clone nobody will use.
		wl.cancelProvisioning()
	}
	// The material went with the process. Dropping the binding keeps the
	// vault from reporting a lease as held by a workload that is gone, which
	// would make a revocation wait for an ack about nothing.
	a.vault.release(handleID)
}

func (w *workload) snapshot() executor.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// draining withholds a terminal state until the output pump has finished
// forwarding the workload's output.
//
// The local backend marks a handle killed the moment a signal is delivered,
// while the process's remaining output is still in the pipe. The control plane
// closes a handle's log stream as soon as a terminal status arrives, so
// answering a signal or a status request with that early terminal state would
// silently discard everything the process printed on its way out — which, for
// a killed or timed-out run, is exactly where the useful output lives.
//
// Reporting "still running" until the pump drains is not a lie: from this
// agent's perspective the workload is not finished until its output is.
// pumpOutput sends the real terminal status, once, immediately afterwards.
func (w *workload) draining(st executor.Status) executor.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished || !st.State.Terminal() {
		return st
	}
	st.State = executor.StateRunning
	st.FinishedAt = time.Time{}
	return st
}

// setProvisionCancel publishes (or clears) the cancel for an in-flight
// workspace fetch, so a stop that arrives before the harness exists has
// something to act on.
func (w *workload) setProvisionCancel(cancel context.CancelFunc) {
	w.mu.Lock()
	w.cancelProvision = cancel
	w.mu.Unlock()
}

// cancelProvisioning aborts an in-flight workspace fetch, reporting whether
// there was one. Clearing the field under the same lock makes it single-shot:
// two concurrent stops cannot both claim to have cancelled the same clone.
func (w *workload) cancelProvisioning() bool {
	w.mu.Lock()
	cancel := w.cancelProvision
	w.cancelProvision = nil
	w.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

// local returns the localprocess handle ID and start time. Both are written
// once, after the slot is reserved but before the output pump starts, so a
// concurrent reader (resumeOffers on a reconnect, a status request) needs the
// lock to avoid observing a half-initialised workload.
func (w *workload) local() (localID string, startedAt time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.localID, w.startedAt
}

// reply sends a typed response frame, best-effort.
func (a *Agent) reply(ctx context.Context, sess *deviceSession, t remote.FrameType, id, handle string, payload any) {
	frame, err := sess.frame(t, id, handle, payload)
	if err != nil {
		a.cfg.logf("encode %s reply: %v", t, err)
		return
	}
	if err := sess.write(ctx, frame); err != nil && !errors.Is(err, remote.ErrSessionClosed) {
		a.cfg.logf("send %s reply: %v", t, err)
	}
}

func (a *Agent) replyError(ctx context.Context, sess *deviceSession, id, code, msg string) {
	a.reply(ctx, sess, remote.TypeError, id, "", remote.ErrorPayload{Code: code, Message: msg})
}
