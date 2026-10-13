package auditforward

// worker.go: one goroutine per sink, tailing every chain from the sink's
// cursors.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// fullCheckEvery bounds how long a caught-up sink trusts a chain whose
	// database has not changed on disk: a stat can miss a write, a query
	// cannot.
	fullCheckEvery = 30 * time.Second

	// maxBatchesPerChain bounds how long one chain holds a sink before the
	// next chain gets a turn; the sink comes straight back for the rest.
	maxBatchesPerChain = 8

	// backoffBase and backoffMax bound the wait after a failed send, which
	// doubles from the base.
	backoffBase = time.Second
	backoffMax  = 5 * time.Minute

	// failureNoteEvery bounds how often a failing sink writes its failure into
	// the cursor table, and failureLogEvery how often it says so on stderr.
	failureNoteEvery = time.Minute
	failureLogEvery  = 10 * time.Minute
)

// Why a sink's cursor stopped lining up with its chain, as the
// audit.forward.discontinuity row says.
const (
	// ReasonPruned: rows after the cursor were pruned before the sink
	// acknowledged them.
	ReasonPruned = "pruned"
	// ReasonTruncated: the chain ends before the cursor.
	ReasonTruncated = "truncated"
	// ReasonRewritten: the cursor's row holds another hash.
	ReasonRewritten = "rewritten"
	// ReasonBroken: the cursor's row is intact, and what follows it does not
	// continue it — rows missing inside the chain, or relinked. The rows are
	// forwarded as they stand.
	ReasonBroken = "broken"
)

type worker struct {
	f   *Forwarder
	cfg config.AuditForwardSink
	hub string
	st  *sinkState
	enc *encoder

	cancel context.CancelFunc
	done   chan struct{}

	// Owned by the worker's goroutine.
	tr       transport
	failures int
	failedAt time.Time
	loggedAt time.Time
	idle     map[string]idleMark
	cursors  map[string]statedb.AuditForwardCursor
	notedAt  map[string]time.Time
	// broken remembers, per chain, the cursor position at which a break in
	// place was recorded, so a sink retrying across it records it once.
	broken map[string]int64
	// chainLoggedAt rate-limits the report of a chain that cannot be read.
	chainLoggedAt map[string]time.Time
	// chainHold backs off a chain whose rows the sink refused for their
	// content, so one row a collector will not take holds up its own chain
	// and not every other.
	chainHold map[string]chainRetry
	// trBuilt is when the transport was built: it is rebuilt — and its
	// credentials read again — at least every credentialMaxAge.
	trBuilt time.Time
}

// chainRetry is one chain's backoff after its rows were refused.
type chainRetry struct {
	fails int
	until time.Time
}

// credentialMaxAge bounds how long a sink keeps the credentials it read: a
// secret rotated in the store is presented within the hour, failure or not.
const credentialMaxAge = time.Hour

type idleMark struct {
	mark chainMark
	at   time.Time
}

func newWorker(f *Forwarder, cfg config.AuditForwardSink, hub string, st *sinkState) *worker {
	return &worker{
		f: f, cfg: cfg, hub: hub, st: st,
		enc:     &encoder{cfg: cfg, hub: hub, version: f.opts.Version},
		idle:    map[string]idleMark{},
		cursors: map[string]statedb.AuditForwardCursor{},
		notedAt: map[string]time.Time{},
		broken:  map[string]int64{},

		chainLoggedAt: map[string]time.Time{},
		chainHold:     map[string]chainRetry{},
	}
}

func (w *worker) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		w.run(ctx)
	}()
}

// stop cancels the worker and waits for it. An in-flight send is abandoned
// with its batch unacknowledged: the cursor has not moved, so the next leader
// sends it again.
func (w *worker) stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *worker) run(ctx context.Context) {
	defer w.dropTransport()
	for {
		progressed, err := w.safeRound(ctx)
		if ctx.Err() != nil {
			return
		}
		var wait time.Duration
		switch {
		case err != nil:
			w.failures++
			wait = backoff(w.failures)
		case progressed:
			w.recovered()
			continue
		default:
			w.recovered()
			wait = w.f.opts.Poll
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// safeRound is round, with a panic turned into a failed send: a worker that
// panicked would otherwise stop its sink until the configuration changed.
func (w *worker) safeRound(ctx context.Context) (progressed bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			w.dropTransport()
			err = fmt.Errorf("worker panicked: %v", r)
			w.f.logf("sink %s: %v", w.cfg.Name, err)
		}
	}()
	return w.round(ctx)
}

// round forwards what each chain has after the sink's cursor. A failed send
// ends the round — the sink is down, and every chain would fail the same way —
// while a chain that cannot be read is reported and passed over.
func (w *worker) round(ctx context.Context) (bool, error) {
	progressed := false
	chains := w.f.currentChains()
	// A chain no longer served has had its cursor retired; forget what this
	// worker remembers of it, so that if it returns its cursor is read — and
	// returned to service — from the database rather than used retired.
	served := make(map[string]bool, len(chains))
	for _, ch := range chains {
		served[ch.Path] = true
	}
	for path := range w.cursors {
		if !served[path] {
			delete(w.cursors, path)
			delete(w.idle, path)
			delete(w.broken, path)
		}
	}
	// Every served chain has a cursor before anything is sent, so the sink
	// holds retention on all of them from the moment it is configured —
	// including while it is down and no send ever gets past the first chain.
	for _, ch := range chains {
		if _, ok := w.cursors[ch.Path]; !ok && ctx.Err() == nil {
			if err := w.ensureCursor(ch); err != nil {
				w.chainProblem(ch, err)
			}
		}
	}
	var refused error
	for i, ch := range chains {
		if ctx.Err() != nil {
			return progressed, nil
		}
		n, sendErr, chainErr := w.forwardChain(ctx, ch)
		if n > 0 {
			progressed = true
		}
		if sendErr != nil {
			if ctx.Err() != nil {
				return progressed, nil
			}
			// The sink took the request and refused these rows: that chain
			// waits out a backoff of its own, and the others carry on.
			var rej *rejectedError
			if errors.As(sendErr, &rej) {
				w.holdChain(ch)
				refused = sendErr
				continue
			}
			// The sink is failing. The rest are not sent to it, and still
			// measured: the backlog and lag the leader exports must grow
			// with every chain while it is down, not only with the first.
			for _, rest := range chains[i+1:] {
				w.measure(rest)
			}
			return progressed, sendErr
		}
		if chainErr != nil && ctx.Err() == nil {
			w.chainProblem(ch, chainErr)
		}
	}
	// A round in which the sink refused rows and accepted none is a failed
	// round: the worker backs off as a whole rather than spin on refusals.
	if refused != nil && !progressed {
		return false, refused
	}
	return progressed, nil
}

// holdChain backs ch off after the sink refused its rows.
func (w *worker) holdChain(ch Chain) {
	r := w.chainHold[ch.Path]
	r.fails++
	r.until = w.f.now().Add(backoff(r.fails))
	w.chainHold[ch.Path] = r
}

// chainProblem reports a chain that could not be read, at most once every
// failureLogEvery per chain: the worker retries it every poll.
func (w *worker) chainProblem(ch Chain, err error) {
	now := w.f.now()
	if last, ok := w.chainLoggedAt[ch.Path]; ok && now.Sub(last) < failureLogEvery {
		return
	}
	w.chainLoggedAt[ch.Path] = now
	w.f.logf("sink %s: chain %s cannot be forwarded: %v", w.cfg.Name, ch.Path, err)
}

// ensureCursor creates — or reads — the sink's cursor on ch.
func (w *worker) ensureCursor(ch Chain) error {
	if _, ok := markOf(ch.Path); !ok {
		return nil
	}
	db, release, err := w.f.handles.get(ch.Path)
	if err != nil {
		return err
	}
	defer release()
	// The chain says which control plane holds its cursors, so a prune run
	// from the project's directory finds the hold.
	w.f.markChain(db, ch)
	cp, err := w.f.controlPlane()
	if err != nil {
		return err
	}
	_, err = w.cursor(cp, db, ch)
	return err
}

// measure refreshes what the status says about one chain without sending:
// its head, and the timestamp of the oldest row the sink has not acknowledged.
func (w *worker) measure(ch Chain) {
	cur, ok := w.cursors[ch.Path]
	if !ok {
		return
	}
	db, release, err := w.f.handles.get(ch.Path)
	if err != nil {
		return
	}
	defer release()
	head, err := db.MaxAuditID()
	if err != nil {
		return
	}
	cs := ChainStatus{Chain: ch, AckedID: cur.AckedID, HeadID: max(head, cur.AckedID)}
	if head > cur.AckedID {
		if rows, err := db.ReadAuditRange(cur.AckedID+1, head, 1); err == nil && len(rows) == 1 {
			cs.PendingSince = rows[0].Timestamp
		}
	}
	w.st.setChain(cs)
}

// untilBreak returns rows up to, not including, the first that does not
// continue the row before it.
func untilBreak(rows []statedb.AuditEvent) []statedb.AuditEvent {
	for i := 1; i < len(rows); i++ {
		if rows[i].ID != rows[i-1].ID+1 || rows[i].PrevHash != rows[i-1].RowHash {
			return rows[:i]
		}
	}
	return rows
}

// continues reports whether row is the one that follows the cursor.
func continues(row statedb.AuditEvent, cur statedb.AuditForwardCursor) bool {
	return row.ID == cur.AckedID+1 && row.PrevHash == cur.AckedHash
}

// forwardChain sends the rows after the sink's cursor on one chain, a batch at
// a time, until it is caught up or has had its turn.
func (w *worker) forwardChain(ctx context.Context, ch Chain) (sent int, sendErr, chainErr error) {
	mark, ok := markOf(ch.Path)
	if !ok {
		return 0, nil, nil
	}
	if r, held := w.chainHold[ch.Path]; held && w.f.now().Before(r.until) {
		w.measure(ch)
		return 0, nil, nil
	}
	if im, idle := w.idle[ch.Path]; idle && im.mark == mark && w.f.now().Sub(im.at) < fullCheckEvery {
		return 0, nil, nil
	}
	db, release, err := w.f.handles.get(ch.Path)
	if err != nil {
		return 0, nil, err
	}
	defer release()
	w.f.markChain(db, ch)
	cp, err := w.f.controlPlane()
	if err != nil {
		return 0, nil, err
	}
	cur, err := w.cursor(cp, db, ch)
	if err != nil {
		return 0, nil, err
	}

	size := w.cfg.EffectiveBatchSize()
	for batch := 0; batch < maxBatchesPerChain; batch++ {
		if ctx.Err() != nil {
			return sent, nil, nil
		}
		head, err := db.MaxAuditID()
		if err != nil {
			return sent, nil, err
		}
		rows, err := db.ReadAuditRange(cur.AckedID+1, math.MaxInt64, size)
		if err != nil {
			return sent, nil, err
		}
		if len(rows) == 0 || !continues(rows[0], cur) {
			moved, err := w.realign(cp, db, ch, &cur, rows)
			if err != nil {
				return sent, nil, err
			}
			if moved {
				continue
			}
			if len(rows) == 0 {
				w.st.setChain(ChainStatus{Chain: ch, AckedID: cur.AckedID, HeadID: max(head, cur.AckedID)})
				w.idle[ch.Path] = idleMark{mark: mark, at: w.f.now()}
				return sent, nil, nil
			}
			// Broken in place: forwarded as it stands, the break recorded.
		}
		w.st.setChain(ChainStatus{Chain: ch, AckedID: cur.AckedID,
			HeadID: max(head, rows[len(rows)-1].ID), PendingSince: rows[0].Timestamp})
		// A batch ends where the chain stops continuing itself: a row missing
		// inside it, or relinked, starts the next batch, which the check
		// above then records — a hole is noticed wherever it falls, not only
		// on a batch boundary.
		rows = untilBreak(rows)

		n, truncated, err := w.deliver(ctx, ch, rows)
		if err != nil {
			if ctx.Err() == nil {
				w.sendFailed(cp, ch, err, n)
			}
			return sent, err, nil
		}
		last := rows[n-1]
		if hook := w.f.opts.Hooks.AfterAck; hook != nil {
			hook(w.cfg.Name, ch, rows[0].ID, last.ID)
		}
		at := w.f.now()
		err = cp.AdvanceAuditForwardCursor(w.cfg.Name, ch.Path, statedb.AuditForwardAdvance{
			FromID: cur.AckedID, FromHash: cur.AckedHash,
			ToID: last.ID, ToHash: last.RowHash, ToRowAt: last.Timestamp,
			Delivered: int64(n), At: at,
		})
		if errors.Is(err, statedb.ErrAuditForwardCursorMoved) || errors.Is(err, statedb.ErrAuditForwardCursorMissing) {
			// Another leader moved it while this one sent — what went out is a
			// duplicate the sink identifies by row_hash — or it is gone and is
			// created again. Carry on from where the cursor really is.
			delete(w.cursors, ch.Path)
			if cur, err = w.cursor(cp, db, ch); err != nil {
				return sent, nil, err
			}
			continue
		}
		if err != nil {
			// Delivered and not recorded: the rows go again next time.
			return sent, nil, fmt.Errorf("record the acknowledgement: %w", err)
		}
		if n-truncated > 0 {
			hubmetrics.AuditForwardRows.Add(float64(n-truncated), w.cfg.Name, hubmetrics.AuditForwardDelivered)
		}
		if truncated > 0 {
			hubmetrics.AuditForwardRows.Add(float64(truncated), w.cfg.Name, hubmetrics.AuditForwardTruncated)
		}
		cur.AckedID, cur.AckedHash, cur.AckedRowAt, cur.AckedAt = last.ID, last.RowHash, last.Timestamp, at
		w.cursors[ch.Path] = cur
		delete(w.chainHold, ch.Path)
		w.st.delivered(at)
		sent += n
		// What is still waiting is no older than the row just acknowledged:
		// its timestamp stands in until the next read, so the lag the leader
		// exports between batches errs high, never at zero.
		var pending time.Time
		switch {
		case n < len(rows):
			pending = rows[n].Timestamp
		case last.ID < head:
			pending = last.Timestamp
		}
		w.st.setChain(ChainStatus{Chain: ch, AckedID: cur.AckedID, HeadID: max(head, last.ID), PendingSince: pending})
	}
	return sent, nil, nil
}

// deliver encodes as many of rows as fit the sink's batch size in bytes — at
// least one — sends them, and reports how many the sink acknowledged and how
// many of those went with their payload left out. On failure n is how many
// were sent and not acknowledged.
func (w *worker) deliver(ctx context.Context, ch Chain, rows []statedb.AuditEvent) (n, truncated int, err error) {
	budget := w.cfg.EffectiveMaxBatchBytes()
	msgs := make([]message, 0, len(rows))
	total := 0
	for i, ev := range rows {
		m, err := w.enc.encode(ev, ch)
		if err != nil {
			return 0, 0, fmt.Errorf("encode row %d: %w", ev.ID, err)
		}
		if i > 0 && total+len(m.data)+16 > budget {
			break
		}
		total += len(m.data) + 16
		msgs = append(msgs, m)
	}
	tr, err := w.transport()
	if err != nil {
		return len(msgs), 0, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, w.cfg.EffectiveTimeout())
	defer cancel()
	err = tr.send(sendCtx, msgs)
	// A receiver that refuses the batch for its size gets it halved, down to
	// one row, and that row with its payload left out.
	for errors.Is(err, errTooLarge) && len(msgs) > 1 {
		msgs = msgs[:len(msgs)/2]
		err = tr.send(sendCtx, msgs)
	}
	if errors.Is(err, errTooLarge) {
		m, serr := w.enc.shrink(rows[0], ch)
		if serr == nil {
			msgs = []message{m}
			err = tr.send(sendCtx, msgs)
		}
	}
	if err != nil {
		w.dropTransport()
		return len(msgs), 0, err
	}
	for _, m := range msgs {
		if m.truncated {
			truncated++
		}
	}
	return len(msgs), truncated, nil
}

// transport returns the sink's transport, building it — and reading its
// credentials — when there is none.
func (w *worker) transport() (transport, error) {
	if w.tr != nil && w.f.now().Sub(w.trBuilt) < credentialMaxAge {
		return w.tr, nil
	}
	w.dropTransport()
	tr, err := newTransport(w.cfg, w.f.opts.Credentials, w.f.opts.Version)
	if err != nil {
		return nil, err
	}
	w.tr, w.trBuilt = tr, w.f.now()
	return tr, nil
}

// dropTransport closes the transport, so the next send connects afresh and
// re-reads the credentials — which is also how a rotated token is picked up.
func (w *worker) dropTransport() {
	if w.tr != nil {
		_ = w.tr.close()
		w.tr = nil
	}
}

// sendFailed records a failed send: always in memory and in the metrics, in
// the cursor table at most once a minute per chain, and on stderr when a run
// of failures starts and every ten minutes while it lasts.
func (w *worker) sendFailed(cp *statedb.DB, ch Chain, err error, rows int) {
	now := w.f.now()
	msg := err.Error()
	w.st.failed(msg, now)
	hubmetrics.AuditForwardRows.Add(float64(rows), w.cfg.Name, hubmetrics.AuditForwardFailed)
	if last, ok := w.notedAt[ch.Path]; !ok || now.Sub(last) >= failureNoteEvery {
		w.notedAt[ch.Path] = now
		if nerr := cp.NoteAuditForwardFailure(w.cfg.Name, ch.Path, msg, now); nerr != nil {
			w.f.logf("sink %s: could not record the failure: %v", w.cfg.Name, nerr)
		}
	}
	if w.failedAt.IsZero() {
		w.failedAt = now
	}
	if w.loggedAt.IsZero() || now.Sub(w.loggedAt) >= failureLogEvery {
		w.loggedAt = now
		w.f.logf("sink %s (%s) is not accepting rows: %s — they stay in the database and are sent when it does",
			w.cfg.Name, w.cfg.Endpoint(), msg)
	}
}

// recovered ends a run of failures, saying so if one was reported.
func (w *worker) recovered() {
	if !w.failedAt.IsZero() && !w.loggedAt.IsZero() {
		w.f.logf("sink %s (%s) is accepting rows again after %s", w.cfg.Name, w.cfg.Endpoint(),
			w.f.now().Sub(w.failedAt).Round(time.Second))
	}
	w.failures, w.failedAt, w.loggedAt = 0, time.Time{}, time.Time{}
	clear(w.notedAt)
}

// backoff is the wait after the n-th consecutive failure: doubling from
// backoffBase to backoffMax, with a fifth of jitter so sinks that failed
// together do not retry in lockstep.
func backoff(n int) time.Duration {
	d := backoffMax
	if n < 20 {
		if b := backoffBase << (n - 1); b > 0 && b < backoffMax {
			d = b
		}
	}
	jitter := time.Duration(rand.Int64N(int64(d)/5 + 1))
	return d - d/10 + jitter
}

// cursor returns the sink's cursor on ch, creating it at the sink's start
// position the first time the sink meets the chain.
func (w *worker) cursor(cp, db *statedb.DB, ch Chain) (statedb.AuditForwardCursor, error) {
	if c, ok := w.cursors[ch.Path]; ok {
		return c, nil
	}
	c, ok, err := cp.AuditForwardCursorFor(w.cfg.Name, ch.Path)
	if err != nil {
		return statedb.AuditForwardCursor{}, err
	}
	if !ok || c.Retired() || c.Source != ch.Source || c.Dir != ch.Dir {
		pos, at, err := startPosition(db, w.cfg.EffectiveStart())
		if err != nil {
			return statedb.AuditForwardCursor{}, err
		}
		c, err = cp.InitAuditForwardCursor(statedb.AuditForwardCursor{
			Sink: w.cfg.Name, Chain: ch.Path, Source: ch.Source, Dir: ch.Dir,
			AckedID: pos.ID, AckedHash: pos.Hash, AckedRowAt: at,
		}, w.f.now())
		if err != nil {
			return statedb.AuditForwardCursor{}, err
		}
	}
	w.cursors[ch.Path] = c
	return c, nil
}

// startPosition is where a sink begins on a chain it has never sent: before
// the oldest row the chain still holds, or at its newest.
func startPosition(db *statedb.DB, start string) (statedb.AuditForwardMark, time.Time, error) {
	head, err := db.AuditHead()
	if err != nil {
		return statedb.AuditForwardMark{}, time.Time{}, err
	}
	if start == config.AuditStartLatest && head.LastID > 0 {
		return statedb.AuditForwardMark{ID: head.LastID, Hash: head.LastRowHash}, head.LastTimestamp, nil
	}
	pos, err := oldestPosition(db, head)
	return pos, time.Time{}, err
}

// oldestPosition is the position just before the oldest row the chain holds:
// the predecessor its first row links to, the boundary of the newest prune
// when the table is empty, or genesis.
func oldestPosition(db *statedb.DB, head statedb.AuditHead) (statedb.AuditForwardMark, error) {
	if head.Rows > 0 {
		first, ok, err := db.AuditRowAt(head.FirstID)
		if err != nil {
			return statedb.AuditForwardMark{}, err
		}
		if ok {
			return statedb.AuditForwardMark{ID: first.ID - 1, Hash: first.PrevHash}, nil
		}
	}
	if a := head.Anchor; a != nil {
		return statedb.AuditForwardMark{ID: a.PrunedThroughID, Hash: a.BoundaryHash}, nil
	}
	return statedb.AuditForwardMark{ID: 0, Hash: statedb.AuditGenesisHash}, nil
}

// realign handles a chain that does not continue from the sink's cursor. It
// reports whether the cursor moved; when it did not, the chain is either
// caught up or broken in place, and rows (if any) are to be forwarded as they
// stand.
func (w *worker) realign(cp, db *statedb.DB, ch Chain, cur *statedb.AuditForwardCursor, rows []statedb.AuditEvent) (bool, error) {
	pos, reason, lost, err := locate(db, *cur, rows)
	if err != nil {
		return false, err
	}
	if reason == "" {
		return false, nil
	}
	here := pos.ID == cur.AckedID && pos.Hash == cur.AckedHash
	if here {
		if seen, ok := w.broken[ch.Path]; ok && seen == cur.AckedID {
			return false, nil
		}
		w.broken[ch.Path] = cur.AckedID
		resumeFrom := cur.AckedID + 1
		if len(rows) > 0 {
			resumeFrom = rows[0].ID
		}
		w.recordDiscontinuity(cp, ch, *cur, reason, resumeFrom, pos.Hash, lost)
		return false, nil
	}
	// The move first, the record after it: a move another leader beat this
	// one to is that leader's to record, and recording before a move that
	// fails would write the row again on every retry.
	err = cp.AdvanceAuditForwardCursor(w.cfg.Name, ch.Path, statedb.AuditForwardAdvance{
		FromID: cur.AckedID, FromHash: cur.AckedHash, ToID: pos.ID, ToHash: pos.Hash,
	})
	switch {
	case err == nil:
		w.recordDiscontinuity(cp, ch, *cur, reason, pos.ID+1, pos.Hash, lost)
	case errors.Is(err, statedb.ErrAuditForwardCursorMoved), errors.Is(err, statedb.ErrAuditForwardCursorMissing):
	default:
		return false, fmt.Errorf("move the cursor to id %d: %w", pos.ID, err)
	}
	delete(w.cursors, ch.Path)
	c, err := w.cursor(cp, db, ch)
	if err != nil {
		return false, err
	}
	*cur = c
	return true, nil
}

// locate decides where a sink whose cursor the chain no longer continues
// should resume, and why. An empty reason means the chain still holds the
// cursor and has nothing after it.
func locate(db *statedb.DB, cur statedb.AuditForwardCursor, rows []statedb.AuditEvent) (statedb.AuditForwardMark, string, int64, error) {
	here := statedb.AuditForwardMark{ID: cur.AckedID, Hash: cur.AckedHash}
	if cur.AckedID > 0 {
		row, ok, err := db.AuditRowAt(cur.AckedID)
		if err != nil {
			return here, "", 0, err
		}
		if ok {
			if row.RowHash != cur.AckedHash {
				return fromMarks(db, cur, ReasonRewritten)
			}
			if len(rows) == 0 {
				return here, "", 0, nil
			}
			return here, ReasonBroken, max(rows[0].ID-cur.AckedID-1, 0), nil
		}
	}
	head, err := db.AuditHead()
	if err != nil {
		return here, "", 0, err
	}
	switch {
	case head.Rows > 0 && cur.AckedID < head.FirstID:
		// The rows after the cursor were pruned: resume at the oldest the
		// chain still holds.
		first, ok, err := db.AuditRowAt(head.FirstID)
		if err != nil || !ok {
			return here, "", 0, err
		}
		if first.ID == cur.AckedID+1 {
			if first.PrevHash == cur.AckedHash {
				return here, "", 0, nil
			}
			return here, ReasonBroken, 0, nil
		}
		return statedb.AuditForwardMark{ID: first.ID - 1, Hash: first.PrevHash}, ReasonPruned, first.ID - cur.AckedID - 1, nil
	case head.Rows == 0 && head.Anchor != nil && head.Anchor.PrunedThroughID >= cur.AckedID:
		a := head.Anchor
		if a.PrunedThroughID == cur.AckedID && a.BoundaryHash == cur.AckedHash {
			return here, "", 0, nil
		}
		return statedb.AuditForwardMark{ID: a.PrunedThroughID, Hash: a.BoundaryHash}, ReasonPruned,
			a.PrunedThroughID - cur.AckedID, nil
	case cur.AckedID == 0:
		// Nothing acknowledged and nothing to send.
		return here, "", 0, nil
	}
	return fromMarks(db, cur, ReasonTruncated)
}

// fromMarks resumes at the newest acknowledged point the chain still holds
// with the hash the sink was sent, or at the chain's beginning when it holds
// none of them.
func fromMarks(db *statedb.DB, cur statedb.AuditForwardCursor, reason string) (statedb.AuditForwardMark, string, int64, error) {
	for i := len(cur.Marks) - 1; i >= 0; i-- {
		m := cur.Marks[i]
		row, ok, err := db.AuditRowAt(m.ID)
		if err != nil {
			return statedb.AuditForwardMark{}, "", 0, err
		}
		if ok && row.RowHash == m.Hash {
			return m, reason, 0, nil
		}
	}
	head, err := db.AuditHead()
	if err != nil {
		return statedb.AuditForwardMark{}, "", 0, err
	}
	pos, err := oldestPosition(db, head)
	return pos, reason, 0, err
}

// recordDiscontinuity appends the audit.forward.discontinuity row, counts what
// was lost, and says so.
func (w *worker) recordDiscontinuity(cp *statedb.DB, ch Chain, cur statedb.AuditForwardCursor, reason string, resumeFrom int64, resumePrev string, lost int64) {
	if lost > 0 {
		hubmetrics.AuditForwardRows.Add(float64(lost), w.cfg.Name, hubmetrics.AuditForwardLost)
	}
	w.f.logf("sink %s: chain %s no longer continues from id %d (%s); resuming at id %d%s",
		w.cfg.Name, ch.Path, cur.AckedID, reason, resumeFrom, lostSuffix(reason, lost))
	ev := statedb.AuditEvent{
		Actor:      "system",
		EventType:  string(auditaction.ActionAuditForwardDiscontinuity),
		EntityType: "audit",
		EntityID:   w.cfg.Name,
		Payload: statedb.MarshalAuditPayload(map[string]any{
			"sink":             w.cfg.Name,
			"source":           ch.Source,
			"dir":              ch.Dir,
			"reason":           reason,
			"cursor_id":        cur.AckedID,
			"cursor_row_hash":  cur.AckedHash,
			"resumed_from_id":  resumeFrom,
			"resume_prev_hash": resumePrev,
			"lost_rows":        lost,
		}),
	}
	if err := cp.AppendAuditEvent(&ev); err != nil {
		w.f.logf("sink %s: could not record the discontinuity: %v", w.cfg.Name, err)
	}
}

func lostSuffix(reason string, lost int64) string {
	switch {
	case lost <= 0:
		return ""
	case reason == ReasonPruned:
		return fmt.Sprintf("; %d row(s) were pruned before the sink acknowledged them and are only in the prune's archive", lost)
	}
	return fmt.Sprintf("; %d row(s) are missing from the chain and never reached the sink", lost)
}
