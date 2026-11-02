package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Sync bounds.
const (
	// syncPageSize is the page size a sync asks connectors for.
	syncPageSize = 100
	// maxSyncPages bounds one sync; a source with more resumes from its cursor
	// at the next one.
	maxSyncPages = 2000
	// maxNarrowedDocuments bounds a connector's answer to one binding's query.
	maxNarrowedDocuments = 250_000
	// DefaultFullListingEvery is how often a source is listed from the
	// beginning even when nothing asked for it, so that what its remote
	// removed or hid without saying so leaves the index.
	DefaultFullListingEvery = 7 * 24 * time.Hour
	// DefaultReconcileEvery is how often a Reconciler's source is reconciled:
	// how long a document deleted, moved out of scope or newly restricted at
	// the remote can stay searchable when nothing else about it changed.
	DefaultReconcileEvery = 6 * time.Hour
	// maxReconciledDocuments bounds a Reconciler's answer.
	maxReconciledDocuments = 250_000
	// reconcileGrace is how recently a sync must have listed a document for a
	// reconciliation to keep it whatever its answer says: an answer read from a
	// remote's search index can lag the listing that just indexed a document,
	// and must not remove it.
	reconcileGrace = time.Hour
	// maxBatchDocuments and maxBatchBytes bound one write transaction of a
	// sync. A page is written in batches of at most this many documents and
	// this much text — each document whole in one batch, alone if it is
	// larger — so a transaction holds the database's write lock, which every
	// other writer of the control plane waits on, for milliseconds rather
	// than for a page of large documents.
	maxBatchDocuments = 50
	maxBatchBytes     = 4 << 20
)

// WithFullListingEvery sets how often a source is listed from the beginning
// (DefaultFullListingEvery); zero or less never forces one.
func WithFullListingEvery(d time.Duration) Option { return func(s *Service) { s.fullEvery = d } }

// WithReconcileEvery sets how often a source whose connector is a Reconciler
// is reconciled (DefaultReconcileEvery); zero or less never reconciles, which
// leaves removing what the remote no longer holds to full listings.
func WithReconcileEvery(d time.Duration) Option { return func(s *Service) { s.reconcileEvery = d } }

// SyncReport says what one sync did.
type SyncReport struct {
	Pages     int
	Listed    int
	Created   int
	Updated   int
	Unchanged int
	// Deleted counts documents the source reported deleted.
	Deleted int
	// Rejected counts documents refused as malformed (no external id, say);
	// the rest of their page was indexed.
	Rejected int
	// Full reports a sync taking part in a full listing — from the
	// beginning, or resuming one an earlier sync began.
	Full bool
	// Swept counts the documents a full listing that reached its end removed
	// because it did not list them.
	Swept int
	// Narrowed counts the bindings whose query matches were recorded.
	Narrowed int
	// Complete reports that the listing reached its end, rather than
	// stopping at maxSyncPages or its time budget to resume next time.
	Complete bool
	// Reconciled reports that the connector was asked which documents the
	// source holds, and Removed counts the documents its answer left out,
	// which the reconciliation removed.
	Reconciled bool
	Removed    int
}

// Counts is the report as the source records it.
func (r SyncReport) Counts() SyncCounts {
	return SyncCounts{
		Pages: r.Pages, Listed: r.Listed, Created: r.Created, Updated: r.Updated, Unchanged: r.Unchanged,
		Deleted: r.Deleted, Rejected: r.Rejected, Removed: r.Swept + r.Removed, Narrowed: r.Narrowed,
		Complete: r.Complete, Full: r.Full,
	}
}

// SyncOptions says how one sync runs.
type SyncOptions struct {
	// Holder is the sync lease the sync holds (see Runner): every write that
	// moves it forward — a batch of documents and the cursor after them, the
	// start and end of a full listing, a reconciliation, its outcome — is
	// refused once it no longer does. Empty for a sync nothing else can
	// overlap, such as a test's.
	Holder string
	// Origin is what started the sync, OriginSchedule or OriginManual; it is
	// recorded with the outcome.
	Origin string
	// Budget bounds how long the sync lists. Past it the sync stops after the
	// page in hand — having listed at least one — and the next resumes from
	// its cursor. Zero leaves only maxSyncPages.
	Budget time.Duration
}

// Why a sync stopped before its end without failing: the runner cancels a
// sync's context with one of these as the cause.
var (
	// ErrSyncInterrupted is the cause of a sync stopped because the hub
	// process running it is stopping or no longer leads its cluster. The
	// sync is recorded interrupted, not failed, and resumes from its cursor.
	ErrSyncInterrupted = errors.New("knowledge: the sync was interrupted")
	// ErrLeaseLost is the cause of a sync stopped because it could no longer
	// renew its source's lease: another may have taken it over.
	ErrLeaseLost = errors.New("knowledge: the sync lost its lease")
)

// Markers a sync's failure carries, for FailureReason.
var (
	errConnectorFailed  = errors.New("knowledge: the connector failed")
	errCredentialFailed = errors.New("knowledge: the source's credential could not be opened")
)

// markedError is an error with a marker errors.Is finds beside it.
type markedError struct {
	err  error
	mark error
}

func (e *markedError) Error() string   { return e.err.Error() }
func (e *markedError) Unwrap() []error { return []error{e.err, e.mark} }

func mark(err, as error) error {
	if err == nil {
		return nil
	}
	return &markedError{err: err, mark: as}
}

// PanicError is a panic the sync recovered: in a connector's call, or in the
// sync's own work. Value is what the panic carried, scrubbed of the source's
// credential and anything else shaped like one; Stack is where it happened.
type PanicError struct {
	Kind  string
	Op    string
	Value string
	Stack []byte
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("the %s connector panicked in %s: %s", e.Kind, e.Op, e.Value)
}

// Sync is SyncWith without a lease, origin or budget.
func (s *Service) Sync(ctx context.Context, id int64) (SyncReport, error) {
	return s.SyncWith(ctx, id, SyncOptions{})
}

// SyncWith brings source id's index up to date with its remote, on the hub.
//
// It opens the source's credential through the Service's Credentials, hands
// it to the connector in-process for the length of the sync, and wipes it
// after: nothing it does reaches an executor. It lists what changed since the
// stored cursor, a page at a time; fetches documents listed without a body;
// and writes each page in bounded batches, each one transaction, each
// document whole in one of them, the page's cursor with the last — so a sync
// that dies part-way leaves no document half-indexed and resumes from the
// last page it committed. An unchanged document is not chunked again; one the
// source reports deleted leaves the index.
//
// A full listing — from the beginning, when the source has no cursor, when
// its configuration changed, or when the last one is older than the Service's
// full-listing interval — is recorded when it starts, and every document
// listed is stamped. When the listing reaches its end, in this sync or in a
// later one that resumed it, every document it did not reach is removed: what
// the remote deleted without saying so, or stopped showing.
//
// A listing that reached its end without error is followed, when the
// connector is a Reconciler and the source's last reconciliation is older than
// the Service's interval, by a reconciliation: the connector reports every
// document the source holds in scope now, and each indexed document it leaves
// out is removed — unless a sync listed it within the last hour, which an
// answer from a lagging search index must not undo. A full listing that ends
// counts as one, its sweep having removed the same documents.
//
// Last, it asks the connector which documents match each binding's query —
// even when the listing failed, since the documents it did index may have
// changed. A binding whose answer could not be had is cleared, and serves
// nothing it narrows until a later sync answers it. A sync that was stopped
// asks nothing more, and every binding keeps its last answer.
//
// The outcome — ok, interrupted, or the error scrubbed of credentials — is
// recorded on the source with what the sync did and how long it took. A panic
// in a connector, or in the sync, fails this sync and nothing else. SyncWith
// authorizes nothing: it is the hub's own work, for whatever schedules it,
// never a request's.
func (s *Service) SyncWith(ctx context.Context, id int64, opts SyncOptions) (report SyncReport, err error) {
	started := s.now()
	row, err := s.db.GetKnowledgeSource(id)
	if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) {
		return report, fmt.Errorf("%w: source %d", ErrNotFound, id)
	}
	if err != nil {
		return report, err
	}
	if !row.Enabled {
		return report, fmt.Errorf("%w: %s", ErrDisabled, row.Name)
	}
	r := &syncRun{s: s, ctx: ctx, row: row, opts: opts, started: started, report: &report}
	conn, ok := s.registry.Lookup(row.Kind)
	if !ok {
		return report, r.finish(fmt.Errorf("%w: no connector of kind %q in this build", ErrUnavailable, row.Kind))
	}
	r.conn = conn
	cred, err := s.openCredential(row)
	if err != nil {
		return report, r.finish(err)
	}
	r.cred = cred
	defer cred.wipe()
	// A panic in the sync's own work — a connector's are recovered at each
	// call — fails this sync like any error. Deferred after the wipe, so it
	// runs first and can still scrub the credential out of what it records.
	defer func() {
		if v := recover(); v != nil {
			err = r.finish(r.panicked("sync", v))
		}
	}()

	listErr := r.listAll()
	if listErr == nil {
		listErr = r.reconcile()
	}
	if overtaken(listErr) || ctx.Err() != nil {
		// Reconfigured, deleted or taken over mid-sync — the bindings are the
		// next sync's to answer for — or stopped, which leaves each binding's
		// last answer standing.
		return report, r.finish(listErr)
	}
	return report, r.finish(errors.Join(listErr, r.narrow()))
}

// syncRun is one sync in progress.
type syncRun struct {
	s       *Service
	ctx     context.Context
	row     statedb.KnowledgeSourceRow
	opts    SyncOptions
	conn    Connector
	cred    Credential
	started time.Time
	report  *SyncReport
}

// fence is the lease every write of the sync is made under.
func (r *syncRun) fence() statedb.KnowledgeSyncFence {
	return statedb.KnowledgeSyncFence{Holder: r.opts.Holder, Now: r.s.now()}
}

// openCredential opens the source's secret, if it names one.
func (s *Service) openCredential(row statedb.KnowledgeSourceRow) (Credential, error) {
	if row.SecretRef == "" {
		return Credential{}, nil
	}
	if s.credentials == nil {
		return Credential{}, mark(fmt.Errorf("%w: this hub has no secret store to open %q with", ErrUnavailable, row.SecretRef),
			errCredentialFailed)
	}
	b, err := s.credentials.SourceCredential(row.SecretRef, row.Owner)
	if err != nil {
		return Credential{}, mark(fmt.Errorf("credential %q: %w", row.SecretRef, err), errCredentialFailed)
	}
	return NewCredential(b), nil
}

// call runs one call into the connector, a panic in it becoming its error:
// one connector's bug fails its own source's sync, not the hub process that
// syncs every source. Every error a call returns is marked as the
// connector's, for FailureReason.
func (r *syncRun) call(op string, fn func() error) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = r.panicked(op, v)
		}
	}()
	return mark(fn(), errConnectorFailed)
}

// panicked records a recovered panic as an error, its value scrubbed while
// the credential is still at hand.
func (r *syncRun) panicked(op string, v any) error {
	return &PanicError{Kind: r.row.Kind, Op: op, Value: r.scrub(fmt.Sprint(v)), Stack: debug.Stack()}
}

// listAll pages through the source's changes from its stored cursor, starting
// a full listing first when one is due, and finishing it — sweeping what it did
// not reach — when the listing ends.
func (r *syncRun) listAll() error {
	s, row := r.s, r.row
	now := s.now()
	started := row.ListingStartedAt
	cursor := row.SyncCursor
	if started.IsZero() && (cursor == "" || s.fullListingDue(row, now)) {
		if err := s.db.StartKnowledgeListingFenced(r.fence(), row.ID, row.UpdatedAt, now); err != nil {
			return err
		}
		started, cursor = now, ""
	}
	r.report.Full = !started.IsZero()
	config := json.RawMessage(row.Config)
	for r.report.Pages < maxSyncPages {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		if r.opts.Budget > 0 && r.report.Pages > 0 && s.now().Sub(r.started) >= r.opts.Budget {
			// Out of time: the next sync resumes from the cursor.
			break
		}
		var page Page
		err := r.call("list", func() (err error) {
			page, err = r.conn.List(r.ctx, ListRequest{Config: config, Credential: r.cred, Scope: row.Scope,
				Cursor: cursor, PageSize: syncPageSize})
			return err
		})
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		r.report.Pages++
		if len(page.Documents) > MaxPageDocuments {
			return mark(fmt.Errorf("the %s connector returned %d documents in one page, more than %d",
				r.conn.Kind(), len(page.Documents), MaxPageDocuments), errConnectorFailed)
		}
		if err := r.writePage(page, now); err != nil {
			return err
		}
		if page.More && page.Cursor == cursor {
			return mark(fmt.Errorf("the %s connector returned another page without moving its cursor", r.conn.Kind()),
				errConnectorFailed)
		}
		cursor = page.Cursor
		if !page.More {
			r.report.Complete = true
			break
		}
	}
	if r.report.Complete && !started.IsZero() {
		n, err := s.db.FinishKnowledgeListingFenced(r.fence(), row.ID, row.UpdatedAt, started, s.now())
		if err != nil {
			return err
		}
		r.report.Swept = n
	}
	return nil
}

// pendingDoc is one document of a page made ready to write.
type pendingDoc struct {
	op   statedb.KnowledgeBatchOp
	size int
}

// writePage writes one page's documents in batches of at most
// maxBatchDocuments and maxBatchBytes of text, and the page's cursor with the
// last of them: the cursor commits only once every document before it has. A
// document the page lists twice is written as it was listed last, as writing
// the two in order would have left it.
func (r *syncRun) writePage(page Page, listedAt time.Time) error {
	var (
		batch []pendingDoc
		bytes int
	)
	flush := func(cursor *string) error {
		ops := make([]statedb.KnowledgeBatchOp, len(batch))
		for i, p := range batch {
			ops[i] = p.op
		}
		res, err := r.s.db.ApplyKnowledgeBatch(statedb.KnowledgeBatch{SourceID: r.row.ID, UpdatedAt: r.row.UpdatedAt,
			Holder: r.opts.Holder, Now: r.s.now(), Ops: ops, Cursor: cursor})
		if err != nil {
			return err
		}
		for i, op := range ops {
			if op.Delete {
				if res.Found[i] {
					r.report.Deleted++
				}
				continue
			}
			switch res.Outcomes[i] {
			case statedb.KnowledgeIndexCreated:
				r.report.Created++
			case statedb.KnowledgeIndexUpdated:
				r.report.Updated++
			case statedb.KnowledgeIndexUnchanged:
				r.report.Unchanged++
			}
		}
		batch, bytes = batch[:0], 0
		return nil
	}
	r.report.Listed += len(page.Documents)
	for _, doc := range lastListings(page.Documents) {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		p, ok, err := r.prepareDoc(doc, listedAt)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if len(batch) > 0 && (len(batch) >= maxBatchDocuments || bytes+p.size > maxBatchBytes) {
			if err := flush(nil); err != nil {
				return err
			}
		}
		batch = append(batch, p)
		bytes += p.size
	}
	cursor := page.Cursor
	return flush(&cursor)
}

// lastListings returns a page's documents with each external id kept once,
// at its last listing.
func lastListings(docs []Document) []Document {
	last := make(map[string]int, len(docs))
	for i, d := range docs {
		if id := strings.TrimSpace(d.ExternalID); id != "" {
			last[id] = i
		}
	}
	out := make([]Document, 0, len(docs))
	for i, d := range docs {
		if id := strings.TrimSpace(d.ExternalID); id != "" && last[id] != i {
			continue
		}
		out = append(out, d)
	}
	return out
}

// prepareDoc makes one listed document ready to write: a deletion, or the
// document fetched if it came without a body, bounded and cleaned, stamped as
// listed at listedAt. ok is false for one refused as malformed, which the
// report counts.
func (r *syncRun) prepareDoc(doc Document, listedAt time.Time) (pendingDoc, bool, error) {
	if doc.Deleted {
		id := strings.TrimSpace(doc.ExternalID)
		if id == "" {
			r.report.Rejected++
			return pendingDoc{}, false, nil
		}
		return pendingDoc{op: statedb.KnowledgeBatchOp{Doc: statedb.KnowledgeDocumentRow{ExternalID: id}, Delete: true}}, true, nil
	}
	if doc.Partial {
		var full Document
		err := r.call("fetch", func() (err error) {
			full, err = r.conn.Fetch(r.ctx, FetchRequest{Config: json.RawMessage(r.row.Config), Credential: r.cred,
				Scope: r.row.Scope, ExternalID: doc.ExternalID})
			return err
		})
		if err != nil {
			return pendingDoc{}, false, fmt.Errorf("fetch %q: %w", doc.ExternalID, err)
		}
		if full.ExternalID == "" {
			full.ExternalID = doc.ExternalID
		}
		if full.ExternalID != doc.ExternalID {
			return pendingDoc{}, false, mark(fmt.Errorf("the %s connector answered a fetch of %q with %q",
				r.conn.Kind(), doc.ExternalID, full.ExternalID), errConnectorFailed)
		}
		full.Partial = false
		return r.prepareDoc(full, listedAt)
	}
	p, err := prepare(r.row.ID, doc, r.s.chunking)
	switch {
	case errors.Is(err, ErrInvalid):
		r.report.Rejected++
		return pendingDoc{}, false, nil
	case err != nil:
		return pendingDoc{}, false, err
	}
	p.row.ListedAt = listedAt
	return pendingDoc{op: statedb.KnowledgeBatchOp{Doc: p.row, Chunk: r.s.chunker(p)}, size: len(p.body)}, true, nil
}

// reconcile asks a Reconciler connector which documents the source holds and
// removes the indexed ones its answer leaves out, when the source's last
// reconciliation is older than the Service's interval. It is skipped for a
// listing that has not reached its end, and for one that took part in a full
// listing: a full listing's own sweep is the reconciliation, at its end.
func (r *syncRun) reconcile() error {
	rec, ok := r.conn.(Reconciler)
	if !ok || !r.report.Complete || r.report.Full || r.s.reconcileEvery <= 0 {
		return nil
	}
	now := r.s.now()
	if !r.row.ReconciledAt.IsZero() && now.Sub(r.row.ReconciledAt) < r.s.reconcileEvery {
		return nil
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	var ids []string
	err := r.call("reconcile", func() (err error) {
		ids, err = rec.Reconcile(r.ctx, ReconcileRequest{Config: json.RawMessage(r.row.Config), Credential: r.cred,
			Scope: r.row.Scope})
		return err
	})
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if len(ids) > maxReconciledDocuments {
		return mark(fmt.Errorf("the %s connector reported %d documents, more than %d", r.conn.Kind(), len(ids),
			maxReconciledDocuments), errConnectorFailed)
	}
	n, err := r.s.db.ReconcileKnowledgeDocumentsFenced(r.fence(), r.row.ID, r.row.UpdatedAt, ids,
		now.Add(-reconcileGrace), now)
	if err != nil {
		return err
	}
	r.report.Reconciled, r.report.Removed = true, n
	return nil
}

// fullListingDue reports whether the source's last full listing is older
// than the Service's interval.
func (s *Service) fullListingDue(row statedb.KnowledgeSourceRow, now time.Time) bool {
	if s.fullEvery <= 0 {
		return false
	}
	return row.FullListingAt.IsZero() || now.Sub(row.FullListingAt) >= s.fullEvery
}

// narrow records, for each binding of the source with a query, which
// documents the connector says match it. A binding it cannot answer for — the
// connector failed, or no longer narrows — is cleared rather than left
// serving an answer nothing vouches for; the others are still answered. A sync
// stopped part-way asks no more: the bindings it did not reach keep their last
// answer, which a stopped sync has given no reason to doubt.
func (r *syncRun) narrow() error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	bindings, err := r.s.db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{SourceID: r.row.ID})
	if err != nil {
		return err
	}
	narrower, canNarrow := r.conn.(QueryNarrower)
	var errs []error
	for _, b := range bindings {
		if b.Query == "" {
			continue
		}
		if err := r.ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		var ids []string
		var err error
		if !canNarrow {
			err = mark(fmt.Errorf("the %s connector cannot narrow by a query", r.conn.Kind()), errConnectorFailed)
		} else {
			err = r.call("narrow", func() (err error) {
				ids, err = narrower.Narrow(r.ctx, NarrowRequest{Config: json.RawMessage(r.row.Config), Credential: r.cred,
					Scope: r.row.Scope, Query: b.Query})
				return err
			})
			if err == nil && len(ids) > maxNarrowedDocuments {
				err = mark(fmt.Errorf("the %s connector matched %d documents, more than %d", r.conn.Kind(), len(ids),
					maxNarrowedDocuments), errConnectorFailed)
			}
		}
		if err != nil && r.ctx.Err() != nil {
			// Stopped mid-answer, which is not the connector failing to give one.
			return errors.Join(append(errs, err)...)
		}
		// Each answer is written — or cleared — only while this sync still
		// holds the source, as the source it read: one that stalled past its
		// lease must not put back matches the sync that took over cleared,
		// nor clear an answer that sync recorded.
		fence := r.fence()
		fence.Version = r.row.UpdatedAt
		if err != nil {
			errs = append(errs, fmt.Errorf("narrow binding %d: %w", b.ID, err))
			if clearErr := r.s.db.ClearKnowledgeBindingDocumentsFenced(fence, b.ID); clearErr != nil {
				if overtaken(clearErr) {
					return errors.Join(append(errs, clearErr)...)
				}
				errs = append(errs, clearErr)
			}
			continue
		}
		err = r.s.db.SetKnowledgeBindingDocumentsFenced(fence, b.ID, b.Query, ids, r.s.now())
		switch {
		case errors.Is(err, statedb.ErrKnowledgeBindingChanged), errors.Is(err, statedb.ErrKnowledgeBindingNotFound):
			// Changed or removed since it was read: a changed query has no
			// matches until the next sync answers it.
			continue
		case overtaken(err):
			return errors.Join(append(errs, err)...)
		case err != nil:
			errs = append(errs, err)
			continue
		}
		r.report.Narrowed++
	}
	return errors.Join(errs...)
}

// overtaken reports an error saying the sync is no longer the one to write:
// it lost its lease, or its source changed under it.
func overtaken(err error) bool {
	return errors.Is(err, statedb.ErrKnowledgeSyncLeaseLost) || errors.Is(err, statedb.ErrKnowledgeSourceChanged)
}

// interrupted reports whether the sync was stopped rather than failed: its
// context ended, and not because it lost its lease.
func (r *syncRun) interrupted() bool {
	return r.ctx.Err() != nil && !errors.Is(context.Cause(r.ctx), ErrLeaseLost)
}

// scrub removes the credential, and anything else shaped like one, from text
// the sync records or returns: a connector's error, or a panic's value, may
// echo a request.
func (r *syncRun) scrub(text string) string {
	if !r.cred.IsZero() {
		text = strings.ReplaceAll(text, string(r.cred.Value()), redact.Marker)
	}
	return clip(redact.Scrub(text), MaxSyncErrorBytes)
}

// errSourceChanged is what a sync overtaken by a change to its source records.
var errSourceChanged = errors.New("the source was changed while it synced; the next sync takes the change up")

// finish records how the sync ended — ok, interrupted, or err scrubbed — with
// what it did and how long it took, and returns err in the same scrubbed form,
// for whatever logs it.
//
// A sync overtaken by a change to its source — reconfigured, renamed,
// re-timed — is interrupted, not failed: nothing went wrong, and the next
// sync, due within a minute, takes the change up.
func (r *syncRun) finish(err error) error {
	status, text := StatusOK, ""
	switch {
	case err == nil && r.ctx.Err() == nil:
	case r.interrupted():
		status = StatusInterrupted
		cause := context.Cause(r.ctx)
		if err == nil {
			err = cause
		}
		text = r.scrub(cause.Error())
	case errors.Is(err, statedb.ErrKnowledgeSourceChanged) && r.ctx.Err() == nil:
		status, text = StatusInterrupted, errSourceChanged.Error()
	default:
		status = StatusError
		if err == nil {
			err = context.Cause(r.ctx)
		}
		if errors.Is(context.Cause(r.ctx), ErrLeaseLost) {
			err = errors.Join(ErrLeaseLost, err)
		}
		text = r.scrub(err.Error())
	}
	counts, _ := json.Marshal(r.report.Counts())
	outcome := statedb.KnowledgeSyncOutcome{
		Status: status, Error: text, Origin: r.opts.Origin, StartedAt: r.started, FinishedAt: r.s.now(),
		Report: string(counts), More: status == StatusInterrupted || (status == StatusOK && !r.report.Complete),
		Holder: r.opts.Holder,
	}
	recErr := r.s.db.RecordKnowledgeSyncOutcome(r.row.ID, outcome)
	if errors.Is(recErr, statedb.ErrKnowledgeSourceNotFound) {
		// Deleted while it ran: there is no source to record it on.
		recErr = nil
	}
	if err == nil && errors.Is(recErr, statedb.ErrKnowledgeSyncLeaseLost) {
		// It finished, but lost its lease before it could say so: whatever
		// it wrote stands, and the sync that holds the source now records
		// its own outcome.
		return &syncError{msg: "knowledge: sync " + r.row.Name + ": " + r.scrub(recErr.Error()), cause: recErr,
			status: StatusError, reason: ReasonLease}
	}
	if err == nil {
		return recErr
	}
	out := &syncError{msg: "knowledge: sync " + r.row.Name + ": " + text, cause: err, status: status,
		reason: failureReason(err, status)}
	if recErr != nil && !errors.Is(recErr, statedb.ErrKnowledgeSyncLeaseLost) {
		return errors.Join(out, recErr)
	}
	return out
}

// syncError is a sync's error as it was recorded: scrubbed. It matches
// whatever its cause matches — ErrUnavailable, context.Canceled — but does
// not unwrap to it, since the cause's own text is what was scrubbed.
type syncError struct {
	msg    string
	cause  error
	status string
	reason string
}

func (e *syncError) Error() string { return e.msg }

// Is reports whether the cause matches target.
func (e *syncError) Is(target error) bool { return errors.Is(e.cause, target) }

// As finds a *PanicError in the cause — its value already scrubbed — and
// nothing else, whose text was not.
func (e *syncError) As(target any) bool {
	pp, ok := target.(**PanicError)
	if !ok {
		return false
	}
	var pe *PanicError
	if errors.As(e.cause, &pe) {
		*pp = pe
		return true
	}
	return false
}

// Why a sync failed, as FailureReason classifies it: the label values of the
// hub's cloop_knowledge_sync_errors_total.
const (
	// ReasonConnector: the connector's call failed — the remote answered an
	// error, could not be reached, or sent what the sync refuses.
	ReasonConnector = "connector"
	// ReasonCredential: the source's secret could not be opened.
	ReasonCredential = "credential"
	// ReasonPanic: a connector, or the sync, panicked.
	ReasonPanic = "panic"
	// ReasonLease: the sync lost its source's lease.
	ReasonLease = "lease"
	// ReasonUnavailable: the hub lacks what the source needs — a connector
	// of its kind, a secret store.
	ReasonUnavailable = "unavailable"
	// ReasonStorage: the hub's database failed a write or a read.
	ReasonStorage = "storage"
)

// FailureReasons lists every reason FailureReason returns.
var FailureReasons = []string{ReasonConnector, ReasonCredential, ReasonPanic, ReasonLease, ReasonUnavailable,
	ReasonStorage}

// FailureReason classifies a failed sync's error. A sync that did not fail —
// ok, or interrupted — has none, and neither has an error no sync returned.
func FailureReason(err error) string {
	var se *syncError
	if errors.As(err, &se) && se.status == StatusError {
		return se.reason
	}
	return ""
}

func failureReason(err error, status string) string {
	if status != StatusError {
		return ""
	}
	var pe *PanicError
	switch {
	case errors.As(err, &pe):
		return ReasonPanic
	case errors.Is(err, ErrLeaseLost), errors.Is(err, statedb.ErrKnowledgeSyncLeaseLost):
		return ReasonLease
	case errors.Is(err, ErrUnavailable):
		return ReasonUnavailable
	case errors.Is(err, errCredentialFailed):
		return ReasonCredential
	case errors.Is(err, errConnectorFailed):
		return ReasonConnector
	}
	return ReasonStorage
}

// SyncStatusOf reports how the sync that returned err ended: StatusOK for
// nil, else StatusError or StatusInterrupted.
func SyncStatusOf(err error) string {
	if err == nil {
		return StatusOK
	}
	var se *syncError
	if errors.As(err, &se) && se.status != "" {
		return se.status
	}
	return StatusError
}
