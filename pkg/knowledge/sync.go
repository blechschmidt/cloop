package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

// WithFullListingEvery sets how often a source is listed from the beginning
// (DefaultFullListingEvery); zero or less never forces one.
func WithFullListingEvery(d time.Duration) Option { return func(s *Service) { s.fullEvery = d } }

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
	// stopping at maxSyncPages to resume next time.
	Complete bool
}

// Sync brings source id's index up to date with its remote, on the hub.
//
// It opens the source's credential through the Service's Credentials, hands
// it to the connector in-process for the length of the sync, and wipes it
// after: nothing it does reaches an executor. It lists what changed since the
// stored cursor, a page at a time, storing the cursor after each page so an
// interrupted sync resumes; fetches documents listed without a body; indexes
// each (an unchanged one is not chunked again) and drops each the source
// reports deleted.
//
// A full listing — from the beginning, when the source has no cursor, when
// its configuration changed, or when the last one is older than the Service's
// full-listing interval — is recorded when it starts, and every document
// listed is stamped. When the listing reaches its end, in this sync or in a
// later one that resumed it, every document it did not reach is removed: what
// the remote deleted without saying so, or stopped showing.
//
// Last, it asks the connector which documents match each binding's query —
// even when the listing failed, since the documents it did index may have
// changed. A binding whose answer could not be had is cleared, and serves
// nothing it narrows until a later sync answers it.
//
// The outcome — ok, or the error, scrubbed of credentials — is recorded on
// the source. Sync authorizes nothing: it is the hub's own work, for whatever
// schedules it, never a request's.
func (s *Service) Sync(ctx context.Context, id int64) (SyncReport, error) {
	var report SyncReport
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
	conn, ok := s.registry.Lookup(row.Kind)
	if !ok {
		err := fmt.Errorf("%w: no connector of kind %q in this build", ErrUnavailable, row.Kind)
		return report, s.recordFailure(row, err, Credential{})
	}
	cred, err := s.openCredential(row)
	if err != nil {
		return report, s.recordFailure(row, err, Credential{})
	}
	defer cred.wipe()

	listErr := s.listAll(ctx, conn, row, cred, &report)
	if errors.Is(listErr, statedb.ErrKnowledgeSourceChanged) {
		// Reconfigured or deleted mid-sync: the bindings are the new
		// configuration's to answer for, at its own first sync.
		return report, s.recordFailure(row, listErr, cred)
	}
	if err := errors.Join(listErr, s.narrow(ctx, conn, row, cred, &report)); err != nil {
		return report, s.recordFailure(row, err, cred)
	}
	if err := s.db.RecordKnowledgeSync(row.ID, "ok", "", s.now()); err != nil {
		return report, err
	}
	return report, nil
}

// openCredential opens the source's secret, if it names one.
func (s *Service) openCredential(row statedb.KnowledgeSourceRow) (Credential, error) {
	if row.SecretRef == "" {
		return Credential{}, nil
	}
	if s.credentials == nil {
		return Credential{}, fmt.Errorf("%w: this hub has no secret store to open %q with", ErrUnavailable, row.SecretRef)
	}
	b, err := s.credentials.SourceCredential(row.SecretRef, row.Owner)
	if err != nil {
		return Credential{}, fmt.Errorf("credential %q: %w", row.SecretRef, err)
	}
	return NewCredential(b), nil
}

// listAll pages through the source's changes from its stored cursor, starting
// a full listing first when one is due, and finishing it — sweeping what it did
// not reach — when the listing ends.
func (s *Service) listAll(ctx context.Context, conn Connector, row statedb.KnowledgeSourceRow, cred Credential, report *SyncReport) error {
	now := s.now()
	started := row.ListingStartedAt
	cursor := row.SyncCursor
	if started.IsZero() && (cursor == "" || s.fullListingDue(row, now)) {
		if err := s.db.StartKnowledgeListing(row.ID, row.UpdatedAt, now); err != nil {
			return err
		}
		started, cursor = now, ""
	}
	report.Full = !started.IsZero()
	config := json.RawMessage(row.Config)
	for report.Pages < maxSyncPages {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := conn.List(ctx, ListRequest{Config: config, Credential: cred, Cursor: cursor, PageSize: syncPageSize})
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		report.Pages++
		if len(page.Documents) > MaxPageDocuments {
			return fmt.Errorf("the %s connector returned %d documents in one page, more than %d",
				conn.Kind(), len(page.Documents), MaxPageDocuments)
		}
		for _, doc := range page.Documents {
			if err := ctx.Err(); err != nil {
				return err
			}
			report.Listed++
			if err := s.syncDocument(ctx, conn, row, cred, doc, now, report); err != nil {
				return err
			}
		}
		if page.More && page.Cursor == cursor {
			return fmt.Errorf("the %s connector returned another page without moving its cursor", conn.Kind())
		}
		if err := s.db.SetKnowledgeSyncCursor(row.ID, row.UpdatedAt, page.Cursor); err != nil {
			return err
		}
		cursor = page.Cursor
		if !page.More {
			report.Complete = true
			break
		}
	}
	if report.Complete && !started.IsZero() {
		n, err := s.db.FinishKnowledgeListing(row.ID, row.UpdatedAt, started, s.now())
		if err != nil {
			return err
		}
		report.Swept = n
	}
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

// syncDocument applies one listed document: drops it, or fetches it if it
// came without a body, and indexes it, stamped as listed at listedAt.
func (s *Service) syncDocument(ctx context.Context, conn Connector, row statedb.KnowledgeSourceRow, cred Credential,
	doc Document, listedAt time.Time, report *SyncReport) error {
	if doc.Deleted {
		id := strings.TrimSpace(doc.ExternalID)
		if id == "" {
			report.Rejected++
			return nil
		}
		found, err := s.db.DeleteKnowledgeDocument(row.ID, id)
		if err != nil {
			return err
		}
		if found {
			report.Deleted++
		}
		return nil
	}
	if doc.Partial {
		full, err := conn.Fetch(ctx, FetchRequest{Config: json.RawMessage(row.Config), Credential: cred, ExternalID: doc.ExternalID})
		if err != nil {
			return fmt.Errorf("fetch %q: %w", doc.ExternalID, err)
		}
		if full.ExternalID == "" {
			full.ExternalID = doc.ExternalID
		}
		if full.ExternalID != doc.ExternalID {
			return fmt.Errorf("the %s connector answered a fetch of %q with %q", conn.Kind(), doc.ExternalID, full.ExternalID)
		}
		full.Partial = false
		return s.syncDocument(ctx, conn, row, cred, full, listedAt, report)
	}
	outcome, err := s.index(row.ID, doc, listedAt)
	switch {
	case errors.Is(err, ErrInvalid):
		report.Rejected++
		return nil
	case err != nil:
		return err
	}
	switch outcome {
	case statedb.KnowledgeIndexCreated:
		report.Created++
	case statedb.KnowledgeIndexUpdated:
		report.Updated++
	case statedb.KnowledgeIndexUnchanged:
		report.Unchanged++
	}
	return nil
}

// narrow records, for each binding of the source with a query, which
// documents the connector says match it. A binding it cannot answer for — the
// connector failed, or no longer narrows — is cleared rather than left
// serving an answer nothing vouches for; the others are still answered.
func (s *Service) narrow(ctx context.Context, conn Connector, row statedb.KnowledgeSourceRow, cred Credential, report *SyncReport) error {
	bindings, err := s.db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{SourceID: row.ID})
	if err != nil {
		return err
	}
	narrower, canNarrow := conn.(QueryNarrower)
	var errs []error
	for _, b := range bindings {
		if b.Query == "" {
			continue
		}
		var ids []string
		err := ctx.Err()
		switch {
		case err != nil:
		case !canNarrow:
			err = fmt.Errorf("the %s connector cannot narrow by a query", conn.Kind())
		default:
			ids, err = narrower.Narrow(ctx, NarrowRequest{Config: json.RawMessage(row.Config), Credential: cred, Query: b.Query})
			if err == nil && len(ids) > maxNarrowedDocuments {
				err = fmt.Errorf("the %s connector matched %d documents, more than %d", conn.Kind(), len(ids), maxNarrowedDocuments)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("narrow binding %d: %w", b.ID, err))
			if clearErr := s.db.ClearKnowledgeBindingDocuments(b.ID); clearErr != nil {
				errs = append(errs, clearErr)
			}
			continue
		}
		err = s.db.SetKnowledgeBindingDocuments(b.ID, b.Query, ids, s.now())
		switch {
		case errors.Is(err, statedb.ErrKnowledgeBindingChanged), errors.Is(err, statedb.ErrKnowledgeBindingNotFound):
			// Changed or removed since it was read: a changed query has no
			// matches until the next sync answers it.
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		report.Narrowed++
	}
	return errors.Join(errs...)
}

// recordFailure records err as the source's last sync outcome — bounded, and
// scrubbed of the credential and of anything else shaped like one, since a
// connector's error may echo a request — and returns it in that same scrubbed
// form, for whatever logs it.
func (s *Service) recordFailure(row statedb.KnowledgeSourceRow, err error, cred Credential) error {
	text := err.Error()
	if !cred.IsZero() {
		text = strings.ReplaceAll(text, string(cred.Value()), redact.Marker)
	}
	text = clip(redact.Scrub(text), MaxSyncErrorBytes)
	out := &syncError{msg: "knowledge: sync " + row.Name + ": " + text, cause: err}
	if recErr := s.db.RecordKnowledgeSync(row.ID, "error", text, s.now()); recErr != nil &&
		!errors.Is(recErr, statedb.ErrKnowledgeSourceNotFound) {
		return errors.Join(out, recErr)
	}
	return out
}

// syncError is a failed sync's error as it was recorded: scrubbed. It matches
// whatever its cause matches — ErrUnavailable, context.Canceled — but does
// not unwrap to it, since the cause's own text is what was scrubbed.
type syncError struct {
	msg   string
	cause error
}

func (e *syncError) Error() string { return e.msg }

// Is reports whether the cause matches target.
func (e *syncError) Is(target error) bool { return errors.Is(e.cause, target) }
