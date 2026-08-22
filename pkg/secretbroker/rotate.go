package secretbroker

// Online sealing-key rotation (Task 20181).
//
// # Why this is resumable without a cursor
//
// The obvious design keeps a bookmark — "rewrapped up to row 4,812" — and
// resumes from it. That bookmark is then a second source of truth about which
// rows are done, and every failure mode of this feature becomes a way for it
// to disagree with reality: a crash between the write and the bookmark update,
// a concurrent writer inserting behind the cursor, a restored backup whose
// bookmark is newer than its rows.
//
// There is no cursor here. The work remaining is defined by the rows
// themselves — everything whose key ID is not the target — so a rotation
// resumes by being run again, and running it again on a finished rotation is a
// no-op that reads zero rows. Interruption at any point (SIGKILL, a hub
// restart, a cancelled context) costs only the row in flight, and that row is
// still sealed under its old KEK, which is still openable, because rotation
// never retires anything. The `key_rotations` table is a record for operators,
// not state the algorithm depends on: delete it and rotation still works.
//
// # Why it is safe against concurrent hub writes
//
// A rotation reads a row, rewraps it, and writes it back. Between the read and
// the write, a live hub may have replaced that row's payload entirely — an
// operator re-minting a credential, a session refreshing its token. Writing
// back a rewrapped copy of what we read would silently revert that change and
// hand out a stale credential; nothing would report an error.
//
// So the write is a compare-and-swap against both the key ID *and the exact
// ciphertext bytes* we decrypted. If anything about the row changed, the swap
// affects zero rows, the rotator counts it as skipped, and the next listing
// picks up whatever the row looks like now. The window is closed by the
// database, in one statement, rather than by a lock the rotator would have to
// hold across an AES operation and every other writer would have to respect.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultRotationBatch is how many rows are listed per round.
//
// Small enough that an interrupted rotation loses almost nothing and that the
// rotator never holds a large slice of ciphertext, large enough that a big
// registry does not turn into thousands of round trips.
const DefaultRotationBatch = 128

// SealedRow is one piece of sealed material as seen by the rotator.
//
// It carries no plaintext and the rotator never produces any: rewrapping
// operates on the DEK, not the payload. AAD is the row's associated data —
// its ID — which must round-trip exactly or the rewrap fails authentication.
type SealedRow struct {
	ID  string
	AAD string
	Env Envelope
}

// SealedSet is one population of rows that participates in rotation.
//
// Implemented by pkg/secretstore (brokered secrets) and pkg/sessionstore
// (session refresh tokens). Anything else that seals long-lived material
// under the hub key implements this and is rotated for free — which is the
// point of the interface: the alternative is a rotation command that knows
// the names of the tables, and therefore silently misses the next one.
type SealedSet interface {
	// SealedSetName identifies the set in reports ("secrets", "sessions").
	SealedSetName() string
	// CountSealedByKey returns row counts keyed by key ID, including
	// LegacyKeyID for pre-envelope rows.
	CountSealedByKey() (map[string]int, error)
	// ListSealedNotUnder returns up to limit rows whose key ID differs from
	// keyID. Order is unspecified; the rotator does not depend on it.
	ListSealedNotUnder(keyID string, limit int) ([]SealedRow, error)
	// ReplaceSealed swaps a row's envelope if and only if the stored one
	// still matches expect exactly. It reports whether the swap happened;
	// false is a normal outcome (a concurrent writer got there first), not
	// an error.
	ReplaceSealed(id string, expect, next Envelope) (bool, error)
}

// RotationRecord is the operator-facing history of a rotation run.
type RotationRecord struct {
	ID         string    `json:"id"`
	ToKeyID    string    `json:"to_key_id"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	StartedBy  string    `json:"started_by,omitempty"`
	Total      int       `json:"total"`
	Rewrapped  int       `json:"rewrapped"`
	Skipped    int       `json:"skipped"`
	Failed     int       `json:"failed"`
	LastError  string    `json:"last_error,omitempty"`
}

// Rotation states.
const (
	RotationRunning     = "running"
	RotationCompleted   = "completed"
	RotationInterrupted = "interrupted"
	RotationFailed      = "failed"
)

// RotationStore persists rotation history. Optional: a rotator without one
// still rotates, it just cannot show progress after the process exits.
type RotationStore interface {
	PutRotation(r RotationRecord) error
	ListRotations(limit int) ([]RotationRecord, error)
}

// Rotator rewraps every sealed row onto the keyring's primary KEK.
type Rotator struct {
	keyring  *Keyring
	sets     []SealedSet
	history  RotationStore
	clock    func() time.Time
	batch    int
	onUpdate func(RotationRecord)
}

// NewRotator builds a rotator over a keyring and one or more sealed sets.
func NewRotator(kr *Keyring, sets ...SealedSet) (*Rotator, error) {
	if kr == nil {
		return nil, fmt.Errorf("%w: nil keyring", ErrInvalidSecret)
	}
	live := make([]SealedSet, 0, len(sets))
	for _, s := range sets {
		if s != nil {
			live = append(live, s)
		}
	}
	if len(live) == 0 {
		return nil, fmt.Errorf("%w: no sealed sets to rotate", ErrInvalidSecret)
	}
	return &Rotator{keyring: kr, sets: live, clock: kr.clock, batch: DefaultRotationBatch}, nil
}

// WithHistory attaches a store for rotation records.
func (r *Rotator) WithHistory(h RotationStore) *Rotator {
	if h != nil {
		r.history = h
	}
	return r
}

// WithBatch overrides the batch size.
func (r *Rotator) WithBatch(n int) *Rotator {
	if n > 0 {
		r.batch = n
	}
	return r
}

// WithProgress installs a callback invoked after each batch, for a CLI
// progress line.
func (r *Rotator) WithProgress(fn func(RotationRecord)) *Rotator {
	r.onUpdate = fn
	return r
}

func (r *Rotator) now() time.Time { return r.clock().UTC() }

// RotateOptions configures one run.
type RotateOptions struct {
	// NewKey mints a fresh KEK and promotes it before rewrapping. This is
	// the normal case: rotating onto the *current* primary is an upgrade of
	// stragglers, not a rotation.
	NewKey bool
	// Actor is recorded on the new key and the rotation record.
	Actor string
	// DryRun reports what would be rewrapped without writing anything.
	DryRun bool
}

// SetReport is per-set rotation detail.
type SetReport struct {
	Name      string   `json:"name"`
	Rewrapped int      `json:"rewrapped"`
	Skipped   int      `json:"skipped"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// RotationReport is the outcome of one Rotate call.
type RotationReport struct {
	RotationID  string      `json:"rotation_id,omitempty"`
	TargetKeyID string      `json:"target_key_id"`
	Sets        []SetReport `json:"sets"`
	Rewrapped   int         `json:"rewrapped"`
	Skipped     int         `json:"skipped"`
	Failed      int         `json:"failed"`
	Complete    bool        `json:"complete"`
	DryRun      bool        `json:"dry_run,omitempty"`
}

// Rotate rewraps every row onto the primary KEK.
//
// Safe to call repeatedly, concurrently with hub traffic, and after an
// interruption — see the file comment. The returned report is complete only
// when every set drained; otherwise ErrRotationFailed is returned alongside a
// report that says precisely how far it got, and re-running continues.
func (r *Rotator) Rotate(ctx context.Context, opts RotateOptions) (RotationReport, error) {
	if err := ctx.Err(); err != nil {
		return RotationReport{}, err
	}
	if opts.NewKey && !opts.DryRun {
		if _, err := r.keyring.AddKey(opts.Actor); err != nil {
			return RotationReport{}, fmt.Errorf("mint rotation key: %w", err)
		}
	}
	target := r.keyring.PrimaryID()
	if target == "" {
		return RotationReport{}, fmt.Errorf("%w: no primary sealing key to rotate onto", ErrSealFailed)
	}

	// A dry run deliberately does not mint a key. But the run it is previewing
	// would, and a brand-new key means *every* row moves — so listing against
	// the current primary would report zero and tell the operator the opposite
	// of the truth. Listing against a sentinel no row can be sealed under
	// counts what the real command would do.
	listTarget := target
	if opts.DryRun && opts.NewKey {
		listTarget = dryRunSentinelKey
	}

	rec := RotationRecord{
		ToKeyID:   target,
		State:     RotationRunning,
		StartedAt: r.now(),
		UpdatedAt: r.now(),
		StartedBy: opts.Actor,
	}
	if id, err := newID("rot"); err == nil {
		rec.ID = id
	}
	rec.Total = r.remaining(listTarget)
	report := RotationReport{RotationID: rec.ID, TargetKeyID: target, DryRun: opts.DryRun}

	// A dry run answers a counting question, so answer it with a count. Walking
	// the listings instead under-reports by exactly one batch: nothing is
	// written, so every round returns the same first `batch` rows and the loop
	// stops as soon as it recognises them. On a 5 000-row hub that reports 128
	// and tells the operator the job is forty times smaller than it is.
	if opts.DryRun {
		for _, set := range r.sets {
			counts, cerr := set.CountSealedByKey()
			if cerr != nil {
				report.Sets = append(report.Sets, SetReport{
					Name:   set.SealedSetName(),
					Failed: 1,
					Errors: []string{fmt.Sprintf("count: %v", cerr)},
				})
				report.Failed++
				continue
			}
			n := 0
			for keyID, c := range counts {
				if keyID != listTarget {
					n += c
				}
			}
			report.Sets = append(report.Sets, SetReport{Name: set.SealedSetName(), Rewrapped: n})
			report.Rewrapped += n
		}
		report.Complete = report.Failed == 0
		return report, nil
	}

	r.save(rec, opts.DryRun)

	var runErr error
	for _, set := range r.sets {
		// The record carries totals across every set, so each set starts from
		// what the previous ones accumulated rather than from zero.
		base := counters{report.Rewrapped, report.Skipped, report.Failed}
		sr, err := r.rotateSet(ctx, set, listTarget, opts, &rec, base)
		report.Sets = append(report.Sets, sr)
		report.Rewrapped += sr.Rewrapped
		report.Skipped += sr.Skipped
		report.Failed += sr.Failed
		rec.Rewrapped = report.Rewrapped
		rec.Skipped = report.Skipped
		rec.Failed = report.Failed
		if err != nil {
			runErr = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				break
			}
		}
	}

	report.Complete = report.Failed == 0 && runErr == nil
	rec.FinishedAt = r.now()
	rec.UpdatedAt = rec.FinishedAt
	switch {
	case report.Complete:
		rec.State = RotationCompleted
	case runErr != nil && (errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)):
		rec.State = RotationInterrupted
	default:
		rec.State = RotationFailed
	}
	r.save(rec, opts.DryRun)

	if runErr != nil {
		return report, runErr
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%w: %d row(s) could not be rewrapped onto %s; re-run to continue",
			ErrRotationFailed, report.Failed, target)
	}
	return report, nil
}

// rotateSet drains one set onto target.
func (r *Rotator) rotateSet(ctx context.Context, set SealedSet, target string,
	opts RotateOptions, rec *RotationRecord, base counters) (SetReport, error) {

	out := SetReport{Name: set.SealedSetName()}

	// Every row this pass has looked at, and how often.
	//
	// Two different failures need this bound, and neither terminates without
	// it. A row that *cannot* be rewrapped — sealed under a retired key —
	// stays in the "not under target" listing forever, so the loop re-reads it
	// every round. And a row that *can* be rewrapped but is immediately pulled
	// back by another writer (a second rotation targeting a different key) also
	// stays in the listing forever, while looking like progress each round: the
	// swap succeeds, so a "did this round rewrap anything" check would never
	// fire.
	//
	// Counting attempts per row catches both, because both share the same
	// observable: the same row keeps coming back. A row that exceeds the budget
	// is reported and dropped from this pass; `--continue` picks it up once
	// whatever is fighting the rotation has stopped.
	const maxRowAttempts = 5
	attempts := make(map[string]int)
	stuck := make(map[string]bool)

	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		rows, err := set.ListSealedNotUnder(target, r.batch)
		if err != nil {
			out.Failed++
			out.Errors = append(out.Errors, fmt.Sprintf("list: %v", err))
			return out, fmt.Errorf("list %s: %w", set.SealedSetName(), err)
		}

		pending := rows[:0:0]
		for _, row := range rows {
			if stuck[row.ID] {
				continue
			}
			attempts[row.ID]++
			if attempts[row.ID] > maxRowAttempts {
				stuck[row.ID] = true
				out.Failed++
				out.Errors = appendCapped(out.Errors, fmt.Sprintf(
					"%s %s: still not under %s after %d attempts (another rotation may be running); "+
						"re-run with --continue",
					set.SealedSetName(), SafeRef(row.ID), target, maxRowAttempts))
				continue
			}
			pending = append(pending, row)
		}
		if len(pending) == 0 {
			return out, nil
		}

		progressed := false
		for _, row := range pending {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			next, rerr := r.keyring.Rewrap(row.AAD, row.Env)
			if rerr != nil {
				stuck[row.ID] = true
				out.Failed++
				out.Errors = appendCapped(out.Errors,
					fmt.Sprintf("%s %s: %v", set.SealedSetName(), SafeRef(row.ID), rerr))
				rec.LastError = truncateErr(RedactString(rerr.Error()))
				continue
			}

			swapped, serr := set.ReplaceSealed(row.ID, row.Env, next)
			if serr != nil {
				stuck[row.ID] = true
				out.Failed++
				out.Errors = appendCapped(out.Errors,
					fmt.Sprintf("%s %s: %v", set.SealedSetName(), SafeRef(row.ID), serr))
				rec.LastError = truncateErr(RedactString(serr.Error()))
				continue
			}
			if swapped {
				out.Rewrapped++
			} else {
				// A concurrent writer replaced the row. Whatever it wrote was
				// sealed under the current primary, so it is already rotated;
				// if it was not, the next listing returns it.
				out.Skipped++
			}
			progressed = true
		}

		rec.Rewrapped = base.rewrapped + out.Rewrapped
		rec.Skipped = base.skipped + out.Skipped
		rec.Failed = base.failed + out.Failed
		rec.UpdatedAt = r.now()
		r.save(*rec, opts.DryRun)
		if r.onUpdate != nil {
			r.onUpdate(*rec)
		}

		if !progressed {
			return out, nil
		}
	}
}

// remaining counts rows not yet under target across every set. Best effort: a
// count that fails to load makes the progress display less precise and must
// not stop the rotation.
func (r *Rotator) remaining(target string) int {
	total := 0
	for _, set := range r.sets {
		counts, err := set.CountSealedByKey()
		if err != nil {
			continue
		}
		for keyID, n := range counts {
			if keyID != target {
				total += n
			}
		}
	}
	return total
}

func (r *Rotator) save(rec RotationRecord, dryRun bool) {
	if r.history == nil || dryRun || rec.ID == "" {
		return
	}
	// A rotation that cannot write its own history row must not abort the
	// rotation: the history is a convenience, the rows are the truth.
	_ = r.history.PutRotation(rec)
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// KeyUsage is how many rows of one set are sealed under one key.
type KeyUsage struct {
	KeyID string         `json:"key_id"`
	Total int            `json:"total"`
	BySet map[string]int `json:"by_set"`
}

// RotationStatus is the whole picture: which keys exist, what each is sealing,
// and how the last rotation went.
type RotationStatus struct {
	PrimaryKeyID string           `json:"primary_key_id"`
	Keys         []KeyInfo        `json:"keys"`
	Usage        []KeyUsage       `json:"usage"`
	Legacy       int              `json:"legacy_rows"`
	LegacyOpen   bool             `json:"legacy_openable"`
	Unrotated    int              `json:"unrotated_rows"`
	Rotations    []RotationRecord `json:"rotations,omitempty"`
}

// Status assembles the report behind `cloop hub key status`.
func (r *Rotator) Status(historyLimit int) (RotationStatus, error) {
	primary := r.keyring.PrimaryID()
	st := RotationStatus{
		PrimaryKeyID: primary,
		Keys:         r.keyring.Keys(),
		LegacyOpen:   r.keyring.HasLegacy(),
	}

	usage := map[string]*KeyUsage{}
	var firstErr error
	for _, set := range r.sets {
		counts, err := set.CountSealedByKey()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("count %s: %w", set.SealedSetName(), err)
			}
			continue
		}
		for keyID, n := range counts {
			if n == 0 {
				continue
			}
			id := keyID
			if id == "" {
				id = LegacyKeyID
			}
			u, ok := usage[id]
			if !ok {
				u = &KeyUsage{KeyID: id, BySet: map[string]int{}}
				usage[id] = u
			}
			u.Total += n
			u.BySet[set.SealedSetName()] += n
			if id == LegacyKeyID {
				st.Legacy += n
			}
			if id != primary {
				st.Unrotated += n
			}
		}
	}
	for _, u := range usage {
		st.Usage = append(st.Usage, *u)
	}
	sort.SliceStable(st.Usage, func(i, j int) bool {
		if st.Usage[i].KeyID == primary != (st.Usage[j].KeyID == primary) {
			return st.Usage[i].KeyID == primary
		}
		return st.Usage[i].KeyID < st.Usage[j].KeyID
	})

	if r.history != nil && historyLimit > 0 {
		if recs, err := r.history.ListRotations(historyLimit); err == nil {
			st.Rotations = recs
		}
	}
	return st, firstErr
}

// RetireKey retires a KEK after confirming nothing references it.
//
// The check here is advisory and the store's is authoritative — a row could be
// written between the two — but running it first turns the common case into a
// message naming the sets and counts that are blocking, instead of a bare
// constraint violation from SQLite.
func (r *Rotator) RetireKey(id string) error {
	id = normaliseKeyID(id)
	if id == "" {
		return fmt.Errorf("%w: empty key id", ErrKeyUnknown)
	}
	var blocking []string
	for _, set := range r.sets {
		counts, err := set.CountSealedByKey()
		if err != nil {
			return fmt.Errorf("count %s: %w", set.SealedSetName(), err)
		}
		if n := counts[id]; n > 0 {
			blocking = append(blocking, fmt.Sprintf("%s (%d)", set.SealedSetName(), n))
		}
	}
	if len(blocking) > 0 {
		sort.Strings(blocking)
		return fmt.Errorf("%w: %s still sealed under %s; run 'cloop hub key rotate' first",
			ErrKeyInUse, strings.Join(blocking, ", "), id)
	}
	return r.keyring.RetireKey(id)
}

// ---------------------------------------------------------------------------

// errorReportCap bounds how many per-row errors a report carries. A rotation
// that fails on ten thousand rows has one problem, not ten thousand, and a
// report that tries to print all of them is unreadable and unbounded in
// memory.
const errorReportCap = 20

// dryRunSentinelKey is a key ID no row can hold, used to make a dry run list
// every row rather than only the stragglers.
const dryRunSentinelKey = "\x00dry-run-preview"

// counters carries running totals into a per-set pass so progress rows show
// the rotation's cumulative state rather than one set's.
type counters struct{ rewrapped, skipped, failed int }

func appendCapped(list []string, msg string) []string {
	if len(list) >= errorReportCap {
		if len(list) == errorReportCap {
			return append(list, "… further errors suppressed")
		}
		return list
	}
	return append(list, msg)
}

func truncateErr(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
