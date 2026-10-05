// A project's journal read as one feed, a page at a time (Task 20384).
//
// The dashboard's Event History panel shows two tables as one list, newest
// first: steps (the result of each provider call) and events (task starts,
// verdicts, evolve rounds, write-backs …). It used to be assembled by loading
// the whole project — every step's output included — plus up to 5,000 events,
// sorting the lot in memory and returning fifty rows, and the dashboard asked
// for it again on every realtime message of a live run. This reads the rows a
// page shows and no others, so the cost of a page does not depend on how long
// the project has been running.
//
// Order. Newest first by timestamp, through the julianday() indexes of
// migration 0059, so rows written in any offset or with trimmed fractions
// still sort as instants. A step and an event at the same instant (to the
// millisecond julianday keeps) list the event first: the orchestrator records
// a step's result before the events that describe it (task_done, write_back
// …). Two rows of one table at the same instant list the later-written first.
//
// Two kinds of position, because the feed is read in two directions that
// cannot share one:
//
//   - Paging down (Before) follows the time order: a HistoryPlace is the place
//     of the last row a page returned, and the next page is the rows after it.
//
//   - Reading what is new (After) follows the write order. A HistoryCursor is
//     the newest step number and event id a reader has seen, and "new" is
//     anything written since — whatever its timestamp. A remote executor's
//     events come back with the device's times when its run ends, so in that
//     direction a position in time would leave every one of them behind it,
//     unread.

package statedb

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf8"
)

// HistoryCursor is a position in the journal's write order: the newest step
// number and event id a reader has seen. Step is -1 when it has seen no step
// (step numbers start at 0) and Event is 0 when it has seen no event.
type HistoryCursor struct {
	Step  int64
	Event int64
}

// HistoryPlace is a row's place in the feed's time order: the julian day it
// happened on (0 for a time that cannot be read), whether it is an event, and
// its step number or event id.
type HistoryPlace struct {
	Day   float64
	Event bool
	Key   int64
}

// after reports whether p lists below q in the feed (newest first).
func (p HistoryPlace) after(q HistoryPlace) bool {
	if p.Day != q.Day {
		return p.Day < q.Day
	}
	if p.Event != q.Event {
		return q.Event // an event lists above a step at the same instant
	}
	return p.Key < q.Key
}

// HistoryRow is one row of the feed: a step or an event, never both.
type HistoryRow struct {
	Step  *StepRow
	Event *EventRow
	// Place is where the row lists in the feed.
	Place HistoryPlace
	// Cut is the full length in bytes of the step's Output or the event's
	// Details when the value here was shortened to HistoryQuery.MaxValue, and
	// 0 when it is whole. A shortened Output is its first MaxValue bytes; a
	// shortened Details is empty, since half a JSON document is not one.
	Cut int
}

// HistoryQuery selects one page of the feed.
type HistoryQuery struct {
	// Before pages down: the Limit rows listed after this place.
	Before *HistoryPlace
	// After returns every row written since this cursor, in feed order, when
	// there are at most Limit of them; otherwise the newest page with
	// HistoryPage.Gap set.
	After *HistoryCursor
	// Offset skips that many rows from the top before the page starts, for
	// callers that page by position. Only without Before and After; it reads
	// one index entry per skipped row, which positions avoid.
	Offset int
	// Limit is the most rows returned; it must be positive.
	Limit int
	// MaxValue, when positive, is the longest step output or event details
	// returned whole; longer ones are cut (see HistoryRow.Cut).
	MaxValue int
}

// HistoryPage is what History returns.
type HistoryPage struct {
	// Rows in feed order, newest first.
	Rows []HistoryRow
	// Top is the newest step and event written when the page was read — what
	// a later After read starts from. On a Before page it is not set.
	Top HistoryCursor
	// Bottom is the place of the page's last row, where the next page down
	// starts; nil when the page is empty and was not itself a Before read.
	Bottom *HistoryPlace
	// More reports rows below Bottom.
	More bool
	// Gap is set on an After read that found more than Limit new rows: the
	// page is the newest page instead, and those rows were not all returned.
	Gap bool
}

// History reads one page of the journal.
//
// Every read is a seek and a LIMIT query per table, on the julianday index for
// a page down and on the primary key for a read of what is new, so its cost
// follows the page size rather than the journal's length. An Offset read also
// walks the index entries it skips.
func (d *DB) History(q HistoryQuery) (HistoryPage, error) {
	if q.Limit <= 0 {
		return HistoryPage{}, fmt.Errorf("history: limit must be positive, got %d", q.Limit)
	}
	if q.Before != nil && q.After != nil {
		return HistoryPage{}, errors.New("history: Before and After are exclusive")
	}
	if q.Offset < 0 || (q.Offset > 0 && (q.Before != nil || q.After != nil)) {
		return HistoryPage{}, errors.New("history: Offset is for positional reads only")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		page HistoryPage
		err  error
	)
	switch {
	case q.After != nil:
		page, err = d.historyAfter(*q.After, q.Limit)
	case q.Before != nil:
		page, err = d.historyBelow(q.Before, q.Limit)
	case q.Offset > 0:
		page, err = d.historyOffset(q.Offset, q.Limit)
	default:
		page, err = d.historyNewest(q.Limit)
	}
	if err != nil {
		return HistoryPage{}, err
	}
	if q.MaxValue > 0 {
		for i := range page.Rows {
			page.Rows[i].shorten(q.MaxValue)
		}
	}
	return page, nil
}

// HistoryTop returns the newest step and event written.
func (d *DB) HistoryTop() (HistoryCursor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.historyTop()
}

// HistoryStep returns step n whole, or nil when there is no such step.
func (d *DB) HistoryStep(n int64) (*StepRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.historySteps(`WHERE step = ?`, []any{n}, 1)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0].Step, nil
}

// HistoryEvent returns event id whole, or nil when there is no such event.
func (d *DB) HistoryEvent(id int64) (*EventRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.historyEvents(`WHERE id = ?`, []any{id}, 1)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0].Event, nil
}

// The feed's order key for each table, exactly as migration 0059 indexes it:
// a query that spells it any other way is not answered from the index.
const (
	stepDay  = `IFNULL(julianday(time), 0)`
	eventDay = `IFNULL(julianday(timestamp), 0)`

	stepColumns  = `SELECT step, task, output, exit_code, duration, time, ` + stepDay + ` FROM steps `
	eventColumns = `SELECT id, timestamp, type, task_id, task_title, step, message, details, ` + eventDay + ` FROM events `
)

// historyNewest is the first page. Top is read before the rows: a row written
// in between is then at most read twice — on this page and again past Top —
// which the reader recognises, rather than counted as seen and never read.
func (d *DB) historyNewest(limit int) (HistoryPage, error) {
	top, err := d.historyTop()
	if err != nil {
		return HistoryPage{}, err
	}
	page, err := d.historyBelow(nil, limit)
	page.Top = top
	return page, err
}

// historyBelow reads the limit rows listed after p, or the newest limit rows
// when p is nil.
func (d *DB) historyBelow(p *HistoryPlace, limit int) (HistoryPage, error) {
	stepTail, eventTail := historyBelowTails(p != nil)
	var stepArgs, eventArgs []any
	if p != nil {
		stepKey, eventKey := p.Key, p.Key
		if p.Event {
			stepKey = math.MaxInt64 // every step at p's instant lists below an event
		} else {
			eventKey = 0 // no event at p's instant lists below a step
		}
		stepArgs, eventArgs = []any{p.Day, stepKey}, []any{p.Day, eventKey}
	}
	// One row more than a page from each table: whatever the merge leaves
	// says whether there is more below.
	steps, err := d.historySteps(stepTail, stepArgs, limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	events, err := d.historyEvents(eventTail, eventArgs, limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	rows, used := mergeHistory(steps, events, limit)
	page := HistoryPage{Rows: rows, Bottom: p, More: used < len(steps)+len(events)}
	if len(rows) > 0 {
		last := rows[len(rows)-1].Place
		page.Bottom = &last
	}
	return page, nil
}

// historyBelowTails are the WHERE and ORDER BY of a page down: all rows in
// feed order, or (bounded) those after a place given as ?1 (its day) and ?2
// (the key below which rows at exactly that day still list after it).
//
// Below a place means an earlier instant, or the same instant and listed
// after it. The range on the indexed day is what SQLite seeks on; the rest
// only sorts out rows at exactly that instant. A row-value comparison reads the
// same and makes SQLite scan the index from the top instead, which
// TestHistory_PagesSeekTheIndex holds it to.
func historyBelowTails(bounded bool) (stepTail, eventTail string) {
	stepTail = `ORDER BY ` + stepDay + ` DESC, step DESC`
	eventTail = `ORDER BY ` + eventDay + ` DESC, id DESC`
	if bounded {
		stepTail = `WHERE ` + stepDay + ` <= ?1 AND (` + stepDay + ` < ?1 OR step < ?2) ` + stepTail
		eventTail = `WHERE ` + eventDay + ` <= ?1 AND (` + eventDay + ` < ?1 OR id < ?2) ` + eventTail
	}
	return stepTail, eventTail
}

// historyAfter reads every row written since c, or the newest page if there
// are more than limit of them.
func (d *DB) historyAfter(c HistoryCursor, limit int) (HistoryPage, error) {
	top, err := d.historyTop()
	if err != nil {
		return HistoryPage{}, err
	}
	// A cursor beyond what the journal holds was handed out for rows that are
	// gone — the database was replaced and its numbering restarted. Rows
	// written since are numbered at or below it, so no read past it would
	// ever return them: start over from the newest page.
	if c.Step > top.Step || c.Event > top.Event {
		return d.gapPage(limit)
	}
	steps, err := d.historySteps(`WHERE step > ? ORDER BY step DESC`, []any{c.Step}, limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	events, err := d.historyEvents(`WHERE id > ? ORDER BY id DESC`, []any{c.Event}, limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	if len(steps)+len(events) > limit {
		return d.gapPage(limit)
	}
	page := HistoryPage{Top: c}
	if len(steps) > 0 {
		page.Top.Step = int64(steps[0].Step.Step)
	}
	if len(events) > 0 {
		page.Top.Event = events[0].Event.ID
	}
	// Read in write order, listed in feed order.
	page.Rows = append(steps, events...)
	sort.Slice(page.Rows, func(i, j int) bool { return page.Rows[j].Place.after(page.Rows[i].Place) })
	return page, nil
}

// gapPage is the newest page, marked as not continuing the caller's cursor.
func (d *DB) gapPage(limit int) (HistoryPage, error) {
	page, err := d.historyNewest(limit)
	page.Gap = err == nil
	return page, err
}

// historyOffset is historyBelow from the place offset rows down.
func (d *DB) historyOffset(offset, limit int) (HistoryPage, error) {
	top, err := d.historyTop()
	if err != nil {
		return HistoryPage{}, err
	}
	// Index entries only: which rows the offset skips depends on their places
	// and nothing else, and the index holds those without the rows' outputs.
	steps, err := d.historyPlaces(`SELECT step, `+stepDay+` FROM steps ORDER BY `+stepDay+` DESC, step DESC LIMIT ?`, false, offset)
	if err != nil {
		return HistoryPage{}, err
	}
	events, err := d.historyPlaces(`SELECT id, `+eventDay+` FROM events ORDER BY `+eventDay+` DESC, id DESC LIMIT ?`, true, offset)
	if err != nil {
		return HistoryPage{}, err
	}
	// The offset-th place in feed order, merged as mergeHistory does.
	var last *HistoryPlace
	for i, j, n := 0, 0, 0; n < offset && (i < len(steps) || j < len(events)); n++ {
		if j == len(events) || (i < len(steps) && events[j].after(steps[i])) {
			last = &steps[i]
			i++
		} else {
			last = &events[j]
			j++
		}
	}
	if last == nil {
		return HistoryPage{Top: top}, nil
	}
	page, err := d.historyBelow(last, limit)
	page.Top = top
	return page, err
}

// historyTop reads the newest step number and event id. Both are MAX over a
// rowid, which SQLite answers from the end of the table without a scan.
func (d *DB) historyTop() (HistoryCursor, error) {
	var c HistoryCursor
	if err := d.conn.QueryRow(`SELECT IFNULL(MAX(step), -1) FROM steps`).Scan(&c.Step); err != nil {
		return c, fmt.Errorf("history: newest step: %w", classifyDriverErr(err))
	}
	if err := d.conn.QueryRow(`SELECT IFNULL(MAX(id), 0) FROM events`).Scan(&c.Event); err != nil {
		return c, fmt.Errorf("history: newest event: %w", classifyDriverErr(err))
	}
	return c, nil
}

// historySteps reads steps; tail is the WHERE and ORDER BY, args its
// parameters.
func (d *DB) historySteps(tail string, args []any, limit int) ([]HistoryRow, error) {
	q, err := d.conn.Query(stepColumns+tail+` LIMIT `+fmt.Sprint(limit), args...)
	if err != nil {
		return nil, fmt.Errorf("history: read steps: %w", classifyDriverErr(err))
	}
	defer q.Close()
	var out []HistoryRow
	for q.Next() {
		var (
			r  StepRow
			ts string
			p  HistoryPlace
		)
		if err := q.Scan(&r.Step, &r.Task, &r.Output, &r.ExitCode, &r.Duration, &ts, &p.Day); err != nil {
			return nil, fmt.Errorf("history: read steps: %w", classifyDriverErr(err))
		}
		// An unreadable time reads as the zero time, as loadSteps has it.
		r.Time, _ = time.Parse(time.RFC3339Nano, ts)
		p.Key = int64(r.Step)
		out = append(out, HistoryRow{Step: &r, Place: p})
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("history: read steps: %w", classifyDriverErr(err))
	}
	return out, nil
}

// historyEvents is historySteps for the events table.
func (d *DB) historyEvents(tail string, args []any, limit int) ([]HistoryRow, error) {
	q, err := d.conn.Query(eventColumns+tail+` LIMIT `+fmt.Sprint(limit), args...)
	if err != nil {
		return nil, fmt.Errorf("history: read events: %w", classifyDriverErr(err))
	}
	defer q.Close()
	var out []HistoryRow
	for q.Next() {
		var (
			r       EventRow
			ts, typ string
			p       = HistoryPlace{Event: true}
		)
		if err := q.Scan(&r.ID, &ts, &typ, &r.TaskID, &r.TaskTitle, &r.Step, &r.Message, &r.Details, &p.Day); err != nil {
			return nil, fmt.Errorf("history: read events: %w", classifyDriverErr(err))
		}
		r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		r.Type = EventType(typ)
		p.Key = r.ID
		out = append(out, HistoryRow{Event: &r, Place: p})
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("history: read events: %w", classifyDriverErr(err))
	}
	return out, nil
}

// historyPlaces reads the places of a table's rows, in feed order.
func (d *DB) historyPlaces(query string, event bool, limit int) ([]HistoryPlace, error) {
	q, err := d.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("history: read places: %w", classifyDriverErr(err))
	}
	defer q.Close()
	var out []HistoryPlace
	for q.Next() {
		p := HistoryPlace{Event: event}
		if err := q.Scan(&p.Key, &p.Day); err != nil {
			return nil, fmt.Errorf("history: read places: %w", classifyDriverErr(err))
		}
		out = append(out, p)
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("history: read places: %w", classifyDriverErr(err))
	}
	return out, nil
}

// mergeHistory interleaves two lists already in feed order into at most n
// rows, and reports how many rows it used.
func mergeHistory(steps, events []HistoryRow, n int) ([]HistoryRow, int) {
	rows := make([]HistoryRow, 0, min(n, len(steps)+len(events)))
	i, j := 0, 0
	for len(rows) < n && (i < len(steps) || j < len(events)) {
		if j == len(events) || (i < len(steps) && events[j].Place.after(steps[i].Place)) {
			rows = append(rows, steps[i])
			i++
		} else {
			rows = append(rows, events[j])
			j++
		}
	}
	return rows, i + j
}

// shorten cuts the row's one large value to max bytes. The page holds its
// own copies of the rows, so this changes nothing in the database.
func (r *HistoryRow) shorten(max int) {
	switch {
	case r.Step != nil && len(r.Step.Output) > max:
		r.Cut = len(r.Step.Output)
		cut := max
		// Back up to the start of a character rather than splitting one.
		for cut > 0 && !utf8.RuneStart(r.Step.Output[cut]) {
			cut--
		}
		r.Step.Output = r.Step.Output[:cut]
	case r.Event != nil && len(r.Event.Details) > max:
		r.Cut = len(r.Event.Details)
		r.Event.Details = ""
	}
}
