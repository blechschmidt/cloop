package approvalnotify

// The leader's loop: scan, record, deliver.
//
// One pass reads the webhooks in force, finds the notices the control plane's
// rows support (Scan), records each under its unique key, and hands every
// webhook the notices after its cursor, oldest first. A pass runs on a timer —
// reminders and lapses are moments nobody announces — and whenever the hub
// nudges it because something just changed, so a request filed in the
// dashboard is in the channel within a second or two rather than a poll later.
//
// Delivery is at least once per webhook: a cursor moves only after the
// receiver acknowledged the notice, or the notice was given up on. A receiver
// that is down is retried with a growing backoff, notices behind the failed
// one wait their turn, and after maxAttempts — or once a notice is a day old —
// it is dropped, counted, and the webhook moves on: a channel that comes back
// after a weekend does not need Friday's reminders.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Delivery outcomes, the `outcome` label of cloop_approval_notifications_total.
const (
	OutcomeDelivered  = hubmetrics.ApprovalNotifyDelivered
	OutcomeFailed     = hubmetrics.ApprovalNotifyFailed
	OutcomeDropped    = hubmetrics.ApprovalNotifyDropped
	OutcomeSuperseded = hubmetrics.ApprovalNotifySuperseded
)

const (
	// DefaultPoll is how often a pass runs with nothing nudging it.
	DefaultPoll = 30 * time.Second

	// maxAttempts is how many failed sends one notice gets before it is
	// dropped.
	maxAttempts = 8

	// maxNoticeAge drops a notice that has waited this long to be delivered.
	maxNoticeAge = 24 * time.Hour

	// retainNotices is how long a delivered notice is kept in the outbox:
	// longer than a request may wait (secretbroker.MaxRequestTTL, 30 days).
	// A notice about something still waiting is kept however old — its row is
	// what stops a new leader announcing it again.
	retainNotices = 45 * 24 * time.Hour

	// forgetRemovedAfter is how long the cursor of a webhook the leader does
	// not configure is kept: members serving one control plane under
	// different overlays hand the lead back and forth, and a cursor dropped
	// on every change would start over at the newest notice each time,
	// skipping whatever was recorded in between. A webhook removed in
	// Settings is forgotten at once.
	forgetRemovedAfter = maxNoticeAge

	// scanSkew widens the window decisions are picked up from: a decision
	// stamped by another member's clock, a little behind the leader's, is
	// still found.
	scanSkew = 2 * time.Minute

	// batch is how many notices one webhook is handed per pass.
	batch = 25

	// watermarkKey records, in the control plane, the time of the last
	// completed scan: where the next leader picks up decisions from.
	watermarkKey = "approvals.notify.scanned_through"

	// watermarkEvery is how stale the stored watermark may grow before a pass
	// writes it again. Decisions are looked for from the stored value, so a
	// pass between writes only looks a little further back — and finds what
	// it already recorded — rather than writing to the control plane every
	// poll.
	watermarkEvery = 5 * time.Minute
)

// Settings is what one pass runs under.
type Settings struct {
	// Webhooks are the destinations in force, already validated.
	Webhooks []config.NotificationWebhook
	// Link is the dashboard address a message points at; empty for none.
	Link string
}

// Options wires the engine to the hub.
type Options struct {
	// OpenDB opens the control plane's database; the engine closes it.
	OpenDB func() (*statedb.DB, error)
	// Settings reads the configuration in force, per pass.
	Settings func() (Settings, error)
	// Snapshot reads the requests and the waiting tokens.
	Snapshot func(ctx context.Context) (Snapshot, error)
	// LookupEnv reads a webhook's url_env; nil means os.LookupEnv.
	LookupEnv func(name string) (string, bool)
	// Record counts one delivery outcome (hubmetrics).
	Record func(sink, event, outcome string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Poll is how often a pass runs; zero means DefaultPoll.
	Poll time.Duration
	// Nudge wakes the loop for a pass now.
	Nudge <-chan struct{}
	// OnRecorded is told, once per pass, of the notices that pass recorded
	// for the first time: how the hub announces a lapse, a waiting token or
	// a change made outside its handlers to its dashboards.
	OnRecorded func([]Notice)
	// Logf reports what the operator should know.
	Logf func(format string, args ...any)
}

// Engine is the notifier.
type Engine struct {
	opts   Options
	passes int
	// recorded holds the keys this engine has seen stored, so a waiting
	// request found again on every pass costs no write: an INSERT that
	// conflicts still takes the database's write lock. Bounded by
	// maxRecordedKeys: past it the cache starts again, and the outbox's
	// unique key keeps the next pass from recording anything twice.
	recorded map[string]bool
}

// maxRecordedKeys bounds the engine's cache of recorded keys over a long
// leadership.
const maxRecordedKeys = 4096

// New returns an engine.
func New(opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Poll <= 0 {
		opts.Poll = DefaultPoll
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Record == nil {
		opts.Record = func(string, string, string) {}
	}
	return &Engine{opts: opts, recorded: map[string]bool{}}
}

// Run passes until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.opts.Poll)
	defer t.Stop()
	e.safePass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.opts.Nudge:
			// Coalesce a burst: a decision broadcast by a handler and the
			// same change seen by the bus arrive together.
			drain(e.opts.Nudge, 200*time.Millisecond)
		}
		if ctx.Err() != nil {
			return
		}
		e.safePass(ctx)
	}
}

func drain(ch <-chan struct{}, wait time.Duration) {
	if ch == nil {
		return
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		select {
		case <-ch:
		case <-deadline.C:
			return
		}
	}
}

func (e *Engine) safePass(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			e.opts.Logf("a pass panicked: %v", r)
		}
	}()
	if err := e.Pass(ctx); err != nil && ctx.Err() == nil {
		e.opts.Logf("%v", err)
	}
}

// Pass runs one scan-record-deliver round.
//
// The scan runs whether or not a webhook is configured: what it records is
// also what the hub announces to dashboards (OnRecorded) — a request lapsing,
// a token starting to wait — which nothing else observes as it happens. A
// webhook configured later starts at the newest notice, so the outbox it
// inherits is not replayed into its channel.
func (e *Engine) Pass(ctx context.Context) error {
	settings, settingsErr := e.opts.Settings()
	db, err := e.opts.OpenDB()
	if err != nil {
		return fmt.Errorf("open the control plane: %w", err)
	}
	defer db.Close()
	now := e.opts.Now()
	e.passes++

	// Unreadable settings are not "no webhooks": syncing to an empty list
	// would forget every webhook's position.
	if settingsErr == nil {
		if err := e.syncCursors(db, settings.Webhooks, now); err != nil {
			return err
		}
	}

	since, stored := now, false
	if raw, ok, merr := db.HubMeta(watermarkKey); merr == nil && ok {
		if t, perr := time.Parse(time.RFC3339Nano, raw); perr == nil && t.Before(now) {
			since, stored = t, true
		}
	}
	mark := func() {
		if !stored || now.Sub(since) >= watermarkEvery {
			_ = db.SetHubMeta(watermarkKey, formatMark(now))
		}
	}
	snap, snapErr := e.opts.Snapshot(ctx)
	// waiting are the keys of notices about what still waits: kept by the
	// prune however old. Nil when the snapshot failed, which skips the prune.
	var waiting map[string]bool
	if snapErr != nil {
		e.opts.Logf("read requests and tokens: %v", snapErr)
	} else {
		recorded := true
		var fresh []Notice
		if len(e.recorded) > maxRecordedKeys {
			clear(e.recorded)
		}
		waiting = map[string]bool{}
		for _, n := range Scan(snap, since.Add(-scanSkew), now) {
			key := n.Key()
			switch n.Event {
			case config.NotifyEventRequestFiled, config.NotifyEventRequestReminder, config.NotifyEventTokenWaiting:
				waiting[key] = true
			}
			if e.recorded[key] {
				continue
			}
			payload, merr := json.Marshal(n)
			if merr != nil {
				continue
			}
			inserted, ierr := db.InsertApprovalNotice(key, n.Event, string(payload), now)
			if ierr != nil {
				recorded = false
				e.opts.Logf("record notice %s: %v", key, ierr)
				continue
			}
			e.recorded[key] = true
			if inserted {
				fresh = append(fresh, n)
			}
		}
		// Only a scan whose notices are all recorded moves the watermark, so
		// a failed write is picked up again by the next pass.
		if recorded {
			mark()
		}
		if len(fresh) > 0 && e.opts.OnRecorded != nil {
			e.opts.OnRecorded(fresh)
		}
	}

	if settingsErr != nil {
		e.prune(db, now, nil, waiting)
		return fmt.Errorf("read notifications settings: %w", settingsErr)
	}
	live := map[string]bool{}
	for _, w := range settings.Webhooks {
		live[w.Name] = true
	}
	for _, w := range settings.Webhooks {
		if ctx.Err() != nil {
			return nil
		}
		e.deliver(ctx, db, w, snap, snapErr == nil, settings.Link, now)
	}
	e.prune(db, now, live, waiting)
	return nil
}

func formatMark(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// syncCursors gives every webhook a cursor: a new one starts at the newest
// notice. A cursor without a webhook is left to prune (forgetRemovedAfter).
func (e *Engine) syncCursors(db *statedb.DB, hooks []config.NotificationWebhook, now time.Time) error {
	cursors, err := db.ApprovalNotifyCursors()
	if err != nil {
		return fmt.Errorf("list webhook cursors: %w", err)
	}
	have := map[string]bool{}
	for _, c := range cursors {
		have[c.Sink] = true
	}
	var head int64 = -1
	for _, w := range hooks {
		if have[w.Name] {
			continue
		}
		if head < 0 {
			if head, err = db.MaxApprovalNoticeID(); err != nil {
				return fmt.Errorf("find the newest notice: %w", err)
			}
		}
		if _, err := db.InitApprovalNotifyCursor(w.Name, head, now); err != nil {
			return fmt.Errorf("start webhook %s: %w", w.Name, err)
		}
	}
	return nil
}

// backoff is how long to wait after the n-th failed send of a notice.
func backoff(n int64) time.Duration {
	d := 30 * time.Second
	for i := int64(1); i < n && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// sender posts one webhook's messages, built on first use in a pass.
type sender struct {
	client *Client
	url    string
	err    error
}

func (e *Engine) newSender(w config.NotificationWebhook) sender {
	url := strings.TrimSpace(w.URL)
	if name := strings.TrimSpace(w.URLEnv); name != "" {
		lookup := e.opts.LookupEnv
		if lookup == nil {
			lookup = os.LookupEnv
		}
		v, ok := lookup(name)
		if !ok || strings.TrimSpace(v) == "" {
			return sender{err: &SendError{Err: fmt.Errorf("url_env %s is not set in this hub's environment", name)}}
		}
		url = strings.TrimSpace(v)
	}
	if err := config.ValidateWebhookURL(url); err != nil {
		return sender{err: err}
	}
	client, err := NewClient(w.AllowedPrefixes(), w.CAFile, w.EffectiveTimeout())
	if err != nil {
		return sender{err: err}
	}
	return sender{client: client, url: url}
}

// deliver hands one webhook the notices after its cursor.
func (e *Engine) deliver(ctx context.Context, db *statedb.DB, w config.NotificationWebhook, snap Snapshot,
	snapOK bool, link string, now time.Time) {
	cur, ok, err := db.ApprovalNotifyCursorFor(w.Name)
	if err != nil || !ok {
		return
	}
	// Hourly, so a configured webhook with nothing to send is never taken
	// for one the configuration dropped (forgetRemovedAfter).
	if now.Sub(cur.UpdatedAt) > time.Hour {
		if err := db.TouchApprovalNotifyCursor(w.Name, now); err != nil {
			e.opts.Logf("webhook %s: touch: %v", w.Name, err)
		}
	}
	if cur.Failures > 0 && now.Before(cur.NextAttemptAt) {
		return
	}
	notices, err := db.ApprovalNoticesAfter(cur.AckedID, batch)
	if err != nil {
		e.opts.Logf("webhook %s: list notices: %v", w.Name, err)
		return
	}
	var s *sender
	for _, rec := range notices {
		if ctx.Err() != nil {
			return
		}
		adv := statedb.ApprovalNotifyAdvance{From: cur.AckedID, To: rec.ID, At: now}
		var n Notice
		decodeErr := json.Unmarshal([]byte(rec.Payload), &n)
		switch {
		case decodeErr != nil:
			adv.Dropped, adv.Error = true, "the notice could not be read: "+decodeErr.Error()
			e.opts.Record(w.Name, rec.Event, OutcomeDropped)
		case !w.Wants(rec.Event):
			// Not this webhook's event: step over it, counting nothing.
		case snapOK && Superseded(n, snap, now):
			e.opts.Record(w.Name, rec.Event, OutcomeSuperseded)
		case now.Sub(rec.CreatedAt) > maxNoticeAge:
			adv.Dropped, adv.Error = true, "undelivered for a day; dropped as stale"
			e.opts.Record(w.Name, rec.Event, OutcomeDropped)
		default:
			if s == nil {
				built := e.newSender(w)
				s = &built
			}
			err := s.err
			if err == nil {
				var body []byte
				if body, err = Render(w.Type, n, link, now); err == nil {
					sendCtx, cancel := context.WithTimeout(ctx, w.EffectiveTimeout()+5*time.Second)
					err = s.client.Post(sendCtx, s.url, body)
					cancel()
				}
			}
			if err == nil {
				adv.Delivered = true
				e.opts.Record(w.Name, rec.Event, OutcomeDelivered)
				break
			}
			e.opts.Record(w.Name, rec.Event, OutcomeFailed)
			msg := err.Error()
			if !IsPermanent(err) && cur.Failures+1 < maxAttempts {
				next := now.Add(backoff(cur.Failures + 1))
				if nerr := db.NoteApprovalNotifyFailure(w.Name, cur.AckedID, msg, next, now); nerr != nil {
					e.opts.Logf("webhook %s: note failure: %v", w.Name, nerr)
				}
				e.opts.Logf("webhook %s: %s %s not delivered, retrying after %s: %s",
					w.Name, rec.Event, rec.Key, next.Sub(now).Round(time.Second), msg)
				return
			}
			adv.Dropped, adv.Error = true, msg
			e.opts.Record(w.Name, rec.Event, OutcomeDropped)
			e.opts.Logf("webhook %s: %s %s dropped: %s", w.Name, rec.Event, rec.Key, msg)
		}
		if err := db.AdvanceApprovalNotifyCursor(w.Name, adv); err != nil {
			// Another leader moved it: this one's view is stale.
			if !errors.Is(err, statedb.ErrApprovalNotifyCursorMoved) {
				e.opts.Logf("webhook %s: advance: %v", w.Name, err)
			}
			return
		}
		cur.AckedID, cur.Failures = rec.ID, 0
	}
}

// prune deletes delivered notices past retention, and forgets the cursors of
// webhooks long gone from the configuration, about once an hour.
//
// live names the webhooks in force — nil when the settings could not be read,
// which forgets no cursor — and waiting the notices about what still waits —
// nil when the snapshot could not be read, which prunes no notice.
func (e *Engine) prune(db *statedb.DB, now time.Time, live, waiting map[string]bool) {
	if e.passes%120 != 1 {
		return
	}
	cursors, err := db.ApprovalNotifyCursors()
	if err != nil {
		return
	}
	floor, err := db.MaxApprovalNoticeID()
	if err != nil {
		return
	}
	for _, c := range cursors {
		if live != nil && !live[c.Sink] && now.Sub(c.UpdatedAt) > forgetRemovedAfter {
			if err := db.DeleteApprovalNotifyCursor(c.Sink); err != nil {
				e.opts.Logf("forget removed webhook %s: %v", c.Sink, err)
			} else {
				continue
			}
		}
		if c.AckedID < floor {
			floor = c.AckedID
		}
	}
	if waiting == nil {
		return
	}
	if _, err := db.PruneApprovalNotices(now.Add(-retainNotices), floor, waiting); err != nil {
		e.opts.Logf("prune notices: %v", err)
	}
}

// Test sends one test message to a webhook, outside the outbox: the Settings
// panel's check that a URL works before anything depends on it.
func Test(ctx context.Context, w config.NotificationWebhook, link string, now time.Time) error {
	e := New(Options{})
	s := e.newSender(w)
	if s.err != nil {
		return s.err
	}
	body, err := Render(w.Type, Notice{Event: EventTest, At: now}, link, now)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, w.EffectiveTimeout()+5*time.Second)
	defer cancel()
	return s.client.Post(ctx, s.url, body)
}
