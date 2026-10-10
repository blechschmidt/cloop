package statedb

// Audit append failures, counted where they happen (Task 20404).
//
// A hash chain cannot see a row that was never appended: the next append links
// to the last one that succeeded, and `cloop hub audit verify` reports an
// intact chain over a trail with holes in it. Until this file the only trace of
// a failed append was whatever its caller chose to do with the error — one
// helper printed the first failure and suppressed every later one for the life
// of the process, and several call sites discarded the error outright. On a
// hub whose disk had reached 98%, that is a trail that lies by omission.
//
// So the accounting lives inside the append path, where no caller can opt out
// of it, and it is the only work done there: a few counters under one short
// lock, a metric and a non-blocking wake-up. Everything slower — stderr, the
// status file, retrying — belongs to one background reporter that exists only
// while something is owed.
//
// What is owed is paid back into the chain itself. The next append on the same
// database that succeeds carries, ahead of its own events and in the same
// transaction, one audit.gap row saying how many events were lost, of which
// actions, when and why; the reporter writes one on its own if nothing else
// succeeds first. The gap row is hash-chained like any other, so the record of
// the loss is as tamper-evident as the events would have been, and the verifier
// can tell "intact" from "intact, with N recorded gaps covering M events".
//
// Two rules keep that from turning on itself. A gap row's own failure is not a
// loss — the claim goes back to what is owed and counting carries on, so a
// database that stays broken does not breed gap rows about gap rows. And the
// account is kept per database file rather than per handle or per process-wide
// total, because the control plane and every project are separate chains, and
// a loss must be recorded in the chain it is a loss of.
//
// The in-transaction writers (offboard.go, projectmembers.go) are deliberately
// outside this: their audit rows commit atomically with the mutation they
// describe, so a failed append there is a failed mutation, not a lost record.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// auditFlushInterval is how often the reporter tries to record what is owed on
// its own, when no append on that chain has succeeded since. Variables rather
// than constants so tests can shorten them.
var auditFlushInterval = 30 * time.Second

// auditReportInterval bounds how often one chain's continuing failures are
// summarised on stderr. The first failure is reported at once.
var auditReportInterval = time.Minute

// auditReportOut is where the reporter writes. Guarded by auditFailures.mu.
var auditReportOut io.Writer = os.Stderr

// auditLossMaxActions bounds the per-action histogram one loss carries. The
// action vocabulary is closed (pkg/auditaction), but an unregistered name can
// still reach the append path, and a gap row must not grow with it.
const auditLossMaxActions = 64

// auditLossOtherAction is the histogram bucket past auditLossMaxActions.
const auditLossOtherAction = "(other)"

// auditLossMaxPIDs bounds how many processes one loss names.
const auditLossMaxPIDs = 16

// auditErrorMax truncates the error text a loss keeps.
const auditErrorMax = 300

// How a gap row came to be written, recorded in its payload.
const (
	// GapRecordedOnRecovery: ahead of the next append that succeeded.
	GapRecordedOnRecovery = "recovery"
	// GapRecordedByFlush: by the background reporter, on its own.
	GapRecordedByFlush = "flush"
	// GapRecordedAtShutdown: by a hub shutting down cleanly.
	GapRecordedAtShutdown = "shutdown"
	// GapRecordedAtExit: by a CLI command finishing.
	GapRecordedAtExit = "exit"
)

// AuditLoss describes audit events that could not be appended to one chain.
type AuditLoss struct {
	// Events is how many audit rows were lost; Appends how many append calls
	// failed (a batch is one call).
	Events  int64 `json:"events"`
	Appends int64 `json:"appends"`

	FirstAt    time.Time `json:"first_at"`
	LastAt     time.Time `json:"last_at"`
	FirstError string    `json:"first_error,omitempty"`
	LastError  string    `json:"last_error,omitempty"`

	// Actions counts the lost events by action name, Reasons by failure class
	// (the hubmetrics.AuditFail* values).
	Actions map[string]int64 `json:"actions,omitempty"`
	Reasons map[string]int64 `json:"reasons,omitempty"`

	// PIDs names the processes whose failures these are: this one, and any
	// whose losses it adopted. AdoptedFrom names the second kind: processes
	// that exited without recording what they lost.
	PIDs        []int `json:"pids,omitempty"`
	AdoptedFrom []int `json:"adopted_from,omitempty"`
}

// Empty reports whether nothing is described.
func (l AuditLoss) Empty() bool { return l.Events == 0 }

// add counts one failed append of evs.
func (l *AuditLoss) add(evs []*AuditEvent, reason, msg string, at time.Time) {
	n := int64(len(evs))
	if l.Events == 0 {
		l.FirstAt, l.FirstError = at, msg
	}
	l.Events += n
	l.Appends++
	l.LastAt, l.LastError = at, msg
	if l.Actions == nil {
		l.Actions = map[string]int64{}
	}
	for _, ev := range evs {
		name := auditLossOtherAction
		if ev != nil && ev.EventType != "" {
			name = ev.EventType
		}
		l.countAction(name, 1)
	}
	if l.Reasons == nil {
		l.Reasons = map[string]int64{}
	}
	l.Reasons[reason] += n
	l.addPID(os.Getpid())
}

func (l *AuditLoss) countAction(name string, n int64) {
	if _, seen := l.Actions[name]; !seen && len(l.Actions) >= auditLossMaxActions {
		name = auditLossOtherAction
	}
	l.Actions[name] += n
}

func (l *AuditLoss) addPID(pid int) { l.PIDs = addPIDTo(l.PIDs, pid) }

// addPIDTo appends pid to pids once, up to auditLossMaxPIDs.
func addPIDTo(pids []int, pid int) []int {
	for _, p := range pids {
		if p == pid {
			return pids
		}
	}
	if len(pids) < auditLossMaxPIDs {
		pids = append(pids, pid)
	}
	return pids
}

// merge folds o into l, keeping the earliest first failure and the latest last.
func (l *AuditLoss) merge(o AuditLoss) {
	if o.Events == 0 {
		return
	}
	if l.Events == 0 || (!o.FirstAt.IsZero() && o.FirstAt.Before(l.FirstAt)) {
		l.FirstAt, l.FirstError = o.FirstAt, o.FirstError
	}
	if o.LastAt.After(l.LastAt) {
		l.LastAt, l.LastError = o.LastAt, o.LastError
	}
	l.Events += o.Events
	l.Appends += o.Appends
	if len(o.Actions) > 0 && l.Actions == nil {
		l.Actions = map[string]int64{}
	}
	for k, v := range o.Actions {
		l.countAction(k, v)
	}
	if len(o.Reasons) > 0 && l.Reasons == nil {
		l.Reasons = map[string]int64{}
	}
	for k, v := range o.Reasons {
		l.Reasons[k] += v
	}
	for _, p := range o.PIDs {
		l.addPID(p)
	}
	for _, p := range o.AdoptedFrom {
		l.AdoptedFrom = addPIDTo(l.AdoptedFrom, p)
	}
}

// clone returns a copy sharing no maps with l.
func (l AuditLoss) clone() AuditLoss {
	out := l
	out.Actions, out.Reasons, out.PIDs, out.AdoptedFrom = nil, nil, nil, nil
	if len(l.Actions) > 0 {
		out.Actions = make(map[string]int64, len(l.Actions))
		for k, v := range l.Actions {
			out.Actions[k] = v
		}
	}
	if len(l.Reasons) > 0 {
		out.Reasons = make(map[string]int64, len(l.Reasons))
		for k, v := range l.Reasons {
			out.Reasons[k] = v
		}
	}
	out.PIDs = append([]int(nil), l.PIDs...)
	out.AdoptedFrom = append([]int(nil), l.AdoptedFrom...)
	return out
}

// topActions renders the most frequent actions, for a one-line summary.
func (l AuditLoss) topActions(n int) string {
	type kv struct {
		k string
		v int64
	}
	var all []kv
	for k, v := range l.Actions {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	var parts []string
	for i, e := range all {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(all)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

// AuditGapPayload is what an audit.gap row's payload holds. VerifyAuditChain
// reads LostEvents back to say how many events a chain's gaps cover.
//
// The histograms are lists of {name, events}, not maps keyed by action. Every
// payload passes through key-based redaction (MarshalAuditPayload), and an
// action such as `secret.lease` or `api_token.created` is exactly the kind of
// key it withholds — as a map key its count would be replaced with a marker,
// for the very actions an auditor most needs counted.
type AuditGapPayload struct {
	LostEvents    int64           `json:"lost_events"`
	FailedAppends int64           `json:"failed_appends"`
	FirstFailedAt string          `json:"first_failed_at"`
	LastFailedAt  string          `json:"last_failed_at"`
	FirstError    string          `json:"first_error,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	Actions       []AuditGapCount `json:"actions,omitempty"`
	Reasons       []AuditGapCount `json:"reasons,omitempty"`
	Recorded      string          `json:"recorded"`
	Host          string          `json:"host,omitempty"`
	PIDs          []int           `json:"pids,omitempty"`
	AdoptedFrom   []int           `json:"adopted_from,omitempty"`
}

// AuditGapCount is one line of a gap row's histogram.
type AuditGapCount struct {
	Name   string `json:"name"`
	Events int64  `json:"events"`
}

// gapCounts renders a histogram as a list, most events first.
func gapCounts(m map[string]int64) []AuditGapCount {
	out := make([]AuditGapCount, 0, len(m))
	for k, v := range m {
		out = append(out, AuditGapCount{Name: k, Events: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// AuditGapLostEvents reads how many events a gap row's payload records as
// lost, ignoring every other field: a reader that wants only the count must
// not lose it to a field of a shape it does not expect.
func AuditGapLostEvents(payload string) int64 {
	var p struct {
		LostEvents int64 `json:"lost_events"`
	}
	_ = json.Unmarshal([]byte(payload), &p)
	if p.LostEvents < 0 {
		return 0
	}
	return p.LostEvents
}

// gapEvent builds the row that records loss in its chain.
func gapEvent(loss AuditLoss, recorded string) *AuditEvent {
	host, _ := os.Hostname()
	return &AuditEvent{
		Actor:      "system",
		EventType:  string(auditaction.ActionAuditGap),
		EntityType: "audit",
		Payload: MarshalAuditPayload(AuditGapPayload{
			LostEvents:    loss.Events,
			FailedAppends: loss.Appends,
			FirstFailedAt: loss.FirstAt.UTC().Format(time.RFC3339Nano),
			LastFailedAt:  loss.LastAt.UTC().Format(time.RFC3339Nano),
			FirstError:    loss.FirstError,
			LastError:     loss.LastError,
			Actions:       gapCounts(loss.Actions),
			Reasons:       gapCounts(loss.Reasons),
			Recorded:      recorded,
			Host:          host,
			PIDs:          loss.PIDs,
			AdoptedFrom:   loss.AdoptedFrom,
		}),
	}
}

// classifyAuditFailure maps an append error onto a hubmetrics.AuditFail* class.
//
// String matching for everything but the lock sentinel, for the reason
// classifyDriverErr gives: the driver exposes no stable codes for these.
func classifyAuditFailure(err error) string {
	if errors.Is(err, ErrDBLocked) {
		return hubmetrics.AuditFailLocked
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "readonly") || strings.Contains(msg, "read-only") ||
		strings.Contains(msg, "read only"):
		return hubmetrics.AuditFailReadOnly
	case strings.Contains(msg, "database or disk is full") || strings.Contains(msg, "disk is full") ||
		strings.Contains(msg, "no space left"):
		return hubmetrics.AuditFailFull
	case strings.Contains(msg, "database is closed"):
		return hubmetrics.AuditFailClosed
	case strings.Contains(msg, "disk i/o error") || strings.Contains(msg, "input/output error"):
		return hubmetrics.AuditFailIO
	case strings.Contains(msg, "locked") || strings.Contains(msg, "busy"):
		return hubmetrics.AuditFailLocked
	}
	return hubmetrics.AuditFailOther
}

// auditChainLabel is the metric label for a handle's role.
func auditChainLabel(r Role) string {
	switch r {
	case RoleControlPlane:
		return hubmetrics.AuditChainControlPlane
	case RoleProject:
		return hubmetrics.AuditChainProject
	}
	return hubmetrics.AuditChainUnclassified
}

// truncateAuditError bounds an error's text for a loss record.
func truncateAuditError(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= auditErrorMax {
		return s
	}
	cut := auditErrorMax
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// auditChainKey names the database a path opens, for the failure accounting:
// absolute and with symlinks resolved, so every handle over one file shares an
// account. A path that cannot be resolved is used as given.
func auditChainKey(path string) string {
	if path == "" || strings.Contains(path, ":memory:") || strings.Contains(path, "mode=memory") {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	return path
}

// chainKey is the account a handle's failures are kept in. A handle with no
// file behind it — an in-memory database — gets one of its own: two such
// handles are two databases, and a loss in one must not be recorded in the
// other.
func (d *DB) chainKey() string {
	if d.auditKey != "" {
		return d.auditKey
	}
	return fmt.Sprintf("handle:%p", d)
}

// ── the account ──────────────────────────────────────────────────────────────

// auditChainAccount is one database's account in this process.
type auditChainAccount struct {
	key  string
	path string
	role Role

	// owed is lost and not yet recorded; claimed is being written as a gap
	// row right now. A loss is in exactly one of them, or recorded.
	owed    AuditLoss
	claimed *AuditLoss

	total            int64 // events lost since this process started
	recorded         int64 // of those, recorded in gap rows
	gapRows          int64
	lastGapID        int64
	lastGapAt        time.Time
	gapWriteFailures int64
	lastGapError     string

	// handle is the handle that failed on a database with no file behind it,
	// the only way to reach that database again; nil for every other.
	handle *DB
	// orphaned is set when the database file is gone: retrying is pointless,
	// and a later handle over a recreated file still records the loss.
	orphaned bool

	// Reporting state, so the reporter says each thing once.
	announced  bool
	reported   int64 // total covered by a printed summary
	lastReport time.Time
	notices    []string // recorded-gap lines not yet printed
}

// unrecorded is everything lost and not yet in the chain.
func (c *auditChainAccount) unrecorded() AuditLoss {
	out := c.owed.clone()
	if c.claimed != nil {
		out.merge(*c.claimed)
	}
	return out
}

// auditFailureLog is the process's set of accounts.
type auditFailureLog struct {
	mu     sync.Mutex
	chains map[string]*auditChainAccount

	// owed is every account's unrecorded events: the append path's fast check
	// for "is anything owed anywhere", one atomic load when the answer is no.
	owed atomic.Int64

	wake    chan struct{}
	running bool

	// statusDir is where this process keeps its status file, or "" for none.
	statusDir string
}

var auditFailures = &auditFailureLog{
	chains: map[string]*auditChainAccount{},
	wake:   make(chan struct{}, 1),
}

// accountLocked returns key's account, creating it.
func (l *auditFailureLog) accountLocked(key, path string) *auditChainAccount {
	c := l.chains[key]
	if c == nil {
		c = &auditChainAccount{key: key, path: path}
		l.chains[key] = c
	}
	if c.path == "" {
		c.path = path
	}
	return c
}

// record counts one failed append. This is the hot path: it never blocks on
// anything slower than the account's lock, and it never writes.
func (l *auditFailureLog) record(d *DB, evs []*AuditEvent, err error) {
	if d == nil || err == nil || len(evs) == 0 {
		return
	}
	reason := classifyAuditFailure(err)
	msg := truncateAuditError(err.Error())
	now := time.Now().UTC()
	role := d.Role()
	n := int64(len(evs))

	// The account names the file by an absolute path — a status file outlives
	// the process, and a relative one would be read against whichever
	// directory the adopting process runs in — but not a resolved one: a
	// .cloop that is a symlink to another volume must still read as a cloop
	// database path when adoption checks it.
	path := d.path
	if abs, err := filepath.Abs(path); err == nil && d.auditKey != "" {
		path = abs
	}

	l.mu.Lock()
	c := l.accountLocked(d.chainKey(), path)
	c.owed.add(evs, reason, msg, now)
	c.total += n
	c.orphaned = false
	if role != RoleUnknown {
		c.role = role
	}
	if d.auditKey == "" && !d.closed.Load() {
		c.handle = d // no file to reopen: the gap can only go through this one
	}
	l.owed.Add(n)
	l.ensureRunningLocked()
	l.mu.Unlock()

	hubmetrics.AuditAppendFailures.Add(float64(n), auditChainLabel(role), reason)
	l.poke()
}

// gapClaim is a loss taken out of an account to be written as a gap row.
type gapClaim struct {
	key  string
	loss AuditLoss
	role Role
}

// claim takes what key owes, for the caller to write as a gap row. Nil when
// nothing is owed, or when a gap is already being written for this chain.
func (l *auditFailureLog) claim(key string) *gapClaim {
	if l.owed.Load() == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.chains[key]
	if c == nil || c.claimed != nil || c.owed.Empty() {
		return nil
	}
	loss := c.owed
	c.owed = AuditLoss{}
	c.claimed = &loss
	return &gapClaim{key: key, loss: loss, role: c.role}
}

// release returns a claim that could not be written. The gap row's failure is
// not itself a loss — counting it would breed gap rows about gap rows — so the
// claim simply becomes owed again. alone says the gap row was the only thing
// being written, which makes its failure worth recording on the account.
func (l *auditFailureLog) release(g *gapClaim, err error, alone bool) {
	if g == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.chains[g.key]
	if c == nil {
		return
	}
	back := g.loss
	back.merge(c.owed) // the claim is older than anything owed since
	c.owed = back
	c.claimed = nil
	if alone && err != nil {
		c.gapWriteFailures++
		c.lastGapError = truncateAuditError(err.Error())
	}
}

// settle marks a claim recorded by the gap row ev.
func (l *auditFailureLog) settle(g *gapClaim, ev *AuditEvent, path string) {
	if g == nil || ev == nil {
		return
	}
	l.mu.Lock()
	c := l.chains[g.key]
	if c != nil {
		c.claimed = nil
		c.recorded += g.loss.Events
		c.gapRows++
		c.lastGapID = ev.ID
		c.lastGapAt = ev.Timestamp
		c.notices = append(c.notices, fmt.Sprintf(
			"[audit] recorded audit.gap #%d in %s: %d event(s) lost between %s and %s",
			ev.ID, path, g.loss.Events,
			g.loss.FirstAt.UTC().Format(time.RFC3339), g.loss.LastAt.UTC().Format(time.RFC3339)))
		l.ensureRunningLocked()
	}
	l.owed.Add(-g.loss.Events)
	l.mu.Unlock()

	hubmetrics.AuditGapEvents.Add(float64(g.loss.Events), auditChainLabel(g.role))
	l.poke()
}

// poke wakes the reporter without waiting for it.
func (l *auditFailureLog) poke() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// ensureRunningLocked starts the reporter if it is not running. Callers hold
// l.mu.
func (l *auditFailureLog) ensureRunningLocked() {
	if l.running {
		return
	}
	l.running = true
	go l.loop()
}

// loop is the reporter. It prints, persists the status file and retries the
// gap rows nothing else wrote, and it exits once nothing is owed that it could
// do anything about, so a process that never fails an append never runs it.
func (l *auditFailureLog) loop() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[audit] failure reporter panicked: %v\n", r)
			l.mu.Lock()
			l.running = false
			l.mu.Unlock()
		}
	}()
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()
	for {
		l.report(false)
		l.persistStatus()
		if l.stopIfIdle() {
			return
		}
		select {
		case <-l.wake:
		case <-ticker.C:
			l.flush(GapRecordedByFlush)
		}
	}
}

// stopIfIdle ends the reporter when no account owes anything it can still
// record and nothing is left to print. Decided and marked under the lock, so a
// failure recorded a moment later starts a fresh reporter instead of being
// missed by this one.
func (l *auditFailureLog) stopIfIdle() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.chains {
		if len(c.notices) > 0 || c.claimed != nil {
			return false
		}
		if !c.owed.Empty() && !c.orphaned {
			return false
		}
		if c.total > c.reported {
			return false
		}
	}
	l.running = false
	return true
}

// report prints what has not been said yet: a chain's first failure at once,
// further failures at most once per auditReportInterval (all of them when
// force is set), and every gap row recorded.
func (l *auditFailureLog) report(force bool) {
	now := time.Now()
	var lines []string
	l.mu.Lock()
	for _, key := range l.sortedKeysLocked() {
		c := l.chains[key]
		lines = append(lines, c.notices...)
		c.notices = nil
		switch {
		case c.total == 0 || c.total == c.reported:
		case !c.announced:
			u := c.unrecorded()
			lines = append(lines, fmt.Sprintf(
				"[audit] could not append to the audit trail at %s: %s — "+
					"counting every failure from here on; they are recorded as an audit.gap row "+
					"once the database takes writes again (%d event(s) so far: %s)",
				c.path, u.LastError, u.Events, u.topActions(3)))
			c.announced, c.reported, c.lastReport = true, c.total, now
		case force || now.Sub(c.lastReport) >= auditReportInterval:
			u := c.unrecorded()
			msg := fmt.Sprintf(
				"[audit] %d more audit event(s) failed to append to %s since %s",
				c.total-c.reported, c.path, c.lastReport.UTC().Format(time.RFC3339))
			if !u.Empty() {
				msg += fmt.Sprintf(" (%d unrecorded since %s: %s); last error: %s",
					u.Events, u.FirstAt.UTC().Format(time.RFC3339), u.topActions(3), u.LastError)
			}
			if c.lastGapError != "" {
				msg += "; recording the gap failed: " + c.lastGapError
			}
			lines = append(lines, msg)
			c.reported, c.lastReport = c.total, now
		}
	}
	out := auditReportOut
	l.mu.Unlock()

	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
}

// sortedKeysLocked lists the accounts in a stable order. Callers hold l.mu.
func (l *auditFailureLog) sortedKeysLocked() []string {
	keys := make([]string, 0, len(l.chains))
	for k := range l.chains {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// flush writes a gap row, on its own, for every chain that owes one. Database
// work happens outside l.mu.
func (l *auditFailureLog) flush(recorded string) {
	l.mu.Lock()
	var keys []string
	for _, key := range l.sortedKeysLocked() {
		c := l.chains[key]
		if !c.owed.Empty() && c.claimed == nil && !c.orphaned {
			keys = append(keys, key)
		}
	}
	l.mu.Unlock()

	for _, key := range keys {
		l.flushChain(key, recorded)
	}
}

// flushChain writes key's gap row on its own.
//
// Through a handle of its own, not the caller's that failed: a flush holds its
// handle's lock for as long as SQLite makes it wait, and a database another
// process holds locked would otherwise park every caller of that handle behind
// the reporter. Only a database with no file to reopen — an in-memory one — is
// written through the handle that failed on it.
//
// One attempt per flush: the reporter is back every auditFlushInterval, which
// is retry enough, and a process on its way out must not wait out a busy
// database at all.
func (l *auditFailureLog) flushChain(key, recorded string) {
	g := l.claim(key)
	if g == nil {
		return
	}
	l.mu.Lock()
	c := l.chains[key]
	d, path := c.handle, c.path
	l.mu.Unlock()

	if !strings.HasPrefix(key, "handle:") {
		if _, err := os.Stat(path); err != nil {
			// Nothing to write the gap into. Leave it owed — a handle over a
			// recreated file still records it — but stop retrying.
			l.release(g, err, true)
			l.mu.Lock()
			c.orphaned = os.IsNotExist(err)
			l.mu.Unlock()
			return
		}
		own, err := Open(path)
		if err != nil {
			l.release(g, err, true)
			return
		}
		defer own.Close()
		d = own
	}
	if d == nil || d.closed.Load() {
		l.release(g, errors.New("statedb audit: no open handle to record the gap through"), true)
		l.mu.Lock()
		c.orphaned = true
		l.mu.Unlock()
		return
	}
	ev, err := d.appendAuditGap(g.loss, recorded, 1)
	if err != nil {
		l.release(g, err, true)
		return
	}
	l.settle(g, ev, path)
}

// appendAuditGap writes loss as a gap row on its own, in at most attempts
// transactions. It does not go through the failure accounting: a gap row's
// failure is not a lost event.
func (d *DB) appendAuditGap(loss AuditLoss, recorded string, attempts int) (*AuditEvent, error) {
	ev := gapEvent(loss, recorded)
	if err := normalizeAuditEvents([]*AuditEvent{ev}); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.appendAuditBatchN([]*AuditEvent{ev}, attempts); err != nil {
		return nil, err
	}
	return ev, nil
}

// ── what the rest of the process sees ────────────────────────────────────────

// AuditChainFailures is one database's account of failed audit appends in
// this process.
type AuditChainFailures struct {
	Path  string `json:"path"`
	Chain string `json:"chain"`
	// Unrecorded is lost and not yet in the chain as an audit.gap row.
	Unrecorded AuditLoss `json:"unrecorded"`
	// TotalEvents were lost since the process started; RecordedEvents of
	// them are in the chain now, in GapRows gap rows.
	TotalEvents      int64     `json:"total_events"`
	RecordedEvents   int64     `json:"recorded_events"`
	GapRows          int64     `json:"gap_rows"`
	LastGapID        int64     `json:"last_gap_id,omitempty"`
	LastGapAt        time.Time `json:"last_gap_at,omitempty"`
	GapWriteFailures int64     `json:"gap_write_failures,omitempty"`
	LastGapError     string    `json:"last_gap_error,omitempty"`
}

// AuditFailures reports every database this process failed an audit append to,
// ordered by path. Empty when it never has.
func AuditFailures() []AuditChainFailures {
	l := auditFailures
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditChainFailures, 0, len(l.chains))
	for _, key := range l.sortedKeysLocked() {
		c := l.chains[key]
		if c.total == 0 && c.unrecorded().Empty() {
			continue
		}
		out = append(out, AuditChainFailures{
			Path:             c.path,
			Chain:            auditChainLabel(c.role),
			Unrecorded:       c.unrecorded(),
			TotalEvents:      c.total,
			RecordedEvents:   c.recorded,
			GapRows:          c.gapRows,
			LastGapID:        c.lastGapID,
			LastGapAt:        c.lastGapAt,
			GapWriteFailures: c.gapWriteFailures,
			LastGapError:     c.lastGapError,
		})
	}
	return out
}

// FlushAuditGaps records what every chain is owed now, rather than at the
// reporter's next tick, and prints whatever has not been said. recorded is one
// of the GapRecorded* values. A hub calls it as it shuts down.
func FlushAuditGaps(recorded string) {
	l := auditFailures
	if l.owed.Load() > 0 {
		l.flush(recorded)
	}
	l.report(true)
	l.persistStatus()
}

// SettleAuditFailuresAtExit is FlushAuditGaps for a process about to exit, and
// says plainly what could not be recorded: a CLI command that failed an append
// may otherwise end before its reporter has printed anything.
func SettleAuditFailuresAtExit() {
	l := auditFailures
	if l.owed.Load() == 0 {
		l.mu.Lock()
		quiet := len(l.chains) == 0
		l.mu.Unlock()
		if quiet {
			return
		}
	}
	FlushAuditGaps(GapRecordedAtExit)

	l.mu.Lock()
	var lines []string
	for _, key := range l.sortedKeysLocked() {
		c := l.chains[key]
		if u := c.unrecorded(); !u.Empty() {
			lines = append(lines, fmt.Sprintf(
				"[audit] %d audit event(s) could not be appended to %s and were not recorded "+
					"before exit (%s); last error: %s",
				u.Events, c.path, u.topActions(3), u.LastError))
		}
	}
	out := auditReportOut
	l.mu.Unlock()
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
}

// isCloopDatabasePath reports whether path is absolute, names a .db file and
// lies inside a .cloop/ directory — the only places cloop keeps a database.
func isCloopDatabasePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".db" {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if part == ".cloop" {
			return true
		}
	}
	return false
}

// ── the status file ──────────────────────────────────────────────────────────
//
// The dashboard can ask this process what it owes; `cloop hub doctor` is
// another process and cannot. So a process that wants to be asked names a
// directory, and the reporter keeps one small file there while anything is
// unrecorded, and removes it once everything is. A file left behind by a
// process that died is the record of what it lost — the next process to start
// there adopts it and writes the gap row the dead one could not.
//
// The file is rewritten at least every auditStatusHeartbeat while anything is
// owed, so a file nobody has rewritten for auditStatusStale belongs to a
// process that is gone — whichever host wrote it, which matters for a
// container whose replacement gets a new hostname and the same PID 1.

// auditStatusHeartbeat bounds how long an unchanged status file goes without
// being rewritten.
const auditStatusHeartbeat = 5 * time.Minute

// auditStatusStale is how long a status file can go unrewritten before its
// writer is taken to be gone.
const auditStatusStale = 3 * auditStatusHeartbeat

// processInstance tells this process from another that had its PID — the
// norm for a hub running as PID 1 in a container.
var processInstance = func() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}()

// AuditFailureStatusDir is where a hub serving workDir keeps its status file,
// and where `cloop hub doctor` looks for it.
func AuditFailureStatusDir(workDir string) string {
	return filepath.Join(workDir, ".cloop", "audit-failures")
}

// AuditFailureStatus is one process's status file.
type AuditFailureStatus struct {
	PID  int    `json:"pid"`
	Host string `json:"host"`
	// Instance tells this process from a later one given the same PID, and
	// ProcStart is the kernel's start time for the PID (Linux), which tells it
	// from an unrelated process that reused the PID.
	Instance  string               `json:"instance,omitempty"`
	ProcStart string               `json:"proc_start,omitempty"`
	UpdatedAt time.Time            `json:"updated_at"`
	Chains    []AuditChainFailures `json:"chains"`

	// File is where it was read from; not stored.
	File string `json:"-"`
}

// SetAuditFailureStatusDir names the directory this process keeps its status
// file in. Empty turns it off.
func SetAuditFailureStatusDir(dir string) {
	l := auditFailures
	l.mu.Lock()
	l.statusDir = dir
	l.mu.Unlock()
	if l.owed.Load() > 0 {
		l.persistStatus()
	}
}

// statusFileName is this process's file name inside the status directory.
func statusFileName() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d-%s.json", sanitizeFileComponent(host), os.Getpid(), processInstance)
}

func sanitizeFileComponent(s string) string {
	if s == "" {
		return "host"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		}
		return '_'
	}, s)
}

// statusState is the reporter's memory of the file it last wrote. Guarded by
// its own lock, never held together with auditFailures.mu: writing the file is
// disk I/O, and the account's lock is one every audit append in the process
// may take.
var statusState struct {
	mu      sync.Mutex
	onDisk  string
	last    []byte
	written time.Time
}

// persistStatus writes or removes this process's status file. Best effort:
// the database is what failed, and the disk under it may be failing too.
func (l *auditFailureLog) persistStatus() {
	statusState.mu.Lock()
	defer statusState.mu.Unlock()

	l.mu.Lock()
	dir := l.statusDir
	l.mu.Unlock()
	if dir == "" {
		return
	}

	var owing []AuditChainFailures
	for _, c := range AuditFailures() {
		if !c.Unrecorded.Empty() {
			owing = append(owing, c)
		}
	}
	path := filepath.Join(dir, statusFileName())

	if len(owing) == 0 {
		if statusState.onDisk != "" {
			_ = os.Remove(statusState.onDisk)
			statusState.onDisk, statusState.last = "", nil
		}
		return
	}
	host, _ := os.Hostname()
	st := AuditFailureStatus{
		PID: os.Getpid(), Host: host, Instance: processInstance,
		ProcStart: procStartTime(os.Getpid()), Chains: owing,
	}
	body, err := json.Marshal(st)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	if statusState.onDisk == path && bytes.Equal(sha256Sum(body), statusState.last) &&
		now.Sub(statusState.written) < auditStatusHeartbeat {
		return
	}
	st.UpdatedAt = now
	stamped, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	// The directory is made, its parent never: a .cloop that is gone is a
	// project that is gone, and recreating it would leave a stray directory
	// where somebody removed one.
	if _, err := os.Stat(filepath.Dir(dir)); err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, stamped, 0o600); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	statusState.onDisk, statusState.last, statusState.written = path, sha256Sum(body), now
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ReadAuditFailureStatus reads every status file in dir. A directory that does
// not exist holds none. Only regular files are read: a symlink planted there
// is not followed.
func ReadAuditFailureStatus(dir string) ([]AuditFailureStatus, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []AuditFailureStatus
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		st, err := readAuditFailureStatus(path)
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// maxAuditFailureStatusBytes bounds one status file. A real one is a few
// kilobytes: one entry per database, each with a capped histogram.
const maxAuditFailureStatusBytes = 1 << 20

func readAuditFailureStatus(path string) (AuditFailureStatus, error) {
	body, err := boundedread.ReadFile(path, maxAuditFailureStatusBytes)
	if err != nil {
		return AuditFailureStatus{}, err
	}
	var st AuditFailureStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return AuditFailureStatus{}, err
	}
	st.File = path
	return st, nil
}

// ProcessRunning reports whether the process a status file names may still be
// running.
//
// On the host that wrote it the process table decides: the PID must be alive,
// be this process only if the instance is this one's, and have the start time
// the file recorded. From another host only age can: a file nobody rewrote for
// auditStatusStale is abandoned, a fresher one is taken to be live, since
// adopting a live process's losses would record them twice.
func (s AuditFailureStatus) ProcessRunning() bool {
	host, _ := os.Hostname()
	if s.Host != host {
		// Nothing here can ask that host; a file its writer stopped
		// refreshing is the only sign it is gone.
		return s.UpdatedAt.IsZero() || time.Since(s.UpdatedAt) <= auditStatusStale
	}
	// On this host the process table answers, and age does not override it:
	// a live process whose reporter stalled still owns its losses, and
	// adopting them would record them twice.
	if s.PID == os.Getpid() {
		return s.Instance == processInstance
	}
	if !pidAlive(s.PID) {
		return false
	}
	if s.ProcStart != "" {
		if now := procStartTime(s.PID); now != "" && now != s.ProcStart {
			return false // the PID is someone else's now
		}
	}
	return true
}

// pidAlive reports whether pid names a live process here. EPERM counts as
// alive: the process exists and is someone else's.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

// procStartTime is the kernel's start time of pid, in clock ticks since boot
// (field 22 of /proc/<pid>/stat), or "" where there is no /proc.
func procStartTime(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// The command name in field 2 may hold spaces and parentheses; the
	// fields after it start at the last ')'.
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return ""
	}
	fields := strings.Fields(string(raw[i+1:]))
	const startTimeField = 22 - 3 // fields after the name begin at field 3
	if len(fields) <= startTimeField {
		return ""
	}
	return fields[startTimeField]
}

// AdoptAuditFailureStatus takes over the losses that processes no longer
// running left in dir: each becomes owed by this process, to be recorded in
// its chain as an audit.gap row naming where it came from, and the file is
// removed. Returns how many events were adopted.
//
// A file is claimed by renaming it before it is read, so two processes starting
// beside one dead one cannot both record its losses. Entries that cannot be
// adopted — a database that is gone, or cannot be confirmed as cloop's — are
// written back to a file of their own and said on stderr, so the record of
// the loss is not destroyed by the attempt to record it.
func AdoptAuditFailureStatus(dir string) (int64, error) {
	statuses, err := ReadAuditFailureStatus(dir)
	if err != nil {
		return 0, err
	}
	own := statusFileName()
	var adopted int64
	for _, st := range statuses {
		base := filepath.Base(st.File)
		if base == own || strings.HasPrefix(base, "unadoptable-") || st.ProcessRunning() {
			continue
		}
		claimed := st.File + ".adopting-" + processInstance
		if err := os.Rename(st.File, claimed); err != nil {
			continue // another process got there first
		}
		st2, err := readAuditFailureStatus(claimed)
		if err != nil {
			_ = os.Remove(claimed)
			continue
		}
		var kept []AuditChainFailures
		for _, c := range st2.Chains {
			n, ok := auditFailures.adopt(c)
			adopted += n
			if !ok {
				kept = append(kept, c)
			}
		}
		if len(kept) > 0 {
			st2.Chains = kept
			keepUnadoptable(dir, st2)
		}
		_ = os.Remove(claimed)
	}
	return adopted, nil
}

// keepUnadoptable writes back the entries of a dead process's status file
// that could not be adopted, under a name adoption passes over and the doctor
// still reads, and says so.
func keepUnadoptable(dir string, st AuditFailureStatus) {
	st.File = ""
	body, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		path := filepath.Join(dir, fmt.Sprintf("unadoptable-%s-%d-%s.json",
			sanitizeFileComponent(st.Host), st.PID, sanitizeFileComponent(st.Instance)))
		if werr := os.WriteFile(path, body, 0o600); werr == nil {
			fmt.Fprintf(auditReportOutLocked(), "[audit] could not record %d audit loss(es) process %d left "+
				"(its database is gone, or is not one this hub can confirm as cloop's); kept in %s\n",
				len(st.Chains), st.PID, path)
			return
		}
	}
	fmt.Fprintf(auditReportOutLocked(), "[audit] could not record %d audit loss(es) process %d left, "+
		"and could not keep them either\n", len(st.Chains), st.PID)
}

// auditReportOutLocked reads the report writer under the lock that guards it.
func auditReportOutLocked() io.Writer {
	auditFailures.mu.Lock()
	defer auditFailures.mu.Unlock()
	return auditReportOut
}

// maxAdoptedEvents bounds what one adopted entry may claim was lost. The file
// came from disk; a count past this is not a loss, it is a forgery.
const maxAdoptedEvents = 1 << 40

// adopt makes another process's unrecorded loss on one chain this process's,
// and reports whether the entry was dealt with — adopted, or found already
// recorded — rather than left for later.
//
// The file came from disk, and recording a gap opens the database it names —
// which applies cloop's migrations to it — so a planted or stale entry must
// not be a way to make the hub write into some other application's SQLite
// file: the path must be where cloop keeps a database, and what it resolves to
// must be a regular file that already holds cloop's audit trail.
//
// A file can also be behind its writer: the process recorded some or all of
// what the file lists, then died before it rewrote the file. So what that
// process's own gap rows record from the entry's first failure on is taken off
// the entry, and only the rest adopted. When part was recorded, which actions
// the rest were is not known, and the gap row says so rather than guess.
func (l *auditFailureLog) adopt(c AuditChainFailures) (int64, bool) {
	loss := c.Unrecorded.clone()
	if loss.Events < 0 || loss.Events > maxAdoptedEvents {
		return 0, true // not a loss: a forgery, dropped
	}
	if loss.Empty() {
		return 0, true
	}
	path, ok := adoptableDatabase(c.Path)
	if !ok {
		return 0, false
	}
	if done := recordedByProcesses(path, loss); done > 0 {
		if done >= loss.Events {
			return 0, true
		}
		rest := loss.Events - done
		loss.Events = rest
		if loss.Appends > rest {
			loss.Appends = rest
		}
		loss.Actions = map[string]int64{auditLossOtherAction: rest}
		loss.Reasons = map[string]int64{hubmetrics.AuditFailOther: rest}
	}
	for _, p := range loss.PIDs {
		loss.AdoptedFrom = addPIDTo(loss.AdoptedFrom, p)
	}
	// Failure classes are metric labels: only the closed set survives.
	reasons := make(map[string]int64, len(loss.Reasons))
	for k, v := range loss.Reasons {
		reasons[knownAuditFailure(k)] += v
	}
	loss.Reasons = reasons

	role := RoleUnknown
	switch c.Chain {
	case hubmetrics.AuditChainControlPlane:
		role = RoleControlPlane
	case hubmetrics.AuditChainProject:
		role = RoleProject
	}
	key := auditChainKey(path)
	l.mu.Lock()
	acct := l.accountLocked(key, c.Path)
	acct.owed.merge(loss)
	acct.total += loss.Events
	// Said once, by the notice below, rather than as this process's failure.
	acct.reported += loss.Events
	acct.orphaned = false
	if acct.role == RoleUnknown {
		acct.role = role
	}
	acct.notices = append(acct.notices, fmt.Sprintf(
		"[audit] adopted %d unrecorded audit event(s) for %s from process(es) %v that exited without recording them",
		loss.Events, c.Path, loss.PIDs))
	l.owed.Add(loss.Events)
	l.ensureRunningLocked()
	l.mu.Unlock()

	// Counted here as well as when recorded, so failures minus gap events
	// stays what this process still owes.
	for reason, n := range reasons {
		hubmetrics.AuditAppendFailures.Add(float64(n), auditChainLabel(role), reason)
	}
	l.poke()
	return loss.Events, true
}

// knownAuditFailure maps a failure class read from disk onto the closed set.
func knownAuditFailure(s string) string {
	switch s {
	case hubmetrics.AuditFailLocked, hubmetrics.AuditFailReadOnly, hubmetrics.AuditFailFull,
		hubmetrics.AuditFailIO, hubmetrics.AuditFailClosed:
		return s
	}
	return hubmetrics.AuditFailOther
}

// adoptableDatabase resolves path and reports whether a gap may be written to
// what it names: a cloop database path as recorded, resolving to a regular
// file that already holds cloop's audit trail — checked read-only, so the
// check itself writes nothing. The resolved path need not sit under a .cloop
// (that directory may be a link to another volume); what it holds is the
// test.
func adoptableDatabase(path string) (string, bool) {
	if !isCloopDatabasePath(path) {
		return "", false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Ext(real) != ".db" {
		return "", false
	}
	if fi, err := os.Stat(real); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	conn, err := OpenConn(real, ReadOnly)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'table' AND name IN ('audit_events', 'schema_migrations')`).Scan(&n); err != nil || n != 2 {
		return "", false
	}
	return real, true
}

// recordedByProcesses is how many of loss's events the processes that lost
// them have already recorded at path: the lost_events of their gap rows whose
// first failure is no earlier than the loss's. Read-only.
func recordedByProcesses(path string, loss AuditLoss) int64 {
	if len(loss.PIDs) == 0 || loss.FirstAt.IsZero() {
		return 0
	}
	pids := map[int]bool{}
	for _, p := range loss.PIDs {
		pids[p] = true
	}
	conn, err := OpenConn(path, ReadOnly)
	if err != nil {
		return 0
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT payload FROM audit_events WHERE event_type = ? ORDER BY id DESC LIMIT 1000`,
		auditGapEventType)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var done int64
	for rows.Next() {
		var payload string
		if rows.Scan(&payload) != nil {
			continue
		}
		var p struct {
			FirstFailedAt string `json:"first_failed_at"`
			PIDs          []int  `json:"pids"`
		}
		if json.Unmarshal([]byte(payload), &p) != nil {
			continue
		}
		first, err := time.Parse(time.RFC3339Nano, p.FirstFailedAt)
		if err != nil || first.Before(loss.FirstAt) {
			continue
		}
		for _, pid := range p.PIDs {
			if pids[pid] {
				done += AuditGapLostEvents(payload)
				break
			}
		}
	}
	return done
}
