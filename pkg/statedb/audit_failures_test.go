package statedb

// Tests for the audit failure accounting (Task 20404): every failed append is
// counted on the way out of the append path, reported, and recorded in its
// chain as an audit.gap row once the database takes writes again.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// syncBuffer is a bytes.Buffer safe for the reporter goroutine to write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureAuditReports sends the reporter's lines to a buffer for the test.
func captureAuditReports(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	auditFailures.mu.Lock()
	prev := auditReportOut
	auditReportOut = buf
	auditFailures.mu.Unlock()
	t.Cleanup(func() {
		auditFailures.mu.Lock()
		auditReportOut = prev
		auditFailures.mu.Unlock()
	})
	return buf
}

// setReadOnly makes the handle's one connection refuse writes, the way a
// read-only database file does — and, unlike chmod, also for root.
func setReadOnly(t *testing.T, d *DB, on bool) {
	t.Helper()
	v := 0
	if on {
		v = 1
	}
	if _, err := d.conn.Exec("PRAGMA query_only=" + strconv.Itoa(v)); err != nil {
		t.Fatalf("query_only=%d: %v", v, err)
	}
}

// refuseAuditWrites makes every connection to d's file refuse audit rows, as
// a read-only or full database does: unlike query_only, which binds one
// connection, a trigger is part of the schema, so the reporter's own handle
// meets it too.
func refuseAuditWrites(t *testing.T, d *DB, on bool) {
	t.Helper()
	stmt := `DROP TRIGGER IF EXISTS test_refuse_audit`
	if on {
		stmt = `CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit_events
			BEGIN SELECT RAISE(ABORT, 'attempt to write a readonly database'); END`
	}
	if _, err := d.conn.Exec(stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

// metricValue reads one series of the default registry, 0 when absent.
func metricValue(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	series := name
	if len(labels) > 0 {
		var parts []string
		for i := 0; i+1 < len(labels); i += 2 {
			parts = append(parts, labels[i]+`="`+labels[i+1]+`"`)
		}
		series += "{" + strings.Join(parts, ",") + "}"
	}
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// accountFor returns this process's account for d's database.
func accountFor(t *testing.T, d *DB) AuditChainFailures {
	t.Helper()
	for _, c := range AuditFailures() {
		if c.Path == d.auditKey || c.Path == d.path {
			return c
		}
	}
	return AuditChainFailures{}
}

func testEvent(action auditaction.Action) *AuditEvent {
	return &AuditEvent{Actor: "test", EventType: string(action), EntityType: "task", EntityID: "1", Payload: `{}`}
}

// The whole path the task names: a forced failure on a read-only database is
// counted, shows up in the metric, is recorded as a gap row on recovery, and
// the chain then verifies as intact with gaps.
func TestAuditAppendFailureIsCountedAndRecordedOnRecovery(t *testing.T) {
	out := captureAuditReports(t)
	d := openFresh(t).AsControlPlane()

	if err := d.AppendAuditEvent(testEvent(auditaction.ActionExecutorCordon)); err != nil {
		t.Fatalf("first append: %v", err)
	}

	failBefore := metricValue(t, "cloop_audit_append_failures_total", "chain", "control-plane", "reason", "readonly")
	gapBefore := metricValue(t, "cloop_audit_gap_events_total", "chain", "control-plane")

	setReadOnly(t, d, true)
	if err := d.AppendAuditEvent(testEvent(auditaction.ActionExecutorCordon)); err == nil {
		t.Fatal("an append to a read-only database succeeded")
	}
	if err := d.AppendAuditEvent(testEvent(auditaction.ActionExecutorDrain)); err == nil {
		t.Fatal("an append to a read-only database succeeded")
	}
	if err := d.AppendAuditEvents([]*AuditEvent{
		testEvent(auditaction.ActionExecutorCordon), testEvent(auditaction.ActionExecutorUncordon),
	}); err == nil {
		t.Fatal("a batch append to a read-only database succeeded")
	}

	acct := accountFor(t, d)
	if acct.Unrecorded.Events != 4 || acct.Unrecorded.Appends != 3 || acct.TotalEvents != 4 {
		t.Fatalf("account after three failed appends of four events: %+v", acct)
	}
	if got := acct.Unrecorded.Actions["executor.cordon"]; got != 2 {
		t.Errorf("executor.cordon lost %d times, want 2 (histogram %v)", got, acct.Unrecorded.Actions)
	}
	if got := acct.Unrecorded.Reasons[hubmetrics.AuditFailReadOnly]; got != 4 {
		t.Errorf("readonly failures = %d, want 4 (reasons %v)", got, acct.Unrecorded.Reasons)
	}
	if acct.Chain != hubmetrics.AuditChainControlPlane {
		t.Errorf("chain = %q, want control-plane", acct.Chain)
	}
	if got := metricValue(t, "cloop_audit_append_failures_total", "chain", "control-plane", "reason", "readonly") - failBefore; got != 4 {
		t.Errorf("cloop_audit_append_failures_total grew by %v, want 4", got)
	}

	setReadOnly(t, d, false)
	recovered := testEvent(auditaction.ActionExecutorUncordon)
	if err := d.AppendAuditEvent(recovered); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}

	rows, _, err := d.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("chain holds %d rows, want 3 (event, gap, event)", len(rows))
	}
	gap := rows[1]
	if gap.EventType != string(auditaction.ActionAuditGap) {
		t.Fatalf("row %d is %s, want the gap row ahead of the recovering append", gap.ID, gap.EventType)
	}
	if rows[2].ID != recovered.ID || recovered.ID != gap.ID+1 {
		t.Errorf("the recovering event is #%d, want it right after gap #%d", recovered.ID, gap.ID)
	}
	var p AuditGapPayload
	if err := json.Unmarshal([]byte(gap.Payload), &p); err != nil {
		t.Fatalf("gap payload: %v", err)
	}
	if p.LostEvents != 4 || p.FailedAppends != 3 || p.Recorded != GapRecordedOnRecovery {
		t.Errorf("gap payload = %+v", p)
	}
	if got := gapCountsOf(p.Actions); got["executor.cordon"] != 2 || got["executor.drain"] != 1 || got["executor.uncordon"] != 1 {
		t.Errorf("gap actions = %v", p.Actions)
	}
	if !strings.Contains(p.FirstError, "readonly") {
		t.Errorf("first error %q does not say why", p.FirstError)
	}

	acct = accountFor(t, d)
	if !acct.Unrecorded.Empty() || acct.RecordedEvents != 4 || acct.GapRows != 1 || acct.LastGapID != gap.ID {
		t.Errorf("account after recovery: %+v", acct)
	}
	if got := metricValue(t, "cloop_audit_gap_events_total", "chain", "control-plane") - gapBefore; got != 4 {
		t.Errorf("cloop_audit_gap_events_total grew by %v, want 4", got)
	}

	rep, err := d.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Status() != AuditChainGaps || rep.Gaps != 1 || rep.GapEvents != 4 {
		t.Errorf("verify = status %s, ok %v, gaps %d covering %d; want gaps, 1 covering 4",
			rep.Status(), rep.OK, rep.Gaps, rep.GapEvents)
	}
	if len(rep.GapIDs) != 1 || rep.GapIDs[0] != gap.ID {
		t.Errorf("gap ids = %v, want [%d]", rep.GapIDs, gap.ID)
	}

	FlushAuditGaps(GapRecordedByFlush) // print what the reporter has not
	text := out.String()
	if !strings.Contains(text, "could not append to the audit trail") {
		t.Errorf("no first-failure report on stderr:\n%s", text)
	}
	if !strings.Contains(text, "recorded audit.gap #"+strconv.FormatInt(gap.ID, 10)) {
		t.Errorf("the recorded gap was not reported:\n%s", text)
	}
	if strings.Contains(text, "suppressed") {
		t.Errorf("a failure report still promises to suppress the next:\n%s", text)
	}
}

// The sync.Once regression: the emit helpers used to print the first failure
// and let every later one vanish. Every one is counted now, through the same
// helpers.
func TestEveryRepeatedAuditFailureIsCounted(t *testing.T) {
	captureAuditReports(t)
	d := openFresh(t).AsProject()
	setReadOnly(t, d, true)

	const n = 25
	for i := 0; i < n; i++ {
		AuditTaskStatus(d, i+1, "pending", "done", "test")
	}
	acct := accountFor(t, d)
	if acct.Unrecorded.Events != n || acct.Unrecorded.Appends != n {
		t.Fatalf("%d failed task.status appends counted as %d events in %d appends, want %d",
			n, acct.Unrecorded.Events, acct.Unrecorded.Appends, n)
	}
	if got := acct.Unrecorded.Actions["task.status"]; got != n {
		t.Errorf("task.status lost %d, want %d", got, n)
	}

	setReadOnly(t, d, false)
	AuditTaskStatus(d, 99, "pending", "done", "test")
	rep, err := d.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if rep.GapEvents != n || rep.Total != 2 {
		t.Errorf("after recovery the chain has %d rows and its gaps cover %d events; want 2 rows covering %d",
			rep.Total, rep.GapEvents, n)
	}
}

// A gap row that cannot be written is not itself a loss: the claim is owed
// again and counting carries on, rather than breeding gap rows about gap rows.
func TestAuditGapFailureDoesNotRecurse(t *testing.T) {
	captureAuditReports(t)
	d := openFresh(t).AsControlPlane()
	refuseAuditWrites(t, d, true)

	_ = d.AppendAuditEvent(testEvent(auditaction.ActionExecutorCordon))
	before := metricValue(t, "cloop_audit_append_failures_total", "chain", "control-plane", "reason", "readonly")

	FlushAuditGaps(GapRecordedByFlush) // the gap row's own write fails here
	FlushAuditGaps(GapRecordedByFlush)

	acct := accountFor(t, d)
	if acct.Unrecorded.Events != 1 || acct.TotalEvents != 1 {
		t.Fatalf("a failed gap write changed the loss: %+v", acct)
	}
	if acct.GapWriteFailures != 2 || acct.LastGapError == "" {
		t.Errorf("gap write failures = %d (%q), want 2 recorded on the account", acct.GapWriteFailures, acct.LastGapError)
	}
	if got := metricValue(t, "cloop_audit_append_failures_total", "chain", "control-plane", "reason", "readonly"); got != before {
		t.Errorf("a failed gap write was counted as a lost event (%v -> %v)", before, got)
	}

	// And a later failure is still counted.
	_ = d.AppendAuditEvent(testEvent(auditaction.ActionExecutorDrain))
	if acct := accountFor(t, d); acct.Unrecorded.Events != 2 {
		t.Errorf("unrecorded = %d after a second failure, want 2", acct.Unrecorded.Events)
	}

	refuseAuditWrites(t, d, false)
	FlushAuditGaps(GapRecordedByFlush)
	rows, _, err := d.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EventType != string(auditaction.ActionAuditGap) {
		t.Fatalf("after the flush the chain holds %v, want one gap row", rows)
	}
	var p AuditGapPayload
	_ = json.Unmarshal([]byte(rows[0].Payload), &p)
	if p.LostEvents != 2 || p.Recorded != GapRecordedByFlush {
		t.Errorf("flushed gap = %+v", p)
	}
}

// The account is per database: a loss in one chain is recorded in that chain,
// not in whichever chain next succeeds.
func TestAuditFailureAccountsArePerDatabase(t *testing.T) {
	captureAuditReports(t)
	lossy := openFresh(t).AsProject()
	other := openFresh(t).AsProject()

	setReadOnly(t, lossy, true)
	_ = lossy.AppendAuditEvent(testEvent(auditaction.ActionTaskUpsert))

	if err := other.AppendAuditEvent(testEvent(auditaction.ActionTaskUpsert)); err != nil {
		t.Fatal(err)
	}
	if rep, _ := other.VerifyAuditChain(); rep.Gaps != 0 {
		t.Fatalf("the other database recorded %d gap(s) for a loss that was not its own", rep.Gaps)
	}

	// A second handle over the lossy file shares its account: the hub opens
	// the control plane afresh for nearly every request.
	setReadOnly(t, lossy, false)
	second, err := Open(lossy.path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.AppendAuditEvent(testEvent(auditaction.ActionTaskUpsert)); err != nil {
		t.Fatal(err)
	}
	if rep, _ := lossy.VerifyAuditChain(); rep.Gaps != 1 || rep.GapEvents != 1 {
		t.Errorf("the lossy database records %d gap(s) covering %d, want 1 covering 1", rep.Gaps, rep.GapEvents)
	}
}

// A handle that was closed cannot record its chain's loss; the flush opens
// one of its own.
func TestAuditGapFlushOpensItsOwnHandle(t *testing.T) {
	captureAuditReports(t)
	path := freshPath(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if err := d.AppendAuditEvent(testEvent(auditaction.ActionStateSave)); err == nil {
		t.Fatal("append through a closed handle succeeded")
	}
	if acct := accountFor(t, d); acct.Unrecorded.Events != 1 || acct.Unrecorded.Reasons[hubmetrics.AuditFailClosed] != 1 {
		t.Fatalf("closed-handle failure accounted as %+v", acct)
	}

	FlushAuditGaps(GapRecordedAtShutdown)

	check, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	rep, err := check.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Gaps != 1 || rep.GapEvents != 1 {
		t.Errorf("after the flush the chain records %d gap(s) covering %d, want 1 covering 1", rep.Gaps, rep.GapEvents)
	}
}

// A process that dies owing the trail leaves its status file behind; the next
// process to start there adopts the loss and records it.
func TestAuditFailureStatusIsAdoptedFromAnExitedProcess(t *testing.T) {
	captureAuditReports(t)
	// A project's database, where cloop keeps one: adoption refuses a path
	// that is not.
	dbPath := filepath.Join(t.TempDir(), ".cloop", "state.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	freshTemplate().Seed(t, dbPath)
	statusDir := filepath.Join(t.TempDir(), "audit-failures")
	if err := os.MkdirAll(statusDir, 0o700); err != nil {
		t.Fatal(err)
	}

	host, _ := os.Hostname()
	const deadPID = 1 << 30 // above any pid_max: certainly not running
	dead := AuditFailureStatus{
		PID: deadPID, Host: host, UpdatedAt: time.Now().UTC(),
		Chains: []AuditChainFailures{{
			Path:  dbPath,
			Chain: hubmetrics.AuditChainProject,
			Unrecorded: AuditLoss{
				Events: 3, Appends: 2,
				FirstAt: time.Now().Add(-time.Hour).UTC(), LastAt: time.Now().Add(-time.Minute).UTC(),
				FirstError: "database or disk is full", LastError: "database or disk is full",
				Actions: map[string]int64{"task.upsert": 3}, Reasons: map[string]int64{"full": 3},
				PIDs: []int{deadPID},
			},
			TotalEvents: 3,
		}},
	}
	body, _ := json.Marshal(dead)
	deadFile := filepath.Join(statusDir, "gone-"+strconv.Itoa(deadPID)+".json")
	if err := os.WriteFile(deadFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// A planted file naming some other application's database is not adopted:
	// recording the gap would open it and apply cloop's migrations to it.
	foreign := filepath.Join(t.TempDir(), "someone-elses.sqlite")
	if err := os.WriteFile(foreign, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	planted := dead
	planted.PID = deadPID + 1
	planted.Chains = []AuditChainFailures{{Path: foreign, Unrecorded: AuditLoss{Events: 9, Appends: 1}}}
	plantedBody, _ := json.Marshal(planted)
	if err := os.WriteFile(filepath.Join(statusDir, "planted.json"), plantedBody, 0o600); err != nil {
		t.Fatal(err)
	}

	statuses, err := ReadAuditFailureStatus(statusDir)
	if err != nil || len(statuses) != 2 || statuses[0].ProcessRunning() {
		t.Fatalf("status read = %+v, %v; want two files of exited processes", statuses, err)
	}

	adopted, err := AdoptAuditFailureStatus(statusDir)
	if err != nil || adopted != 3 {
		t.Fatalf("adopted %d (%v), want 3 — the planted file's 9 refused", adopted, err)
	}
	if fi, err := os.Stat(foreign); err != nil || fi.Size() != 0 {
		t.Errorf("the foreign database was touched: %v %v", fi, err)
	}
	if _, err := os.Stat(deadFile); !os.IsNotExist(err) {
		t.Errorf("the adopted file is still there: %v", err)
	}
	// A second adoption finds nothing: the loss is recorded once.
	if again, _ := AdoptAuditFailureStatus(statusDir); again != 0 {
		t.Errorf("a second adoption took %d more", again)
	}

	d, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.AppendAuditEvent(testEvent(auditaction.ActionTaskUpsert)); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := d.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionAuditGap)})
	if len(rows) != 1 {
		t.Fatalf("%d gap rows after adoption, want 1", len(rows))
	}
	var p AuditGapPayload
	_ = json.Unmarshal([]byte(rows[0].Payload), &p)
	if p.LostEvents != 3 || len(p.AdoptedFrom) != 1 || p.AdoptedFrom[0] != deadPID {
		t.Errorf("adopted gap = %+v, want 3 events adopted from %d", p, deadPID)
	}
}

// The status file is what `cloop hub doctor` reads: written while a loss is
// unrecorded, removed once it is recorded.
func TestAuditFailureStatusFileFollowsTheAccount(t *testing.T) {
	captureAuditReports(t)
	statusDir := filepath.Join(t.TempDir(), "audit-failures")
	SetAuditFailureStatusDir(statusDir)
	t.Cleanup(func() { SetAuditFailureStatusDir("") })

	d := openFresh(t).AsControlPlane()
	refuseAuditWrites(t, d, true)
	_ = d.AppendAuditEvent(testEvent(auditaction.ActionSessionRevoked))
	FlushAuditGaps(GapRecordedByFlush) // still refusing: the file is written

	statuses, err := ReadAuditFailureStatus(statusDir)
	if err != nil {
		t.Fatal(err)
	}
	var mine *AuditChainFailures
	for _, st := range statuses {
		if st.PID != os.Getpid() {
			continue
		}
		for i := range st.Chains {
			if st.Chains[i].Path == d.auditKey {
				mine = &st.Chains[i]
			}
		}
	}
	if mine == nil || mine.Unrecorded.Events != 1 {
		t.Fatalf("the status file does not report this process's loss: %+v", statuses)
	}

	refuseAuditWrites(t, d, false)
	FlushAuditGaps(GapRecordedByFlush)
	statuses, _ = ReadAuditFailureStatus(statusDir)
	for _, st := range statuses {
		for _, c := range st.Chains {
			if c.Path == d.auditKey {
				t.Errorf("the status file still reports a loss that was recorded: %+v", c)
			}
		}
	}
}

func TestClassifyAuditFailure(t *testing.T) {
	cases := map[string]string{
		"attempt to write a readonly database (8)": hubmetrics.AuditFailReadOnly,
		"database or disk is full (13)":            hubmetrics.AuditFailFull,
		"sql: database is closed":                  hubmetrics.AuditFailClosed,
		"disk I/O error (10)":                      hubmetrics.AuditFailIO,
		"database is locked (5)":                   hubmetrics.AuditFailLocked,
		"something else entirely":                  hubmetrics.AuditFailOther,
	}
	for msg, want := range cases {
		if got := classifyAuditFailure(errString(msg)); got != want {
			t.Errorf("classify(%q) = %s, want %s", msg, got, want)
		}
	}
	if got := classifyAuditFailure(ErrDBLocked); got != hubmetrics.AuditFailLocked {
		t.Errorf("classify(ErrDBLocked) = %s", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// The histogram a loss carries is bounded, whatever reaches the append path.
func TestAuditLossHistogramIsBounded(t *testing.T) {
	var l AuditLoss
	for i := 0; i < auditLossMaxActions*3; i++ {
		l.add([]*AuditEvent{{EventType: "made.up." + strconv.Itoa(i)}}, "other", "x", time.Now())
	}
	if len(l.Actions) > auditLossMaxActions+1 {
		t.Errorf("histogram holds %d actions, cap is %d plus the overflow bucket", len(l.Actions), auditLossMaxActions)
	}
	if l.Actions[auditLossOtherAction] == 0 {
		t.Error("nothing went to the overflow bucket")
	}
	if l.Events != int64(auditLossMaxActions*3) {
		t.Errorf("events = %d", l.Events)
	}
}

func gapCountsOf(list []AuditGapCount) map[string]int64 {
	out := map[string]int64{}
	for _, c := range list {
		out[c.Name] += c.Events
	}
	return out
}

// Every payload passes through key-based redaction, and the actions an
// auditor most needs counted — secret.lease, api_token.created — are exactly
// the names it withholds as keys. The gap row keeps them as values, so their
// counts survive, and the count every reader needs survives either way.
func TestAuditGapCountsSurviveRedaction(t *testing.T) {
	captureAuditReports(t)
	d := openFresh(t).AsControlPlane()
	setReadOnly(t, d, true)
	for _, a := range []auditaction.Action{
		auditaction.ActionSecretLease, auditaction.ActionSecretLease, auditaction.ActionAPITokenCreated,
	} {
		_ = d.AppendAuditEvent(testEvent(a))
	}
	setReadOnly(t, d, false)
	if err := d.AppendAuditEvent(testEvent(auditaction.ActionExecutorCordon)); err != nil {
		t.Fatal(err)
	}
	rows, _, err := d.ListAuditEvents(AuditFilter{EventType: string(auditaction.ActionAuditGap)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("gap rows: %v %v", rows, err)
	}
	if strings.Contains(rows[0].Payload, "[redacted]") {
		t.Errorf("the gap row was redacted: %s", rows[0].Payload)
	}
	var p AuditGapPayload
	if err := json.Unmarshal([]byte(rows[0].Payload), &p); err != nil {
		t.Fatalf("gap payload: %v\n%s", err, rows[0].Payload)
	}
	got := gapCountsOf(p.Actions)
	if got["secret.lease"] != 2 || got["api_token.created"] != 1 {
		t.Errorf("histogram = %v", p.Actions)
	}
	if rep, _ := d.VerifyAuditChain(); rep.GapEvents != 3 {
		t.Errorf("verify counts %d lost events, want 3", rep.GapEvents)
	}
	// A reader wanting only the count gets it from a payload of any shape —
	// including the map form an older build wrote.
	if n := AuditGapLostEvents(`{"lost_events":7,"actions":{"secret.lease":"[redacted]"}}`); n != 7 {
		t.Errorf("AuditGapLostEvents = %d, want 7", n)
	}
}

// A hub in a container is PID 1 every time it starts, and a replacement Pod
// has a new hostname: neither may make a dead process's file look live. And a
// loss its writer recorded before dying — the gap row committed, the file not
// yet rewritten — is not recorded a second time.
func TestAuditFailureStatusLivenessAndDedup(t *testing.T) {
	captureAuditReports(t)
	host, _ := os.Hostname()
	now := time.Now().UTC()

	cases := []struct {
		name    string
		st      AuditFailureStatus
		running bool
	}{
		{"this process", AuditFailureStatus{PID: os.Getpid(), Host: host, Instance: processInstance, UpdatedAt: now}, true},
		{"this process, its file gone stale", AuditFailureStatus{PID: os.Getpid(), Host: host, Instance: processInstance, UpdatedAt: now.Add(-time.Hour)}, true},
		{"an earlier process with this PID", AuditFailureStatus{PID: os.Getpid(), Host: host, Instance: "earlier", UpdatedAt: now}, false},
		{"a live PID of another start", AuditFailureStatus{PID: 1, Host: host, ProcStart: "not-its-start-time", UpdatedAt: now}, procStartTime(1) == ""},
		{"another host, fresh", AuditFailureStatus{PID: 7, Host: host + "-elsewhere", UpdatedAt: now}, true},
		{"another host, stale", AuditFailureStatus{PID: 7, Host: host + "-elsewhere", UpdatedAt: now.Add(-time.Hour)}, false},
	}
	for _, c := range cases {
		if got := c.st.ProcessRunning(); got != c.running {
			t.Errorf("%s: ProcessRunning = %v, want %v", c.name, got, c.running)
		}
	}

	// Dedup: the dead process recorded its loss, then died before rewriting
	// its file.
	dbPath := filepath.Join(t.TempDir(), ".cloop", "state.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	freshTemplate().Seed(t, dbPath)
	d, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const deadPID = 1<<30 + 7
	loss := AuditLoss{Events: 2, Appends: 2, FirstAt: now.Add(-time.Minute), LastAt: now,
		Actions: map[string]int64{"task.upsert": 2}, Reasons: map[string]int64{"full": 2}, PIDs: []int{deadPID}}
	if _, err := d.appendAuditGap(loss, GapRecordedOnRecovery, 1); err != nil {
		t.Fatal(err)
	}
	statusDir := t.TempDir()
	body, _ := json.Marshal(AuditFailureStatus{PID: deadPID, Host: host, UpdatedAt: now,
		Chains: []AuditChainFailures{{Path: dbPath, Unrecorded: loss}}})
	if err := os.WriteFile(filepath.Join(statusDir, "dead.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := AdoptAuditFailureStatus(statusDir); err != nil || n != 0 {
		t.Errorf("adopted %d (%v) of a loss already in the chain, want 0", n, err)
	}

	// The file lists more than the process got to record: two recorded, three
	// more lost after. Only the three are adopted.
	more := loss
	more.Events, more.Appends = 5, 5
	body, _ = json.Marshal(AuditFailureStatus{PID: deadPID, Host: host, UpdatedAt: now,
		Chains: []AuditChainFailures{{Path: dbPath, Unrecorded: more}}})
	if err := os.WriteFile(filepath.Join(statusDir, "dead-more.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := AdoptAuditFailureStatus(statusDir); err != nil || n != 3 {
		t.Errorf("adopted %d (%v) of a loss partly recorded, want the 3 that were not", n, err)
	}

	// A planted file naming a symlink that resolves outside .cloop is
	// refused, though the path as written looks like a cloop database.
	foreignDir := t.TempDir()
	foreign := filepath.Join(foreignDir, "app.sqlite")
	if err := os.WriteFile(foreign, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), ".cloop")
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "state.db")
	if err := os.Symlink(foreign, link); err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(AuditFailureStatus{PID: deadPID + 1, Host: host, UpdatedAt: now,
		Chains: []AuditChainFailures{{Path: link, Unrecorded: AuditLoss{Events: 5, Appends: 1, FirstAt: now, PIDs: []int{deadPID + 1}}}}})
	if err := os.WriteFile(filepath.Join(statusDir, "planted.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, _ := AdoptAuditFailureStatus(statusDir); n != 0 {
		t.Errorf("adopted %d events for a database that is not cloop's", n)
	}
	if fi, err := os.Stat(foreign); err != nil || fi.Size() != 0 {
		t.Errorf("the foreign file was written: %v %v", fi, err)
	}
	// The entry it could not adopt is kept where the doctor reads it, and
	// adoption does not take it up again.
	statuses, err := ReadAuditFailureStatus(statusDir)
	if err != nil {
		t.Fatal(err)
	}
	var kept bool
	for _, st := range statuses {
		if strings.HasPrefix(filepath.Base(st.File), "unadoptable-") && len(st.Chains) == 1 && st.Chains[0].Path == link {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the unadoptable entry was not kept: %+v", statuses)
	}
	if n, _ := AdoptAuditFailureStatus(statusDir); n != 0 {
		t.Errorf("an unadoptable entry was retried into %d events", n)
	}
}
