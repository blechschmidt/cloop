package auditforward

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditretention"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// rawExec runs statements against path behind statedb's back, as someone
// holding the file would.
func rawExec(t testing.TB, path string, stmts ...string) {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, s := range stmts {
		if _, err := conn.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// rehashFrom rewrites the payload of row from and re-hashes every row after it
// so the chain verifies again: the rewrite a hash chain alone cannot catch.
func rehashFrom(t testing.TB, path string, from int64) {
	t.Helper()
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	prevRow, ok, err := db.AuditRowAt(from - 1)
	if err != nil || !ok {
		t.Fatalf("row %d: %v", from-1, err)
	}
	rows, err := db.ReadAuditRange(from, 1<<62, 5000)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	prev := prevRow.RowHash
	for i, ev := range rows {
		if i == 0 {
			ev.Payload = `{"rewritten":true}`
		}
		ev.PrevHash = prev
		want, _ := statedb.AuditChainLink(ev)
		if _, err := conn.Exec(`UPDATE audit_events SET payload = ?, prev_hash = ?, row_hash = ? WHERE id = ?`,
			ev.Payload, ev.PrevHash, want, ev.ID); err != nil {
			t.Fatal(err)
		}
		prev = want
	}
}

// A chain re-hashed after the forwarder sent it is sent again from the newest
// point the sink acknowledged that the chain still holds: the receiver holds
// both versions of the rewritten rows — forks, by id — and the hub records the
// discontinuity.
func TestARewrittenChainIsResentAsAFork(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 30)
	collector := newHTTPSReceiver(t)
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "siem", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t), BatchSize: 4,
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the chain to be delivered", 20*time.Second, func() bool {
		return cursorOf(t, cp, "siem", proj).AckedID == 30
	})

	rehashFrom(t, proj, 21)
	appendRows(t, proj, 2)
	waitForLogged(t, h, "the rewritten chain to be delivered", 20*time.Second, func() bool {
		c := cursorOf(t, cp, "siem", proj)
		return c.AckedID == 32 && len(auditRows(t, cp, auditaction.ActionAuditForwardDiscontinuity)) > 0
	})

	v := chainVerdict(t, verify(t, collector.stream()), SourceProject, projDir)
	if len(v.Forks) == 0 || v.Forks[0] != 21 {
		t.Fatalf("forks at %v; the rewritten rows should arrive beside the originals from id 21", v.Forks)
	}
	if len(v.Gaps) != 0 || len(v.BadHashes) != 0 {
		t.Fatalf("the resend left gaps %v or bad hashes %v", v.Gaps, v.BadHashes)
	}
	disc := auditRows(t, cp, auditaction.ActionAuditForwardDiscontinuity)
	if !strings.Contains(disc[0].Payload, `"reason":"rewritten"`) || !strings.Contains(disc[0].Payload, `"cursor_id":30`) {
		t.Errorf("discontinuity row = %s, want reason rewritten at cursor 30", disc[0].Payload)
	}
}

// A tail deleted after it was forwarded, and written past, arrives at the
// sink as a second version of the ids it reused, while the deleted rows stay
// at the sink as they were.
func TestATruncatedTailWrittenPastArrivesAsAFork(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 20)
	collector := newHTTPSReceiver(t)
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "siem", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t), BatchSize: 3,
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the chain to be delivered", 20*time.Second, func() bool {
		return cursorOf(t, cp, "siem", proj).AckedID == 20
	})

	rawExec(t, proj, `DELETE FROM audit_events WHERE id > 14`)
	appendRows(t, proj, 3) // ids 15..17 again, with other contents
	waitForLogged(t, h, "the new rows to be delivered", 20*time.Second, func() bool {
		return cursorOf(t, cp, "siem", proj).AckedID == 17
	})

	v := chainVerdict(t, verify(t, collector.stream()), SourceProject, projDir)
	if v.LastID != 20 {
		t.Fatalf("the sink holds ids up to %d; the deleted rows 15…20 must still be there", v.LastID)
	}
	if len(v.Forks) != 3 || v.Forks[0] != 15 {
		t.Fatalf("forks at %v; ids 15…17 should arrive in two versions", v.Forks)
	}
	disc := auditRows(t, cp, auditaction.ActionAuditForwardDiscontinuity)
	if len(disc) != 1 || !strings.Contains(disc[0].Payload, `"reason":"truncated"`) {
		t.Fatalf("discontinuity rows = %+v, want one with reason truncated", disc)
	}
}

// Retention stops at the slowest live sink's cursor: a prune asked to remove
// everything removes only what every sink acknowledged, and says which sink
// held the rest. Forced past it, the prune removes the rest, and the forwarder
// records what the slow sink lost.
func TestAPruneRefusesToPassAnUnacknowledgedCursor(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 25)
	fast := filepath.Join(t.TempDir(), "fast.jsonl")
	slow := newHTTPSReceiver(t)
	// slow takes its first batch and refuses everything after, until it is
	// brought back up.
	var slowUp atomic.Bool
	slow.status = func(n int) int {
		if n == 1 || slowUp.Load() {
			return http.StatusOK
		}
		return http.StatusServiceUnavailable
	}
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{
		{Name: "fast", Type: config.AuditSinkFile, Path: fast},
		{Name: "slow", Type: config.AuditSinkHTTPS, URL: slow.srv.URL, CAFile: slow.caFile(t), BatchSize: 5},
	}})
	_, stop := h.start(Hooks{})
	waitForLogged(t, h, "fast to deliver everything and slow its first batch", 20*time.Second, func() bool {
		return cursorOf(t, cp, "fast", proj).AckedID == 25 && cursorOf(t, cp, "slow", proj).AckedID == 5
	})
	stop()

	db, err := statedb.Open(proj)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hold, held, consulted, err := RetentionHold(db, proj, "")
	if err != nil || !held {
		t.Fatalf("RetentionHold = %+v, %v, %v; the project names the hub forwarding it", hold, held, err)
	}
	if hold.Sink != "slow" || hold.ThroughID != 5 || len(consulted) != 2 {
		t.Fatalf("hold = %+v (consulted %v), want slow at id 5 read from the project and its hub", hold, consulted)
	}
	cutoff := time.Now().Add(time.Hour)
	archive := t.TempDir()
	rep, err := auditretention.Prune(db, auditretention.Options{Before: cutoff, ExportDir: archive, Hold: &hold})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clamped || rep.HeldBy != "slow" || rep.Candidate.ThroughID != 5 || rep.Requested.ThroughID != 25 {
		t.Fatalf("report = %+v; want the prune of 1…25 clamped to slow's 5", rep)
	}
	if head, _ := db.AuditHead(); head.FirstID != 6 {
		t.Fatalf("the chain starts at %d after the prune; only rows slow acknowledged may go", head.FirstID)
	}

	// Forced: the rest goes, and slow — back up — is told what it lost.
	rep, err = auditretention.Prune(db, auditretention.Options{Before: cutoff, ExportDir: archive, Hold: &hold, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Pruned || len(rep.ForcedPast) != 1 || rep.ForcedPast[0] != "slow" {
		t.Fatalf("forced report = %+v, want slow named as forced past", rep)
	}
	appendRows(t, proj, 2)
	slowUp.Store(true)
	h.start(Hooks{})
	waitForLogged(t, h, "slow to resume past the prune", 20*time.Second, func() bool {
		return cursorOf(t, cp, "slow", proj).AckedID == 27
	})
	disc := auditRows(t, cp, auditaction.ActionAuditForwardDiscontinuity)
	if len(disc) != 1 || !strings.Contains(disc[0].Payload, `"reason":"pruned"`) ||
		!strings.Contains(disc[0].Payload, `"lost_rows":20`) {
		t.Fatalf("discontinuity rows = %+v, want one: pruned, 20 rows lost", disc)
	}
	v := chainVerdict(t, verify(t, slow.stream()), SourceProject, projDir)
	if len(v.Gaps) != 1 || v.Gaps[0] != (IDRange{From: 6, To: 25}) {
		t.Fatalf("slow's stream has gaps %v; the rows forced out before it got them are the gap 6…25", v.Gaps)
	}
}

// A sink taken out of the configuration stops holding retention: its cursors
// are retired, and the hold is the remaining sinks'.
func TestARemovedSinkStopsHoldingRetention(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 10)
	down := newHTTPSReceiver(t)
	down.status = func(int) int { return http.StatusServiceUnavailable }
	out := filepath.Join(t.TempDir(), "copy.jsonl")
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	file := config.AuditForwardSink{Name: "file", Type: config.AuditSinkFile, Path: out}
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{
		file, {Name: "gone", Type: config.AuditSinkHTTPS, URL: down.srv.URL, CAFile: down.caFile(t)},
	}})
	h.start(Hooks{})
	waitForLogged(t, h, "file to deliver", 10*time.Second, func() bool {
		return cursorOf(t, cp, "file", cp).AckedID == maxID(t, cp) && cursorOf(t, cp, "gone", cp).Sink == "gone"
	})
	holdOf := func() statedb.AuditForwardHold {
		db, err := statedb.Open(cp)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		hold, _, err := db.AuditForwardHoldFor(cp)
		if err != nil {
			t.Fatal(err)
		}
		return hold
	}
	if hold := holdOf(); hold.Sink != "gone" || hold.ThroughID != 0 {
		t.Fatalf("hold = %+v, want the down sink holding everything", hold)
	}
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{file}})
	waitForLogged(t, h, "the removed sink's cursor to be retired", 10*time.Second, func() bool {
		return cursorOf(t, cp, "gone", cp).Retired()
	})
	if hold := holdOf(); hold.Sink != "file" {
		t.Fatalf("hold = %+v, want only the configured sink holding", hold)
	}
}

// start: latest begins each chain at its head when the forwarder first meets
// it, and sends what is written after.
func TestStartLatestBeginsAtTheHead(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 15)
	collector := newHTTPSReceiver(t)
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "new", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t),
		Start: config.AuditStartLatest,
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the cursor to be created at the head", 10*time.Second, func() bool {
		return cursorOf(t, cp, "new", proj).AckedID == 15
	})
	appendRows(t, proj, 3)
	waitForLogged(t, h, "the new rows", 10*time.Second, func() bool { return collector.count() == 3 })
	v := chainVerdict(t, verify(t, collector.stream()), SourceProject, projDir)
	if v.FirstID != 16 || v.LastID != 18 || !v.OK() {
		t.Fatalf("received %+v, want ids 16…18 and nothing before", v)
	}
}

// A sink that is down from the moment it is configured still holds retention
// on every chain: each gets its cursor before anything is sent, so no prune
// can remove rows the sink has never had (Task 20426).
func TestASinkDownFromTheStartHoldsEveryChain(t *testing.T) {
	hubDir, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, cp, 3)
	appendRows(t, proj, 9)
	down := newHTTPSReceiver(t)
	down.status = func(int) int { return http.StatusServiceUnavailable }
	h := newHarness(t, cp,
		Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp},
		Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "down", Type: config.AuditSinkHTTPS, URL: down.srv.URL, CAFile: down.caFile(t),
	}}})
	fwd, _ := h.start(Hooks{})
	waitForLogged(t, h, "both chains to have a cursor", 10*time.Second, func() bool {
		return cursorOf(t, cp, "down", cp).Sink == "down" && cursorOf(t, cp, "down", proj).Sink == "down"
	})
	db, err := statedb.Open(proj)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hold, held, _, err := RetentionHold(db, proj, "")
	if err != nil || !held || hold.ThroughID != 0 {
		t.Fatalf("hold on the project chain = %+v, %v, %v; the down sink must hold all of it", hold, held, err)
	}
	// And its backlog counts every chain, not only the one whose send failed.
	waitForLogged(t, h, "the backlog to cover both chains", 10*time.Second, func() bool {
		for _, st := range fwd.Snapshot() {
			if st.Name == "down" && st.Backlog() >= 12 {
				return true
			}
		}
		return false
	})
}

// audit.gap rows are forwarded like any other row, and a payload reaches the
// sink with the redaction it was written with: the forwarder sends what the
// chain holds.
func TestGapRowsAndRedactedPayloadsReachTheSinkAsWritten(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 2)
	// Lose an append, through a handle closed under its emitter; the next
	// append that succeeds records the loss as an audit.gap row.
	closed, err := statedb.Open(proj)
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	var lost statedb.AuditEvent
	lost.EventType = string(auditaction.ActionTaskUpsert)
	if err := closed.AppendAuditEvent(&lost); err == nil {
		t.Fatal("an append through a closed handle succeeded")
	}
	db, err := statedb.Open(proj)
	if err != nil {
		t.Fatal(err)
	}
	var ev statedb.AuditEvent
	ev.EventType, ev.EntityType = string(auditaction.ActionTaskUpsert), "task"
	ev.Payload = statedb.MarshalAuditPayload(map[string]any{"note": "kept", "token": "ghp_" + "notreallyatoken000000000000000000000"})
	if err := db.AppendAuditEvent(&ev); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	out := filepath.Join(t.TempDir(), "sink.jsonl")
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{Name: "f", Type: config.AuditSinkFile, Path: out}}})
	h.start(Hooks{})
	waitForLogged(t, h, "delivery", 10*time.Second, func() bool { return cursorOf(t, cp, "f", proj).AckedID == maxID(t, proj) })
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	stream := string(b)
	if !strings.Contains(stream, `"event_type":"audit.gap"`) || !strings.Contains(stream, `"lost_events":1`) {
		t.Fatalf("the audit.gap row did not reach the sink:\n%s", stream)
	}
	if !strings.Contains(stream, `"token":"[redacted]"`) || strings.Contains(stream, "notreallyatoken") {
		t.Fatalf("the payload did not arrive as it was written, redacted:\n%s", stream)
	}
	if v := chainVerdict(t, verify(t, stream), SourceProject, projDir); !v.OK() {
		t.Fatalf("the stream does not verify: %+v", v)
	}
}
