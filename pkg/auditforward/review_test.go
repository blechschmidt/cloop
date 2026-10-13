package auditforward

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// A leader that starts with no sinks configured still takes the cursors of
// sinks removed while the hub was down out of service: they must not hold
// retention for a sink nothing forwards to.
func TestAStartWithNoSinksRetiresLeftoverCursors(t *testing.T) {
	hubDir, cp := chainDir(t)
	db, err := statedb.Open(cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InitAuditForwardCursor(statedb.AuditForwardCursor{
		Sink: "removed", Chain: cp, AckedID: 0, AckedHash: statedb.AuditGenesisHash,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.setConfig(config.AuditForwardConfig{})
	h.start(Hooks{})
	waitForLogged(t, h, "the leftover cursor to be retired", 10*time.Second, func() bool {
		return cursorOf(t, cp, "removed", cp).Retired()
	})
}

// A chain that drops out of the served list for a pass and comes back has its
// cursor back in service while its sink is still down in backoff — the hold
// must not lapse for the rest of the outage.
func TestAChainThatReturnsIsHeldAgainWhileItsSinkIsDown(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 5)
	down := newHTTPSReceiver(t)
	down.status = func(int) int { return http.StatusServiceUnavailable }
	project := Chain{Source: SourceProject, Dir: projDir, Path: proj}
	h := newHarness(t, cp, project)
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "down", Type: config.AuditSinkHTTPS, URL: down.srv.URL, CAFile: down.caFile(t),
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the cursor", 10*time.Second, func() bool { return cursorOf(t, cp, "down", proj).Sink == "down" })
	h.setChains()
	waitForLogged(t, h, "the cursor to be retired", 10*time.Second, func() bool { return cursorOf(t, cp, "down", proj).Retired() })
	h.setChains(project)
	waitForLogged(t, h, "the cursor back in service", 10*time.Second, func() bool {
		c := cursorOf(t, cp, "down", proj)
		return c.Sink == "down" && !c.Retired()
	})
}

// A file that does not end in a newline — a write cut short — gets one before
// the next batch, so the batch's first record is not read as part of the
// fragment.
func TestTheFileSinkStartsAfterAHalfWrittenLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sink.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":7,"timestamp":"2026-10-13T00:00:00Z","ro`), 0o600); err != nil {
		t.Fatal(err)
	}
	ft := &fileTransport{path: path}
	if err := ft.send(context.Background(), []message{{id: 8, data: []byte(`{"id":8}`)}, {id: 9, data: []byte(`{"id":9}`)}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if want := "\"ro\n{\"id\":8}\n{\"id\":9}\n"; !bytes.HasSuffix(b, []byte(want)) {
		t.Fatalf("file = %q; the batch must begin on a line of its own", b)
	}
}

// A hole inside what one batch read is noticed where it falls, not only on a
// batch boundary: the batch stops before it, the break is recorded with the
// rows it lost, and what follows is forwarded as it stands.
func TestAGapInsideABatchIsRecorded(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 12)
	rawExec(t, proj, `DELETE FROM audit_events WHERE id IN (5, 6)`)
	out := filepath.Join(t.TempDir(), "sink.jsonl")
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{Name: "f", Type: config.AuditSinkFile, Path: out, BatchSize: 50}}})
	h.start(Hooks{})
	waitForLogged(t, h, "delivery past the hole", 10*time.Second, func() bool { return cursorOf(t, cp, "f", proj).AckedID == 12 })
	disc := auditRows(t, cp, auditaction.ActionAuditForwardDiscontinuity)
	if len(disc) != 1 || !strings.Contains(disc[0].Payload, `"reason":"broken"`) ||
		!strings.Contains(disc[0].Payload, `"lost_rows":2`) || !strings.Contains(disc[0].Payload, `"cursor_id":4`) {
		t.Fatalf("discontinuity rows = %+v; want one: broken after id 4, two rows lost", disc)
	}
	b, _ := os.ReadFile(out)
	if v := chainVerdict(t, verify(t, string(b)), SourceProject, projDir); len(v.Gaps) != 1 || v.Gaps[0] != (IDRange{From: 5, To: 6}) {
		t.Fatalf("the sink's stream: %+v; want the hole 5…6 and nothing else missing", v)
	}
}

// A payload whose escaping lengthens it still fits the syslog message size:
// the encoded message is measured, not the raw excerpt.
func TestAnEscapedPayloadStillFitsTheSyslogMessageSize(t *testing.T) {
	enc := &encoder{cfg: config.AuditForwardSink{Name: "s", Type: config.AuditSinkSyslog}, hub: "h", version: "t"}
	var ev statedb.AuditEvent
	ev.ID, ev.Timestamp, ev.Actor, ev.EventType = 3, time.Now().UTC(), "a", "task.upsert"
	ev.Payload = `{"x":"` + strings.Repeat(`<&>`, 5000) + `"}`
	ev.PrevHash, ev.RowHash = strings.Repeat("0", 64), strings.Repeat("1", 64)
	m, err := enc.encode(ev, Chain{Source: SourceProject, Dir: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.truncated || len(m.data) > config.AuditForwardMaxMessageBytesDefault {
		t.Fatalf("message of %d bytes (truncated %v); the bound is %d", len(m.data), m.truncated, config.AuditForwardMaxMessageBytesDefault)
	}
}

// The hold is found through a path that reaches the database by another
// spelling — a symlinked directory — and a hub named on the command line that
// does not exist is an error, not "nothing holds it".
func TestTheRetentionHoldMatchesTheFileNotItsSpelling(t *testing.T) {
	_, cp := chainDir(t)
	projDir, proj := chainDir(t)
	appendRows(t, proj, 4)
	down := newHTTPSReceiver(t)
	down.status = func(int) int { return http.StatusServiceUnavailable }
	h := newHarness(t, cp, Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "down", Type: config.AuditSinkHTTPS, URL: down.srv.URL, CAFile: down.caFile(t),
	}}})
	_, stop := h.start(Hooks{})
	waitForLogged(t, h, "the cursor", 10*time.Second, func() bool { return cursorOf(t, cp, "down", proj).Sink == "down" })
	stop()

	link := filepath.Join(t.TempDir(), "via-link")
	if err := os.Symlink(projDir, link); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(link, ".cloop", "state.db")
	db, err := statedb.Open(viaLink)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hold, held, _, err := RetentionHold(db, viaLink, "")
	if err != nil || !held || hold.Sink != "down" {
		t.Fatalf("hold through a symlinked path = %+v, %v, %v; want the down sink's", hold, held, err)
	}
	if _, _, _, err := RetentionHold(db, viaLink, filepath.Join(t.TempDir(), "typo", ".cloop", "state.db")); !errors.Is(err, ErrHoldUnreadable) {
		t.Fatalf("a named hub that does not exist = %v, want ErrHoldUnreadable", err)
	}
}

// A row the sink refuses for its content holds up its own chain, not every
// chain behind it.
func TestARefusedRowHoldsUpOnlyItsOwnChain(t *testing.T) {
	hubDir, cp := chainDir(t)
	projDir, proj := chainDir(t)
	db, err := statedb.Open(cp)
	if err != nil {
		t.Fatal(err)
	}
	var poison statedb.AuditEvent
	poison.EventType, poison.Payload = string(auditaction.ActionTaskUpsert), `{"poison":true}`
	if err := db.AppendAuditEvent(&poison); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	appendRows(t, proj, 6)
	collector := newHTTPSReceiver(t)
	collector.reject = func(body []byte) bool { return bytes.Contains(body, []byte(`poison`)) }
	h := newHarness(t, cp,
		Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp},
		Chain{Source: SourceProject, Dir: projDir, Path: proj})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{
		Name: "picky", Type: config.AuditSinkHTTPS, URL: collector.srv.URL, CAFile: collector.caFile(t),
	}}})
	h.start(Hooks{})
	waitForLogged(t, h, "the project chain to be delivered past the refused control-plane row", 15*time.Second, func() bool {
		return cursorOf(t, cp, "picky", proj).AckedID == 6
	})
	if c := cursorOf(t, cp, "picky", cp); c.AckedID != 0 || c.LastError == "" {
		t.Fatalf("control-plane cursor = %+v; the refused row must hold it, with the refusal recorded", c)
	}
}

// A cursor row that disappears under a running forwarder — deleted by hand, a
// control plane restored — is created again, not retried against forever.
func TestADeletedCursorIsCreatedAgain(t *testing.T) {
	hubDir, cp := chainDir(t)
	appendRows(t, cp, 5)
	out := filepath.Join(t.TempDir(), "sink.jsonl")
	h := newHarness(t, cp, Chain{Source: SourceControlPlane, Dir: hubDir, Path: cp})
	h.setConfig(config.AuditForwardConfig{Sinks: []config.AuditForwardSink{{Name: "f", Type: config.AuditSinkFile, Path: out}}})
	h.start(Hooks{})
	waitForLogged(t, h, "delivery", 10*time.Second, func() bool { return cursorOf(t, cp, "f", cp).AckedID == maxID(t, cp) })
	rawExec(t, cp, `DELETE FROM audit_forward_cursors WHERE sink = 'f'`)
	appendRows(t, cp, 2)
	waitForLogged(t, h, "the cursor to be created again and reach the head", 10*time.Second, func() bool {
		c := cursorOf(t, cp, "f", cp)
		return c.Sink == "f" && c.AckedID == maxID(t, cp)
	})
	b, _ := os.ReadFile(out)
	if v := chainVerdict(t, verify(t, string(b)), SourceControlPlane, hubDir); !v.OK() || v.LastID != maxID(t, cp) {
		t.Fatalf("the sink's stream after the cursor was recreated: %+v", v)
	}
}
