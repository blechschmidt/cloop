package ui

// CI relay sessions outlive their hub process (Task 20390). These drive the
// real HTTP stack of ci_api_test.go's harness and play a hub restart in one
// test binary: the service — registry, reaper, audit handle — is dropped and
// the process's member id changes, so the next relay call reaches a hub that
// has never heard of the session, exactly as the job's next call reaches a
// restarted or rolled hub.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ciMembers stands in for the hub cluster: which process this one is, and
// which others are alive.
type ciMembers struct {
	mu    sync.Mutex
	self  string
	alive map[string]bool
	gen   int
	// explode makes asking whether a member is alive panic, as a fault
	// anywhere in a restore would.
	explode bool
}

func (m *ciMembers) current() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.self
}

func (m *ciMembers) isAlive(holder string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.explode {
		panic("ciMembers: asked while exploding")
	}
	return m.alive[holder]
}

// setAlive marks a member live or gone.
func (m *ciMembers) setAlive(holder string, alive bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alive[holder] = alive
}

func (m *ciMembers) setExplode(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.explode = on
}

// next makes this process a new one; the previous one is gone.
func (m *ciMembers) next() (old, cur string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old = m.self
	delete(m.alive, old)
	m.gen++
	m.self = fmt.Sprintf("hub-process-%d", m.gen)
	m.alive[m.self] = true
	return old, m.self
}

// durableCI is a CI harness whose sessions are recorded.
type durableCI struct {
	*ciHarness
	members *ciMembers
}

func newDurableCI(t *testing.T, mutate ...func(*config.Config)) *durableCI {
	t.Helper()
	h := newCIHarness(t, mutate...)
	m := &ciMembers{alive: map[string]bool{}}
	m.next()
	prevHolder, prevAlive := leaseHolderID, ciHolderAlive
	leaseHolderID = m.current
	ciHolderAlive = m.isAlive
	t.Cleanup(func() { leaseHolderID, ciHolderAlive = prevHolder, prevAlive })
	return &durableCI{ciHarness: h, members: m}
}

// restart plays the hub stopping — gracefully, as systemd's SIGTERM, or
// killed — and a new process starting in its place.
func (d *durableCI) restart(t *testing.T, graceful bool) (old, cur string) {
	t.Helper()
	d.waitRelayed()
	if graceful {
		d.srv.closeCI()
	} else if svc := d.srv.ci.svc.Swap(nil); svc != nil {
		// Killed: no checkpoint, no suspension, no close row. The reaper
		// and the handle go with the process.
		svc.stopReaping()
		_ = svc.auditDB.Close()
	}
	// The new process has never been told to stop.
	d.srv.ci.stopped.Store(false)
	return d.members.next()
}

func (d *durableCI) db(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(d.dir))
	if err != nil {
		t.Fatalf("open the hub's database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (d *durableCI) record(t *testing.T, id string) statedb.CISessionRow {
	t.Helper()
	row, err := d.db(t).GetCISession(id)
	if err != nil {
		t.Fatalf("the session's record: %v", err)
	}
	return row
}

// auditOf returns the payloads of the hub's audit rows of one type for one
// session.
func (d *durableCI) auditOf(t *testing.T, eventType, sessionID string) []map[string]any {
	t.Helper()
	events, _, err := d.db(t).ListAuditEvents(statedb.AuditFilter{EventType: eventType, EntityID: sessionID, Limit: 500})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	var out []map[string]any
	for _, e := range events {
		if e.EntityID != sessionID {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(e.Payload), &p)
		out = append(out, p)
	}
	return out
}

func (d *durableCI) exchanges(t *testing.T) int {
	t.Helper()
	rows, err := d.db(t).ListCIExchanges(100)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func ciRelayBodyFor(model string) string {
	return `{"model":"` + model + `","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
}

// TestCI_SessionSurvivesAHubRestart: a job relaying through the hub when it
// restarts — stopped gracefully or killed — carries on with the session it
// has. Its next call is served by the new process without a new exchange: the
// record taken over, the session restored under its id and token, its spend
// carried on.
func TestCI_SessionSurvivesAHubRestart(t *testing.T) {
	for _, graceful := range []bool{true, false} {
		name := "killed"
		if graceful {
			name = "stopped"
		}
		t.Run(name, func(t *testing.T) {
			d := newDurableCI(t)
			d.addRule(t, ciBasicRule)
			_, sess := d.exchange(t, d.forge.token(nil))
			if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
				t.Fatalf("relay before the restart = %d", r.StatusCode)
			}
			rec := d.record(t, sess.SessionID)
			if rec.Holder != d.members.current() || !rec.Open() || strings.Contains(rec.Provenance+rec.Policy, sess.Token) {
				t.Fatalf("the session's record = %+v", rec)
			}
			if !graceful {
				// What the 15-second checkpoint would have written by now.
				d.srv.ci.svc.Load().reg.Checkpoint()
			}
			exchanges := d.exchanges(t)
			restoresBefore := restoreCount(hubmetrics.RestoreKindCI, hubmetrics.RestoreRestored)
			old, cur := d.restart(t, graceful)

			rec = d.record(t, sess.SessionID)
			if !rec.Open() || rec.Holder != old {
				t.Fatalf("after the stop the record = %+v, want it open and still held by %s", rec, old)
			}
			if graceful {
				if got := d.auditOf(t, string(claudeproxy.EventSessionSuspended), sess.SessionID); len(got) != 1 {
					t.Fatalf("suspended rows = %d, want 1", len(got))
				}
			}

			r := d.relay(t, sess.Token, ciRelayBody)
			if r.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(r.Body)
				t.Fatalf("relay after the restart = %d %s", r.StatusCode, b)
			}
			if got := d.exchanges(t); got != exchanges {
				t.Fatalf("exchanges = %d after the restart, was %d: the job federated again", got, exchanges)
			}
			if n := d.up.count(); n != 2 {
				t.Fatalf("the upstream saw %d calls, want 2", n)
			}
			rec = d.record(t, sess.SessionID)
			if rec.Holder != cur || !rec.Open() {
				t.Fatalf("after the restore the record = %+v, want it held by %s", rec, cur)
			}
			restored := d.auditOf(t, string(claudeproxy.EventSessionRestored), sess.SessionID)
			if len(restored) != 1 || !strings.Contains(fmt.Sprint(restored[0]["detail"]), old) {
				t.Fatalf("restored rows = %v, want one naming %s", restored, old)
			}
			if got := restoreCount(hubmetrics.RestoreKindCI, hubmetrics.RestoreRestored); got != restoresBefore+1 {
				t.Errorf("cloop_proxy_session_restores_total{kind=ci,outcome=restored} = %v, was %v", got, restoresBefore)
			}
			svc := d.srv.ci.svc.Load()
			live, ok := svc.reg.Session(sess.SessionID)
			if !ok {
				t.Fatal("the restoring process does not serve the session")
			}
			if u := live.Usage(); u.Requests != 2 || u.OutputTokens != 18 {
				t.Fatalf("restored usage = %+v, want the first call's spend carried on", u)
			}
		})
	}
}

// TestCI_RestoredSessionIsHeldToItsRuleAsItStandsNow: a restore re-reads the
// session's rule. A rule gone, disabled or no longer admitting the pipeline,
// or a hub that no longer federates its identity, gets the job the 401 it
// would have got and closes the session; a narrowed policy applies, a
// widened one does not.
func TestCI_RestoredSessionIsHeldToItsRuleAsItStandsNow(t *testing.T) {
	for _, tc := range []struct {
		name string
		// change is made while no process serves the session, behind the
		// API's back where the API would close the session itself.
		change func(t *testing.T, d *durableCI, db *statedb.DB, ruleID string)
		// calls are relayed after the restart, by model, with the status
		// each must get.
		calls []struct {
			model string
			want  int
		}
		closed string
	}{
		{
			name: "rule deleted",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				if _, err := db.DeleteCIPipelineRule(id); err != nil {
					t.Fatal(err)
				}
			},
			calls: []struct {
				model string
				want  int
			}{{"claude-sonnet-4-6", http.StatusUnauthorized}},
			closed: "its rule was deleted",
		},
		{
			name: "rule disabled",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				editCIRule(t, db, id, func(r *statedb.CIPipelineRuleRow) { r.Enabled = false })
			},
			calls: []struct {
				model string
				want  int
			}{{"claude-sonnet-4-6", http.StatusUnauthorized}},
			closed: "its rule is disabled",
		},
		{
			name: "pipeline no longer admitted",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				editCIRule(t, db, id, func(r *statedb.CIPipelineRuleRow) { r.Repository = "acme/other" })
			},
			calls: []struct {
				model string
				want  int
			}{{"claude-sonnet-4-6", http.StatusUnauthorized}},
			closed: "its rule no longer admits this pipeline",
		},
		{
			name: "identity no longer federated",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				cfg, err := config.Load(d.dir)
				if err != nil {
					t.Fatal(err)
				}
				cfg.UI.CI.Audience = "another-hub"
				if err := config.Save(d.dir, cfg); err != nil {
					t.Fatal(err)
				}
			},
			calls: []struct {
				model string
				want  int
			}{{"claude-sonnet-4-6", http.StatusUnauthorized}},
			closed: "no longer federates",
		},
		{
			name: "narrowed models apply",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				editCIRule(t, db, id, func(r *statedb.CIPipelineRuleRow) { r.Models = []string{"claude-sonnet-4-6"} })
			},
			calls: []struct {
				model string
				want  int
			}{
				{"claude-sonnet-4-6", http.StatusOK}, {"claude-sonnet-5", http.StatusForbidden},
			},
		},
		{
			name: "widened models do not",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				editCIRule(t, db, id, func(r *statedb.CIPipelineRuleRow) { r.Models = []string{"claude-*"} })
			},
			calls: []struct {
				model string
				want  int
			}{
				{"claude-haiku-4-5", http.StatusForbidden}, {"claude-sonnet-4-6", http.StatusOK},
			},
		},
		{
			name: "narrowed budget applies",
			change: func(t *testing.T, d *durableCI, db *statedb.DB, id string) {
				editCIRule(t, db, id, func(r *statedb.CIPipelineRuleRow) { r.MaxRequests = 1 })
			},
			calls: []struct {
				model string
				want  int
			}{{"claude-sonnet-4-6", http.StatusTooManyRequests}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDurableCI(t)
			ruleID := d.addRule(t, ciBasicRule)
			_, sess := d.exchange(t, d.forge.token(nil))
			if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
				t.Fatalf("relay before the restart = %d", r.StatusCode)
			}
			d.restart(t, true)
			tc.change(t, d, d.db(t), ruleID)

			for _, c := range tc.calls {
				r := d.relay(t, sess.Token, ciRelayBodyFor(c.model))
				if r.StatusCode != c.want {
					b, _ := io.ReadAll(r.Body)
					t.Fatalf("relay %s after the restart = %d %s, want %d", c.model, r.StatusCode, b, c.want)
				}
			}
			rec := d.record(t, sess.SessionID)
			if tc.closed == "" {
				if !rec.Open() || rec.Holder != d.members.current() {
					t.Fatalf("the restored session's record = %+v", rec)
				}
				return
			}
			if rec.Open() || !strings.Contains(rec.CloseReason, tc.closed) {
				t.Fatalf("the refused session's record = %+v, want it closed: %s", rec, tc.closed)
			}
			if got := d.auditOf(t, string(claudeproxy.EventSessionClosed), sess.SessionID); len(got) != 1 ||
				!strings.Contains(fmt.Sprint(got[0]["detail"]), tc.closed) {
				t.Fatalf("closed rows = %v", got)
			}
			if got := d.auditOf(t, string(claudeproxy.EventSessionRestored), sess.SessionID); len(got) != 0 {
				t.Fatalf("a refused session was restored: %v", got)
			}
			// Refused for good: a second call finds a closed record.
			if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("a second call = %d, want 401", r.StatusCode)
			}
		})
	}
}

func editCIRule(t *testing.T, db *statedb.DB, id string, edit func(*statedb.CIPipelineRuleRow)) {
	t.Helper()
	row, err := db.GetCIPipelineRule(id)
	if err != nil {
		t.Fatal(err)
	}
	edit(&row)
	if err := db.PutCIPipelineRule(row); err != nil {
		t.Fatal(err)
	}
}

// TestCI_RestoreNeedsTheSessionsToken: knowing a session's id — it is in every
// audit row — restores nothing; only its token does.
func TestCI_RestoreNeedsTheSessionsToken(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	old, _ := d.restart(t, true)
	forged := claudeproxy.TokenPrefix + sess.SessionID + "." + strings.Repeat("0", 64)
	if r := d.relay(t, forged, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a forged token = %d, want 401", r.StatusCode)
	}
	if rec := d.record(t, sess.SessionID); rec.Holder != old || !rec.Open() {
		t.Fatalf("a forged token moved the record: %+v", rec)
	}
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("the real token after the forgery = %d", r.StatusCode)
	}
}

// TestCI_ParallelCallsShareOneRestore: a job's calls arriving together after a
// restart are all served, by one restore.
func TestCI_ParallelCallsShareOneRestore(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	d.restart(t, false)
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, d.http.URL+ciMountPath+"/v1/messages",
				strings.NewReader(ciRelayBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+sess.Token)
			resp, err := d.client.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	d.waitRelayed()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("call %d = %d", i, c)
		}
	}
	if got := d.auditOf(t, string(claudeproxy.EventSessionRestored), sess.SessionID); len(got) != 1 {
		t.Fatalf("restored rows = %d, want one restore for every call", len(got))
	}
}

// TestCI_OperatorChangesReachSuspendedSessions: deleting a rule, revoking a
// session or switching federation off ends the records of sessions no process
// serves, so the job's next call is refused rather than restored.
func TestCI_OperatorChangesReachSuspendedSessions(t *testing.T) {
	t.Run("rule deleted", func(t *testing.T) {
		d := newDurableCI(t)
		id := d.addRule(t, ciBasicRule)
		_, sess := d.exchange(t, d.forge.token(nil))
		d.restart(t, true)
		resp := d.do(t, http.MethodDelete, "/api/ci/rules/"+id, nil)
		var out struct {
			Revoked int `json:"revoked_sessions"`
		}
		d.decode(t, resp, &out)
		if resp.StatusCode != http.StatusOK || out.Revoked != 1 {
			t.Fatalf("delete = %d, revoked %d; want the suspended session counted", resp.StatusCode, out.Revoked)
		}
		if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("relay after the delete = %d, want 401", r.StatusCode)
		}
		if rec := d.record(t, sess.SessionID); rec.Open() || rec.CloseReason != "rule deleted" {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("session revoked", func(t *testing.T) {
		d := newDurableCI(t)
		d.addRule(t, ciBasicRule)
		_, sess := d.exchange(t, d.forge.token(nil))
		d.restart(t, true)
		var list struct {
			Sessions []ciSessionView `json:"sessions"`
		}
		d.decode(t, d.do(t, http.MethodGet, "/api/ci/sessions", nil), &list)
		if len(list.Sessions) != 1 || list.Sessions[0].ID != sess.SessionID || !list.Sessions[0].Suspended {
			t.Fatalf("sessions listed = %+v, want the suspended one", list.Sessions)
		}
		if resp := d.do(t, http.MethodDelete, "/api/ci/sessions/"+sess.SessionID, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke = %d", resp.StatusCode)
		}
		if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("relay after the revocation = %d, want 401", r.StatusCode)
		}
	})
	t.Run("federation disabled", func(t *testing.T) {
		d := newDurableCI(t)
		d.addRule(t, ciBasicRule)
		_, sess := d.exchange(t, d.forge.token(nil))
		d.restart(t, true)
		for _, on := range []bool{false, true} {
			if resp := d.do(t, http.MethodPut, "/api/ci/config", map[string]any{"enabled": on}); resp.StatusCode != http.StatusOK {
				t.Fatalf("enabled=%v = %d", on, resp.StatusCode)
			}
		}
		if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("relay after switching federation off and on = %d, want 401", r.StatusCode)
		}
	})
}

// TestCI_SessionRecordJanitor: the leader retires closed records and lapsed
// ones nobody serves, and leaves a live holder's alone.
func TestCI_SessionRecordJanitor(t *testing.T) {
	d := newDurableCI(t)
	db := d.db(t)
	now := time.Now().UTC()
	for _, row := range []statedb.CISessionRow{
		{SessionID: "closed000000000000000000", Holder: "dead", ExpiresAt: now.Add(time.Hour)},
		{SessionID: "lapsed000000000000000000", Holder: "dead", ExpiresAt: now.Add(-time.Minute)},
		{SessionID: "liveheld0000000000000000", Holder: "live", ExpiresAt: now.Add(-time.Minute)},
		{SessionID: "dormant00000000000000000", Holder: "dead", ExpiresAt: now.Add(time.Hour)},
	} {
		row.TokenSHA256, row.RuleID, row.IssuedAt = "aa", "r1", now.Add(-time.Hour)
		if err := db.InsertCISession(row); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := db.CloseCISession("closed000000000000000000", "dead", now, "expired", ""); !ok {
		t.Fatal("close")
	}
	alive := func(h string) bool { return h == "live" }
	if n := sweepCISessionRecords(db, now, "self", alive, func(string) bool { return false }); n != 2 {
		t.Fatalf("retired %d, want the closed and the lapsed one", n)
	}
	left, _ := db.ListCISessions(statedb.CISessionFilter{})
	var ids []string
	for _, r := range left {
		ids = append(ids, r.SessionID)
	}
	if strings.Join(ids, ",") != "liveheld0000000000000000,dormant00000000000000000" &&
		strings.Join(ids, ",") != "dormant00000000000000000,liveheld0000000000000000" {
		t.Fatalf("left = %v", ids)
	}
	if got := d.auditOf(t, string(claudeproxy.EventSessionClosed), "lapsed000000000000000000"); len(got) != 1 {
		t.Fatalf("the lapsed record's close rows = %d, want 1", len(got))
	}
}

// TestCI_ARecordClosedElsewhereReachesALiveSession: a rule withdrawn through
// another hub member closes the records of every session it minted; a member
// still serving one stops at its next checkpoint, so the revocation reaches
// the whole cluster within one checkpoint interval.
func TestCI_ARecordClosedElsewhereReachesALiveSession(t *testing.T) {
	d := newDurableCI(t)
	ruleID := d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("relay = %d", r.StatusCode)
	}
	svc := d.srv.ci.svc.Load()
	svc.reg.Checkpoint() // its spend written: nothing moves until the next call
	// What another member's DELETE /api/ci/rules/{id} does to the records.
	if n := closeCISessionRecordsForRule(d.db(t), ruleID, "rule deleted"); n != 1 {
		t.Fatalf("closed %d records, want the live session's", n)
	}
	// The next tick: an idle session is dropped all the same.
	svc.reg.Checkpoint()
	svc.reconcileHeld()
	if svc.reg.Known(sess.SessionID) {
		t.Fatal("an idle session whose record was closed elsewhere is still served")
	}
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("relay after the rule was withdrawn elsewhere = %d, want 401", r.StatusCode)
	}
}

// TestCI_AStoppingHubRestoresNothing: a call reaching a hub after it began
// shutting down is refused, and does not restore the session it just
// suspended into a registry nothing would suspend again.
func TestCI_AStoppingHubRestoresNothing(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	d.srv.closeCI()
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("relay to a stopping hub = %d, want 503", r.StatusCode)
	}
	if rec := d.record(t, sess.SessionID); !rec.Open() || rec.Holder != d.members.current() {
		t.Fatalf("the suspended session's record = %+v", rec)
	}
	if got := d.auditOf(t, string(claudeproxy.EventSessionRestored), sess.SessionID); len(got) != 0 {
		t.Fatalf("a stopping hub restored the session: %v", got)
	}
}

// TestCI_RevokeReachesARecordNoProcessServes: a session whose record a live
// process took over but does not serve — its restore failed part-way — is
// still revocable, and stays revoked.
func TestCI_RevokeReachesARecordNoProcessServes(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	d.restart(t, true)
	db := d.db(t)
	rec := d.record(t, sess.SessionID)
	if ok, err := db.TakeCISession(sess.SessionID, rec.Holder, "hub-peer", rec.Instance); err != nil || !ok {
		t.Fatalf("take = %v %v", ok, err)
	}
	d.members.setAlive("hub-peer", true)
	if resp := d.do(t, http.MethodDelete, "/api/ci/sessions/"+sess.SessionID, nil); resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("revoke = %d %s", resp.StatusCode, b)
	}
	if got := d.record(t, sess.SessionID); got.Open() || got.CloseReason != "revoked by operator" {
		t.Fatalf("record after the revoke = %+v", got)
	}
}

// otherInstance is the port of another hub instance in the harness's
// directory, whose overlay may set federation otherwise.
const otherInstance = 8082

// setInstanceFederation writes the other instance's overlay with federation on
// or off, as a Settings save on that instance would.
func (d *durableCI) setInstanceFederation(t *testing.T, port int, on bool) {
	t.Helper()
	cfg, err := config.Load(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	ci := cfg.UI.CI
	ci.Enabled = on
	if err := config.SaveUIInstanceCI(config.UIInstanceConfigPath(d.dir, port), ci); err != nil {
		t.Fatal(err)
	}
}

// foreignRecords records three sessions this process never served: one a live
// peer of this hub instance serves, one whose holder of this instance is gone,
// and one whose holder of another instance — another port, whose overlay has
// federation on — is gone: restarting right now, say.
func (d *durableCI) foreignRecords(t *testing.T) (peer, gone, elsewhere string) {
	t.Helper()
	d.setInstanceFederation(t, otherInstance, true)
	db := d.db(t)
	now := time.Now().UTC()
	self := d.srv.ciInstance()
	peer, gone, elsewhere = "peer000000000000000000aa", "gone000000000000000000aa", "else000000000000000000aa"
	for _, row := range []statedb.CISessionRow{
		{SessionID: peer, Holder: "hub-peer", Instance: self},
		{SessionID: gone, Holder: "hub-gone", Instance: self},
		{SessionID: elsewhere, Holder: "hub-restarting", Instance: strconv.Itoa(otherInstance)},
	} {
		row.TokenSHA256, row.RuleID, row.IssuedAt, row.ExpiresAt = "aa", "r1", now, now.Add(time.Hour)
		if err := db.InsertCISession(row); err != nil {
			t.Fatal(err)
		}
	}
	d.members.setAlive("hub-peer", true)
	return peer, gone, elsewhere
}

// wantOpen fails the test unless each record is open or closed as given.
func (d *durableCI) wantOpen(t *testing.T, want map[string]bool) {
	t.Helper()
	for id, open := range want {
		if got := d.record(t, id).Open(); got != open {
			t.Errorf("record %s open = %v, want %v", id, got, open)
		}
	}
}

// editConfig changes the hub's configuration file, as an operator editing it
// would: no request announces it.
func (d *durableCI) editConfig(t *testing.T, edit func(*config.Config)) {
	t.Helper()
	cfg, err := config.Load(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	edit(cfg)
	if err := config.Save(d.dir, cfg); err != nil {
		t.Fatal(err)
	}
}

// TestCI_AConfigChangeEndsOnlyDormantRecords: reconfiguring federation on one
// member ends its own sessions and its instance's records no live member
// serves; a session a live peer serves is the peer's to end, and another
// instance's records are governed by that instance's configuration.
func TestCI_AConfigChangeEndsOnlyDormantRecords(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, mine := d.exchange(t, d.forge.token(nil))
	peer, gone, elsewhere := d.foreignRecords(t)
	d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.DefaultModels = []string{"claude-haiku-*"} })
	if _, err := d.srv.ciSvc(); err != nil { // rebuilt under the new configuration
		t.Fatal(err)
	}
	d.wantOpen(t, map[string]bool{mine.SessionID: false, peer: true, gone: false, elsewhere: true})
}

// TestCI_SwitchingFederationOffLeavesALivePeersSessions: federation is
// switched per hub instance — its overlay may set it — so switching it off
// through one member's Settings ends that member's sessions and its
// instance's records no live member serves. A live peer's are the peer's,
// which keeps to its own switch, and another instance's — one restarting
// right now, say — are that instance's.
func TestCI_SwitchingFederationOffLeavesALivePeersSessions(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, mine := d.exchange(t, d.forge.token(nil))
	peer, gone, elsewhere := d.foreignRecords(t)
	if resp := d.do(t, http.MethodPut, "/api/ci/config", map[string]any{"enabled": false}); resp.StatusCode != http.StatusOK {
		t.Fatalf("switch off = %d", resp.StatusCode)
	}
	d.wantOpen(t, map[string]bool{mine.SessionID: false, peer: true, gone: false, elsewhere: true})
	if got := d.auditOf(t, string(claudeproxy.EventSessionClosed), gone); len(got) != 1 {
		t.Errorf("close rows of the dormant record = %d, want 1", len(got))
	}
}

// TestCI_AHubProcessEnforcesItsOwnSwitch: federation switched off in this hub
// process's configuration file, which no Settings request announces, ends the
// sessions it serves at its next checkpoint tick — or at once, when another
// member's Settings save says the configuration moved — and a configuration
// that has federation on switches nothing off.
func TestCI_AHubProcessEnforcesItsOwnSwitch(t *testing.T) {
	for _, via := range []string{"checkpoint tick", "a peer's notice"} {
		t.Run(via, func(t *testing.T) {
			prevEvery, prevConfirm := ciCheckpointInterval, ciSwitchConfirm
			t.Cleanup(func() { ciCheckpointInterval, ciSwitchConfirm = prevEvery, prevConfirm })
			ciSwitchConfirm = time.Millisecond
			if via == "checkpoint tick" {
				ciCheckpointInterval = 40 * time.Millisecond
			}
			d := newDurableCI(t)
			d.addRule(t, ciBasicRule)
			_, mine := d.exchange(t, d.forge.token(nil))
			peer, gone, elsewhere := d.foreignRecords(t)
			notice := hubcluster.Event{Topic: busTopicInvalidate, Key: invalidateCIConfig}
			if via != "checkpoint tick" {
				d.srv.recheckCIService()
				if d.srv.ci.svc.Load() == nil {
					t.Fatal("a configuration with federation on retired the service")
				}
			}
			d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.Enabled = false })
			if via != "checkpoint tick" {
				d.srv.onBusInvalidate(notice)
			}
			deadline := time.Now().Add(5 * time.Second)
			for d.srv.ci.svc.Load() != nil {
				if time.Now().After(deadline) {
					t.Fatal("the service still serves after its configuration switched federation off")
				}
				time.Sleep(10 * time.Millisecond)
			}
			d.wantOpen(t, map[string]bool{mine.SessionID: false, peer: true, gone: false, elsewhere: true})
			if got := d.record(t, mine.SessionID).CloseReason; got != "CI federation is disabled" {
				t.Errorf("close reason = %q", got)
			}
			// Its end is written once: closed, not also suspended.
			if got := d.auditOf(t, string(claudeproxy.EventSessionClosed), mine.SessionID); len(got) != 1 {
				t.Errorf("close rows = %d, want 1", len(got))
			}
			if got := d.auditOf(t, string(claudeproxy.EventSessionSuspended), mine.SessionID); len(got) != 0 {
				t.Errorf("suspend rows = %d, want none", len(got))
			}
		})
	}
}

// TestCI_TheJanitorHoldsEachRecordToItsInstancesSwitch: the leader ends the
// records no live process serves whose own instance has federation off — the
// file edited and the hub restarted, say, or the instance switched off while
// it was down — reading each instance's configuration as that instance does.
// A session this process still serves is its registry's to end, a live peer's
// is the peer's, and another instance's whose overlay keeps federation on is
// left alone until that instance is switched off too.
func TestCI_TheJanitorHoldsEachRecordToItsInstancesSwitch(t *testing.T) {
	prev := ciSwitchConfirm
	t.Cleanup(func() { ciSwitchConfirm = prev })
	ciSwitchConfirm = time.Millisecond
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, suspended := d.exchange(t, d.forge.token(nil))
	d.restart(t, true)
	_, served := d.exchange(t, d.forge.token(nil))
	peer, gone, elsewhere := d.foreignRecords(t)
	db := d.db(t)
	if n := d.srv.closeCIRecordsSwitchedOff(db); n != 0 {
		t.Fatalf("with federation on everywhere, closed %d records", n)
	}
	d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.Enabled = false })
	if n := d.srv.closeCIRecordsSwitchedOff(db); n != 2 {
		t.Fatalf("closed %d records, want the suspended one and the gone holder's", n)
	}
	d.wantOpen(t, map[string]bool{suspended.SessionID: false, gone: false, served.SessionID: true, peer: true,
		elsewhere: true})
	d.setInstanceFederation(t, otherInstance, false)
	if n := d.srv.closeCIRecordsSwitchedOff(db); n != 1 {
		t.Fatalf("closed %d records once the other instance was switched off, want its one", n)
	}
	d.wantOpen(t, map[string]bool{elsewhere: false, served.SessionID: true, peer: true})
}

// TestCI_ARestoreIsHeldToItsInstancesSwitch: a session suspended by an
// instance whose federation was switched off while none of its processes
// served it — stopped, or come back on another port — is not restored by
// another instance where federation is on: the job gets its 401 and the
// record is closed. While that instance keeps federation on, it is restored.
func TestCI_ARestoreIsHeldToItsInstancesSwitch(t *testing.T) {
	prev := ciSwitchConfirm
	t.Cleanup(func() { ciSwitchConfirm = prev })
	ciSwitchConfirm = time.Millisecond
	for _, on := range []bool{true, false} {
		t.Run(fmt.Sprintf("its instance on=%v", on), func(t *testing.T) {
			d := newDurableCI(t)
			d.setInstanceFederation(t, otherInstance, true)
			d.srv.Port = otherInstance // minted by the other instance
			d.addRule(t, ciBasicRule)
			_, sess := d.exchange(t, d.forge.token(nil))
			d.restart(t, true)
			d.srv.Port = 0 // the job's next call reaches this one
			d.setInstanceFederation(t, otherInstance, on)
			r := d.relay(t, sess.Token, ciRelayBody)
			rec := d.record(t, sess.SessionID)
			if on {
				if r.StatusCode != http.StatusOK || !rec.Open() {
					t.Fatalf("relay = %d, record open %v; want it restored", r.StatusCode, rec.Open())
				}
				return
			}
			if r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("relay = %d, want 401", r.StatusCode)
			}
			if rec.Open() || !strings.Contains(rec.CloseReason, "switched off on the hub instance that served it (port 8082)") {
				t.Fatalf("record = open %v, reason %q", rec.Open(), rec.CloseReason)
			}
		})
	}
}

// TestCI_AReplacedServiceLeavesItsSuccessorsSessions: a configuration change
// swaps the new service in before the old one is torn down, and a session the
// new one minted in between is not taken for one nobody serves.
func TestCI_AReplacedServiceLeavesItsSuccessorsSessions(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, before := d.exchange(t, d.forge.token(nil))
	old := d.srv.ci.svc.Load()
	cfg, err := d.srv.loadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	next, err := d.srv.buildCIService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.srv.ci.svc.Store(next) // as ciSvc swaps it in, before the old one goes
	_, after := d.exchange(t, d.forge.token(nil))
	old.shutdown("configuration changed", d.srv.ciSessionServed)
	d.wantOpen(t, map[string]bool{before.SessionID: false, after.SessionID: true})
	if r := d.relay(t, after.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("relay on the successor's session = %d", r.StatusCode)
	}
}

// TestCI_ATornConfigurationReadEndsNothing: a configuration read once in a
// changed form — a file an editor is half-way through writing — rebuilds
// nothing unless a second read a moment later agrees, so the sessions it would
// end live on.
func TestCI_ATornConfigurationReadEndsNothing(t *testing.T) {
	prev := ciSwitchConfirm
	t.Cleanup(func() { ciSwitchConfirm = prev })
	ciSwitchConfirm = 400 * time.Millisecond
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	svc := d.srv.ci.svc.Load()
	original, err := config.Load(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.DefaultModels = []string{"claude-haiku-*"} })
	restored := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond) // well inside the confirming wait
		restored <- config.Save(d.dir, original)
	}()
	got, err := d.srv.ciSvc()
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	if err != nil || got != svc {
		t.Fatalf("ciSvc = %p, %v; want the service it had, %p", got, err, svc)
	}
	d.wantOpen(t, map[string]bool{sess.SessionID: true})
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("relay after the torn read = %d", r.StatusCode)
	}
}

// TestCI_RevokeWritesOneCloseRow: whichever way a revocation goes, the
// session's end is written once — by the registry that closed it, or, for a
// record no registry here serves, by the revocation — including a record this
// process holds without serving it.
func TestCI_RevokeWritesOneCloseRow(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, served := d.exchange(t, d.forge.token(nil))
	now := time.Now().UTC()
	held := "held000000000000000000aa"
	if err := d.db(t).InsertCISession(statedb.CISessionRow{SessionID: held, Holder: d.members.current(),
		TokenSHA256: "aa", RuleID: "r1", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{served.SessionID, held} {
		if resp := d.do(t, http.MethodDelete, "/api/ci/sessions/"+id, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke %s = %d", id, resp.StatusCode)
		}
		if got := d.auditOf(t, string(claudeproxy.EventSessionClosed), id); len(got) != 1 {
			t.Errorf("close rows of %s = %d, want 1", id, len(got))
		}
	}
	d.wantOpen(t, map[string]bool{served.SessionID: false, held: false})
}

// TestCI_ARestoreThatPanicsHoldsUpNothing: a fault part-way through a restore
// fails the call that met it, and the job's next call restores the session:
// the restore in flight is released however it ends.
func TestCI_ARestoreThatPanicsHoldsUpNothing(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	d.restart(t, true)
	call := func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.http.URL+ciMountPath+"/v1/messages",
			strings.NewReader(ciRelayBody))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		resp, err := d.client.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	d.members.setExplode(true)
	if code, err := call(); err == nil && code == http.StatusOK {
		t.Fatal("the call whose restore panicked was served")
	}
	d.members.setExplode(false)
	d.waitRelayed()
	ciRestoreFlights.Lock()
	_, stuck := ciRestoreFlights.m[sess.SessionID]
	ciRestoreFlights.Unlock()
	if stuck {
		t.Fatal("the restore that panicked still holds its flight: every later call for the session would wait on it")
	}
	code, err := call()
	if err != nil {
		t.Fatalf("the next call did not complete: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("the next call = %d, want the session restored and served", code)
	}
}

// TestCI_ARestoreMovesTheRecordToTheRestoringInstance: a session restored by a
// process of another hub instance is governed by that instance's
// configuration from then on, so its record names that instance.
func TestCI_ARestoreMovesTheRecordToTheRestoringInstance(t *testing.T) {
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	if got := d.record(t, sess.SessionID).Instance; got != d.srv.ciInstance() {
		t.Fatalf("minted under instance %q, want %q", got, d.srv.ciInstance())
	}
	d.restart(t, true)
	d.srv.Port = 8099 // the job's next call reaches another instance
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("relay = %d", r.StatusCode)
	}
	if rec := d.record(t, sess.SessionID); rec.Instance != "8099" || rec.Holder != d.members.current() {
		t.Fatalf("restored record = holder %q, instance %q; want %q, 8099", rec.Holder, rec.Instance, d.members.current())
	}
}

// TestCI_ATornReadSwitchesNothingOff: a configuration read once with
// federation off — a file an editor is half-way through writing — ends no
// record unless the confirming read a moment later agrees.
func TestCI_ATornReadSwitchesNothingOff(t *testing.T) {
	prev := ciSwitchConfirm
	t.Cleanup(func() { ciSwitchConfirm = prev })
	ciSwitchConfirm = 400 * time.Millisecond
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	_, sess := d.exchange(t, d.forge.token(nil))
	d.restart(t, true) // its record now held by no live process
	original, err := config.Load(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.Enabled = false })
	restored := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond) // well inside the confirming wait
		restored <- config.Save(d.dir, original)
	}()
	n := d.srv.closeCIRecordsSwitchedOff(d.db(t))
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a torn read closed %d records", n)
	}
	if r := d.relay(t, sess.Token, ciRelayBody); r.StatusCode != http.StatusOK {
		t.Fatalf("relay after the torn read = %d, want the session restored", r.StatusCode)
	}
}

// TestCI_TheConfirmingWaitHandsOutNoStoppedService: a call that waited to
// confirm a configuration change, and found none, is served by the service
// there is after the wait — not by the one it read before, which the hub may
// have stopped meanwhile.
func TestCI_TheConfirmingWaitHandsOutNoStoppedService(t *testing.T) {
	prev := ciSwitchConfirm
	t.Cleanup(func() { ciSwitchConfirm = prev })
	ciSwitchConfirm = 300 * time.Millisecond
	d := newDurableCI(t)
	d.addRule(t, ciBasicRule)
	d.exchange(t, d.forge.token(nil))
	original, err := config.Load(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	d.editConfig(t, func(cfg *config.Config) { cfg.UI.CI.DefaultModels = []string{"claude-haiku-*"} })
	stopped := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond) // well inside the confirming wait
		err := config.Save(d.dir, original)
		d.srv.closeCI()
		stopped <- err
	}()
	got, err := d.srv.ciSvc()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if got != nil || !errors.Is(err, errCIStopped) {
		t.Fatalf("ciSvc after the hub stopped during its wait = %p, %v; want errCIStopped", got, err)
	}
}
