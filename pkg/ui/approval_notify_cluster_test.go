package ui

// Approval notifications across a hub cluster (Task 20427): three members
// serve one control plane, each registers the notifier as a leader duty, and a
// webhook hears each moment once — including across a change of leader.

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// webhookReceiver is a JSON webhook on loopback that records what it is sent.
type webhookReceiver struct {
	srv    *httptest.Server
	caFile string
	mu     sync.Mutex
	got    []map[string]any
}

func newWebhookReceiver(t *testing.T) *webhookReceiver {
	t.Helper()
	rec := &webhookReceiver{}
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			rec.mu.Lock()
			rec.got = append(rec.got, m)
			rec.mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(rec.srv.Close)
	rec.caFile = filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.srv.Certificate().Raw})
	if err := os.WriteFile(rec.caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return rec
}

// count reports how many messages of event about request id arrived.
func (rec *webhookReceiver) count(event, id string) int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, m := range rec.got {
		req, _ := m["request"].(map[string]any)
		if m["event"] == event && req != nil && req["id"] == id {
			n++
		}
	}
	return n
}

// webhook is the receiver as a notifications.webhooks entry.
func (rec *webhookReceiver) webhook(name string) config.NotificationWebhook {
	return config.NotificationWebhook{Name: name, Type: config.NotifyJSON, URL: rec.srv.URL + "/hook",
		AllowAddresses: []string{"127.0.0.1"}, CAFile: rec.caFile}
}

// configureNotifications writes webhooks into the hub's config.yaml.
func configureNotifications(t *testing.T, dir string, hooks ...config.NotificationWebhook) {
	t.Helper()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Notifications.Webhooks = hooks
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

// TestApprovalRemindersGoOutOncePerCluster: a request twelve hours from
// lapsing is reminded about once, however many members run the notifier's
// duty and whichever of them leads — the leader sends, a new leader resumes
// from the cursor the old one left in the control plane, and the outbox key
// keeps a moment from being recorded twice.
func TestApprovalRemindersGoOutOncePerCluster(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir := setupProjectDir(t, "one control plane, three hubs", nil)
	rec := newWebhookReceiver(t)
	configureNotifications(t, dir, rec.webhook("approvers"))

	now := time.Now()
	due := pendingRequest("req_due", "dev@example.com", "project:"+dir, now)
	due.CreatedAt, due.ExpiresAt = now.Add(-61*time.Hour), now.Add(11*time.Hour)
	seedRequests(t, dir, due)

	members := []*clusterMember{newClusterMember(t, dir), newClusterMember(t, dir), newClusterMember(t, dir)}
	waitCluster(t, "the members to see each other", func() bool {
		for _, m := range members {
			if !m.node.HasPeers() {
				return false
			}
		}
		return true
	})
	for _, m := range members {
		m.srv.approvalNotify.poll = 40 * time.Millisecond
		m.srv.runLeaderDuty(t.Context(), "approval-notify", m.srv.watchApprovalNotices)
	}

	deadline := time.Now().Add(10 * time.Second)
	for rec.count("request.reminder", "req_due") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Many passes later, on whichever members ran them.
	time.Sleep(600 * time.Millisecond)
	if n := rec.count("request.reminder", "req_due"); n != 1 {
		t.Fatalf("the webhook was reminded %d time(s), want once", n)
	}
	if n := rec.count("request.filed", "req_due"); n != 1 {
		t.Fatalf("the webhook heard of the filing %d time(s), want once", n)
	}

	// The leader goes; another takes over and passes from the same cursor.
	var leader *clusterMember
	for _, m := range members {
		if m.node.IsLeader() {
			leader = m
		}
	}
	if leader == nil {
		t.Fatal("no member leads")
	}
	_ = leader.node.Close()
	waitCluster(t, "another member to lead", func() bool {
		for _, m := range members {
			if m != leader && m.node.IsLeader() {
				return true
			}
		}
		return false
	})
	time.Sleep(600 * time.Millisecond)
	if n := rec.count("request.reminder", "req_due"); n != 1 {
		t.Fatalf("after a change of leader the webhook was reminded %d time(s), want once", n)
	}

	// The new leader still notices what happens next — once.
	fresh := pendingRequest("req_new", "dev@example.com", "project:"+dir, time.Now())
	seedRequests(t, dir, fresh)
	deadline = time.Now().Add(10 * time.Second)
	for rec.count("request.filed", "req_new") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := rec.count("request.filed", "req_new"); n != 1 {
		t.Fatalf("the new leader announced a filing %d time(s), want once", n)
	}

	// A decision no dashboard handler made — `cloop hub grant request deny`
	// on the hub's host writes the row and broadcasts nothing — still reaches
	// the channel once, and every member's dashboards, through the notifier.
	var follower *clusterMember
	for _, m := range members {
		if m != leader && !m.node.IsLeader() {
			follower = m
		}
	}
	if follower == nil {
		t.Fatal("no member follows")
	}
	watcher := subscribe(t, follower.srv, dir, "admin@example.com")
	fresh.State, fresh.DecidedBy, fresh.DecidedAt = secretbroker.RequestDenied, "operator@example.com", time.Now()
	seedRequests(t, dir, fresh)
	for {
		msg := nextMessage(t, watcher, "approvals_update")
		var p struct{ Event, ID string }
		_ = json.Unmarshal(msg.Data, &p)
		if p.Event == "request_denied" && p.ID == "req_new" {
			break
		}
	}
	deadline = time.Now().Add(10 * time.Second)
	for rec.count("request.denied", "req_new") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := rec.count("request.denied", "req_new"); n != 1 {
		t.Fatalf("the denial reached the webhook %d time(s), want once", n)
	}
}
