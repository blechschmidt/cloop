package security

// Guarantee 9, extended to the approvals inbox and its notifications (Task
// 20427).
//
// The inbox puts the access request queue in front of everyone who may decide
// it, and Settings → Notifications configures where the hub posts about it. A
// request names a credential and never carries one, and a webhook URL is the
// credential for its channel — so the inbox must hold no material whatever the
// seeded secrets are, its rows must be a closed, reviewed set of keys, and the
// settings must never hand the URL back.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fileRequestPerCanary files one access request for every seeded secret, as a
// developer would, each narrowed the way its kind requires.
func fileRequestPerCanary(t *testing.T, dir string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range uiRouteCanaries {
		if _, err := broker.RequestAccess(context.Background(), secretbroker.AccessRequestInput{
			SecretRef: c.name, Subject: secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-02"},
			Constraints: c.constraints, TTL: time.Hour, Justification: "conformance: " + c.name,
			Actor: "dev@example.com",
		}); err != nil {
			t.Fatalf("RequestAccess %s: %v", c.name, err)
		}
	}
}

func TestApprovalsInboxNeverDisclosesMaterial(t *testing.T) {
	ts, dir := newSecretsAPIFixture(t)
	fileRequestPerCanary(t, dir)

	inbox := mustBody(t, ts, http.MethodGet, "/api/approvals", nil)
	count := mustBody(t, ts, http.MethodGet, "/api/approvals/count", nil)
	var parsed struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(inbox), &parsed); err != nil {
		t.Fatalf("decode /api/approvals: %v", err)
	}
	// A hub with no sign-on decides everything for its local caller, so every
	// request is in the inbox: the scan below has every kind to look at.
	if len(parsed.Items) != len(uiRouteCanaries) {
		t.Fatalf("the inbox lists %d item(s), want %d — the scan would be vacuous", len(parsed.Items), len(uiRouteCanaries))
	}
	for _, c := range uiRouteCanaries {
		for sink, body := range map[string]string{"GET /api/approvals": inbox, "GET /api/approvals/count": count} {
			assertNoSecretLeak(t, body, c.canary, fmt.Sprintf("%s (canary %s)", sink, c.name))
		}
	}

	// The keys, closed and reviewed, as for /api/secrets and /api/grants.
	itemKeys := map[string]bool{"kind": true, "id": true, "deadline": true, "deadline_in_seconds": true, "request": true, "token": true}
	requestKeys := map[string]bool{
		"id": true, "requested_by": true, "secret_id": true, "secret_name": true, "kind": true, "subject": true,
		"constraints": true, "scope": true, "ttl_minutes": true, "justification": true, "state": true,
		"created_at": true, "expires_at": true, "expires_in_seconds": true, "decided_by": true, "decided_at": true,
		"decision_note": true, "grant_id": true, "grant_expires_at": true, "mine": true, "decidable": true,
		"approvers": true,
	}
	for _, it := range parsed.Items {
		for k := range it {
			if !itemKeys[k] {
				t.Errorf("an inbox item carries unreviewed field %q", k)
			}
		}
		var req map[string]json.RawMessage
		if err := json.Unmarshal(it["request"], &req); err != nil {
			t.Fatalf("decode the request view: %v", err)
		}
		for k := range req {
			if !requestKeys[k] {
				t.Errorf("an inbox request carries unreviewed field %q: if it is metadata, review it here; "+
					"if it could hold credential material, it must not be serialised", k)
			}
		}
	}
}

func TestNotificationSettingsNeverReturnTheWebhookURL(t *testing.T) {
	ts, dir := newSecretsAPIFixture(t)
	const canary = "T0UIROUTECANARY/B0UIROUTECANARY/notifycanary0123456789"
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Notifications.Webhooks = []config.NotificationWebhook{{
		Name: "approvers", Type: config.NotifySlack, URL: "https://hooks.slack.com/services/" + canary,
	}}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	body := mustBody(t, ts, http.MethodGet, "/api/config/notifications", nil)
	if !strings.Contains(body, "https://hooks.slack.com") || !strings.Contains(body, `"url_set":true`) {
		t.Fatalf("the settings do not describe the webhook: %s", body)
	}
	assertNoSecretLeak(t, body, canary, "GET /api/config/notifications")
	// Nor does a save's answer, nor a refusal built from the request.
	_, saved := doJSON(t, ts, http.MethodPut, "/api/config/notifications", map[string]any{"webhooks": []map[string]any{{
		"name": "approvers", "type": "slack", "url": "https://hooks.slack.com/services/" + canary,
	}}})
	assertNoSecretLeak(t, saved, canary, "PUT /api/config/notifications")
	_, refused := doJSON(t, ts, http.MethodPut, "/api/config/notifications", map[string]any{"webhooks": []map[string]any{{
		"name": "approvers", "type": "slack", "url": "http://hooks.slack.com/services/" + canary,
	}}})
	assertNoSecretLeak(t, refused, canary, "PUT /api/config/notifications (refused)")
}
