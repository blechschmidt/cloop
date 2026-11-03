package ui

// POST /api/knowledge/test-connection (Task 20473): who may try what, that a
// failure comes back scrubbed of the credential it was tried with, that it
// asks a stale session to sign in again, and that a person cannot turn it
// into a scanner.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// uiFakeConnector is a remote the dashboard's knowledge tests connect, sync
// and search: {"site": "<name>"} lists the site's documents — among them ones
// whose titles, paths and text are markup — and {"fail": true} fails the way
// a remote that refuses a token does, quoting the request it was sent, the
// credential in it.
type uiFakeConnector struct{}

func (uiFakeConnector) Kind() string { return "uifake" }

func (uiFakeConnector) Validate(req knowledge.ValidateRequest) error {
	var c struct {
		BaseURL string `json:"base_url"`
	}
	if err := json.Unmarshal(req.Config, &c); err != nil {
		return err
	}
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("base_url must be an https URL")
	}
	return nil
}

func (uiFakeConnector) List(_ context.Context, req knowledge.ListRequest) (knowledge.Page, error) {
	var c struct {
		Site string `json:"site"`
		Fail bool   `json:"fail"`
	}
	_ = json.Unmarshal(req.Config, &c)
	if c.Fail {
		return knowledge.Page{}, fmt.Errorf("GET https://wiki.example.com/rest/api/content?limit=5 sent "+
			"Authorization: Bearer %s and got 401 Unauthorized", req.Credential.Value())
	}
	return knowledge.Page{Cursor: "end", Documents: uiFakeDocs(c.Site)}, nil
}

func (uiFakeConnector) Fetch(context.Context, knowledge.FetchRequest) (knowledge.Document, error) {
	return knowledge.Document{}, errors.New("no fetch")
}

// uiFakeDocs is site's content: a runbook, a postmortem whose title, path and
// text are hostile markup, and a restricted page the connector withholds.
func uiFakeDocs(site string) []knowledge.Document {
	return []knowledge.Document{
		{ExternalID: site + "-1", Title: "Rollback runbook for " + site, URL: "https://wiki.example.com/pages/" + site + "/1",
			Space: "ENG", Ancestors: []string{"Runbooks", "Deploys"},
			Body: "# Rolling back\n\nTo roll back the " + site + " ingest pipeline, drain the queue first, then redeploy the previous tag."},
		{ExternalID: site + "-2", URL: "javascript:window.__xss='kn-url'",
			Title: `<img src=x onerror="window.__xss='kn-title'">Postmortem: the ` + site + ` ingest outage`,
			Space: "OPS", Ancestors: []string{`<svg onload="window.__xss='kn-path'"></svg>Incidents`},
			Body: `What broke: the ingest pipeline backed up. <script>window.__xss='kn-snippet'</script> ` +
				`"><img src=x onerror="window.__xss='kn-attr'"> The fix was to roll back the ingest consumer.`},
		{ExternalID: site + "-3", Deleted: true},
	}
}

var registerUIFake sync.Once

func knowledgeConnectionHub(t *testing.T) *sudoHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "knowledge-connection-test-passphrase")
	registerUIFake.Do(func() { knowledge.MustRegister(uiFakeConnector{}) })
	// Each test's people start with a full bucket: the buckets are the
	// process's, and these tests sign the same people in.
	connectionTests.mu.Lock()
	clear(connectionTests.buckets)
	connectionTests.mu.Unlock()
	return knowledgeHub(t)
}

type connectionAnswer struct {
	Result knowledgeTestView `json:"result"`
}

func TestKnowledgeTestConnectionAPI(t *testing.T) {
	h := knowledgeConnectionHub(t)
	admin := h.signIn(t, "ada@example.com", false, "owners")
	lead := h.signIn(t, "lead@example.com", false, "leads")
	bob := h.signIn(t, "bob@example.com", false, "engineers")
	staleLead := h.signIn(t, "lead@example.com", true, "leads")
	const token = "lead-sekrit-token-value-1234567890abcdef"

	call := func(c *http.Client, body map[string]any, want int) []byte {
		t.Helper()
		resp, raw := h.call(t, c, http.MethodPost, "/api/knowledge/test-connection", body)
		if resp.StatusCode != want {
			t.Fatalf("test-connection %v = %d %s, want %d", body, resp.StatusCode, raw, want)
		}
		return raw
	}
	resp, raw := h.call(t, lead, http.MethodPost, "/api/secrets", map[string]any{"name": "lead-wiki-token", "kind": "env",
		"payload": `{"TOKEN":"` + token + `"}`, "personal": true})
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("store the lead's token = %d %s", resp.StatusCode, raw)
	}

	// A source being connected, tried before it is saved.
	var ok connectionAnswer
	decodeBody(t, call(lead, map[string]any{"kind": "uifake", "name": "Lead's wiki", "secret_ref": "lead-wiki-token",
		"config": map[string]any{"site": "alpha", "base_url": "https://wiki.example.com"}}, http.StatusOK), &ok)
	if !ok.Result.OK || ok.Result.Documents != 2 || ok.Result.Withheld != 1 || len(ok.Result.Titles) != 2 {
		t.Fatalf("a good test = %+v", ok.Result)
	}

	// A failure, in the remote's words, without the credential in them.
	var bad connectionAnswer
	raw = call(lead, map[string]any{"kind": "uifake", "secret_ref": "lead-wiki-token", "config": map[string]any{"fail": true}}, http.StatusOK)
	decodeBody(t, raw, &bad)
	if bad.Result.OK || bad.Result.Reason != knowledge.TestFailedConnector || !strings.Contains(bad.Result.Failure, "401 Unauthorized") {
		t.Fatalf("a failing test = %+v", bad.Result)
	}
	if strings.Contains(string(raw), token) || !strings.Contains(bad.Result.Failure, redact.Marker) {
		t.Errorf("the answer carries the credential or no marker where it was: %s", raw)
	}
	db, err := h.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceTest)})
	db.Close()
	if err != nil || len(evs) != 2 {
		t.Fatalf("audit rows = %d, %v; want one per test", len(evs), err)
	}
	for _, ev := range evs {
		if strings.Contains(ev.Payload, token) {
			t.Errorf("an audit row carries the credential: %s", ev.Payload)
		}
		if ev.Actor != "lead@example.com" {
			t.Errorf("an audit row's actor = %q", ev.Actor)
		}
	}

	// Who may try what.
	if p := requiredPermission(call(bob, map[string]any{"kind": "uifake", "scope": "org", "config": map[string]any{}}, http.StatusForbidden)); p != "knowledge.admin" {
		t.Errorf("an operator trying an organisation source was refused for %q", p)
	}
	resp, raw = h.call(t, lead, http.MethodPost, "/api/knowledge/sources", map[string]any{"kind": "uifake", "name": "Lead's wiki",
		"scope": "personal", "secret_ref": "lead-wiki-token", "config": map[string]any{"site": "alpha"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Source knowledgeSourceView `json:"source"`
	}
	decodeBody(t, raw, &created)
	id := created.Source.ID
	call(bob, map[string]any{"source_id": id}, http.StatusNotFound)
	call(admin, map[string]any{"source_id": id, "config": map[string]any{"site": "elsewhere"}}, http.StatusForbidden)
	call(lead, map[string]any{"kind": "uifake", "secret_ref": "no-such-secret", "config": map[string]any{}}, http.StatusBadRequest)
	call(lead, map[string]any{"kind": "uifake", "config": map[string]any{"base_url": "http://plain.example"}}, http.StatusBadRequest)
	// A stale session confirms it is the person first: the test sends their
	// credential where the form says.
	if code := reauthCode(call(staleLead, map[string]any{"source_id": id}, http.StatusUnauthorized)); code != "REAUTH_REQUIRED" {
		t.Errorf("a stale session's test answered %q", code)
	}
	var mine connectionAnswer
	decodeBody(t, call(lead, map[string]any{"source_id": id}, http.StatusOK), &mine)
	if !mine.Result.OK || mine.Result.Documents != 2 {
		t.Errorf("the owner's test of their source = %+v", mine.Result)
	}
}

func TestKnowledgeTestConnectionIsRateLimited(t *testing.T) {
	h := knowledgeConnectionHub(t)
	lead := h.signIn(t, "rate@example.com", false, "leads")
	// Under the limiter's own lock: the hub's handlers read them there, and a
	// request crossing a socket is no happens-before edge for the race
	// detector.
	connectionTests.mu.Lock()
	oldBurst, oldEvery := connectionTestBurst, connectionTestEvery
	connectionTestBurst, connectionTestEvery = 3, time.Hour
	connectionTests.mu.Unlock()
	t.Cleanup(func() {
		connectionTests.mu.Lock()
		connectionTestBurst, connectionTestEvery = oldBurst, oldEvery
		connectionTests.mu.Unlock()
	})
	body := map[string]any{"kind": "uifake", "config": map[string]any{"site": "rate"}}
	for i := range 3 {
		if resp, raw := h.call(t, lead, http.MethodPost, "/api/knowledge/test-connection", body); resp.StatusCode != http.StatusOK {
			t.Fatalf("test %d = %d %s", i+1, resp.StatusCode, raw)
		}
	}
	resp, raw := h.call(t, lead, http.MethodPost, "/api/knowledge/test-connection", body)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(raw), "RATE_LIMITED") {
		t.Fatalf("the fourth test in a row = %d %s, want 429", resp.StatusCode, raw)
	}
	// Another person's bucket is their own.
	other := h.signIn(t, "rate-other@example.com", false, "leads")
	if resp, raw := h.call(t, other, http.MethodPost, "/api/knowledge/test-connection", body); resp.StatusCode != http.StatusOK {
		t.Fatalf("another person's test = %d %s", resp.StatusCode, raw)
	}
}
