package cmd

// `cloop knowledge` (Task 20470): a terminal signed in to an SSO hub lists the
// knowledge sources it may see, syncs one and follows the sync to its end, and
// searches what a project's sources hold — and is refused what the hub
// refuses its dashboard.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// cliKnowledgeConnector is the source the terminal syncs: two runbooks.
type cliKnowledgeConnector struct{}

func (cliKnowledgeConnector) Kind() string                             { return "clitest" }
func (cliKnowledgeConnector) Validate(knowledge.ValidateRequest) error { return nil }

func (cliKnowledgeConnector) List(context.Context, knowledge.ListRequest) (knowledge.Page, error) {
	return knowledge.Page{Cursor: "end", Documents: []knowledge.Document{
		{ExternalID: "RB-1", Title: "Deploy runbook", URL: "https://wiki.example/RB-1",
			Body: "# Rollback\n\nTo roll the widgets API back, redeploy the previous image tag."},
		{ExternalID: "RB-2", Title: "On-call guide", Body: "Page the owner before any rollback of production."},
	}}, nil
}

func (cliKnowledgeConnector) Fetch(context.Context, knowledge.FetchRequest) (knowledge.Document, error) {
	return knowledge.Document{}, fmt.Errorf("no fetch")
}

var registerCLIKnowledge sync.Once

// runKnowledgeCLI runs `cloop knowledge <args>` as a terminal would.
func runKnowledgeCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(knowledgeCmd)
	t.Cleanup(func() { resetFlags(knowledgeCmd) })
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"knowledge"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := rootCmd.ExecuteContextC(ctx)
	return out.String(), err
}

func TestKnowledgeCLI(t *testing.T) {
	registerCLIKnowledge.Do(func() { knowledge.MustRegister(cliKnowledgeConnector{}) })
	defer func(d time.Duration) { knowledgePoll = d }(knowledgePoll)
	knowledgePoll = 25 * time.Millisecond

	w := newRemoteWorld(t)
	path := rootProject(t, w)
	root := w.browser(t, rootEmail)
	status, body := w.hub.Call(t, root, http.MethodPost, "/api/knowledge/sources", map[string]any{
		"kind": "clitest", "name": "Eng wiki", "scope": "org", "config": map[string]any{}, "sync_interval_minutes": 120,
	})
	if status != http.StatusCreated {
		t.Fatalf("create the source = %d %s", status, body)
	}
	var created struct {
		Source hubclient.KnowledgeSource `json:"source"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	idx := projectIdxFor(t, w, root, path)
	if status, body := w.hub.Call(t, root, http.MethodPost, fmt.Sprintf("/api/projects/%d/knowledge/bindings", idx),
		map[string]any{"source_id": created.Source.ID}); status != http.StatusCreated {
		t.Fatalf("bind the source = %d %s", status, body)
	}

	w.as(t, rootEmail)
	out, err := runKnowledgeCLI(t, "sources")
	if err != nil || !strings.Contains(out, "Eng wiki") || !strings.Contains(out, "never synced") ||
		!strings.Contains(out, "clitest") {
		t.Fatalf("sources before a sync = %v\n%s", err, out)
	}

	out, err = runKnowledgeCLI(t, "sync", "eng wiki", "--wait")
	if err != nil || !strings.Contains(out, "Syncing Eng wiki on ") || !strings.Contains(out, "Synced Eng wiki") ||
		!strings.Contains(out, "2 new") || !strings.Contains(out, "It holds 2 documents.") {
		t.Fatalf("sync --wait = %v\n%s", err, out)
	}

	out, err = runKnowledgeCLI(t, "sources", "--json")
	if err != nil {
		t.Fatalf("sources --json: %v\n%s", err, out)
	}
	var list hubclient.KnowledgeSources
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Sources) != 1 {
		t.Fatalf("sources --json = %q (%v)", out, err)
	}
	s := list.Sources[0]
	if s.Sync.Status != "ok" || s.Documents != 2 || s.Sync.Origin != "manual" || s.Sync.IntervalMinutes != 120 ||
		s.Sync.Running != nil || s.Sync.Counts == nil || s.Sync.Counts.Created != 2 {
		t.Fatalf("the source after its sync = %+v", s)
	}

	out, err = runKnowledgeCLI(t, "search", "widgets", "rollback")
	if err != nil || !strings.Contains(out, "1. ") || !strings.Contains(out, "Deploy runbook") ||
		!strings.Contains(out, "«rollback»") && !strings.Contains(out, "«Rollback»") || !strings.Contains(out, "Eng wiki (clitest)") {
		t.Fatalf("search = %v\n%s", err, out)
	}
	out, err = runKnowledgeCLI(t, "search", "widgets", "nonexistentword", "--json")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("a search that finds nothing, as JSON = %v %q", err, out)
	}

	// An operator may not sync the organisation's source — the hub refuses,
	// and the terminal says which permission it takes.
	w.as(t, oliveEmail, ssohubtest.GroupOperators)
	if _, err := runKnowledgeCLI(t, "sync", fmt.Sprint(created.Source.ID)); err == nil ||
		!strings.Contains(err.Error(), "knowledge.admin") {
		t.Fatalf("an operator syncing the organisation's source = %v, want the hub's refusal", err)
	}
}

// TestWaitingForASyncThatRecordedNothing: `--wait` follows the sync it
// started, reports the outcome recorded when its lease went — and when none
// was, says so rather than polling forever.
func TestWaitingForASyncThatRecordedNothing(t *testing.T) {
	defer func(d time.Duration) { knowledgePoll = d }(knowledgePoll)
	knowledgePoll = 5 * time.Millisecond
	since := "2026-11-02T10:00:05Z"
	for _, tc := range []struct {
		name   string
		states []string // the sync object each read returns, in turn
		want   string   // "" for the outcome, else a substring of the error
	}{
		{"its outcome", []string{
			`{"status":"","running":{"member":"m","origin":"manual","since":"` + since + `"}}`,
			`{"status":"ok","started_at":"2026-11-02T10:00:05Z","at":"2026-11-02T10:00:09Z"}`,
		}, ""},
		{"its outcome while another runs", []string{
			`{"status":"ok","started_at":"2026-11-02T10:00:06Z","running":{"member":"m","origin":"schedule","since":"2026-11-02T10:00:20Z"}}`,
		}, ""},
		{"an older outcome only", []string{
			`{"status":"ok","started_at":"2026-11-02T09:30:00Z","running":{"member":"m","origin":"manual","since":"` + since + `"}}`,
			`{"status":"ok","started_at":"2026-11-02T09:30:00Z"}`,
		}, "ended without recording how it went"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			i := 0
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				state := tc.states[min(i, len(tc.states)-1)]
				i++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"source":{"id":1,"name":"Eng wiki","enabled":true,"sync":%s}}`, state)
			}))
			defer hub.Close()
			c, err := hubclient.New(hub.URL, "", "cloop_pat_x")
			if err != nil {
				t.Fatal(err)
			}
			src, err := waitForKnowledgeSync(context.Background(), c, 1, &hubclient.KnowledgeRunning{Since: since})
			switch {
			case tc.want == "" && (err != nil || src.Sync.Status != "ok"):
				t.Fatalf("waiting = %+v, %v; want the outcome", src, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("waiting = %+v, %v; want an error saying %q", src, err, tc.want)
			}
		})
	}
}
