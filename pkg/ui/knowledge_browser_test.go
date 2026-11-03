package ui

// The knowledge panels in a real browser (Task 20473): Settings → Knowledge
// sources, a project's Knowledge tab and a task's citations, driven by
// testdata/knowledge_browser.js as a maintainer who is not an administrator,
// on an SSO hub with a role policy, against the fake connector. The driver's
// header says what it proves; this sets the hub up, gives the driver the
// levers it pulls as other people, and holds what it saw to the rules.
// Skips without Chrome or node, like the other browser gates here.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
)

type knowledgeBrowserHit struct {
	Title   string `json:"title"`
	Href    string `json:"href"`
	Target  string `json:"target"`
	Rel     string `json:"rel"`
	Marks   int    `json:"marks"`
	Markup  int    `json:"markup"`
	Where   string `json:"where"`
	Snippet string `json:"snippet"`
}

type knowledgeBrowserResult struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Debug            json.RawMessage       `json:"debug"`
	Requests         []string              `json:"requests"`
	Me               string                `json:"me"`
	SettingsNames    []string              `json:"settings_names"`
	OrgControls      []string              `json:"org_controls"`
	BobOnPage        bool                  `json:"bob_on_page"`
	OrgScopeDisabled bool                  `json:"org_scope_disabled"`
	PersonalChecked  bool                  `json:"personal_scope_checked"`
	FailText         string                `json:"fail_text"`
	ValueCleared     bool                  `json:"value_cleared"`
	CredSelected     string                `json:"cred_selected"`
	TokenInPage      bool                  `json:"token_in_page"`
	OKText           string                `json:"ok_text"`
	SyncedCard       string                `json:"synced_card"`
	ListRefetches    int                   `json:"list_refetches"`
	KnowledgeFrames  int                   `json:"knowledge_frames"`
	FramesNamingBob  int                   `json:"frames_naming_bob"`
	BobOnPageAfter   bool                  `json:"bob_on_page_after"`
	Bindable         []string              `json:"bindable"`
	Hits             []knowledgeBrowserHit `json:"hits"`
	Mode             string                `json:"mode"`
	RetrievalSaved   bool                  `json:"retrieval_saved"`
	NarrowedHits     []knowledgeBrowserHit `json:"narrowed_hits"`
	Unbound          bool                  `json:"unbound"`
	Cites            struct {
		Text   string   `json:"text"`
		Links  []string `json:"links"`
		Markup int      `json:"markup"`
	} `json:"cites"`
	XSS *string  `json:"xss"`
	CSP []string `json:"csp"`
}

func TestKnowledgePanelsInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())
	h := knowledgeConnectionHub(t)
	old := knowledgePushGap.Swap(int64(100 * time.Millisecond))
	t.Cleanup(func() { knowledgePushGap.Store(old) })

	// Everyone signs in before Chrome starts: the fake provider's claims are
	// never flipped while the browser runs.
	admin := h.signIn(t, "ada@example.com", false, "owners")
	bob := h.signIn(t, "bob@example.com", false, "engineers")
	lead := h.signIn(t, "lead@example.com", false, "leads")
	create := func(c *http.Client, name, scope, site string) int64 {
		t.Helper()
		resp, raw := h.call(t, c, http.MethodPost, "/api/knowledge/sources", map[string]any{
			"kind": "uifake", "name": name, "scope": scope, "config": map[string]any{"site": site}})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s = %d %s", name, resp.StatusCode, raw)
		}
		var d struct {
			Source knowledgeSourceView `json:"source"`
		}
		decodeBody(t, raw, &d)
		return d.Source.ID
	}
	org := create(admin, "kb-browser-org-wiki", "org", "orgsite")
	bobs := create(bob, "kb-browser-bob-secret-notes", "personal", "bobsite")

	// A task whose run cited what it read: a page linked, and one whose title
	// is markup and whose URL is a script.
	ps, err := state.Load(h.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Plan == nil {
		ps.Plan = &pm.Plan{Goal: "ship it"}
	}
	taskID := 1
	for _, tk := range ps.Plan.Tasks {
		taskID = max(taskID, tk.ID+1)
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, &pm.Task{ID: taskID, Title: "Roll the ingest consumer back", Status: pm.TaskDone,
		Result: "rolled back", Citations: []pm.Citation{
			{Kind: pm.CitationInjected, Title: "Rollback runbook", URL: "https://wiki.example.com/pages/orgsite/1",
				Source: "kb-browser-org-wiki", SourceKind: "uifake", DocumentID: 1, RunID: "run_b"},
			{Kind: pm.CitationFetched, Title: `<img src=x onerror="window.__xss='cite'">Postmortem`, URL: "javascript:window.__xss='cite-url'",
				Source: "kb-browser-org-wiki", SourceKind: "uifake", DocumentID: 2, RunID: "run_b"},
		}})
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	send := func(c *http.Client, method, path string, body any) error {
		var rdr io.Reader = http.NoBody
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = strings.NewReader(string(b))
		}
		req, err := http.NewRequest(method, h.ts.URL+path, rdr)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("%s %s = %d %s", method, path, resp.StatusCode, b)
		}
		return nil
	}
	control := http.NewServeMux()
	control.HandleFunc("POST /org-sync", func(w http.ResponseWriter, r *http.Request) {
		if err := send(admin, http.MethodPost, fmt.Sprintf("/api/knowledge/sources/%d/sync", org), map[string]any{}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	control.HandleFunc("POST /bob-rename", func(w http.ResponseWriter, r *http.Request) {
		if err := send(bob, http.MethodPatch, fmt.Sprintf("/api/knowledge/sources/%d", bobs),
			map[string]any{"name": "kb-browser-bob-secret-notes-renamed"}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	ctl := httptest.NewServer(control)
	defer ctl.Close()

	const token = "kb-browser-credential-0f9e8d7c6b5a4f3e2d1c"
	cmd := exec.Command(node, mustAbs(t, "testdata/knowledge_browser.js"), chrome, h.ts.URL, ctl.URL, fmt.Sprint(taskID))
	cmd.Env = append(os.Environ(), "KNOWLEDGE_COOKIE="+sessionCookie(t, lead, h.ts.URL), "KNOWLEDGE_TOKEN="+token)
	out, err := cmd.Output()
	if os.Getenv("KNOWLEDGE_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got knowledgeBrowserResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver: %s\ndebug: %s\nrequests: %v", got.Error.Message, got.Debug, got.Requests)
	}
	if strings.Contains(string(out), token) {
		t.Errorf("the credential the dialog stored came back to the page somewhere: %s", out)
	}
	if got.Me != "lead@example.com" {
		t.Fatalf("the browser is signed in as %q", got.Me)
	}

	// RBAC visibility: the organisation's source and nothing of bob's, before
	// and after bob changed his; no control on the organisation source but
	// the ones a maintainer has — none.
	if strings.Join(got.SettingsNames, ",") != "kb-browser-org-wiki" {
		t.Errorf("a maintainer's Settings listed %v, want the organisation's source alone", got.SettingsNames)
	}
	if len(got.OrgControls) != 0 {
		t.Errorf("a maintainer's card for the organisation source offers %v; it is an administrator's to manage", got.OrgControls)
	}
	if got.BobOnPage || got.BobOnPageAfter || got.FramesNamingBob != 0 {
		t.Errorf("a colleague's personal source reached the page: listed %v, after his change %v, in %d frames",
			got.BobOnPage, got.BobOnPageAfter, got.FramesNamingBob)
	}
	if !got.OrgScopeDisabled || !got.PersonalChecked {
		t.Errorf("the connect dialog: organisation scope disabled %v, personal chosen %v", got.OrgScopeDisabled, got.PersonalChecked)
	}

	// The credential: stored through the form, never shown again, and
	// redacted out of the failure that quoted it.
	if !strings.Contains(got.FailText, "401 Unauthorized") || !strings.Contains(got.FailText, redact.Marker) {
		t.Errorf("the failed test said %q: want the remote's words with the credential redacted", got.FailText)
	}
	if !got.ValueCleared || got.CredSelected != "lead-browser-token" || got.TokenInPage {
		t.Errorf("after storing the credential: value cleared %v, picker on %q, value anywhere in the page %v",
			got.ValueCleared, got.CredSelected, got.TokenInPage)
	}
	if !strings.Contains(got.OKText, "Connected") || !strings.Contains(got.OKText, "2 documents") {
		t.Errorf("the passing test said %q", got.OKText)
	}

	// Live status from pushes: the card synced without the list being read.
	if !strings.Contains(got.SyncedCard, "2 documents") || got.ListRefetches != 0 {
		t.Errorf("after Sync now the card says %q, with the list read %d more times (want 0: pushed)",
			got.SyncedCard, got.ListRefetches)
	}
	if got.KnowledgeFrames == 0 {
		t.Error("the page received no knowledge_source frame")
	}

	// Bind → search.
	if len(got.Bindable) != 1 || !strings.Contains(got.Bindable[0], "Lead's runbooks") {
		t.Errorf("the bind form offered %v; a maintainer binds their own source, not the organisation's", got.Bindable)
	}
	if len(got.Hits) != 2 {
		t.Fatalf("the search found %d passages, want 2: %+v", len(got.Hits), got.Hits)
	}
	var linked, hostile *knowledgeBrowserHit
	for i := range got.Hits {
		if strings.Contains(got.Hits[i].Title, "Rollback runbook for leadsite") {
			linked = &got.Hits[i]
		}
		if strings.Contains(got.Hits[i].Title, "Postmortem") {
			hostile = &got.Hits[i]
		}
	}
	if linked == nil || linked.Href != "https://wiki.example.com/pages/leadsite/1" || linked.Target != "_blank" ||
		!strings.Contains(linked.Rel, "noopener") || linked.Marks == 0 || !strings.Contains(linked.Where, "Lead's runbooks") ||
		!strings.Contains(linked.Where, "Runbooks › Deploys") {
		t.Errorf("the runbook's passage: %+v", linked)
	}
	if hostile == nil || hostile.Href != "" || hostile.Markup != 0 || !strings.Contains(hostile.Title, `<img src=x`) ||
		!strings.Contains(hostile.Snippet, "<script>") || !strings.Contains(hostile.Where, "<svg") {
		t.Errorf("the hostile passage must show its markup as text and link nowhere: %+v", hostile)
	}
	if !got.RetrievalSaved {
		t.Error("the retrieval setting was not saved")
	}
	if len(got.NarrowedHits) != 1 || !strings.Contains(got.NarrowedHits[0].Title, "Rollback runbook") {
		t.Errorf("narrowed to ENG, the search found %+v", got.NarrowedHits)
	}
	if !got.Unbound {
		t.Error("the source was not unbound")
	}

	// Citations, and nothing anywhere ran.
	if !strings.Contains(got.Cites.Text, "Rollback runbook") || !strings.Contains(got.Cites.Text, "<img src=x") ||
		strings.Join(got.Cites.Links, ",") != "https://wiki.example.com/pages/orgsite/1" || got.Cites.Markup != 0 {
		t.Errorf("the task's citations: %+v", got.Cites)
	}
	if got.XSS != nil {
		t.Errorf("window.__xss = %q: a hostile string ran", *got.XSS)
	}
	if len(got.CSP) != 0 {
		t.Errorf("the page recorded CSP violations: %v", got.CSP)
	}
}
