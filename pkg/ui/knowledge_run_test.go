package ui

// The run-scoped knowledge search (Task 20472), over HTTP: what a run's
// knowledge session token opens — its own project's knowledge and nothing
// else, for as long as its run lives — and what every answer is held to.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// knowledgeRemoteExec stands in for an enrolled device: it isolates from the
// hub and shares nothing with it.
type knowledgeRemoteExec struct{ stubExecutor }

func (*knowledgeRemoteExec) ID() string   { return "edge-1" }
func (*knowledgeRemoteExec) Kind() string { return executor.KindRemoteAgent }
func (*knowledgeRemoteExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote, NetworkEgress: true}
}

// knowledgeRunFixture is a hub whose control plane holds two projects, each
// with a knowledge source of its own bound to it.
type knowledgeRunFixture struct {
	srv          *Server
	ts           *httptest.Server
	dir          string
	projA, projB string
	docA, docB   int64
	urlB         string
}

func newKnowledgeRunFixture(t *testing.T) *knowledgeRunFixture {
	t.Helper()
	registerUITestConnector.Do(func() { knowledge.MustRegister(uiTestConnector{}) })
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	useControlPlaneDir(t, dir)
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.ExternalURL = ts.URL
	setKnowledgeRunServer(srv)

	f := &knowledgeRunFixture{srv: srv, ts: ts, dir: dir,
		// Outside the control plane, as the hub requires a project to be.
		projA: filepath.Join(t.TempDir(), "alpha"), projB: filepath.Join(t.TempDir(), "bravo"),
		urlB: "https://wiki.example/bravo/secrets"}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cp := db.AsControlPlane()
	svc := knowledge.New(cp)
	admin := svc.For(knowledge.Principal{Actor: "test", Decide: func(authz.Scope) authz.Decision {
		return authz.AllowAll(authz.SourceAuthzDisabled, "test")
	}})
	ctx := context.Background()
	add := func(name, project, extID, title, url, body string) int64 {
		src, err := admin.CreateSource(ctx, knowledge.SourceInput{Kind: "uitest", Name: name, Scope: knowledge.ScopeOrg,
			Config: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Index(src.ID, knowledge.Document{ExternalID: extID, Title: title, URL: url, Space: "ENG",
			UpdatedAt: time.Now(), Body: body}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := admin.Bind(ctx, knowledge.Project{Path: project}, src.ID, knowledge.Filter{}); err != nil {
			t.Fatal(err)
		}
		docs, err := cp.KnowledgeProjectDocuments(ctx, project, statedb.KnowledgeDocumentLookup{URL: url})
		if err != nil || len(docs) != 1 {
			t.Fatalf("the fixture's document %s: %v %v", url, docs, err)
		}
		return docs[0].ID
	}
	f.docA = add("Alpha wiki", f.projA, "a1", "Deploy runbook", "https://wiki.example/alpha/runbook",
		"# Rollback\nRoll the deploy back with the undo command, then page the on-call engineer.")
	f.docB = add("Bravo wiki", f.projB, "b1", "Deploy secrets for bravo", f.urlB,
		"# Deploy\nBravo's deploy keys live in the vault under bravo/prod; only bravo may read this.")
	return f
}

// mint dispatches a run of project on a device and returns the knowledge
// session token its environment was given.
func (f *knowledgeRunFixture) mint(t *testing.T, project string) (string, *runKnowledge, executor.Spec) {
	t.Helper()
	spec, k := applyKnowledgeSession(executor.Spec{WorkDir: project}, &knowledgeRemoteExec{}, project, "run-"+filepath.Base(project),
		"alice@example.com", []string{"cloop", "run"})
	if k == nil {
		t.Fatalf("no knowledge session for a run of %s, which has a bound source", project)
	}
	token := ""
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvToken+"="); ok {
			token = v
		}
	}
	if !strings.HasPrefix(token, knowledgerun.TokenPrefix) {
		t.Fatalf("the run's environment carries no knowledge session token: %v", spec.Env)
	}
	return token, k, spec
}

// post sends body to the run endpoint path with token, and decodes the answer
// into out when it is 200.
func (f *knowledgeRunFixture) post(t *testing.T, token, path string, body, out any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+knowledgerun.MountPath+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
	}
	return resp.StatusCode
}

func (f *knowledgeRunFixture) db(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db.AsControlPlane()
}

// TestRunKnowledgeSessionIsMintedForTheRunAlone: a run of a project with a
// bound source is dispatched with the session's URL and token — the token
// declared sensitive, so it is scrubbed from the run's output and never
// stored with its spec — and the hub keeps only the token's hash. Nothing of
// the credentials the hub reads the sources with goes with it, and a project
// with no bound source, or a dispatch that is not a run, gets nothing.
func TestRunKnowledgeSessionIsMintedForTheRunAlone(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	token, k, spec := f.mint(t, f.projA)

	added := map[string]string{}
	for _, kv := range spec.Env {
		name, value, _ := strings.Cut(kv, "=")
		added[name] = value
	}
	if len(added) != 3 || added[knowledgerun.EnvURL] != f.ts.URL+knowledgerun.MountPath ||
		added[redact.EnvKey] != knowledgerun.EnvToken {
		t.Fatalf("a device run's environment is %v: want exactly the URL, the token and the token declared sensitive", added)
	}
	row, err := f.db(t).GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if err != nil {
		t.Fatal(err)
	}
	if row.TokenSHA256 != tokenSHA256(token) || strings.Contains(row.Scope+row.Counters, token) {
		t.Fatalf("the session's record holds %+v: want the token's hash and never the token", row)
	}
	if row.ProjectID != f.projA || row.RunID != "run-alpha" || row.ExecutorID != "edge-1" || !row.Open() {
		t.Fatalf("the session's record = %+v", row)
	}
	if spec.Redactor() == nil {
		t.Fatalf("the spec declares no sensitive value, so the token would reach the run's stored output")
	}

	other := filepath.Join(t.TempDir(), "charlie")
	if _, k := applyKnowledgeSession(executor.Spec{WorkDir: other}, &knowledgeRemoteExec{}, other, "run-c", "", []string{"cloop", "run"}); k != nil {
		t.Fatalf("a project with no bound source was given a knowledge session")
	}
	if _, k := applyKnowledgeSession(executor.Spec{WorkDir: f.projA}, &knowledgeRemoteExec{}, f.projA, "run-d", "",
		[]string{"cloop", "task", "ai-blocker", "1"}); k != nil {
		t.Fatalf("a dispatch that is not a run was given a knowledge session")
	}
}

// TestRemoteRunTokenReachesOnlyItsOwnProject: a device run's token searches
// and reads its own project's knowledge, through the project's bindings, and
// nothing of another project's — not by search, not by the other project's
// document id, not by its URL. The other project's own run reads it, so the
// knowledge is there to be refused.
func TestRemoteRunTokenReachesOnlyItsOwnProject(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	tokenA, _, _ := f.mint(t, f.projA)
	tokenB, _, _ := f.mint(t, f.projB)

	var res knowledgerun.SearchResponse
	if code := f.post(t, tokenA, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "deploy", K: 10}, &res); code != http.StatusOK {
		t.Fatalf("search = %d", code)
	}
	if len(res.Hits) != 1 || res.Hits[0].DocumentID != f.docA || !strings.Contains(res.Hits[0].Text, "undo command") ||
		res.Hits[0].Source.Name != "Alpha wiki" || res.Hits[0].URL == "" {
		t.Fatalf("alpha's run searched %+v; want alpha's runbook alone, with its text", res.Hits)
	}
	for _, ref := range []knowledgerun.GetRequest{{DocumentID: f.docB}, {URL: f.urlB}} {
		var got knowledgerun.GetResponse
		if code := f.post(t, tokenA, knowledgerun.PathGet, ref, &got); code != http.StatusOK {
			t.Fatalf("get %+v = %d", ref, code)
		}
		if len(got.Documents) != 0 {
			t.Fatalf("alpha's run read bravo's document by %+v: %+v", ref, got.Documents)
		}
	}
	var own knowledgerun.GetResponse
	if code := f.post(t, tokenA, knowledgerun.PathGet, knowledgerun.GetRequest{DocumentID: f.docA}, &own); code != http.StatusOK ||
		len(own.Documents) != 1 || !strings.Contains(own.Documents[0].Text, "## Rollback") {
		t.Fatalf("alpha's run reads its own document = %d %+v", code, own)
	}
	var theirs knowledgerun.GetResponse
	if code := f.post(t, tokenB, knowledgerun.PathGet, knowledgerun.GetRequest{URL: f.urlB}, &theirs); code != http.StatusOK ||
		len(theirs.Documents) != 1 || theirs.Documents[0].ID != f.docB {
		t.Fatalf("bravo's own run reads its document = %d %+v", code, theirs)
	}
}

// TestEndedRunTokensAreRefused: a token is refused — identically, so the
// answer says nothing about which sessions exist — once its session has
// lapsed or been closed, and when it is forged, malformed or missing.
func TestEndedRunTokensAreRefused(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	search := knowledgerun.SearchRequest{Query: "deploy"}

	live, _, _ := f.mint(t, f.projA)
	if code := f.post(t, live, knowledgerun.PathSearch, search, nil); code != http.StatusOK {
		t.Fatalf("a live session's search = %d", code)
	}
	forged := live[:len(live)-4] + "AAAA"
	if forged == live {
		forged = live[:len(live)-4] + "BBBB"
	}
	for name, token := range map[string]string{
		"forged secret": forged, "malformed": "cloop_know1_nope", "another kind": "cloop_relay_0123.abcdefghijk",
		"missing": "",
	} {
		if code := f.post(t, token, knowledgerun.PathSearch, search, nil); code != http.StatusUnauthorized {
			t.Errorf("%s token: %d, want 401", name, code)
		}
	}

	// Lapsed: the run stopped renewing it.
	expired, ek, _ := f.mint(t, f.projA)
	db := f.db(t)
	row, err := db.GetProxySession(statedb.ProxySessionKnowledge, ek.id)
	if err != nil {
		t.Fatal(err)
	}
	row.ExpiresAt = time.Now().Add(-time.Minute)
	if err := db.PutProxySession(row); err != nil {
		t.Fatal(err)
	}
	if code := f.post(t, expired, knowledgerun.PathSearch, search, nil); code != http.StatusUnauthorized {
		t.Errorf("an expired session's search = %d, want 401", code)
	}

	// Revoked: the run ended, and its session with it.
	revoked, rk, _ := f.mint(t, f.projA)
	rk.bindHandle(&knowledgeRemoteExec{}, "handle-revoked")
	if code := f.post(t, revoked, knowledgerun.PathGet, knowledgerun.GetRequest{DocumentID: f.docA}, nil); code != http.StatusOK {
		t.Fatalf("a live session's get = %d", code)
	}
	closeRunKnowledge("handle-revoked", "the run ended")
	for _, path := range []string{knowledgerun.PathSearch, knowledgerun.PathGet, knowledgerun.PathCitations} {
		if code := f.post(t, revoked, path, map[string]any{"query": "deploy", "document_id": f.docA}, nil); code != http.StatusUnauthorized {
			t.Errorf("%s with a closed session = %d, want 401", path, code)
		}
	}
	if row, err := db.GetProxySession(statedb.ProxySessionKnowledge, rk.id); err != nil || row.Open() ||
		row.CloseReason != "the run ended" {
		t.Fatalf("the ended run's session = %+v, %v", row, err)
	}
}

// TestRunKnowledgeScrubsWhatLeavesTheHub: a credential in the index — a
// pattern added after the page was synced, an index an older build wrote — is
// scrubbed from every answer on its way to the run.
func TestRunKnowledgeScrubsWhatLeavesTheHub(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	token, _, _ := f.mint(t, f.projA)
	var res knowledgerun.SearchResponse
	if code := f.post(t, token, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "rollback"}, &res); code != http.StatusOK || len(res.Hits) == 0 {
		t.Fatalf("search = %d %+v", code, res)
	}
	pat := "ghp_" + strings.Repeat("Ab1", 12)
	raw, err := sql.Open("sqlite", state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE knowledge_chunks_fts SET body = ? WHERE rowid = ?`,
		"Rollback: export GITHUB_TOKEN="+pat+" before running the undo command.", res.Hits[0].ChunkID); err != nil {
		t.Fatal(err)
	}
	var again knowledgerun.SearchResponse
	if code := f.post(t, token, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "rollback"}, &again); code != http.StatusOK || len(again.Hits) == 0 {
		t.Fatalf("search = %d %+v", code, again)
	}
	var doc knowledgerun.GetResponse
	if code := f.post(t, token, knowledgerun.PathGet, knowledgerun.GetRequest{DocumentID: f.docA}, &doc); code != http.StatusOK || len(doc.Documents) != 1 {
		t.Fatalf("get = %d %+v", code, doc)
	}
	for what, text := range map[string]string{"search": again.Hits[0].Text, "get": doc.Documents[0].Text} {
		if strings.Contains(text, pat) || !strings.Contains(text, "the undo command") {
			t.Fatalf("the %s answer is %q: want the credential scrubbed and the rest kept", what, text)
		}
	}
}

// TestRunKnowledgeIsBoundedAuditedAndCited: every query is on the audit trail
// with its run and the documents it was answered with; a session that asks
// too often is refused (and that is audited too); a document's text is held
// to the bound asked for; and what the agent read — never what the
// orchestrator asked for its prompt — is handed back once as the task's
// fetched citations.
func TestRunKnowledgeIsBoundedAuditedAndCited(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	token, k, _ := f.mint(t, f.projA)

	var doc knowledgerun.GetResponse
	if code := f.post(t, token, knowledgerun.PathGet, knowledgerun.GetRequest{DocumentID: f.docA, MaxBytes: 20, Task: 3}, &doc); code != http.StatusOK ||
		len(doc.Documents) != 1 || len(doc.Documents[0].Text) > 20 || !doc.Documents[0].Truncated {
		t.Fatalf("get with max_bytes 20 = %d %+v", code, doc)
	}
	if code := f.post(t, token, knowledgerun.PathSearch,
		knowledgerun.SearchRequest{Query: "undo command", Task: 4, Purpose: knowledgerun.PurposeInject}, nil); code != http.StatusOK {
		t.Fatalf("search = %d", code)
	}

	var cites knowledgerun.CitationsResponse
	if code := f.post(t, token, knowledgerun.PathCitations, knowledgerun.CitationsRequest{Task: 3}, &cites); code != http.StatusOK {
		t.Fatalf("citations = %d", code)
	}
	if len(cites.Citations) != 1 || cites.Citations[0].Kind != pm.CitationFetched || cites.Citations[0].DocumentID != f.docA ||
		cites.Citations[0].Title != "Deploy runbook" || cites.Citations[0].RunID != "run-alpha" ||
		cites.Citations[0].Source != "Alpha wiki" || cites.Citations[0].URL == "" {
		t.Fatalf("task 3's citations = %+v", cites.Citations)
	}
	for task := range []int{3, 4} {
		var again knowledgerun.CitationsResponse
		if code := f.post(t, token, knowledgerun.PathCitations, knowledgerun.CitationsRequest{Task: []int{3, 4}[task]}, &again); code != http.StatusOK ||
			len(again.Citations) != 0 {
			t.Fatalf("task %d's citations a second time = %d %+v: what was handed back, and what the orchestrator "+
				"asked for itself, are not the agent's reads", []int{3, 4}[task], code, again.Citations)
		}
	}

	db := f.db(t)
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "knowledge_session", EntityID: k.id})
	if err != nil {
		t.Fatal(err)
	}
	var search, get map[string]any
	for _, r := range rows {
		var p map[string]any
		_ = json.Unmarshal([]byte(r.Payload), &p)
		switch r.EventType {
		case string(auditaction.ActionKnowledgeRunSearch):
			search = p
		case string(auditaction.ActionKnowledgeRunGet):
			get = p
		}
	}
	if search == nil || search["query"] != "undo command" || search["run_id"] != "run-alpha" || search["project"] != f.projA ||
		search["purpose"] != knowledgerun.PurposeInject || search["outcome"] != "ok" ||
		!slices.Contains(anyInts(search["documents"]), f.docA) {
		t.Fatalf("the search's audit row = %v", search)
	}
	if get == nil || get["outcome"] != "ok" || !slices.Contains(anyInts(get["documents"]), f.docA) {
		t.Fatalf("the get's audit row = %v", get)
	}

	prevRate, prevBurst := runKnowledgeRate, runKnowledgeBurst
	runKnowledgeRate, runKnowledgeBurst = 0.001, 2
	t.Cleanup(func() { runKnowledgeRate, runKnowledgeBurst = prevRate, prevBurst })
	limited, lk, _ := f.mint(t, f.projA)
	codes := []int{}
	for range 3 {
		codes = append(codes, f.post(t, limited, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "deploy"}, nil))
	}
	if !slices.Equal(codes, []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests}) {
		t.Fatalf("a session with a burst of 2 answered %v", codes)
	}
	refused, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "knowledge_session", EntityID: lk.id,
		Search: `"outcome":"refused"`})
	if err != nil || len(refused) != 1 {
		t.Fatalf("the refused request's audit rows = %v, %v", refused, err)
	}
}

func anyInts(v any) []int64 {
	list, _ := v.([]any)
	out := make([]int64, 0, len(list))
	for _, x := range list {
		if f, ok := x.(float64); ok {
			out = append(out, int64(f))
		}
	}
	return out
}

// TestKnowledgeSessionsFollowTheRun: a knowledge session is renewed while its
// workload runs and closed when it ends; a process adopting the run takes the
// session over, and one whose session closed while nobody held it does not
// bring it back.
func TestKnowledgeSessionsFollowTheRun(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	running := &knowledgeStatusExec{state: executor.StateRunning}
	_, k, _ := f.mint(t, f.projA)
	k.bindHandle(running, "handle-renew")
	db := f.db(t)
	before, err := db.GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	renewKnowledgeSessions()
	after, _ := db.GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if !after.ExpiresAt.After(before.ExpiresAt) || !after.Open() {
		t.Fatalf("a running workload's session was not renewed: %v → %v", before.ExpiresAt, after.ExpiresAt)
	}
	running.state = executor.StateExited
	renewKnowledgeSessions()
	ended, _ := db.GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if ended.Open() || liveKnowledge.known(k.id) {
		t.Fatalf("an ended workload's session = %+v (kept: %v)", ended, liveKnowledge.known(k.id))
	}

	// Adoption: a session another process holds is taken over here.
	_, adopted, _ := f.mint(t, f.projB)
	row, _ := db.GetProxySession(statedb.ProxySessionKnowledge, adopted.id)
	row.Holder = "member-that-died"
	if err := db.PutProxySession(row); err != nil {
		t.Fatal(err)
	}
	restoreRunKnowledge(f.projB, &knowledgeStatusExec{state: executor.StateRunning}, "handle-adopted", []string{adopted.id})
	taken, _ := db.GetProxySession(statedb.ProxySessionKnowledge, adopted.id)
	if taken.Holder != leaseHolderID() || !liveKnowledge.known(adopted.id) {
		t.Fatalf("the adopted run's session = %+v (kept here: %v)", taken, liveKnowledge.known(adopted.id))
	}
	if ids := liveKnowledge.idsForHandle("handle-adopted"); !slices.Equal(ids, []string{adopted.id}) {
		t.Fatalf("the run's owner row would name %v", ids)
	}
	closeRunKnowledge("handle-adopted", "the run ended")
	retireRunKnowledge([]string{adopted.id}, "again")
	if row, _ := db.GetProxySession(statedb.ProxySessionKnowledge, adopted.id); row.Open() || row.CloseReason != "the run ended" {
		t.Fatalf("the adopted run's session after its end = %+v", row)
	}
	restoreRunKnowledge(f.projB, &knowledgeStatusExec{state: executor.StateRunning}, "handle-late", []string{adopted.id})
	if liveKnowledge.known(adopted.id) {
		t.Fatalf("a closed session was brought back by an adoption")
	}
}

// knowledgeStatusExec reports a settable state for one workload.
type knowledgeStatusExec struct {
	stubExecutor
	state executor.State
}

func (e *knowledgeStatusExec) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{State: e.state}, nil
}

// TestKnowledgeSessionLivesAsLongAsItsDispatchedRun: dispatched through the
// real start path, a run holding no secret lease keeps its knowledge session
// — the lease watcher, which returns at once for such a run, does not end it
// — and the session ends where every run is settled.
func TestKnowledgeSessionLivesAsLongAsItsDispatchedRun(t *testing.T) {
	f := newKnowledgeRunFixture(t)
	stub := newEgressStub("knowledge-run", executor.KindLocalProcess)
	registerStub(t, stub)
	if err := executor.Bind(f.projA, stub.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(f.projA) })
	if err := os.MkdirAll(f.projA, 0o755); err != nil {
		t.Fatal(err)
	}
	_, handle, err := startWorkloadAs(nil, nil, "alice@example.com", f.projA, []string{"cloop", "run"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { stub.finish(handle.ID, 0, time.Second) })
	token, _ := envOf(stub.lastSpec(t).Env, knowledgerun.EnvToken)
	if !strings.HasPrefix(token, knowledgerun.TokenPrefix) {
		t.Fatalf("the dispatched run carries no knowledge session: %v", stub.lastSpec(t).Env)
	}
	ids := liveKnowledge.idsForHandle(handle.ID)
	if len(ids) != 1 {
		t.Fatalf("the run's owner row would name sessions %v", ids)
	}
	// Long enough for the exit watchers the dispatch started to have run.
	time.Sleep(200 * time.Millisecond)
	if code := f.post(t, token, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "deploy"}, nil); code != http.StatusOK {
		t.Fatalf("the running run's search = %d: its session ended with the dispatch", code)
	}
	stub.finish(handle.ID, 0, time.Second)
	f.srv.runEnded(f.projA, stub, handle.ID)
	if code := f.post(t, token, knowledgerun.PathSearch, knowledgerun.SearchRequest{Query: "deploy"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("the ended run's search = %d, want 401", code)
	}
	if row, err := f.db(t).GetProxySession(statedb.ProxySessionKnowledge, ids[0]); err != nil || row.Open() {
		t.Fatalf("the ended run's session = %+v, %v", row, err)
	}
}
