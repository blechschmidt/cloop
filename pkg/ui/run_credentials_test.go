package ui

// A run's credentials reach its own project and nothing else (Task 20499).
//
// The fixture is a hub with two projects, alpha and bravo, each with tasks and
// a knowledge source of its own. Every credential the hub mints for a run is
// minted for alpha's, and then turned on bravo: at every route of the
// dashboard's API, with bravo's index, task and attachment ids in the request;
// at the run-scoped knowledge search, naming bravo, its documents and its
// tasks; at the git proxy and the Kubernetes access monitor, at bravo's
// repository and namespace; and an executor pool controller's credential at
// another pool's runner. Each attempt is answered 403 or 404, changes nothing,
// and leaves a row on the audit trail. The one way across — a read of a
// project whose readers list names alpha — is then opened, and shown to close
// again the moment the list changes.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// runScopeFixture is a hub serving two projects that share nothing.
type runScopeFixture struct {
	srv          *Server
	handler      http.Handler
	dir          string // the control plane
	alpha, bravo string
	bravoIdx     int
	docA, docB   int64
	urlB         string
}

func newRunScopeFixture(t *testing.T, token string) *runScopeFixture {
	t.Helper()
	registerUITestConnector.Do(func() { knowledge.MustRegister(uiTestConnector{}) })
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	useControlPlaneDir(t, dir)
	alpha := setupProjectDir(t, "alpha's goal", []*pm.Task{
		{ID: 1, Title: "alpha's task", Status: pm.TaskPending, Priority: 1},
	})
	bravo := setupProjectDir(t, "bravo's goal", []*pm.Task{
		{ID: 1, Title: "bravo's first task", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "bravo's second task", Status: pm.TaskDone, Priority: 2},
	})
	if err := multiui.AddPathsOwned([]string{alpha, bravo}, ""); err != nil {
		t.Fatal(err)
	}
	srv := New(dir, 0, token)
	srv.RPS, srv.Burst = 100000, 100000
	srv.ExternalURL = "https://hub.example.com"
	setKnowledgeRunServer(srv)
	f := &runScopeFixture{srv: srv, handler: srv.Handler(), dir: dir, alpha: alpha, bravo: bravo, bravoIdx: -1,
		urlB: "https://wiki.example/bravo/deploy"}
	for i, e := range srv.allProjectEntries() {
		if e.Path == bravo {
			f.bravoIdx = i
		}
	}
	if f.bravoIdx < 0 {
		t.Fatalf("bravo is not in the hub's list: %v", srv.allProjectEntries())
	}

	db := f.controlPlane(t)
	svc := knowledge.New(db)
	admin := svc.For(knowledge.Principal{Actor: "test", Decide: func(authz.Scope) authz.Decision {
		return authz.AllowAll(authz.SourceAuthzDisabled, "test")
	}})
	add := func(name, project, extID, title, url, body string) int64 {
		src, err := admin.CreateSource(context.Background(), knowledge.SourceInput{Kind: "uitest", Name: name,
			Scope: knowledge.ScopeOrg, Config: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Index(src.ID, knowledge.Document{ExternalID: extID, Title: title, URL: url, Space: "ENG",
			UpdatedAt: time.Now(), Body: body}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := admin.Bind(context.Background(), knowledge.Project{Path: project}, src.ID,
			knowledge.Filter{}); err != nil {
			t.Fatal(err)
		}
		docs, err := db.KnowledgeProjectDocuments(context.Background(), project, statedb.KnowledgeDocumentLookup{URL: url})
		if err != nil || len(docs) != 1 {
			t.Fatalf("the fixture's document %s: %v %v", url, docs, err)
		}
		return docs[0].ID
	}
	f.docA = add("Alpha wiki", alpha, "a1", "Alpha deploy runbook", "https://wiki.example/alpha/runbook",
		"# Deploy\nAlpha deploys with the release train every Tuesday.")
	f.docB = add("Bravo wiki", bravo, "b1", "Bravo deploy secrets", f.urlB,
		"# Deploy\nBravo's deploy keys live in the vault under bravo/prod; only bravo may read this.")
	return f
}

// controlPlane opens the hub's own database for the test.
func (f *runScopeFixture) controlPlane(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db.AsControlPlane()
}

// list puts reader on project's readers list, as a project administrator does.
func (f *runScopeFixture) list(t *testing.T, project, reader string) {
	t.Helper()
	if _, _, err := projectreaders.Add(f.controlPlane(t), project, reader, "test", nil); err != nil {
		t.Fatalf("list %s as a reader of %s: %v", reader, project, err)
	}
}

// unlist takes reader off project's readers list.
func (f *runScopeFixture) unlist(t *testing.T, project, reader string) {
	t.Helper()
	if _, err := projectreaders.Remove(f.controlPlane(t), project, reader, nil); err != nil {
		t.Fatalf("take %s off %s's readers list: %v", reader, project, err)
	}
}

// auditRows lists the control plane's rows of action, oldest first.
func (f *runScopeFixture) auditRows(t *testing.T, action auditaction.Action) []statedb.AuditEvent {
	t.Helper()
	rows, _, err := f.controlPlane(t).ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// payload decodes an audit row's payload.
func payloadOf(t *testing.T, e statedb.AuditEvent) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(e.Payload), &m); err != nil {
		t.Fatalf("payload %q: %v", e.Payload, err)
	}
	return m
}

// dbFingerprint hashes every row of every table of the database at path but
// the ones named in skip, so a test can say "nothing here changed".
func dbFingerprint(t *testing.T, path string, skip ...string) string {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(skip, name) && !strings.HasPrefix(name, "sqlite_") {
			tables = append(tables, name)
		}
	}
	_ = rows.Close()
	h := sha256.New()
	for _, table := range tables {
		r, err := raw.Query(`SELECT * FROM "` + table + `"`)
		if err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		cols, _ := r.Columns()
		var lines []string
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprintf("%v", vals))
		}
		_ = r.Close()
		sort.Strings(lines)
		fmt.Fprintf(h, "%s:%d\n%s\n", table, len(lines), strings.Join(lines, "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprint is everything a refused request must leave alone: both
// projects' databases whole, and the control plane's but for its audit trail,
// which a refusal is supposed to add to.
func (f *runScopeFixture) fingerprint(t *testing.T) string {
	t.Helper()
	return dbFingerprint(t, state.DBPath(f.alpha)) + dbFingerprint(t, state.DBPath(f.bravo)) +
		dbFingerprint(t, state.DBPath(f.dir), "audit_events", "audit_checkpoints")
}

// runCredential is one of alpha's run credentials, as a run is handed it.
type runCredential struct {
	kind  string
	value string
	// user is the basic credential's user half, for the kinds a client
	// presents as one.
	user string
	// live reports a session the hub recorded for alpha's run, which a
	// refusal can name.
	live bool
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randomB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// alphaCredentials mints one credential of every kind for a run of alpha: its
// knowledge session as a dispatch mints it, its model relay and Kubernetes
// monitor sessions recorded as the hub records them, and the rest as the
// minting code shapes them.
func (f *runScopeFixture) alphaCredentials(t *testing.T) []runCredential {
	t.Helper()
	var out []runCredential
	spec, k := applyKnowledgeSession(executor.Spec{WorkDir: f.alpha}, &knowledgeRemoteExec{}, f.alpha, "run-alpha",
		"alice@example.com", []string{"cloop", "run"})
	if k == nil {
		t.Fatal("alpha's run got no knowledge session")
	}
	tok, _ := envOf(spec.Env, knowledgerun.EnvToken)
	out = append(out, runCredential{kind: "knowledge_session", value: tok, live: true})

	db := f.controlPlane(t)
	now := time.Now().UTC()
	record := func(kind, id, token string) {
		if err := db.PutProxySession(statedb.ProxySessionRow{Kind: kind, SessionID: id, TokenSHA256: tokenSHA256(token),
			Holder: "test", RunID: "run-alpha", ProjectID: f.alpha, ExecutorID: "edge-1", Actor: "alice@example.com",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	relayID := randomHex(t, 12)
	relay := redact.RelayTokenPrefix + relayID + "." + randomHex(t, 32)
	record(statedb.ProxySessionModel, relayID, relay)
	out = append(out, runCredential{kind: "model_relay_session", value: relay, live: true})

	kubeID := redact.KubeGuardTokenPrefix + randomB64(t, 12)
	kube := kubeID + "." + randomB64(t, 32)
	record(statedb.ProxySessionKube, kubeID, kube)
	out = append(out, runCredential{kind: "kube_guard_session", value: kube, live: true})

	reg, err := gitproxy.NewRegistry("https://proxy.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	m, err := reg.Mint(gitproxy.MintRequest{Upstream: "https://github.com/acme/alpha.git", ProjectID: f.alpha,
		RunID: "run-alpha", Policy: gitproxy.Policy{AllowFetch: true, AllowCreate: true}})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, runCredential{kind: "git_proxy_session", value: m.Token, user: m.Session.ID},
		runCredential{kind: "egress_session", value: redact.EgressTokenPrefix + randomHex(t, 32), user: randomHex(t, 8)},
		runCredential{kind: "ci_relay_session", value: claudeproxy.TokenPrefix + randomHex(t, 12) + "." + randomHex(t, 32)},
		runCredential{kind: "pool_controller", value: executorpool.CredentialPrefix + randomB64(t, 12) + "." + randomB64(t, 32)},
		runCredential{kind: "runner_token",
			value: remote.RunnerTokenMarker + randomB64(t, 12) + "." + randomB64(t, 32) + "." + randomHex(t, 16)},
		runCredential{kind: "runner_credential",
			value: remote.RunnerCredentialMarker + randomB64(t, 12) + "." + randomB64(t, 32) + "." + randomHex(t, 16)},
	)
	if len(out) != len(runCredentialKinds) {
		t.Fatalf("the test mints %d kinds of credential, the hub knows %d: mint the new one here", len(out),
			len(runCredentialKinds))
	}
	return out
}

// presentations are the ways a client puts a credential in a request.
var presentations = []string{"bearer", "basic", "x-api-key", "query"}

// present puts c in req the way named.
func present(req *http.Request, c runCredential, how string) {
	switch how {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.value)
	case "basic":
		user := c.user
		if user == "" {
			user = "x-access-token"
		}
		req.SetBasicAuth(user, c.value)
	case "x-api-key":
		req.Header.Set("X-Api-Key", c.value)
	case "query":
		q := req.URL.Query()
		q.Set("token", c.value)
		req.URL.RawQuery = q.Encode()
	}
}

var routeParam = regexp.MustCompile(`\{[^}]*\}`)

// requestFor builds a request to route's path for method, with bravo's
// coordinates wherever the route takes a project, and a task or attachment id
// of bravo's wherever it takes one.
func (f *runScopeFixture) requestFor(pattern, method string) *http.Request {
	path := pattern
	if _, p, ok := splitPattern(pattern); ok {
		path = p
	}
	path = routeParam.ReplaceAllStringFunc(path, func(seg string) string {
		if seg == "{idx}" {
			return strconv.Itoa(f.bravoIdx)
		}
		return "1"
	})
	if strings.HasSuffix(path, "/") && path != "/" {
		path += "x"
	}
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = strings.NewReader(`{"project_idx":` + strconv.Itoa(f.bravoIdx) + `,"task_id":1,"id":1}`)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1"+path+"?project_idx="+strconv.Itoa(f.bravoIdx), body)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:40000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// beforeAuth reports a request one of the hub's own entry points answers
// before its authentication: classified by tests/arch/runcredentials_test.go,
// not by this sweep.
func beforeAuth(r *http.Request) bool {
	return servedBeforeAuth(r) || r.URL.Path == executorConnectPath || r.URL.Path == forwarderConnectPath ||
		strings.HasPrefix(r.URL.Path, clusterAPIPrefix) || r.URL.Path == "/healthz" || r.URL.Path == "/readyz"
}

// refusalOf decodes a run credential refusal, failing the test for any other
// answer.
func refusalOf(t *testing.T, what string, rec *httptest.ResponseRecorder, kind string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Errorf("%s: %d %s, want 403", what, rec.Code, strings.TrimSpace(rec.Body.String()))
		return
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if detail(body, "reason") != "run_credential" || detail(body, "credential") != kind {
		t.Errorf("%s: refused as %s/%s, want run_credential/%s: %s", what, detail(body, "reason"),
			detail(body, "credential"), kind, rec.Body.String())
	}
}

// liftRunCredentialAuditLimits lets a sweep write a row for every refusal.
func liftRunCredentialAuditLimits(t *testing.T) {
	t.Helper()
	burst, rate, minute := runCredentialAuditBurst, runCredentialAuditPerSecond, runCredentialAuditPerMinute
	unverified, tracked := runCredentialUnverifiedPerMinute, runCredentialTracked
	runCredentialAuditBurst, runCredentialAuditPerSecond, runCredentialAuditPerMinute = 1e9, 1e9, 1<<30
	runCredentialUnverifiedPerMinute, runCredentialTracked = 1<<30, 1<<30
	t.Cleanup(func() {
		runCredentialAuditBurst, runCredentialAuditPerSecond, runCredentialAuditPerMinute = burst, rate, minute
		runCredentialUnverifiedPerMinute, runCredentialTracked = unverified, tracked
	})
}

// TestARunsCredentialsOpenNoRouteOfTheDashboard sends every route of the
// dashboard's API one of alpha's run credentials, aimed at bravo — every kind
// of credential and every way of presenting one taking turns across the
// table — and then the routes that touch a project's tasks, attachments,
// runs, list and registration every kind at once. Each is refused 403 for
// what it is, nothing changes, and each refusal is a row naming the
// credential, the route and, for a live session, alpha's run.
func TestARunsCredentialsOpenNoRouteOfTheDashboard(t *testing.T) {
	f := newRunScopeFixture(t, "")
	liftRunCredentialAuditLimits(t)
	creds := f.alphaCredentials(t)
	before := f.fingerprint(t)

	type attempt struct {
		pattern, method string
		cred            runCredential
		how             string
	}
	var attempts []attempt
	i := 0
	for _, rs := range f.srv.routeTable() {
		for _, m := range rs.methods() {
			if beforeAuth(f.requestFor(rs.Pattern, m)) {
				// Answered before authentication, which only a public
				// route may be: a bypass widened over a gated route would
				// take that route out of this sweep, and out of every
				// permission check with it.
				if rs.permFor(m) != authz.PermPublic {
					t.Errorf("%s %s needs %s, yet is answered before authentication", m, rs.Pattern, rs.permFor(m))
				}
				continue
			}
			c := creds[i%len(creds)]
			attempts = append(attempts, attempt{rs.Pattern, m, c, presentations[(i/len(creds))%len(presentations)]})
			i++
		}
	}
	if len(attempts) < 300 {
		t.Fatalf("only %d routes swept: the route table went blind", len(attempts))
	}
	// The routes that act on a project's tasks, attachments, runs, list and
	// registration, with every kind of credential.
	for _, rt := range []struct{ pattern, method string }{
		{"PATCH /api/tasks/{id}", http.MethodPatch},
		{"POST /api/tasks", http.MethodPost},
		{"DELETE /api/tasks/{id}", http.MethodDelete},
		{"GET /api/tasks/{id}/attachments", http.MethodGet},
		{"DELETE /api/tasks/{id}/attachments/{aid}", http.MethodDelete},
		{"/api/run", http.MethodPost},
		{"POST /api/run/adopt-build", http.MethodPost},
		{"PUT /api/projects/{idx}/readers", http.MethodPut},
		{"/api/state", http.MethodGet},
	} {
		for _, c := range creds {
			attempts = append(attempts, attempt{rt.pattern, rt.method, c, "bearer"})
		}
	}

	for _, a := range attempts {
		req := f.requestFor(a.pattern, a.method)
		present(req, a.cred, a.how)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		refusalOf(t, fmt.Sprintf("%s %s with %s as %s", a.method, req.URL.Path, a.cred.kind, a.how), rec, a.cred.kind)
	}
	if t.Failed() {
		return
	}

	if after := f.fingerprint(t); after != before {
		t.Fatal("a refused request changed a project's or the hub's state")
	}
	rows := f.auditRows(t, auditaction.ActionRunCredentialRefused)
	if len(rows) != len(attempts) {
		t.Fatalf("%d run.credential_refused rows for %d refusals", len(rows), len(attempts))
	}
	for n, row := range rows {
		a := attempts[n]
		p := payloadOf(t, row)
		if p["kind"] != a.cred.kind || p["method"] != a.method {
			t.Fatalf("row %d is %v, for %s %s with %s", n, p, a.method, a.pattern, a.cred.kind)
		}
		if strings.Contains(row.Payload, a.cred.value) {
			t.Fatalf("row %d carries the credential itself", n)
		}
		if a.cred.live {
			if p["verified"] != true || p["project"] != f.alpha || p["run_id"] != "run-alpha" {
				t.Errorf("row %d does not name alpha's run for its live %s session: %v", n, a.cred.kind, p)
			}
		} else if p["verified"] == true {
			t.Errorf("row %d calls an unrecorded %s verified", n, a.cred.kind)
		}
	}
}

// TestARunsCredentialIsRefusedOnEveryKindOfHub: the refusal comes before the
// hub's own credentials are looked at, so it is the same on a hub with a
// static token, one with single sign-on and one with neither — where the
// request would otherwise have been served as the hub's operator.
func TestARunsCredentialIsRefusedOnEveryKindOfHub(t *testing.T) {
	t.Run("static token", func(t *testing.T) {
		f := newRunScopeFixture(t, "the-static-admin-token-of-this-hub")
		liftRunCredentialAuditLimits(t)
		for _, c := range f.alphaCredentials(t) {
			req := f.requestFor("PATCH /api/tasks/{id}", http.MethodPatch)
			present(req, c, "bearer")
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			refusalOf(t, "static token hub, "+c.kind, rec, c.kind)
		}
		if n := len(f.auditRows(t, auditaction.ActionRunCredentialRefused)); n != len(runCredentialKinds) {
			t.Errorf("%d refusal rows, want %d", n, len(runCredentialKinds))
		}
	})
	t.Run("single sign-on", func(t *testing.T) {
		mf := newMemberFixture(t, true)
		liftRunCredentialAuditLimits(t)
		token := knowledgerun.TokenPrefix + randomHex(t, 12) + "." + randomB64(t, 32)
		for _, path := range []string{"/api/tasks/1?project_idx=0", "/api/state?project_idx=0", "/api/projects"} {
			req, _ := http.NewRequest(http.MethodGet, mf.ts.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "run_credential") {
				t.Errorf("GET %s on an SSO hub with a run's token: %d %s, want 403 run_credential", path,
					resp.StatusCode, body)
			}
		}
	})
	t.Run("no sign-in", func(t *testing.T) {
		f := newRunScopeFixture(t, "")
		liftRunCredentialAuditLimits(t)
		// Without the credential an open hub serves anyone who reaches it;
		// with a run's credential, the request is the run's, and refused.
		req := f.requestFor("/api/state", http.MethodGet)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("the open hub's own GET /api/state: %d", rec.Code)
		}
		req = f.requestFor("/api/state", http.MethodGet)
		present(req, f.alphaCredentials(t)[0], "bearer")
		rec = httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		refusalOf(t, "open hub", rec, "knowledge_session")
	})
}

// knowledgeCall posts body to the run-scoped knowledge search's path with
// token, returning the status and the answer.
func (f *runScopeFixture) knowledgeCall(t *testing.T, token, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+knowledgerun.MountPath+path, bytes.NewReader(raw))
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// knowledgeToken dispatches a run of workDir and returns its knowledge token.
func (f *runScopeFixture) knowledgeToken(t *testing.T, workDir, runID string) string {
	t.Helper()
	spec, k := applyKnowledgeSession(executor.Spec{WorkDir: workDir}, &knowledgeRemoteExec{}, workDir, runID,
		"alice@example.com", []string{"cloop", "run"})
	if k == nil {
		t.Fatalf("a run of %s got no knowledge session", workDir)
	}
	tok, _ := envOf(spec.Env, knowledgerun.EnvToken)
	return tok
}

// hitDocuments are the document ids a search answer holds.
func hitDocuments(body map[string]any) []int64 {
	var out []int64
	hits, _ := body["hits"].([]any)
	for _, h := range hits {
		if m, ok := h.(map[string]any); ok {
			if id, ok := m["document_id"].(float64); ok {
				out = append(out, int64(id))
			}
		}
	}
	return out
}

// lastKnowledgeRow is the newest row of action.
func (f *runScopeFixture) lastKnowledgeRow(t *testing.T, action auditaction.Action) map[string]any {
	t.Helper()
	rows := f.auditRows(t, action)
	if len(rows) == 0 {
		t.Fatalf("no %s rows", action)
	}
	return payloadOf(t, rows[len(rows)-1])
}

// TestARunsKnowledgeSessionReachesAnotherProjectOnlyThroughItsReadersList is
// the knowledge half of the table: alpha's run asks for bravo's knowledge by
// every name the search takes — the project, a document id, a URL, a task's
// citations — and is answered 404 each time, with nothing recorded as read and
// a row saying why. Once bravo's readers list names alpha, the run reads it,
// read-only; the moment the entry goes, it is refused again. A feature of
// alpha is never on bravo's list by grace of alpha's entry.
func TestARunsKnowledgeSessionReachesAnotherProjectOnlyThroughItsReadersList(t *testing.T) {
	f := newRunScopeFixture(t, "")
	token := f.knowledgeToken(t, f.alpha, "run-alpha")
	db := f.controlPlane(t)
	readsOf := func() int {
		var n int
		raw, err := sql.Open("sqlite", state.DBPath(f.dir))
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if err := raw.QueryRow(`SELECT COUNT(*) FROM knowledge_run_reads`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := f.fingerprint(t)

	for _, tc := range []struct {
		name, path string
		body       map[string]any
		action     auditaction.Action
		reason     string
	}{
		{"search naming bravo", knowledgerun.PathSearch,
			map[string]any{"query": "deploy", "project": f.bravo, "task": 1}, auditaction.ActionKnowledgeRunSearch,
			"readers list does not name"},
		{"get bravo's document by id", knowledgerun.PathGet,
			map[string]any{"document_id": f.docB, "task": 1}, auditaction.ActionKnowledgeRunGet,
			"knowledge not bound to"},
		{"get bravo's document by URL", knowledgerun.PathGet,
			map[string]any{"url": f.urlB, "task": 1}, auditaction.ActionKnowledgeRunGet, "knowledge not bound to"},
		{"get from bravo naming it", knowledgerun.PathGet,
			map[string]any{"document_id": f.docB, "project": f.bravo, "task": 2}, auditaction.ActionKnowledgeRunGet,
			"readers list does not name"},
		{"bravo's citations", knowledgerun.PathCitations,
			map[string]any{"task": 2, "project": f.bravo}, auditaction.ActionKnowledgeRunCitations,
			"citations are the run's own"},
		{"a project that is not on the hub", knowledgerun.PathSearch,
			map[string]any{"query": "deploy", "project": filepath.Join(t.TempDir(), "nowhere")},
			auditaction.ActionKnowledgeRunSearch, "no project is registered"},
	} {
		code, body := f.knowledgeCall(t, token, tc.path, tc.body)
		// A lookup of a document by name answers as for a name nothing
		// holds — 200, no documents — so the run cannot tell another
		// project's name from none (R-31,
		// TestRemoteRunTokenReachesOnlyItsOwnProject); every other attempt
		// is 404.
		_, named := tc.body["project"]
		if tc.path == knowledgerun.PathGet && !named {
			if docs, _ := body["documents"].([]any); code != http.StatusOK || len(docs) != 0 {
				t.Errorf("%s: %d %v, want 200 with no documents", tc.name, code, body)
				continue
			}
		} else if code != http.StatusNotFound {
			t.Errorf("%s: %d %v, want 404", tc.name, code, body)
			continue
		}
		row := f.lastKnowledgeRow(t, tc.action)
		if row["outcome"] != "refused" || !strings.Contains(fmt.Sprint(row["reason"]), tc.reason) ||
			row["project"] != f.alpha {
			t.Errorf("%s: the refusal's row is %v, want refused because %q, on alpha's session", tc.name, row, tc.reason)
		}
	}
	// The same answer whether the path names a project or not, so a run
	// cannot map the hub's projects by asking.
	_, named := f.knowledgeCall(t, token, knowledgerun.PathSearch, map[string]any{"query": "x", "project": f.bravo})
	_, unnamed := f.knowledgeCall(t, token, knowledgerun.PathSearch, map[string]any{"query": "x",
		"project": filepath.Join(t.TempDir(), "nowhere")})
	if fmt.Sprint(named["error"]) != fmt.Sprint(unnamed["error"]) {
		t.Errorf("the refusals tell a project from no project:\n%v\n%v", named["error"], unnamed["error"])
	}
	if code, _ := f.knowledgeCall(t, token, knowledgerun.PathSearch, map[string]any{"query": "x",
		"project": "relative/path"}); code != http.StatusBadRequest {
		t.Errorf("a project that is no path: %d, want 400", code)
	}
	if n := readsOf(); n != 0 {
		t.Fatalf("%d documents recorded as read by refused requests", n)
	}
	if after := f.fingerprint(t); after != before {
		t.Fatal("a refused knowledge request changed a project's or the hub's state")
	}

	// bravo lists alpha: the run reads bravo's knowledge, and only reads it.
	f.list(t, f.bravo, f.alpha)
	code, body := f.knowledgeCall(t, token, knowledgerun.PathSearch,
		map[string]any{"query": "deploy", "project": f.bravo, "task": 1})
	if code != http.StatusOK || !slices.Contains(hitDocuments(body), f.docB) {
		t.Fatalf("a search of bravo, which lists alpha: %d %v, want bravo's document", code, body)
	}
	if slices.Contains(hitDocuments(body), f.docA) {
		t.Error("a search of bravo answered with alpha's own document")
	}
	if row := f.lastKnowledgeRow(t, auditaction.ActionKnowledgeRunSearch); row["outcome"] != "ok" ||
		row["read_project"] != f.bravo || row["reader"] != f.alpha {
		t.Errorf("the search's row does not name what was read for whom: %v", row)
	}
	if code, _ := f.knowledgeCall(t, token, knowledgerun.PathGet,
		map[string]any{"document_id": f.docB, "project": f.bravo, "task": 1}); code != http.StatusOK {
		t.Errorf("reading bravo's document from bravo, which lists alpha: %d", code)
	}
	// What the agent read of bravo is cited on alpha's task, as its own reads
	// are; bravo's citations stay out of reach.
	code, body = f.knowledgeCall(t, token, knowledgerun.PathCitations, map[string]any{"task": 1})
	cites, _ := body["citations"].([]any)
	if code != http.StatusOK || len(cites) == 0 || !strings.Contains(fmt.Sprint(cites), "bravo/deploy") {
		t.Errorf("alpha's citations after reading bravo: %d %v", code, body)
	}
	if code, _ := f.knowledgeCall(t, token, knowledgerun.PathCitations,
		map[string]any{"task": 1, "project": f.bravo}); code != http.StatusNotFound {
		t.Errorf("bravo's citations while bravo lists alpha: %d, want 404 — a citation is taken, not read", code)
	}

	// A feature of alpha reads no other project on alpha's entry.
	feature := filepath.Join(f.alpha, ".cloop", "features", "spike")
	featureToken := f.knowledgeToken(t, feature, "run-alpha-spike")
	if code, _ := f.knowledgeCall(t, featureToken, knowledgerun.PathSearch,
		map[string]any{"query": "deploy", "project": f.bravo}); code != http.StatusNotFound {
		t.Errorf("a feature of alpha searched bravo on alpha's entry: %d, want 404", code)
	}
	if row := f.lastKnowledgeRow(t, auditaction.ActionKnowledgeRunSearch); !strings.Contains(fmt.Sprint(row["reason"]), "feature") {
		t.Errorf("the feature's refusal does not say why: %v", row)
	}
	for _, own := range []string{"", f.alpha, feature} {
		if code, body := f.knowledgeCall(t, featureToken, knowledgerun.PathSearch,
			map[string]any{"query": "deploy", "project": own}); code != http.StatusOK ||
			!slices.Contains(hitDocuments(body), f.docA) {
			t.Errorf("a feature of alpha searching alpha's own knowledge, naming %q: %d %v", own, code, body)
		}
	}

	// Taken off the list: refused at the next request.
	f.unlist(t, f.bravo, f.alpha)
	if code, _ := f.knowledgeCall(t, token, knowledgerun.PathSearch,
		map[string]any{"query": "deploy", "project": f.bravo}); code != http.StatusNotFound {
		t.Errorf("a search of bravo after it took alpha off its list: %d, want 404", code)
	}
	_ = db
}

// TestARunGetsAKnowledgeSessionForWhatItMayRead: a project with no knowledge
// of its own, which another project's readers list names, gets a session for
// its runs — and that session reads the other project and its own empty one,
// and nothing else.
func TestARunGetsAKnowledgeSessionForWhatItMayRead(t *testing.T) {
	f := newRunScopeFixture(t, "")
	charlie := setupProjectDir(t, "charlie's goal", nil)
	if err := multiui.AddPathsOwned([]string{charlie}, ""); err != nil {
		t.Fatal(err)
	}
	if _, k := applyKnowledgeSession(executor.Spec{WorkDir: charlie}, &knowledgeRemoteExec{}, charlie, "run-c",
		"alice@example.com", []string{"cloop", "run"}); k != nil {
		t.Fatal("a project with no knowledge and nothing to read got a knowledge session")
	}
	f.list(t, f.bravo, charlie)
	token := f.knowledgeToken(t, charlie, "run-c")
	if code, body := f.knowledgeCall(t, token, knowledgerun.PathSearch,
		map[string]any{"query": "deploy", "project": f.bravo}); code != http.StatusOK ||
		!slices.Contains(hitDocuments(body), f.docB) {
		t.Errorf("charlie's run searching bravo, which lists it: %d %v", code, body)
	}
	if code, body := f.knowledgeCall(t, token, knowledgerun.PathSearch,
		map[string]any{"query": "deploy", "project": f.alpha}); code != http.StatusNotFound {
		t.Errorf("charlie's run searching alpha, which does not list it: %d %v", code, body)
	}
	if code, body := f.knowledgeCall(t, token, knowledgerun.PathSearch,
		map[string]any{"query": "deploy"}); code != http.StatusOK || len(hitDocuments(body)) != 0 {
		t.Errorf("charlie's run searching its own, empty, knowledge: %d %v", code, body)
	}
}

// gitProxyRequest sends one smart-HTTP request through the hub's git proxy
// with a session's credential.
func gitProxyRequest(t *testing.T, svc *gitProxyService, m *gitproxy.Minted, method, path string) (int, string) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("0000")
	}
	req, _ := http.NewRequest(method, svc.BaseURL()+path, body)
	req.SetBasicAuth(m.Session.ID, m.Token)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("%s %s through the git proxy: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// TestARunsGitSessionsReachAnotherProjectsRepositoryOnlyToRead: through the
// hub's own git proxy, alpha's session for its repository is refused bravo's,
// fetch and push; a foreign read of bravo's repository is refused until
// bravo's readers list names alpha, refuses every push whatever the list
// says, and asks the list again at every request. Each refusal is a
// gitproxy.rejected row naming alpha's project and, for a foreign read,
// bravo's.
func TestARunsGitSessionsReachAnotherProjectsRepositoryOnlyToRead(t *testing.T) {
	f := newRunScopeFixture(t, "")
	cfg := gitProxyTestConfig(t)
	svc, err := startGitProxy(cfg, f.dir)
	if err != nil || svc == nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	defer svc.Close()

	own, err := svc.reg.Mint(gitproxy.MintRequest{Upstream: "https://github.com/acme/alpha.git", ProjectID: f.alpha,
		RunID: "run-alpha", Policy: gitproxy.Policy{AllowFetch: true, AllowCreate: true, AllowUpdate: true}})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := svc.reg.Mint(gitproxy.MintRequest{Upstream: "https://github.com/acme/bravo.git", ProjectID: f.alpha,
		ReadsProject: f.bravo, RunID: "run-alpha",
		Policy: gitproxy.Policy{AllowFetch: true, AllowCreate: true, AllowUpdate: true}})
	if err != nil {
		t.Fatal(err)
	}
	if p := foreign.Session.Policy; p.AllowCreate || p.AllowUpdate {
		t.Fatalf("a foreign read was minted able to push: %+v", p)
	}
	before := f.fingerprint(t)
	rejected := func() int { return len(f.auditRows(t, auditaction.ActionGitProxyRejected)) }

	for _, tc := range []struct {
		name, method, path string
		m                  *gitproxy.Minted
		says               string
	}{
		{"alpha's session fetching bravo's repository", http.MethodGet,
			"/acme/bravo/info/refs?service=git-upload-pack", own, "not acme/bravo"},
		{"alpha's session pushing to bravo's repository", http.MethodPost,
			"/acme/bravo/git-receive-pack", own, "not acme/bravo"},
		{"a foreign read bravo's list does not allow", http.MethodGet,
			"/acme/bravo/info/refs?service=git-upload-pack", foreign, "refused by the readers list"},
		{"a foreign read pushing", http.MethodGet,
			"/acme/bravo/info/refs?service=git-receive-pack", foreign, "never pushes"},
		{"a foreign read pushing a pack", http.MethodPost,
			"/acme/bravo/git-receive-pack", foreign, "never pushes"},
	} {
		n := rejected()
		code, body := gitProxyRequest(t, svc, tc.m, tc.method, tc.path)
		if code != http.StatusForbidden || !strings.Contains(body, tc.says) {
			t.Errorf("%s: %d %q, want 403 saying %q", tc.name, code, body, tc.says)
			continue
		}
		rows := f.auditRows(t, auditaction.ActionGitProxyRejected)
		if len(rows) != n+1 {
			t.Errorf("%s: %d gitproxy.rejected rows written, want 1", tc.name, len(rows)-n)
			continue
		}
		p := payloadOf(t, rows[len(rows)-1])
		if p["project_id"] != f.alpha || (tc.m == foreign && p["reads_project"] != f.bravo) {
			t.Errorf("%s: the row does not name the projects: %v", tc.name, p)
		}
	}
	if after := f.fingerprint(t); after != before {
		t.Fatal("a refused git request changed a project's or the hub's state")
	}

	// The hub's answer to the proxy, as the list changes: for bravo's own
	// repository, the origin its checkout names, and no other.
	if err := os.MkdirAll(filepath.Join(f.bravo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.bravo, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = https://github.com/acme/bravo.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.bravo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gate := gitProxyReaders(f.controlPlane(t))
	read := func(reader, project, repo string) error {
		return gate(gitproxy.ForeignRead{Reader: reader, Project: project, ForgeHost: "github.com", Repo: repo})
	}
	if err := read(f.alpha, f.bravo, "acme/bravo"); err == nil {
		t.Fatal("the hub lets alpha read bravo with alpha on no list")
	}
	f.list(t, f.bravo, f.alpha)
	if err := read(f.alpha, f.bravo, "acme/bravo"); err != nil {
		t.Fatalf("bravo lists alpha, and the hub still refuses: %v", err)
	}
	if err := read(f.alpha, f.bravo, "acme/payroll"); err == nil || !strings.Contains(err.Error(), "not") {
		t.Errorf("a foreign read of bravo was let at another repository: %v", err)
	}
	// Now the proxy goes past the list to the forge — and still refuses to push.
	if code, body := gitProxyRequest(t, svc, foreign, http.MethodPost, "/acme/bravo/git-receive-pack"); code != http.StatusForbidden ||
		!strings.Contains(body, "never pushes") {
		t.Errorf("a listed foreign read pushing: %d %q, want 403", code, body)
	}
	for _, reader := range []string{filepath.Join(f.alpha, ".cloop", "features", "spike"), f.bravo} {
		if err := read(reader, f.bravo, "acme/bravo"); err == nil {
			t.Errorf("the hub lets %s read bravo on alpha's entry", reader)
		}
	}
	f.unlist(t, f.bravo, f.alpha)
	if code, body := gitProxyRequest(t, svc, foreign, http.MethodGet,
		"/acme/bravo/info/refs?service=git-upload-pack"); code != http.StatusForbidden ||
		!strings.Contains(body, "refused by the readers list") {
		t.Errorf("a foreign read after bravo took alpha off its list: %d %q, want 403", code, body)
	}
}

// insecureTLS trusts the test listeners' self-signed certificates.
func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

// TestARunsKubernetesSessionReachesOnlyItsGrantsNamespaces: alpha's session on
// the hub's Kubernetes access monitor, minted from alpha's grant for its
// namespace, asks for bravo's: refused before the cluster is reached, and a
// kubeguard row names alpha's project.
func TestARunsKubernetesSessionReachesOnlyItsGrantsNamespaces(t *testing.T) {
	f := newRunScopeFixture(t, "")
	certDir := t.TempDir()
	cert, key := filepath.Join(certDir, "guard.crt"), filepath.Join(certDir, "guard.key")
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{Hosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Executors.KubeGuard = config.KubeGuardConfig{Enabled: true, ListenAddr: "127.0.0.1:0", CertFile: cert, KeyFile: key}
	svc, err := startKubeGuard(cfg, f.dir)
	if err != nil || svc == nil {
		t.Fatalf("startKubeGuard: %v", err)
	}
	defer svc.Close()
	res, err := kubeGuard{svc: svc}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
		Kubeconfig: testKubeconfigYAML(), Verbs: []string{"get", "list", "watch"}, Namespaces: []string{"team-a"},
		GrantID: "grant-alpha", LeaseID: "lease-alpha", ProjectID: f.alpha, Owner: "alice@example.com",
	})
	if err != nil || !res.Guarded() {
		t.Fatalf("GuardKubeconfig: %v", err)
	}
	token := ""
	for _, line := range strings.Split(string(res.Kubeconfig), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "token: "); ok {
			token = strings.Trim(v, `"'`)
		}
	}
	if !strings.HasPrefix(token, redact.KubeGuardTokenPrefix) {
		t.Fatalf("no monitor token in the delivered kubeconfig:\n%s", res.Kubeconfig)
	}
	u, _ := url.Parse(svc.BaseURL())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+u.Host+"/api/v1/namespaces/team-b/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alpha's session reading bravo's namespace: %d %s, want 403", resp.StatusCode, body)
	}
	rows := f.auditRows(t, auditaction.KubeGuardEvent("request_denied"))
	if len(rows) == 0 {
		t.Fatal("the monitor's refusal is not on the audit trail")
	}
	if p := payloadOf(t, rows[len(rows)-1]); p["project_id"] != f.alpha {
		t.Errorf("the monitor's refusal does not name alpha's project: %v", p)
	}
}

// TestAPoolControllersCredentialReachesOnlyItsOwnPoolsRunners: a controller
// asking to retire another pool's runner is told it is unknown, the runner is
// untouched, and the attempt is a row naming both pools.
func TestAPoolControllersCredentialReachesOnlyItsOwnPoolsRunners(t *testing.T) {
	r := newPoolRig(t)
	ownID, own := r.createPool(map[string]any{"name": "alpha-pool", "max_runners": 2})
	otherID, other := r.createPool(map[string]any{"name": "bravo-pool", "max_runners": 2})
	st, body := r.call(http.MethodPost, poolRunnersPath, other, map[string]int{"count": 1})
	if st != http.StatusCreated {
		t.Fatalf("mint bravo-pool's runner: %d %v", st, body)
	}
	runner := body["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	st, body = r.call(http.MethodPost, poolRetirePath, own, map[string]any{"runners": []string{runner}})
	if st != http.StatusOK || retireOutcomes(body)[runner] != "unknown" {
		t.Fatalf("alpha-pool's controller retiring bravo-pool's runner: %d %v, want it unknown", st, body)
	}
	if row, err := store.DB().GetExecutorPoolRunner(runner); err != nil || row.State != statedb.PoolRunnerPending {
		t.Fatalf("bravo-pool's runner is %+v (%v) after another pool's request", row, err)
	}
	evs, _, err := store.DB().ListAuditEvents(statedb.AuditFilter{
		EventType: string(auditaction.ActionExecutorPoolRunnerRetireRefused), Limit: 10})
	if err != nil || len(evs) != 1 {
		t.Fatalf("%d runner_retire_refused rows (%v), want 1", len(evs), err)
	}
	p := payloadOf(t, evs[0])
	if evs[0].EntityID != ownID || p["runner_pool_id"] != otherID || p["enrollment_id"] != runner {
		t.Errorf("the refusal's row is %s %v, want alpha-pool's asking for bravo-pool's runner", evs[0].EntityID, p)
	}
}

// resetRunCredentialAuditLimiter forgets every bucket and window, for a test
// that measures the limiter from a clean start.
func resetRunCredentialAuditLimiter(t *testing.T) {
	t.Helper()
	reset := func() {
		l := &runCredentialAuditLimiter
		l.mu.Lock()
		l.buckets = map[string]*runCredentialBucket{}
		l.window, l.verified, l.unverified, l.untracked = time.Time{}, 0, 0, 0
		l.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// TestAFloodOfMadeUpCredentialsDoesNotHideARunsRefusal: values made up to look
// like run credentials are refused like real ones, but are written from a
// budget of their own and tracked in a bounded table, so a run that floods the
// dashboard with them first is still recorded when it presents its real token
// — and the rows written say how many refusals were not.
func TestAFloodOfMadeUpCredentialsDoesNotHideARunsRefusal(t *testing.T) {
	f := newRunScopeFixture(t, "")
	resetRunCredentialAuditLimiter(t)
	unverified, tracked := runCredentialUnverifiedPerMinute, runCredentialTracked
	runCredentialUnverifiedPerMinute, runCredentialTracked = 5, 8
	t.Cleanup(func() { runCredentialUnverifiedPerMinute, runCredentialTracked = unverified, tracked })

	send := func(token string) {
		t.Helper()
		req := f.requestFor("/api/state", http.MethodGet)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a run-shaped credential got %d, want 403", rec.Code)
		}
	}
	for i := 0; i < 40; i++ {
		send(knowledgerun.TokenPrefix + randomHex(t, 12) + "." + randomB64(t, 32))
	}
	runCredentialAuditLimiter.mu.Lock()
	held := len(runCredentialAuditLimiter.buckets)
	runCredentialAuditLimiter.mu.Unlock()
	if held > 8 {
		t.Fatalf("the limiter holds %d buckets, past its bound of 8", held)
	}
	rows := f.auditRows(t, auditaction.ActionRunCredentialRefused)
	if len(rows) != 5 {
		t.Fatalf("%d rows for 40 made-up credentials, want the unverified budget's 5", len(rows))
	}

	// The run's real token is still recorded, and named.
	token := f.knowledgeToken(t, f.alpha, "run-alpha")
	send(token)
	rows = f.auditRows(t, auditaction.ActionRunCredentialRefused)
	if len(rows) != 6 {
		t.Fatalf("the live session's refusal was not written after the flood: %d rows", len(rows))
	}
	p := payloadOf(t, rows[5])
	if p["verified"] != true || p["project"] != f.alpha {
		t.Fatalf("the live session's row is %v", p)
	}
	if n, _ := p["untracked"].(float64); n < 1 {
		t.Errorf("the row written after the flood does not count the refusals no bucket was kept for: %v", p)
	}
}
