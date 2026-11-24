package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/readonlysnap"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var runArgv = []string{"cloop", "run"}

// readOnlyExec is an executor delivering read-only projects as delivery says.
type readOnlyExec struct {
	stubExecutor
	delivery executor.ReadOnlyDelivery
	isolates bool
}

func (e *readOnlyExec) ID() string { return "ro-exec" }
func (e *readOnlyExec) Kind() string {
	if e.isolates {
		return executor.KindContainer
	}
	return executor.KindLocalProcess
}
func (e *readOnlyExec) Capabilities() executor.Capabilities {
	c := executor.Capabilities{Isolation: executor.IsolationNone, SharesHostFilesystem: true,
		ReadOnlyProjects: e.delivery}
	if e.isolates {
		c.Isolation = executor.IsolationContainer
	}
	return c
}

// withSource gives project a file of its own, so it has a tree to read.
func withSource(t *testing.T, project string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(project, "README.md"), []byte("readme of "+filepath.Base(project)+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
}

func journalHas(t *testing.T, workDir, text string) bool {
	t.Helper()
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListEventsOfType(statedb.EventKnowledge, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.Message, text) {
			return true
		}
	}
	return false
}

// TestARunIsGivenOnlyTheProjectsWhoseReadersListsNameIt: what a dispatch is
// given is the readers lists' literal answer — nothing before bravo lists
// alpha, bravo after, and never for anything but a run of a project.
func TestARunIsGivenOnlyTheProjectsWhoseReadersListsNameIt(t *testing.T) {
	f := newRunScopeFixture(t, "")
	withSource(t, f.bravo)
	if got, _ := resolveReadOnly(f.alpha, runArgv); len(got) != 0 {
		t.Fatalf("alpha was given %+v before any list named it", got)
	}
	f.list(t, f.bravo, f.alpha)
	got, notes := resolveReadOnly(f.alpha, runArgv)
	if len(got) != 1 || got[0].Project != f.bravo || !executor.ValidReadOnlySlug(got[0].Slug) || len(notes) != 0 {
		t.Fatalf("alpha was given %+v (notes %v), want bravo alone", got, notes)
	}
	// Not the other way round, not for a dashboard model call, and not for a
	// feature of alpha: the list names alpha, never its features.
	if got, _ := resolveReadOnly(f.bravo, runArgv); len(got) != 0 {
		t.Errorf("bravo was given %+v by alpha's entry on bravo's list", got)
	}
	if got, _ := resolveReadOnly(f.alpha, []string{"cloop", "plan", "--json"}); len(got) != 0 {
		t.Errorf("a model call was given %+v", got)
	}
	if got, _ := resolveReadOnly(filepath.Join(f.alpha, ".cloop", "features", "spike"), runArgv); len(got) != 0 {
		t.Errorf("a feature of alpha was given %+v", got)
	}
	// A project with no source on the hub is left out, and the journal says.
	if err := os.Remove(filepath.Join(f.bravo, "README.md")); err != nil {
		t.Fatal(err)
	}
	got, notes = resolveReadOnly(f.alpha, runArgv)
	if len(got) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "keeps no source") {
		t.Errorf("a project with nothing but its control directory was given (%+v) or not said (%v)", got, notes)
	}
	if why := readOnlyRefusal(f.dir); why == "" {
		t.Error("the hub's own directory would be given to a run")
	}
}

// TestApplyReadOnlyGivesEachExecutorTheDeliveryItCan: a container binds the
// project at /readonly/<slug>, a host run reads it where it is, a Pod or a
// device fetches a snapshot from the hub's endpoint; an executor that can do
// none of these, or a run with no session to ask with, is given nothing and
// the journal says why.
func TestApplyReadOnlyGivesEachExecutorTheDeliveryItCan(t *testing.T) {
	f := newRunScopeFixture(t, "")
	withSource(t, f.bravo)
	f.list(t, f.bravo, f.alpha)
	grants, notes := resolveReadOnly(f.alpha, runArgv)
	session := &runKnowledge{id: "s", workDir: f.alpha, base: "https://hub.example.com" + knowledgerun.MountPath}
	slug := grants[0].Slug

	for _, tc := range []struct {
		delivery executor.ReadOnlyDelivery
		path     string
	}{
		{executor.ReadOnlyBind, "/readonly/" + slug},
		{executor.ReadOnlyInPlace, f.bravo},
		{executor.ReadOnlySnapshot, "/readonly/" + slug},
	} {
		t.Run(string(tc.delivery), func(t *testing.T) {
			ex := &readOnlyExec{delivery: tc.delivery, isolates: tc.delivery != executor.ReadOnlyInPlace}
			spec := applyReadOnly(executor.Spec{WorkDir: f.alpha, Env: []string{"PATH=/bin"}}, ex, f.alpha, grants,
				notes, session)
			if len(spec.ReadOnly) != 1 || spec.ReadOnly[0].Project != f.bravo {
				t.Fatalf("spec gives %+v", spec.ReadOnly)
			}
			p := spec.ReadOnly[0]
			switch tc.delivery {
			case executor.ReadOnlySnapshot:
				if p.Source != "" || p.Snapshot == nil ||
					p.Snapshot.URL != session.base+knowledgerun.PathReadOnlySnapshot ||
					p.Snapshot.TokenEnv != knowledgerun.EnvReadersToken {
					t.Errorf("a snapshot executor was given %+v", p)
				}
			default:
				if p.Source != f.bravo || p.Snapshot != nil {
					t.Errorf("a %s executor was given %+v", tc.delivery, p)
				}
			}
			v, _ := envOf(spec.Env, executor.EnvReadOnlyProjects)
			entries, err := executor.DecodeReadOnlyManifest(v)
			if err != nil || len(entries) != 1 || entries[0].Path != tc.path || entries[0].Project != f.bravo {
				t.Errorf("the run is told %q (%v), want bravo at %s", v, err, tc.path)
			}
			if spec.Labels[LabelReadOnlyProjects] != slug {
				t.Errorf("label %q, want %q", spec.Labels[LabelReadOnlyProjects], slug)
			}
			if err := spec.Validate(); err != nil && !strings.Contains(err.Error(), "argv") {
				t.Errorf("the spec does not validate: %v", err)
			}
		})
	}

	// What an executor cannot deliver is left out before the session is
	// minted, saying why: nothing at all, a run with no network to ask with,
	// a hidden entry a container's mount flag cannot carry.
	if kept, n := deliverableReadOnly(grants, executor.Spec{}, &readOnlyExec{}, nil); len(kept) != 0 ||
		len(n) != 1 || !strings.Contains(n[0], "cannot give a run another project's tree") {
		t.Errorf("an executor that delivers nothing kept %+v (%v)", kept, n)
	}
	if kept, n := deliverableReadOnly(grants, executor.Spec{DisableNetwork: true},
		&readOnlyExec{delivery: executor.ReadOnlyBind, isolates: true}, nil); len(kept) != 0 ||
		len(n) != 1 || !strings.Contains(n[0], "no network") {
		t.Errorf("a run with no network kept %+v (%v)", kept, n)
	}
	if err := os.WriteFile(filepath.Join(f.bravo, ".env.prod:bak"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if kept, n := deliverableReadOnly(grants, executor.Spec{}, &readOnlyExec{delivery: executor.ReadOnlyBind,
		isolates: true}, nil); len(kept) != 0 || len(n) != 1 || !strings.Contains(n[0], "mount flag") {
		t.Errorf("a project whose hidden entry a mount flag cannot carry was kept for a container: %+v (%v)", kept, n)
	}
	if kept, _ := deliverableReadOnly(grants, executor.Spec{}, &readOnlyExec{delivery: executor.ReadOnlyInPlace},
		nil); len(kept) != 1 {
		t.Errorf("a host run, which reads the project where it is, lost it to the mount flag: %+v", kept)
	}
	nosession := applyReadOnly(executor.Spec{WorkDir: f.alpha}, &readOnlyExec{delivery: executor.ReadOnlyBind},
		f.alpha, grants, notes, nil)
	if len(nosession.ReadOnly) != 0 || !journalHas(t, f.alpha, "could not give the run a session") {
		t.Errorf("a run with no session was given %+v, or the journal was not told", nosession.ReadOnly)
	}
}

// TestARunWithNoKnowledgeIsNotToldItHasASearch: a session minted only for the
// projects a run reads is handed over under the readers variables, not the
// knowledge ones, and records what the run was given.
func TestARunWithNoKnowledgeIsNotToldItHasASearch(t *testing.T) {
	f := newRunScopeFixture(t, "")
	charlie := setupProjectDir(t, "charlie's goal", []*pm.Task{{ID: 1, Title: "c", Status: pm.TaskPending}})
	delta := setupProjectDir(t, "delta's goal", []*pm.Task{{ID: 1, Title: "d", Status: pm.TaskPending}})
	withSource(t, delta)
	if err := multiui.AddPathsOwned([]string{charlie, delta}, ""); err != nil {
		t.Fatal(err)
	}
	f.list(t, delta, charlie)
	grants, _ := resolveReadOnly(charlie, runArgv)
	if len(grants) != 1 {
		t.Fatalf("charlie was given %+v", grants)
	}
	spec, k := applyRunSession(executor.Spec{WorkDir: charlie}, &knowledgeRemoteExec{}, charlie, "run-c", "",
		runArgv, grants)
	if k == nil {
		t.Fatal("a run given a project to read got no session")
	}
	if _, ok := envOf(spec.Env, knowledgerun.EnvToken); ok {
		t.Error("a run with no knowledge sources was told it has a knowledge search")
	}
	if tok, ok := envOf(spec.Env, knowledgerun.EnvReadersToken); !ok || !strings.HasPrefix(tok, knowledgerun.TokenPrefix) {
		t.Errorf("the readers token is missing: %q", tok)
	}
	row, err := f.controlPlane(t).GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if err != nil {
		t.Fatal(err)
	}
	var scope knowledgeScope
	if err := json.Unmarshal([]byte(row.Scope), &scope); err != nil || len(scope.ReadOnly) != 1 ||
		scope.ReadOnly[0].Project != delta || scope.Knowledge {
		t.Errorf("the session records %q (%v), want delta and no knowledge", row.Scope, err)
	}
	// A run given nothing and with no knowledge gets no session at all.
	if _, k := applyRunSession(executor.Spec{WorkDir: delta}, &knowledgeRemoteExec{}, delta, "run-d", "", runArgv,
		nil); k != nil {
		t.Error("a run given nothing, with no knowledge, got a session")
	}
}

// readOnlyCall posts body to a run endpoint with token.
func (f *runScopeFixture) readOnlyCall(t *testing.T, token, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+knowledgerun.MountPath+path, bytes.NewReader(raw))
	req.Host, req.RemoteAddr = "127.0.0.1", "127.0.0.1:40000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// TestTheHubServesAReadOnlyProjectOnlyWhileItsListNamesTheRun: the run's
// boundary question and its executor's snapshot are answered from the list as
// it is at that request — bravo is readable and served while its list names
// alpha, and the moment the entry goes the next question says so and no
// snapshot is served again; both changes are on the audit trail.
func TestTheHubServesAReadOnlyProjectOnlyWhileItsListNamesTheRun(t *testing.T) {
	f := newRunScopeFixture(t, "")
	withSource(t, f.bravo)
	if err := os.MkdirAll(filepath.Join(f.bravo, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.bravo, "src", "bravo.go"), []byte("package bravo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.list(t, f.bravo, f.alpha)
	grants, _ := resolveReadOnly(f.alpha, runArgv)
	spec, k := applyRunSession(executor.Spec{WorkDir: f.alpha}, &knowledgeRemoteExec{}, f.alpha, "run-ro",
		"alice@example.com", runArgv, grants)
	if k == nil {
		t.Fatal("no session")
	}
	token, _ := envOf(spec.Env, knowledgerun.EnvReadersToken)
	slug := grants[0].Slug

	rec := f.readOnlyCall(t, token, knowledgerun.PathReadOnly, struct{}{})
	var status knowledgerun.ReadOnlyResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &status) != nil || len(status.Projects) != 1 ||
		!status.Projects[0].Readable || status.Projects[0].Slug != slug {
		t.Fatalf("the boundary question = %d %s", rec.Code, rec.Body.String())
	}
	rec = f.readOnlyCall(t, token, knowledgerun.PathReadOnlySnapshot, knowledgerun.SnapshotRequest{Slug: slug})
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("the snapshot = %d %s", rec.Code, rec.Body.String())
	}
	dest := filepath.Join(t.TempDir(), slug)
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readonlysnap.Remove(dest) })
	if _, err := readonlysnap.Extract(bytes.NewReader(rec.Body.Bytes()), dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "src", "bravo.go")); err != nil || string(b) != "package bravo\n" {
		t.Fatalf("the snapshot's src/bravo.go = %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(dest, ".cloop")); err == nil {
		t.Fatal("the snapshot carries bravo's control directory")
	}
	if rows := f.auditRows(t, auditaction.ActionKnowledgeRunSnapshot); len(rows) != 1 ||
		payloadOf(t, rows[0])["outcome"] != "ok" || payloadOf(t, rows[0])["read_project"] != f.bravo {
		t.Fatalf("snapshot rows: %+v", rows)
	}

	// Another project's slug, or none the run was given: not found, the same
	// answer as a path that names no project.
	if rec := f.readOnlyCall(t, token, knowledgerun.PathReadOnlySnapshot,
		knowledgerun.SnapshotRequest{Slug: "nope"}); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown slug = %d", rec.Code)
	}
	if rec := f.readOnlyCall(t, knowledgerun.TokenPrefix+"bogus.token", knowledgerun.PathReadOnly,
		struct{}{}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token that is no session's = %d", rec.Code)
	}

	// The entry goes.
	f.unlist(t, f.bravo, f.alpha)
	rec = f.readOnlyCall(t, token, knowledgerun.PathReadOnly, struct{}{})
	status = knowledgerun.ReadOnlyResponse{}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &status) != nil || len(status.Projects) != 1 ||
		status.Projects[0].Readable {
		t.Fatalf("after the entry went, the boundary question = %d %s", rec.Code, rec.Body.String())
	}
	if rows := f.auditRows(t, auditaction.ActionKnowledgeRunReadOnly); len(rows) != 1 ||
		payloadOf(t, rows[0])["outcome"] != "changed" {
		t.Fatalf("readonly rows: %+v", rows)
	}
	rec = f.readOnlyCall(t, token, knowledgerun.PathReadOnlySnapshot, knowledgerun.SnapshotRequest{Slug: slug})
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "bravo") {
		t.Fatalf("a snapshot after the entry went = %d %s", rec.Code, rec.Body.String())
	}
	rows := f.auditRows(t, auditaction.ActionKnowledgeRunSnapshot)
	if last := payloadOf(t, rows[len(rows)-1]); last["outcome"] != "refused" || last["read_project"] != f.bravo {
		t.Fatalf("the refused snapshot's row: %+v", last)
	}
}

// TestARunPausedForAReadersChangeIsStartedAgainAtOnce: the member that settles
// it hands it to its resumer, which restarts it without waiting for a sweep;
// any other pause is left to the sweep.
func TestARunPausedForAReadersChangeIsStartedAgainAtOnce(t *testing.T) {
	dir := setupProjectDir(t, "g", []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}})
	started := make(chan string, 4)
	srv := &Server{WorkDir: dir, autoResumeStart: func(workDir string) error {
		started <- workDir
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.watchResumeAtOnce(ctx)
	waitFor(t, 5*time.Second, "the resumer to start", func() bool {
		srv.resumeNowMu.Lock()
		defer srv.resumeNowMu.Unlock()
		return srv.resumeNow != nil
	})

	pause := func(r pausereason.Reason) {
		st, err := state.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		st.SetPaused(r)
		if err := st.Save(); err != nil {
			t.Fatal(err)
		}
	}
	pause(pausereason.New(pausereason.CodeOperator, "stopped"))
	srv.resumeAtOnceAfter(dir, false, projectseed.MergeReport{}, time.Time{})
	select {
	case got := <-started:
		t.Fatalf("an operator's stop was restarted: %s", got)
	case <-time.After(200 * time.Millisecond):
	}

	pause(pausereason.NewUntil(pausereason.CodeReadersChanged, "bravo no longer lists this project", time.Now()))
	srv.resumeAtOnceAfter(dir, false, projectseed.MergeReport{}, time.Time{})
	select {
	case got := <-started:
		if got != dir {
			t.Fatalf("restarted %s, want %s", got, dir)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a run paused for a readers change was not restarted")
	}
}

// TestTheReadersListsUnreadableIsNotARemoval: a list the hub could not read
// is said as such, so the run's boundary question is answered "unavailable"
// rather than "taken off".
func TestTheReadersListsUnreadableIsNotARemoval(t *testing.T) {
	err := runMayRead(nil, "/p/a", "/p/b")
	if !errors.Is(err, errRunRead) || !errors.Is(err, errRunReadUnavailable) {
		t.Fatalf("runMayRead with no database = %v; want a refusal marked unavailable", err)
	}
	if err := runMayRead(nil, "/p/a", "/p/a"); errors.Is(err, errRunReadUnavailable) {
		t.Fatalf("a run's own project was answered unavailable: %v", err)
	}
}

// TestASessionIsBuiltOneSnapshotAtATimeAndAFewOfEach: one run cannot keep the
// hub building snapshots for it.
func TestASessionIsBuiltOneSnapshotAtATimeAndAFewOfEach(t *testing.T) {
	g := &readOnlySnapshotGate{sessions: map[string]*snapshotSession{}}
	release, why := g.take("s1", "api")
	if why != "" {
		t.Fatalf("the first snapshot was refused: %s", why)
	}
	if _, why := g.take("s1", "web"); why == "" {
		t.Fatal("a second build in flight for one session was admitted")
	}
	if r, why := g.take("s2", "api"); why != "" {
		t.Fatalf("another session's build waited on this one's: %s", why)
	} else {
		r()
	}
	release()
	for i := 1; i < maxSnapshotsPerProject; i++ {
		r, why := g.take("s1", "api")
		if why != "" {
			t.Fatalf("snapshot %d of api was refused: %s", i+1, why)
		}
		r()
	}
	if _, why := g.take("s1", "api"); why == "" {
		t.Fatalf("a snapshot past %d of one project was admitted", maxSnapshotsPerProject)
	}
	if r, why := g.take("s1", "web"); why != "" {
		t.Fatalf("another project's first snapshot was refused: %s", why)
	} else {
		r()
	}
}

// TestADeviceRunGivenAProjectToReadIsConfinedWhereTheDeviceCan: on a device
// that can sandbox its host payloads, a run given another project to read is
// confined — that is what makes the snapshot read-only to it — and on one
// that cannot, it runs as before rather than being refused.
func TestADeviceRunGivenAProjectToReadIsConfinedWhereTheDeviceCan(t *testing.T) {
	f := newHostSandboxFixture(t, "")
	device := newHarnessExec("edge-1", executor.KindRemoteAgent, executor.IsolationRemote)
	device.shares = false
	withDeviceSharing(t, func(string, string) bool { return false })
	spec := executor.Spec{WorkDir: f.project, Argv: []string{"cloop", "run"},
		ReadOnly: []executor.ReadOnlyProject{{Slug: "api", Project: "/p/api",
			Snapshot: &executor.ReadOnlySnapshotRef{URL: "https://hub/x", TokenEnv: "T"}}}}
	for _, can := range []bool{true, false} {
		fn := func(executor.Executor) bool { return can }
		deviceSandboxFn.Store(&fn)
		out, err := applyHostSandbox(spec, device, f.project, newHarnessClearance(f.project, adminPerson, ""), nil)
		deviceSandboxFn.Store(nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.ConfineToProject != can {
			t.Errorf("device can sandbox = %v: ConfineToProject = %v", can, out.ConfineToProject)
		}
	}
	plain := spec
	plain.ReadOnly = nil
	if out, _ := applyHostSandbox(plain, device, f.project, newHarnessClearance(f.project, adminPerson, ""),
		nil); out.ConfineToProject {
		t.Error("a run given nothing to read, on a device serving one project, was confined")
	}
}
