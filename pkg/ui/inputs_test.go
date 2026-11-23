package ui

// Input files (Task 20511): a person uploads a file for a task's agent, and a
// run seeded into its sandbox fetches it with its run session.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// upload posts body to a task's upload route with the given content type and
// extra headers, and returns the status and the decoded answer.
func upload(t *testing.T, base, path, contentType string, body io.Reader, header map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func storedRows(t *testing.T, dir string, task int) []statedb.AttachmentRow {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.TaskAttachments(task)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestUploadingAnInputFile(t *testing.T) {
	dir := setupProjectWithTasks(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "build the API", Status: pm.TaskPending},
		{ID: 2, Title: "running now", Status: pm.TaskInProgress},
	})
	ts := newTestServer(t, dir, nil)
	const octet = "application/octet-stream"
	spec := []byte("# API\nGET /hello returns 200\n")

	t.Run("the file becomes an input file of the task", func(t *testing.T) {
		status, out := upload(t, ts.URL, "/api/tasks/1/attachments?name=docs%2Fapi%20spec.md&note=The%20contract",
			octet, bytes.NewReader(spec), nil)
		if status != http.StatusCreated || out["ok"] != true || out["running"] != false {
			t.Fatalf("upload = %d %v", status, out)
		}
		a, _ := out["attachment"].(map[string]any)
		sum := sha256.Sum256(spec)
		if a["role"] != "input" || a["source"] != "upload" || a["name"] != "api spec.md" || a["note"] != "The contract" ||
			a["sha256"] != hex.EncodeToString(sum[:]) || a["size"] != float64(len(spec)) || a["media_type"] != "text/markdown" {
			t.Fatalf("the attachment = %v", a)
		}
		rows := storedRows(t, dir, 1)
		if len(rows) != 1 || rows[0].Role != statedb.AttachmentRoleInput {
			t.Fatalf("task 1's attachments = %+v", rows)
		}
		data, err := os.ReadFile(filepath.Join(attachments.StoreDir(state.DBPath(dir)), rows[0].ID))
		if err != nil || !bytes.Equal(data, spec) {
			t.Fatalf("the stored bytes = %q, %v", data, err)
		}
		list := apiGET(t, ts, "/api/tasks/1/attachments")
		if items, _ := list["attachments"].([]any); len(items) != 1 || items[0].(map[string]any)["role"] != "input" {
			t.Fatalf("the list = %v", list)
		}
		// On the project's audit trail and in its journal.
		evs := auditRowsOf(t, dir, auditaction.ActionTaskAttachmentAdd)
		if len(evs) != 1 || !strings.Contains(evs[0].Payload, `"role":"input"`) ||
			!strings.Contains(evs[0].Payload, `"via":"dashboard"`) || evs[0].EntityID != "1" {
			t.Fatalf("audit rows = %+v", evs)
		}
		events, _, err := state.ListEvents(dir, 0, 50)
		if err != nil {
			t.Fatal(err)
		}
		journaled := false
		for _, e := range events {
			journaled = journaled || (e.Type == state.EventTaskAttachments && e.TaskID == 1 &&
				strings.Contains(e.Message, "api spec.md") && strings.Contains(e.Message, "input file"))
		}
		if !journaled {
			t.Fatalf("no journal row for the upload: %+v", events)
		}
	})

	t.Run("a running attempt is said to have started without it", func(t *testing.T) {
		status, out := upload(t, ts.URL, "/api/tasks/2/attachments?name=late.txt", octet, strings.NewReader("late"), nil)
		if status != http.StatusCreated || out["running"] != true {
			t.Fatalf("upload to a running task = %d %v", status, out)
		}
	})

	t.Run("only the file itself, as application/octet-stream", func(t *testing.T) {
		for _, ct := range []string{"application/json", "", "text/plain"} {
			status, out := upload(t, ts.URL, "/api/tasks/1/attachments?name=x.txt", ct, strings.NewReader(`{"a":1}`), nil)
			if status != http.StatusUnsupportedMediaType {
				t.Errorf("Content-Type %q: %d %v, want 415", ct, status, out)
			}
		}
		var b bytes.Buffer
		b.WriteString("--x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n\r\nhi\r\n--x--\r\n")
		if status, _ := upload(t, ts.URL, "/api/tasks/1/attachments?name=x.txt", "multipart/form-data; boundary=x", &b, nil); status != http.StatusUnsupportedMediaType {
			t.Errorf("a multipart form: %d, want 415", status)
		}
		// And octet-stream is no body any other route takes.
		if status, _ := upload(t, ts.URL, "/api/task/add", octet, strings.NewReader(`{"title":"sneaky"}`), nil); status != http.StatusUnsupportedMediaType {
			t.Errorf("octet-stream to /api/task/add: %d, want 415", status)
		}
		if len(storedRows(t, dir, 1)) != 1 {
			t.Fatal("a refused upload was attached")
		}
	})

	t.Run("a request a page on another site made is refused", func(t *testing.T) {
		status, _ := upload(t, ts.URL, "/api/tasks/1/attachments?name=x.txt", octet, strings.NewReader("x"),
			map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://attacker.example"})
		if status != http.StatusForbidden {
			t.Fatalf("a cross-site upload: %d, want 403", status)
		}
		status, _ = upload(t, ts.URL, "/api/tasks/1/attachments?name=ok.txt", octet, strings.NewReader("x"),
			map[string]string{"Sec-Fetch-Site": "same-origin"})
		if status != http.StatusCreated {
			t.Fatalf("a same-origin upload: %d, want 201", status)
		}
	})

	t.Run("what is refused", func(t *testing.T) {
		if status, _ := upload(t, ts.URL, "/api/tasks/1/attachments", octet, strings.NewReader("x"), nil); status != http.StatusBadRequest {
			t.Errorf("no name: %d, want 400", status)
		}
		if status, _ := upload(t, ts.URL, "/api/tasks/99/attachments?name=x.txt", octet, strings.NewReader("x"), nil); status != http.StatusNotFound {
			t.Errorf("no such task: %d, want 404", status)
		}
		long := strings.Repeat("n", maxUploadNoteBytes+1)
		if status, _ := upload(t, ts.URL, "/api/tasks/1/attachments?name=x.txt&note="+long, octet, strings.NewReader("x"), nil); status != http.StatusBadRequest {
			t.Errorf("a note over its limit: %d, want 400", status)
		}
		before := len(storedRows(t, dir, 1))
		big := bytes.Repeat([]byte("x"), int(attachments.MaxFileBytes)+1)
		status, out := upload(t, ts.URL, "/api/tasks/1/attachments?name=big.bin", octet, bytes.NewReader(big), nil)
		if status != http.StatusRequestEntityTooLarge || !strings.Contains(out["error"].(string), "32.0 MiB") {
			t.Errorf("a file over the limit: %d %v, want 413", status, out)
		}
		// Sent without a length, it is read up to the limit and refused.
		status, _ = upload(t, ts.URL, "/api/tasks/1/attachments?name=big.bin", octet,
			io.MultiReader(bytes.NewReader(big)), nil)
		if status != http.StatusRequestEntityTooLarge {
			t.Errorf("a chunked file over the limit: %d, want 413", status)
		}
		if after := len(storedRows(t, dir, 1)); after != before {
			t.Fatalf("a refused file was attached: %d attachments, then %d", before, after)
		}
		entries, _ := os.ReadDir(attachments.StoreDir(state.DBPath(dir)))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("a refused upload left %s in the store", e.Name())
			}
		}
	})

	t.Run("the task's file limit", func(t *testing.T) {
		have := len(storedRows(t, dir, 1))
		for i := have; i < attachments.MaxTaskFiles; i++ {
			attachTo(t, dir, 1, "f.txt", []byte("x"))
		}
		status, out := upload(t, ts.URL, "/api/tasks/1/attachments?name=one-too-many.txt", octet, strings.NewReader("x"), nil)
		if status != http.StatusRequestEntityTooLarge || !strings.Contains(out["error"].(string), "already has 100") {
			t.Fatalf("the 101st file: %d %v, want 413 naming the limit", status, out)
		}
	})
}

// inputsRunFixture is a hub with a public URL, and two projects whose tasks
// have input files and results.
type inputsRunFixture struct {
	srv          *Server
	ts           *httptest.Server
	dir          string
	alpha, bravo string
	spec, report statedb.AttachmentRow // alpha's task 1: an input file and a result
	other        statedb.AttachmentRow // alpha's task 2's input file
	bravoInput   statedb.AttachmentRow // bravo's task 1's input file
}

func attachInputTo(t *testing.T, dir string, task int, name string, data []byte) statedb.AttachmentRow {
	t.Helper()
	dbPath := state.DBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := attachments.Put(db, dbPath, task, attachments.Meta{Name: name, Source: statedb.AttachmentSourceUpload,
		Role: statedb.AttachmentRoleInput, CreatedAt: time.Now()}, bytes.NewReader(data), attachments.MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func newInputsRunFixture(t *testing.T) *inputsRunFixture {
	t.Helper()
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	useControlPlaneDir(t, dir)
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.ExternalURL = ts.URL
	setKnowledgeRunServer(srv)
	f := &inputsRunFixture{srv: srv, ts: ts, dir: dir}
	tasks := func() []*pm.Task {
		return []*pm.Task{{ID: 1, Title: "build the API", Status: pm.TaskPending}, {ID: 2, Title: "test it", Status: pm.TaskPending}}
	}
	f.alpha = setupProjectWithTasks(t, cloopGoal, tasks())
	f.bravo = setupProjectWithTasks(t, cloopGoal, tasks())
	f.spec = attachInputTo(t, f.alpha, 1, "spec.md", []byte("# alpha's spec\n"))
	f.report = attachTo(t, f.alpha, 1, "report.txt", []byte("a result, not an input"))
	f.other = attachInputTo(t, f.alpha, 2, "task-two.txt", []byte("task 2's"))
	f.bravoInput = attachInputTo(t, f.bravo, 1, "bravo-secret.md", []byte("bravo's alone"))
	return f
}

// dispatch mints the session of a run of project, seeded into its sandbox or
// not, and returns the input files' token its environment was given ("" for
// none) and the session.
func (f *inputsRunFixture) dispatch(t *testing.T, project string, seeded bool) (string, *runKnowledge, executor.Spec) {
	t.Helper()
	spec := executor.Spec{WorkDir: project}
	if seeded {
		spec.ProjectSeed = []byte("a seed")
	}
	spec, k := applyRunSession(spec, &knowledgeRemoteExec{}, project, "run-"+filepath.Base(project), "alice@example.com",
		[]string{"cloop", "run"}, nil)
	token := ""
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvInputsToken+"="); ok {
			token = v
		}
	}
	return token, k, spec
}

func (f *inputsRunFixture) post(t *testing.T, token, path string, body any) (int, []byte) {
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
	return resp.StatusCode, data
}

func TestASeededRunIsGivenASessionForItsInputFiles(t *testing.T) {
	f := newInputsRunFixture(t)
	token, k, spec := f.dispatch(t, f.alpha, true)
	if k == nil || !strings.HasPrefix(token, knowledgerun.TokenPrefix) {
		t.Fatalf("a seeded run of a project without knowledge got no session for its input files: %v", spec.Env)
	}
	env := map[string]string{}
	for _, kv := range spec.Env {
		name, value, _ := strings.Cut(kv, "=")
		env[name] = value
	}
	if env[knowledgerun.EnvInputsURL] != f.ts.URL+knowledgerun.MountPath ||
		env[redact.EnvKey] != knowledgerun.EnvInputsToken+","+knowledgerun.EnvResultsToken ||
		env[knowledgerun.EnvURL] != "" || env[knowledgerun.EnvToken] != "" {
		t.Fatalf("the run's environment = %v: want the input files' URL and token, the tokens declared sensitive, "+
			"and no knowledge search for a project without knowledge", env)
	}
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := db.AsControlPlane().GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if err != nil || !strings.Contains(row.Scope, `"inputs":true`) || row.TokenSHA256 != tokenSHA256(token) {
		t.Fatalf("the session's record = %+v, %v", row, err)
	}
	// A run on a copy of the project's own directory reads the store itself.
	if token, k, _ := f.dispatch(t, f.bravo, false); token != "" || k != nil {
		t.Fatalf("a run that is not seeded was given a session for input files")
	}
}

func TestARunsSessionOpensItsOwnTasksInputFilesAlone(t *testing.T) {
	f := newInputsRunFixture(t)
	token, _, _ := f.dispatch(t, f.alpha, true)
	listing := func(task int, title string) knowledgerun.InputsResponse {
		t.Helper()
		status, data := f.post(t, token, knowledgerun.PathInputs,
			knowledgerun.InputsRequest{Task: task, TitleSHA256: knowledgerun.TitleDigest(title)})
		if status != http.StatusOK {
			t.Fatalf("list task %d: %d %s", task, status, data)
		}
		var out knowledgerun.InputsResponse
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	list := func(task int, title string) []knowledgerun.InputFile { return listing(task, title).Files }
	files := list(1, "build the API")
	if len(files) != 1 || files[0].ID != f.spec.ID || files[0].Name != "spec.md" || files[0].SHA256 != f.spec.SHA256 {
		t.Fatalf("task 1's input files = %+v: want spec.md, and never its result", files)
	}
	// A task the run numbers differently — one it created itself — is told
	// it has none, as is a task the hub does not have.
	if got := list(1, "a task the run created"); len(got) != 0 {
		t.Fatalf("a title that is not the hub's: %+v", got)
	}
	if got := list(99, "build the API"); len(got) != 0 {
		t.Fatalf("a task the hub does not have: %+v", got)
	}
	// The hub's task under another title is named as such when it has input
	// files — the run's copy was renamed or replaced on the hub — and not
	// when it has none: a task the run created colliding with it has none.
	if got := listing(1, "the title before a rename"); len(got.Files) != 0 || !strings.Contains(got.Mismatch, "renamed or replaced") {
		t.Fatalf("a renamed task with input files: %+v", got)
	}
	if status, data := f.post(t, token, knowledgerun.PathInputs, knowledgerun.InputsRequest{Task: 1, TitleSHA256: "build the API"}); status != http.StatusBadRequest {
		t.Fatalf("a title where its digest belongs: %d %s, want 400", status, data)
	}

	fetch := func(task int, title, id string) (int, []byte) {
		return f.post(t, token, knowledgerun.PathInputFile,
			knowledgerun.InputFileRequest{Task: task, TitleSHA256: knowledgerun.TitleDigest(title), ID: id})
	}
	if status, data := fetch(1, "build the API", f.spec.ID); status != http.StatusOK || string(data) != "# alpha's spec\n" {
		t.Fatalf("spec.md = %d %q", status, data)
	}
	for name, c := range map[string]struct {
		task  int
		title string
		id    string
	}{
		"a result of the task":             {1, "build the API", f.report.ID},
		"another task's input, named here": {1, "build the API", f.other.ID},
		"another project's input":          {1, "build the API", f.bravoInput.ID},
		"a task under another title":       {1, "renamed", f.spec.ID},
		"not an id":                        {1, "build the API", "../../etc/passwd"},
	} {
		if status, data := fetch(c.task, c.title, c.id); status != http.StatusNotFound || bytes.Contains(data, []byte("bravo's")) {
			t.Errorf("%s: %d %s, want 404", name, status, data)
		}
	}

	// Every file served and every one refused is on the control plane's
	// trail, with its run.
	evs := auditRowsOf(t, f.dir, auditaction.ActionRunInputFetch)
	ok, refused := 0, 0
	for _, e := range evs {
		if !strings.Contains(e.Payload, `"run_id":"run-`+filepath.Base(f.alpha)+`"`) {
			t.Errorf("an audit row without its run: %s", e.Payload)
		}
		switch {
		case strings.Contains(e.Payload, `"outcome":"ok"`):
			ok++
		case strings.Contains(e.Payload, `"outcome":"refused"`):
			refused++
		}
	}
	if ok != 1 || refused != 5 {
		t.Fatalf("audit rows: %d served, %d refused; want 1 and 5", ok, refused)
	}
}

func TestASessionWithoutInputFilesOpensNone(t *testing.T) {
	f := newInputsRunFixture(t)
	// A run that is not seeded but has the session for another reason —
	// here, projects it was given to read — reads the store itself.
	spec, k := applyRunSession(executor.Spec{WorkDir: f.alpha}, &knowledgeRemoteExec{}, f.alpha, "run-ro", "alice",
		[]string{"cloop", "run"}, []readOnlyGrant{{Slug: "bravo", Project: f.bravo}})
	if k == nil {
		t.Fatal("no session for a run given a project to read")
	}
	token := ""
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvReadersToken+"="); ok {
			token = v
		}
		if strings.HasPrefix(kv, knowledgerun.EnvInputsToken+"=") {
			t.Fatalf("a run that is not seeded was given %s", knowledgerun.EnvInputsToken)
		}
	}
	if status, data := f.post(t, token, knowledgerun.PathInputs, knowledgerun.InputsRequest{Task: 1, TitleSHA256: knowledgerun.TitleDigest("build the API")}); status != http.StatusForbidden {
		t.Fatalf("a session minted without input files listed them: %d %s", status, data)
	}
	if status, _ := f.post(t, token, knowledgerun.PathInputFile, knowledgerun.InputFileRequest{Task: 1, TitleSHA256: knowledgerun.TitleDigest("build the API"), ID: f.spec.ID}); status != http.StatusForbidden {
		t.Fatalf("a session minted without input files fetched one: %d", status)
	}
	// And no token, or a closed session, opens nothing.
	if status, _ := f.post(t, "", knowledgerun.PathInputs, knowledgerun.InputsRequest{Task: 1}); status != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", status)
	}
	seededToken, sk, _ := f.dispatch(t, f.alpha, true)
	sk.abandon("the run ended")
	if status, _ := f.post(t, seededToken, knowledgerun.PathInputFile, knowledgerun.InputFileRequest{Task: 1, TitleSHA256: knowledgerun.TitleDigest("build the API"), ID: f.spec.ID}); status != http.StatusUnauthorized {
		t.Fatalf("a closed session's token: %d, want 401", status)
	}
}

func TestARunThatCannotReachTheHubIsNoted(t *testing.T) {
	f := newInputsRunFixture(t)
	f.srv.ExternalURL = "" // no address a device could reach the hub at
	if token, k, _ := f.dispatch(t, f.alpha, true); token != "" || k != nil {
		t.Fatal("a session was minted for a run that cannot reach the hub")
	}
	events, _, err := state.ListEvents(f.alpha, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	noted := false
	for _, e := range events {
		noted = noted || strings.Contains(e.Message, "Input files are attached to tasks of this project, but its runs on edge-1 cannot reach this hub")
	}
	if !noted {
		t.Fatalf("the project's journal does not say its run's agents get no input files: %+v", events)
	}
	// Nor does a run with no network to reach it with, wherever the hub is.
	f.srv.ExternalURL = f.ts.URL
	offline, k := applyRunSession(executor.Spec{WorkDir: f.alpha, ProjectSeed: []byte("a seed"), DisableNetwork: true},
		&knowledgeRemoteExec{}, f.alpha, "run-offline", "alice", []string{"cloop", "run"}, nil)
	if k != nil || strings.Contains(strings.Join(offline.Env, " "), knowledgerun.EnvInputsToken) {
		t.Fatal("a run with no network was given a session to fetch its input files with")
	}
	events, _, err = state.ListEvents(f.alpha, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	noted = false
	for _, e := range events {
		noted = noted || strings.Contains(e.Message, "this run has no network to fetch them from the hub with")
	}
	if !noted {
		t.Fatal("the project's journal does not say a run with no network gets no input files")
	}
	f.srv.ExternalURL = ""

	// A project without input files is not told about them.
	charlie := setupProjectWithTasks(t, cloopGoal, []*pm.Task{{ID: 1, Title: "no files", Status: pm.TaskPending}})
	if _, k, _ := f.dispatch(t, charlie, true); k != nil {
		t.Fatal("a session was minted for a run that cannot reach the hub")
	}
	events, _, err = state.ListEvents(charlie, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(e.Message, "Input files") {
			t.Fatalf("a project without input files was told about them: %s", e.Message)
		}
	}
}

func TestUploadsInFlightTakeTheirRoomFirst(t *testing.T) {
	g := &uploadGate{projects: map[string]*projectUploads{}, swept: map[string]time.Time{}}
	const mib = 1 << 20
	near := statedb.AttachmentUsage{TaskFiles: 1, TaskBytes: 100 * mib, ProjectFiles: 1, ProjectBytes: 100 * mib}

	limit, release1, why, _ := g.take("/p/a.db", 1, near, 20*mib)
	if why != "" || limit != 20*mib {
		t.Fatalf("the first upload: limit %d, %q", limit, why)
	}
	// The second finds the room the first is taking gone, though the
	// database does not record either yet.
	if _, _, why, status := g.take("/p/a.db", 1, near, 20*mib); status != http.StatusRequestEntityTooLarge || why == "" {
		t.Fatalf("an upload past the task's limit with another in flight: %d %q", status, why)
	}
	// Another task of the project is held to what the project has left.
	if _, release, why, _ := g.take("/p/a.db", 2, statedb.AttachmentUsage{ProjectBytes: 100 * mib}, 20*mib); why != "" {
		t.Fatalf("an upload to another task: %q", why)
	} else {
		release()
	}
	release1()
	release1() // twice is once
	if limit, release, why, _ := g.take("/p/a.db", 1, near, 20*mib); why != "" || limit != 20*mib {
		t.Fatalf("after the first ended: %d %q", limit, why)
	} else {
		release()
	}
	// A body sent without a length takes all that is left.
	limit, release, why, _ := g.take("/p/a.db", 1, near, -1)
	if why != "" || limit != 28*mib {
		t.Fatalf("an upload without a length may take %d (%q), want the 28 MiB the task has left", limit, why)
	}
	if _, _, why, status := g.take("/p/a.db", 1, near, 1); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("an upload while one without a length holds the rest: %d %q", status, why)
	}
	release()

	// At most four at once to a project, and sixteen in all.
	var releases []func()
	for i := 0; i < maxUploadsPerProject; i++ {
		_, r, why, _ := g.take("/p/b.db", 1, statedb.AttachmentUsage{}, 1)
		if why != "" {
			t.Fatalf("upload %d: %q", i, why)
		}
		releases = append(releases, r)
	}
	if _, _, _, status := g.take("/p/b.db", 1, statedb.AttachmentUsage{}, 1); status != http.StatusTooManyRequests {
		t.Fatalf("a fifth upload to one project: %d, want 429", status)
	}
	for i := 0; len(releases) < maxUploadsInFlight; i++ {
		_, r, why, _ := g.take("/p/other-"+strconv.Itoa(i/maxUploadsPerProject)+".db", 1, statedb.AttachmentUsage{}, 1)
		if why != "" {
			t.Fatalf("upload %d in all: %q", len(releases), why)
		}
		releases = append(releases, r)
	}
	if _, _, _, status := g.take("/p/c.db", 1, statedb.AttachmentUsage{}, 1); status != http.StatusTooManyRequests {
		t.Fatalf("a seventeenth upload: %d, want 429", status)
	}
	for _, r := range releases {
		r()
	}
	if g.total != 0 || len(g.projects) != 0 {
		t.Fatalf("the gate holds %d uploads in %d projects after every release", g.total, len(g.projects))
	}
}

func TestAnUploadSweepsWhatADeadOneLeft(t *testing.T) {
	dir := setupProjectWithTasks(t, cloopGoal, []*pm.Task{{ID: 1, Title: "t", Status: pm.TaskPending}})
	ts := newTestServer(t, dir, nil)
	dbPath := state.DBPath(dir)
	attachTo(t, dir, 1, "keep.txt", []byte("kept"))
	stale := filepath.Join(attachments.StoreDir(dbPath), "."+strings.Repeat("d", 32)+".tmp")
	if err := os.WriteFile(stale, []byte("half an upload"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	attachmentUploads.mu.Lock()
	delete(attachmentUploads.swept, dbPath)
	attachmentUploads.mu.Unlock()
	if status, out := upload(t, ts.URL, "/api/tasks/1/attachments?name=x.txt", "application/octet-stream",
		strings.NewReader("x"), nil); status != http.StatusCreated {
		t.Fatalf("upload = %d %v", status, out)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("the partial copy a dead upload left is still in the store: %v", err)
	}
	if rows := storedRows(t, dir, 1); len(rows) != 2 {
		t.Fatalf("the sweep took a recorded file: %d left", len(rows))
	}
}

func TestARunsInputTransfersAreHeld(t *testing.T) {
	now := time.Now()
	id := "session-" + t.Name()
	r1, why, _ := takeInputTransfer(id, 10, now)
	r2, why2, _ := takeInputTransfer(id, 10, now)
	if why != "" || why2 != "" {
		t.Fatalf("two transfers at once: %q %q", why, why2)
	}
	if _, why, wait := takeInputTransfer(id, 10, now); why == "" || wait < 1 {
		t.Fatalf("a third transfer at once was admitted: %q %d", why, wait)
	}
	r1()
	r1()
	r2()
	// The byte budget: two tasks' worth at once, then what refills.
	big := int64(runInputBytesBurst) - 20
	rb, why, _ := takeInputTransfer(id, big, now)
	if why != "" {
		t.Fatalf("a transfer within the budget: %q", why)
	}
	rb()
	_, why, wait := takeInputTransfer(id, 4<<20, now)
	if why == "" || wait < 2 {
		t.Fatalf("a transfer past the budget: %q, wait %d", why, wait)
	}
	if r, why, _ := takeInputTransfer(id, 4<<20, now.Add(3*time.Second)); why != "" {
		t.Fatalf("after the budget refilled: %q", why)
	} else {
		r()
	}
}
