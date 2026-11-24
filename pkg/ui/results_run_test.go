package ui

// Task 20513: a run seeded into its sandbox sends the files it attaches to the
// hub with its run session, and the hub attaches each to the task, or holds it
// for the run's result to place.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// redactingExec is a device whose handles scrub with set.
type redactingExec struct {
	knowledgeRemoteExec
	set *redact.Set
}

func (r *redactingExec) HandleRedaction(string) (*redact.Set, bool) { return r.set, true }

// resultsToken is the token a seeded dispatch's environment was given to send
// files with, "" for none.
func resultsToken(spec executor.Spec) string {
	for _, kv := range spec.Env {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvResultsToken+"="); ok {
			return v
		}
	}
	return ""
}

func fileSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sendResult posts one file as a seeded run's orchestrator does, and returns
// the status and the answer.
func (f *inputsRunFixture) sendResult(t *testing.T, token string, u knowledgerun.ResultUpload, body []byte,
	contentType string) (int, knowledgerun.ResultResponse, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.ts.URL+runResultsPath+"?"+u.Query().Encode(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out knowledgerun.ResultResponse
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func upload20513(id string, task int, title, name string, data []byte) knowledgerun.ResultUpload {
	return knowledgerun.ResultUpload{ID: id, Task: task, TitleSHA256: knowledgerun.TitleDigest(title), Name: name,
		Size: int64(len(data)), SHA256: fileSHA(data), CreatedAt: time.Now().Add(-time.Minute)}
}

func TestASeededRunIsGivenASessionToSendItsFilesWith(t *testing.T) {
	f := newInputsRunFixture(t)
	_, k, spec := f.dispatch(t, f.alpha, true)
	token := resultsToken(spec)
	if k == nil || !strings.HasPrefix(token, knowledgerun.TokenPrefix) {
		t.Fatalf("a seeded run got no session to send its files with: %v", spec.Env)
	}
	env := map[string]string{}
	for _, kv := range spec.Env {
		name, value, _ := strings.Cut(kv, "=")
		env[name] = value
	}
	if env[knowledgerun.EnvResultsURL] != f.ts.URL+knowledgerun.MountPath ||
		!strings.Contains(env[redact.EnvKey], knowledgerun.EnvResultsToken) {
		t.Fatalf("the run's environment = %v: want the URL, and the token declared sensitive", env)
	}
	db, err := statedb.Open(state.DBPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := db.AsControlPlane().GetProxySession(statedb.ProxySessionKnowledge, k.id)
	if err != nil || !strings.Contains(row.Scope, `"results":true`) {
		t.Fatalf("the session's record = %+v, %v", row, err)
	}
	// A run on the project's own directory attaches into the store itself,
	// and one with no network has nothing to send with.
	if _, _, spec := f.dispatch(t, f.bravo, false); resultsToken(spec) != "" {
		t.Fatal("a run that is not seeded was given a session to send files with")
	}
	noNet := executor.Spec{WorkDir: f.alpha, ProjectSeed: []byte("a seed"), DisableNetwork: true}
	noNet, _ = applyRunSession(noNet, &knowledgeRemoteExec{}, f.alpha, "run-nonet", "alice@example.com",
		[]string{"cloop", "run"}, nil)
	if resultsToken(noNet) != "" {
		t.Fatal("a run with no network was given a session to send files with")
	}
}

func TestARunsFilesAreHeldUntilTheHubCanTellTheirTask(t *testing.T) {
	f := newInputsRunFixture(t)
	_, _, spec := f.dispatch(t, f.alpha, true)
	token := resultsToken(spec)
	runID := "run-" + filepath.Base(f.alpha)
	data := bytes.Repeat([]byte("frame,"), 200_000) // 1.2 MB: three times what a result carries
	u := upload20513(strings.Repeat("a", 32), 1, "build the API", "profile.csv", data)

	// No hub process streams this run here, so nothing scrubs it with the
	// run's set: held, whole, for the merge.
	status, out, raw := f.sendResult(t, token, u, data, "application/octet-stream")
	if status != http.StatusCreated || out.Outcome != knowledgerun.ResultHeld || out.ID != u.ID {
		t.Fatalf("send = %d %s", status, raw)
	}
	held, err := attachments.Held(state.DBPath(f.alpha), runID)
	if err != nil || len(held) != 1 || held[0].Size != int64(len(data)) || held[0].SHA256 != u.SHA256 {
		t.Fatalf("held = %+v, %v", held, err)
	}
	if rows := storedRows(t, f.alpha, 1); len(rows) != 2 { // the fixture's spec.md and report.txt
		t.Fatalf("a held file was attached: %+v", rows)
	}
	// Sent again — the first answer was lost — it is answered from what is
	// here.
	if status, out, raw := f.sendResult(t, token, u, data, "application/octet-stream"); status != http.StatusOK || out.Outcome != knowledgerun.ResultHeld {
		t.Fatalf("resend = %d %s", status, raw)
	}

	// A task the run created is held whatever task of the hub's has its id.
	created := upload20513(strings.Repeat("b", 32), 2, "test it", "made.txt", []byte("made"))
	created.Created = true
	if status, out, raw := f.sendResult(t, token, created, []byte("made"), "application/octet-stream"); status != http.StatusCreated || out.Outcome != knowledgerun.ResultHeld {
		t.Fatalf("a created task's file = %d %s", status, raw)
	}

	// What does not check out is refused, and nothing of it kept.
	bad := upload20513(strings.Repeat("c", 32), 1, "build the API", "bad.txt", []byte("the real thing"))
	if status, _, raw := f.sendResult(t, token, bad, []byte("a forged thing"), "application/octet-stream"); status != http.StatusBadRequest {
		t.Fatalf("bytes that do not match their digest: %d %s", status, raw)
	}
	if _, ok := attachments.HeldNow(state.DBPath(f.alpha), runID, bad.ID); ok {
		t.Fatal("a file that did not check out was kept")
	}
	if status, _, raw := f.sendResult(t, token, u, data, "application/json"); status != http.StatusUnsupportedMediaType {
		t.Fatalf("a JSON body: %d %s", status, raw)
	}
	tooBig := upload20513(strings.Repeat("d", 32), 1, "build the API", "huge.bin", nil)
	tooBig.Size = attachments.MaxFileBytes + 1
	if status, _, raw := f.sendResult(t, token, tooBig, nil, "application/octet-stream"); status != http.StatusRequestEntityTooLarge &&
		status != http.StatusBadRequest {
		t.Fatalf("a file over the limit: %d %s", status, raw)
	}
	// An id that is another attachment's on the task is refused.
	clash := upload20513(f.spec.ID, 1, "build the API", "clash.txt", []byte("x"))
	if status, _, raw := f.sendResult(t, token, clash, []byte("x"), "application/octet-stream"); status != http.StatusConflict {
		t.Fatalf("another attachment's id: %d %s", status, raw)
	}
	if got := storedRows(t, f.alpha, 1); len(got) != 2 {
		t.Fatalf("the clash changed task 1's attachments: %+v", got)
	}
	// Without the session's token, or with a session minted without it.
	if status, _, _ := f.sendResult(t, "", u, data, "application/octet-stream"); status != http.StatusUnauthorized {
		t.Fatalf("no token: %d", status)
	}
	plain := executor.Spec{WorkDir: f.bravo}
	plain, _ = applyRunSession(plain, &knowledgeRemoteExec{}, f.bravo, "run-plain", "", []string{"cloop", "run"},
		[]readOnlyGrant{{Slug: "alpha", Project: f.alpha}})
	readersToken := ""
	for _, kv := range plain.Env {
		if v, ok := strings.CutPrefix(kv, knowledgerun.EnvReadersToken+"="); ok {
			readersToken = v
		}
	}
	if readersToken == "" {
		t.Fatalf("a run given another project to read got no session: %v", plain.Env)
	}
	if status, _, raw := f.sendResult(t, readersToken, u, data, "application/octet-stream"); status != http.StatusForbidden {
		t.Fatalf("a session minted without it: %d %s", status, raw)
	}

	// Every file is on the control plane's trail.
	evs := auditRowsOf(t, f.dir, auditaction.ActionRunResultUpload)
	outcomes := map[string]int{}
	for _, e := range evs {
		var p map[string]any
		_ = json.Unmarshal([]byte(e.Payload), &p)
		outcomes[p["outcome"].(string)]++
		if p["run_id"] == "" {
			t.Errorf("an audit row without its run: %s", e.Payload)
		}
	}
	if outcomes[knowledgerun.ResultHeld] != 2 || outcomes["refused"] < 4 {
		t.Fatalf("audit outcomes = %v", outcomes)
	}

	// The run's merge attaches the held files to the tasks the result names.
	ex := &knowledgeRemoteExec{}
	r := &projectseed.Result{Format: projectseed.ResultFormat, Attachments: []projectseed.Attachment{
		{ID: u.ID, TaskID: 1, TaskTitle: "build the API", Name: "profile.csv", Size: u.Size, SHA256: u.SHA256, Sent: true},
	}}
	rep, err := projectseed.Apply(f.alpha, r, projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()},
		func(s string) string { return s }, projectseed.WithRedaction(nil))
	if err != nil {
		t.Fatal(err)
	}
	// made.txt was sent for a task the run created, which this result does
	// not describe: only a result can place it, so it is let go of rather
	// than given to the hub's task of the same id.
	if rep.Attached != 1 || !strings.Contains(strings.Join(rep.NotRecorded, " "), "made.txt") {
		t.Fatalf("merge: %+v", rep)
	}
	for _, row := range storedRows(t, f.alpha, 2) {
		if row.Name == "made.txt" {
			t.Fatalf("a created task's file went to the hub's task of the same id: %+v", row)
		}
	}
	var profile statedb.AttachmentRow
	for _, row := range storedRows(t, f.alpha, 1) {
		if row.Name == "profile.csv" {
			profile = row
		}
	}
	if profile.ID != u.ID || profile.Size != int64(len(data)) || profile.Unavailable != "" {
		t.Fatalf("profile.csv on the hub = %+v", profile)
	}
	if got, _ := os.ReadFile(filepath.Join(attachments.StoreDir(state.DBPath(f.alpha)), profile.ID)); !bytes.Equal(got, data) {
		t.Fatalf("the stored file is %d bytes, not the %d sent", len(got), len(data))
	}
}

// The hub process streaming a run attaches what the run sends to the task at
// once, scrubbed with the set that scrubs the run's log.
func TestTheHubStreamingARunAttachesItsFilesAtOnce(t *testing.T) {
	f := newInputsRunFixture(t)
	const secret = "ghp_s3cretTokenValueForTheRun01"
	ex := &redactingExec{set: redact.New(secret)}
	runID := "run-" + filepath.Base(f.alpha)
	spec := executor.Spec{WorkDir: f.alpha, ProjectSeed: []byte("a seed")}
	spec, _ = applyRunSession(spec, ex, f.alpha, runID, "alice@example.com", []string{"cloop", "run"}, nil)
	token := resultsToken(spec)
	rememberSeededDispatch(ex, "h-1", projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-1") })
	f.srv.trackRun(f.alpha, ex, "h-1")

	data := []byte("the run printed " + secret + " into its report\n")
	u := upload20513(strings.Repeat("e", 32), 1, "build the API", "report.md", data)
	status, out, raw := f.sendResult(t, token, u, data, "application/octet-stream")
	if status != http.StatusCreated || out.Outcome != knowledgerun.ResultAttached || out.Task != 1 || out.ID != u.ID {
		t.Fatalf("send = %d %s", status, raw)
	}
	var row statedb.AttachmentRow
	for _, r := range storedRows(t, f.alpha, 1) {
		if r.ID == u.ID {
			row = r
		}
	}
	if row.Name != "report.md" || row.RunID != runID || row.Source != statedb.AttachmentSourceRun || row.Role != statedb.AttachmentRoleResult {
		t.Fatalf("the attached row = %+v", row)
	}
	got, err := os.ReadFile(filepath.Join(attachments.StoreDir(state.DBPath(f.alpha)), row.ID))
	if err != nil || bytes.Contains(got, []byte(secret)) || !bytes.HasPrefix(got, []byte("the run printed ")) {
		t.Fatalf("stored = %q, %v: scrubbed of the run's credential", got, err)
	}
	if _, ok := attachments.HeldNow(state.DBPath(f.alpha), runID, u.ID); ok {
		t.Fatal("an attached file is still held")
	}
	// Sent again, it is the same attachment.
	if status, out, raw := f.sendResult(t, token, u, data, "application/octet-stream"); status != http.StatusOK ||
		out.Outcome != knowledgerun.ResultAttached || out.ID != u.ID {
		t.Fatalf("resend = %d %s", status, raw)
	}
	n := 0
	for _, r := range storedRows(t, f.alpha, 1) {
		if r.Name == "report.md" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("report.md is attached %d times", n)
	}
	// A task the hub has under another title is held instead.
	other := upload20513(strings.Repeat("f", 32), 1, "the run's title for it", "other.txt", []byte("x"))
	if status, out, raw := f.sendResult(t, token, other, []byte("x"), "application/octet-stream"); status != http.StatusCreated ||
		out.Outcome != knowledgerun.ResultHeld {
		t.Fatalf("a renamed task's file = %d %s", status, raw)
	}
	// And the run's merge counts the attached one once.
	r := &projectseed.Result{Format: projectseed.ResultFormat, Attachments: []projectseed.Attachment{
		{ID: u.ID, TaskID: 1, TaskTitle: "build the API", Name: "report.md", Size: u.Size, SHA256: u.SHA256, Sent: true},
	}}
	rep, err := projectseed.Apply(f.alpha, r, projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()},
		ex.set.String, projectseed.WithRedaction(ex.set))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Delivered != 1 || rep.Attached != 0 {
		t.Fatalf("merge: delivered %d, attached %d", rep.Delivered, rep.Attached)
	}
}

// collectRunResult attaches what a run sent even when its result never came.
func TestARunWithoutAResultKeepsTheFilesItSent(t *testing.T) {
	f := newInputsRunFixture(t)
	ex := &resultExecutor{id: "edge-1", returns: true, err: executor.ErrProjectResultUnavailable}
	runID := "run-lost"
	data := []byte("sent while it ran")
	if _, err := attachments.Hold(state.DBPath(f.alpha), runID, attachments.HeldFile{
		ID: strings.Repeat("9", 32), Task: 1, TitleSHA256: knowledgerun.TitleDigest("build the API"), Name: "kept.txt",
		Size: int64(len(data)), SHA256: fileSHA(data), CreatedAt: time.Now(),
	}, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	rememberSeededDispatch(ex, "h-lost", projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()})
	f.srv.collectRunResult(f.alpha, ex, "h-lost", false)
	var kept statedb.AttachmentRow
	for _, r := range storedRows(t, f.alpha, 1) {
		if r.Name == "kept.txt" {
			kept = r
		}
	}
	if kept.ID != strings.Repeat("9", 32) || kept.Unavailable != "" {
		t.Fatalf("kept.txt = %+v", kept)
	}
	if held, _ := attachments.Held(state.DBPath(f.alpha), runID); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	found := false
	for _, e := range projectResultEvents(t, f.alpha) {
		found = found || strings.Contains(e.Message, "1 file was attached to the tasks they were sent for")
	}
	if !found {
		t.Fatalf("the journal does not say what became of the run's files: %+v", projectResultEvents(t, f.alpha))
	}
}

// An attach given back because the task went over a limit at the same moment
// leaves the file held for the merge, and says so: it is never lost.
func TestAnAttachGivenBackLeavesTheFileHeld(t *testing.T) {
	f := newInputsRunFixture(t)
	ex := &redactingExec{set: redact.New("unused-secret-value")}
	runID := "run-" + filepath.Base(f.alpha)
	spec := executor.Spec{WorkDir: f.alpha, ProjectSeed: []byte("a seed")}
	spec, _ = applyRunSession(spec, ex, f.alpha, runID, "alice@example.com", []string{"cloop", "run"}, nil)
	token := resultsToken(spec)
	rememberSeededDispatch(ex, "h-2", projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-2") })
	f.srv.trackRun(f.alpha, ex, "h-2")
	over := overLimitsAfterAttach
	overLimitsAfterAttach = func(statedb.AttachmentUsage) bool { return true }
	t.Cleanup(func() { overLimitsAfterAttach = over })

	data := []byte("a chart")
	u := upload20513(strings.Repeat("1", 32), 1, "build the API", "chart.png", data)
	status, out, raw := f.sendResult(t, token, u, data, "application/octet-stream")
	if status != http.StatusCreated || out.Outcome != knowledgerun.ResultHeld {
		t.Fatalf("send = %d %s: the run must be told the file is held", status, raw)
	}
	if _, ok := attachments.HeldNow(state.DBPath(f.alpha), runID, u.ID); !ok {
		t.Fatal("the file given back is not held: it is lost")
	}
	for _, row := range storedRows(t, f.alpha, 1) {
		if row.ID == u.ID {
			t.Fatalf("the row given back is still there: %+v", row)
		}
	}
	overLimitsAfterAttach = over
	rep, err := projectseed.Apply(f.alpha, &projectseed.Result{Format: projectseed.ResultFormat, Attachments: []projectseed.Attachment{
		{ID: u.ID, TaskID: 1, TaskTitle: "build the API", Name: "chart.png", Size: u.Size, SHA256: u.SHA256, Sent: true},
	}}, projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()}, ex.set.String, projectseed.WithRedaction(ex.set))
	if err != nil || rep.Attached != 1 {
		t.Fatalf("the merge: %+v, %v", rep, err)
	}
}

// A file's name is kept and audited without the credentials the run was
// leased, nor anything shaped like a credential.
func TestARunsFileNamesAreScrubbed(t *testing.T) {
	f := newInputsRunFixture(t)
	const secret = "s3cr3tValueOfTheRunsLease"
	ex := &redactingExec{set: redact.New(secret)}
	runID := "run-" + filepath.Base(f.alpha)
	spec := executor.Spec{WorkDir: f.alpha, ProjectSeed: []byte("a seed")}
	spec, _ = applyRunSession(spec, ex, f.alpha, runID, "alice@example.com", []string{"cloop", "run"}, nil)
	token := resultsToken(spec)
	rememberSeededDispatch(ex, "h-3", projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()})
	t.Cleanup(func() { takeSeededDispatch(ex, "h-3") })
	f.srv.trackRun(f.alpha, ex, "h-3")

	pat := "ghp_" + strings.Repeat("A1b2", 9)
	for i, name := range []string{"dump-" + secret + ".txt", "token-" + pat + ".txt"} {
		data := []byte("x")
		u := upload20513(strings.Repeat(string(rune('a'+i)), 32), 1, "build the API", name, data)
		if status, _, raw := f.sendResult(t, token, u, data, "application/octet-stream"); status != http.StatusCreated {
			t.Fatalf("send %s = %d %s", name, status, raw)
		}
	}
	for _, row := range storedRows(t, f.alpha, 1) {
		if strings.Contains(row.Name, secret) || strings.Contains(row.Name, pat) {
			t.Errorf("a row keeps a credential in its name: %q", row.Name)
		}
	}
	for _, e := range auditRowsOf(t, f.dir, auditaction.ActionRunResultUpload) {
		if strings.Contains(e.Payload, secret) || strings.Contains(e.Payload, pat) {
			t.Errorf("an audit row keeps a credential: %s", e.Payload)
		}
	}
}

// What a run the hub lost track of left held is swept before an upload's room
// is reckoned, so it cannot keep every later file out; a live run's is not.
func TestHeldFilesOfLostRunsAreSweptBeforeTheRoomIsReckoned(t *testing.T) {
	f := newInputsRunFixture(t)
	_, _, spec := f.dispatch(t, f.alpha, true)
	token := resultsToken(spec)
	dbPath := state.DBPath(f.alpha)
	plant := func(run string) string {
		data := []byte("left behind")
		if _, err := attachments.Hold(dbPath, run, attachments.HeldFile{ID: strings.Repeat("e", 32), Task: 1,
			TitleSHA256: knowledgerun.TitleDigest("x"), Name: "old.txt", Size: int64(len(data)), SHA256: fileSHA(data)},
			bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(attachments.StoreDir(dbPath), attachments.HeldDirName, attachments.RunKey(run))
		old := time.Now().Add(-72 * time.Hour)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.Chtimes(filepath.Join(dir, e.Name()), old, old)
		}
		_ = os.Chtimes(dir, old, old)
		return dir
	}
	lost := plant("a-run-nobody-merged")
	live := plant("run-" + filepath.Base(f.alpha)) // the session's own run: open
	data := []byte("new")
	u := upload20513(strings.Repeat("f", 32), 1, "renamed", "new.txt", data)
	if status, _, raw := f.sendResult(t, token, u, data, "application/octet-stream"); status != http.StatusCreated {
		t.Fatalf("send = %d %s", status, raw)
	}
	if _, err := os.Stat(lost); !os.IsNotExist(err) {
		t.Errorf("a lost run's held files were not swept: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Errorf("a live run's held files were swept: %v", err)
	}
}

// A result that cannot be read still leaves the run's held files attached.
func TestAnUnreadableResultKeepsTheFilesTheRunSent(t *testing.T) {
	f := newInputsRunFixture(t)
	ex := &resultExecutor{id: "edge-1", returns: true, result: executor.ProjectResult{Data: []byte("not a result")}}
	runID := "run-garbled"
	data := []byte("sent while it ran")
	if _, err := attachments.Hold(state.DBPath(f.alpha), runID, attachments.HeldFile{
		ID: strings.Repeat("8", 32), Task: 1, TitleSHA256: knowledgerun.TitleDigest("build the API"), Name: "kept.txt",
		Size: int64(len(data)), SHA256: fileSHA(data), CreatedAt: time.Now(),
	}, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	rememberSeededDispatch(ex, "h-garbled", projectseed.Provenance{RunID: runID, ExecutorID: ex.ID()})
	f.srv.collectRunResult(f.alpha, ex, "h-garbled", false)
	found := false
	for _, r := range storedRows(t, f.alpha, 1) {
		found = found || (r.Name == "kept.txt" && r.Unavailable == "")
	}
	if !found {
		t.Fatalf("kept.txt was not attached: %+v", storedRows(t, f.alpha, 1))
	}
}
