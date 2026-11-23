package projectseed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Task 20513: a seeded run sends the files it attaches to the hub while it
// runs. Its result then describes them without carrying them, and the merge
// finds each — attached already, or held for the run — under the id the run
// gave it, so every file arrives whole and once, whatever its size.

func hexSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hold puts a file the run sent into the hub's hold for the run, as the hub's
// endpoint does.
func hold(t *testing.T, hub, runID string, row statedb.AttachmentRow, task int, title string, data []byte) {
	t.Helper()
	if _, err := attachments.Hold(state.DBPath(hub), runID, attachments.HeldFile{
		ID: row.ID, Task: task, TitleSHA256: knowledgerun.TitleDigest(title), Name: row.Name,
		Size: int64(len(data)), SHA256: hexSHA(data), CreatedAt: row.CreatedAt,
	}, bytes.NewReader(data)); err != nil {
		t.Fatalf("hold %s: %v", row.Name, err)
	}
}

func storedBytes(t *testing.T, hub string, row statedb.AttachmentRow) []byte {
	t.Helper()
	f, _, err := attachments.Open(state.DBPath(hub), row)
	if err != nil {
		t.Fatalf("open %s on the hub: %v", row.Name, err)
	}
	defer f.Close()
	var b bytes.Buffer
	if _, err := b.ReadFrom(f); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestARunsSentFilesArriveWholeAndOnce(t *testing.T) {
	isolateHome(t)
	const runID = "hub-run-9"
	const secret = "ghp_s3cretTokenValue0123456789"
	set := redact.New(secret)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Benchmark and chart", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)

	// 600 KB with the run's credential in it: far past what a result
	// carries, and scrubbed on the hub as it is copied into the store.
	big := append([]byte("leaked "+secret+"\n"), bytes.Repeat([]byte("sample,"), 90_000)...)
	small := []byte("a small table\n")
	direct := []byte("attached straight away\n")
	var bigRow, smallRow, directRow statedb.AttachmentRow
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		bigRow = deviceAttach(t, dir, 1, "big.csv", big)
		smallRow = deviceAttach(t, dir, 1, "small.txt", small)
		directRow = deviceAttach(t, dir, 1, "direct.txt", direct)
		// The orchestrator sent big.csv and direct.txt and marked them.
		for _, id := range []string{bigRow.ID, directRow.ID} {
			if err := attachments.MarkSent(state.DBPath(dir), id); err != nil {
				t.Fatal(err)
			}
		}
	})
	// The hub held big.csv for the run, and attached direct.txt to its task
	// at once, under the run's id.
	hold(t, hub, runID, bigRow, 1, "Benchmark and chart", big)
	hubDB, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachments.Put(hubDB, state.DBPath(hub), 1, attachments.Meta{ID: directRow.ID, Name: "direct.txt",
		Source: statedb.AttachmentSourceRun, RunID: runID, AddedBy: "agent"}, bytes.NewReader(direct),
		attachments.MaxFileBytes, nil); err != nil {
		t.Fatal(err)
	}
	hubDB.Close()

	data, err := Harvest(dev, seed, set.String)
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Attachment{}
	for _, a := range r.Attachments {
		byName[a.Name] = a
	}
	for name, row := range map[string]statedb.AttachmentRow{"big.csv": bigRow, "direct.txt": directRow} {
		if a := byName[name]; !a.Sent || len(a.Data) != 0 || a.ID != row.ID || a.Left != "" {
			t.Errorf("%s in the result = sent %v, %d bytes, id %q, left %q: described as sent, not carried",
				name, a.Sent, len(a.Data), a.ID, a.Left)
		}
	}
	if a := byName["small.txt"]; a.Sent || string(a.Data) != string(small) || a.ID != smallRow.ID {
		t.Errorf("small.txt in the result = sent %v, %q, id %q: carried, under the run's id", a.Sent, a.Data, a.ID)
	}

	rep, err := Apply(hub, r, Provenance{RunID: runID, ExecutorID: "edge-1"}, set.String, WithRedaction(set))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Attached != 2 || rep.Delivered != 1 || len(rep.LeftBehind) != 0 || len(rep.NotRecorded) != 0 {
		t.Fatalf("merge: attached %d, delivered %d, left %v, not recorded %v", rep.Attached, rep.Delivered,
			rep.LeftBehind, rep.NotRecorded)
	}
	if s := rep.Summary(); !strings.Contains(s, "1 file it had already sent while it ran") {
		t.Errorf("Summary = %q", s)
	}
	rows := hubAttachments(t, hub, 1)
	if len(rows) != 3 {
		t.Fatalf("the hub's task 1 has %d attachments, want 3 — each once: %v", len(rows), rows)
	}
	bigHub := rows["big.csv"]
	if bigHub.ID != bigRow.ID || bigHub.Unavailable != "" || bigHub.RunID != runID {
		t.Fatalf("big.csv on the hub = %+v", bigHub)
	}
	got := storedBytes(t, hub, bigHub)
	if bytes.Contains(got, []byte(secret)) || !bytes.HasPrefix(got, []byte("leaked ")) ||
		len(got) < len(big)-len(secret) {
		t.Errorf("big.csv was stored as %d bytes, not the whole file scrubbed", len(got))
	}
	if rows["small.txt"].ID != smallRow.ID || string(storedBytes(t, hub, rows["small.txt"])) != string(small) {
		t.Errorf("small.txt on the hub = %+v", rows["small.txt"])
	}
	if held, _ := attachments.Held(state.DBPath(hub), runID); len(held) != 0 {
		t.Errorf("the merge left %d held files", len(held))
	}
}

// A run lost before its outcome came merges its last progress report, which
// carries no attachments: the files it sent are attached by their own
// description, to the hub's numbering of the task, and one sent for a task the
// hub has under another title is let go of.
func TestALostRunsSentFilesAreKept(t *testing.T) {
	isolateHome(t)
	const runID = "lost-run"
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Profile the service", Status: pm.TaskPending},
		{ID: 2, Title: "the hub's own task 2", Status: pm.TaskPending},
		{ID: 3, Title: "renamed on the hub", Status: pm.TaskPending},
	}}})
	created := &pm.Task{ID: 2, Title: "Write the report", Status: pm.TaskDone}
	r := &Result{Format: ResultFormat, Interim: true, Tasks: []TaskChange{
		{Before: &pm.Task{ID: 1, Title: "Profile the service", Status: pm.TaskPending},
			After: &pm.Task{ID: 1, Title: "Profile the service", Status: pm.TaskDone}},
		{After: created},
	}}
	flame := []byte("<svg>flame graph</svg>")
	report := []byte("# Report\n")
	stray := []byte("for a task the hub renamed")
	hold(t, hub, runID, statedb.AttachmentRow{ID: strings.Repeat("1", 32), Name: "flame.svg", CreatedAt: time.Now()},
		1, "Profile the service", flame)
	// The run created this task, and sent its file as such.
	if _, err := attachments.Hold(state.DBPath(hub), runID, attachments.HeldFile{
		ID: strings.Repeat("2", 32), Task: 2, TitleSHA256: knowledgerun.TitleDigest("Write the report"), Name: "report.md",
		Size: int64(len(report)), SHA256: hexSHA(report), CreatedAt: time.Now(), Created: true,
	}, bytes.NewReader(report)); err != nil {
		t.Fatal(err)
	}
	hold(t, hub, runID, statedb.AttachmentRow{ID: strings.Repeat("3", 32), Name: "stray.txt", CreatedAt: time.Now()},
		3, "the run's title for task 3", stray)

	rep, err := Apply(hub, r, Provenance{RunID: runID}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	newID, ok := rep.Renumbered[2]
	if !ok {
		t.Fatalf("the created task was not renumbered: %+v", rep.Renumbered)
	}
	if rep.Attached != 2 {
		t.Fatalf("attached %d, want 2; not recorded %v", rep.Attached, rep.NotRecorded)
	}
	if row := hubAttachments(t, hub, 1)["flame.svg"]; row.ID != strings.Repeat("1", 32) || string(storedBytes(t, hub, row)) != string(flame) {
		t.Errorf("flame.svg on task 1 = %+v", row)
	}
	if row := hubAttachments(t, hub, newID)["report.md"]; row.ID != strings.Repeat("2", 32) {
		t.Errorf("report.md on the created task #%d = %+v", newID, row)
	}
	if rows := hubAttachments(t, hub, 2); len(rows) != 0 {
		t.Errorf("the hub's own task 2 inherited the run's file: %v", rows)
	}
	if rows := hubAttachments(t, hub, 3); len(rows) != 0 {
		t.Errorf("a task renamed on the hub inherited the run's file: %v", rows)
	}
	if !strings.Contains(strings.Join(rep.NotRecorded, " "), "stray.txt") {
		t.Errorf("not recorded = %v", rep.NotRecorded)
	}
	if held, _ := attachments.Held(state.DBPath(hub), runID); len(held) != 0 {
		t.Errorf("the merge left %d held files", len(held))
	}
}

// A run whose result never came still has what it sent attached to the tasks
// it named, when the hub has them under the run's titles.
func TestClaimHeldWithoutAResult(t *testing.T) {
	isolateHome(t)
	const runID = "no-result"
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskInProgress},
	}}})
	kept := []byte("kept")
	hold(t, hub, runID, statedb.AttachmentRow{ID: strings.Repeat("4", 32), Name: "kept.txt"}, 1, "one", kept)
	hold(t, hub, runID, statedb.AttachmentRow{ID: strings.Repeat("5", 32), Name: "made.txt"}, 9, "a task the run made", []byte("x"))
	rep, err := ClaimHeld(hub, Provenance{RunID: runID}, func(s string) string { return s }, WithRedaction(nil))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Attached != 1 || len(rep.NotRecorded) != 1 {
		t.Fatalf("claim: attached %d, not recorded %v", rep.Attached, rep.NotRecorded)
	}
	if row := hubAttachments(t, hub, 1)["kept.txt"]; string(storedBytes(t, hub, row)) != "kept" {
		t.Errorf("kept.txt = %+v", row)
	}
	if held, _ := attachments.Held(state.DBPath(hub), runID); len(held) != 0 {
		t.Errorf("ClaimHeld left %d held files", len(held))
	}
	if _, err := os.Stat(state.DBPath(hub)); err != nil {
		t.Fatal(err)
	}
}

// A file the run says it sent and the hub no longer has — a person deleted it
// while the run went on — is not put back; and a run's id that is another
// attachment's costs the run's file its id, never the other attachment.
func TestApplyBelievesASentMarkOnlyAsFarAsTheFile(t *testing.T) {
	isolateHome(t)
	const runID = "run-x"
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskDone},
	}}})
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	input, err := attachments.Put(db, state.DBPath(hub), 1, attachments.Meta{Name: "spec.md", Source: statedb.AttachmentSourceUpload,
		Role: statedb.AttachmentRoleInput}, strings.NewReader("the spec"), attachments.MaxFileBytes, nil)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	r := &Result{Format: ResultFormat, Attachments: []Attachment{
		{ID: strings.Repeat("8", 32), TaskID: 1, TaskTitle: "one", Name: "deleted.txt", Size: 5, Sent: true},
		{ID: input.ID, TaskID: 1, TaskTitle: "one", Name: "collides.txt", Data: []byte("mine"), Size: 4},
	}}
	rep, err := Apply(hub, r, Provenance{RunID: runID}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	rows := hubAttachments(t, hub, 1)
	if _, ok := rows["deleted.txt"]; ok {
		t.Error("a file the hub no longer has was recorded again")
	}
	if !strings.Contains(strings.Join(rep.NotRecorded, " "), "no longer has it") {
		t.Errorf("not recorded = %v", rep.NotRecorded)
	}
	col := rows["collides.txt"]
	if col.ID == "" || col.ID == input.ID || string(storedBytes(t, hub, col)) != "mine" {
		t.Errorf("collides.txt = %+v: attached under a fresh id", col)
	}
	if got := rows["spec.md"]; got.ID != input.ID || string(storedBytes(t, hub, got)) != "the spec" {
		t.Errorf("the input file became %+v", got)
	}
}

func TestDecodeResultRefusesBadAttachmentIDs(t *testing.T) {
	for name, a := range map[string]Attachment{
		"not an id":       {ID: "../etc", TaskID: 1, Name: "x"},
		"sent with bytes": {ID: strings.Repeat("a", 32), TaskID: 1, Name: "x", Sent: true, Data: []byte("x"), Size: 1},
	} {
		doc, err := json.Marshal(Result{Format: ResultFormat, Attachments: []Attachment{a}})
		if err != nil {
			t.Fatal(err)
		}
		raw := gzipBytes(t, doc)
		if _, err := DecodeResult(raw); err == nil {
			t.Errorf("%s: DecodeResult accepted %+v", name, a)
		}
	}
}

// A file sent for a task the run was given keeps that task's id, even when the
// run created another task that took the same number and the hub renumbered
// that one: only a file of a task the run created follows the renumbering.
func TestOnlyACreatedTasksHeldFileFollowsTheRenumbering(t *testing.T) {
	isolateHome(t)
	const runID = "renumbering"
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskPending},
		{ID: 2, Title: "two", Status: pm.TaskPending},
	}}})
	// The run deleted task 2 and created a new task 2, which the hub
	// renumbers because it still has its own task 2.
	r := &Result{Format: ResultFormat, Interim: true, Tasks: []TaskChange{
		{After: &pm.Task{ID: 2, Title: "a new two", Status: pm.TaskDone}},
	}}
	sent := []byte("made for the original task 2")
	made := []byte("made for the new task 2")
	hold(t, hub, runID, statedb.AttachmentRow{ID: strings.Repeat("c", 32), Name: "original.txt"}, 2, "two", sent)
	if _, err := attachments.Hold(state.DBPath(hub), runID, attachments.HeldFile{
		ID: strings.Repeat("d", 32), Task: 2, TitleSHA256: knowledgerun.TitleDigest("a new two"), Name: "new.txt",
		Size: int64(len(made)), SHA256: hexSHA(made), Created: true,
	}, bytes.NewReader(made)); err != nil {
		t.Fatal(err)
	}
	rep, err := Apply(hub, r, Provenance{RunID: runID}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	newID := rep.Renumbered[2]
	if newID == 0 || rep.Attached != 2 {
		t.Fatalf("merge: renumbered %v, attached %d, not recorded %v", rep.Renumbered, rep.Attached, rep.NotRecorded)
	}
	if row := hubAttachments(t, hub, 2)["original.txt"]; row.ID == "" {
		t.Errorf("the original task 2's file did not stay with task 2: %v", hubAttachments(t, hub, 2))
	}
	if row := hubAttachments(t, hub, newID)["new.txt"]; row.ID == "" {
		t.Errorf("the created task's file did not follow it to #%d: %v", newID, hubAttachments(t, hub, newID))
	}
}
