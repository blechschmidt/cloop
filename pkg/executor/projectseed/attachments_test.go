package projectseed

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// deviceAttach stores a file in the device workspace's attachment store, as
// the orchestrator running there does when an attempt ends.
func deviceAttach(t *testing.T, dir string, taskID int, name string, data []byte) statedb.AttachmentRow {
	t.Helper()
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := attachments.Put(db, dbPath, taskID, attachments.Meta{Name: name, Source: statedb.AttachmentSourceRun, RunID: "device-run"},
		bytes.NewReader(data), attachments.MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func hubAttachments(t *testing.T, hub string, taskID int) map[string]statedb.AttachmentRow {
	t.Helper()
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.TaskAttachments(taskID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]statedb.AttachmentRow{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestARemoteRunsAttachmentsReachTheHub: files a run attached on an executor
// that does not share the hub's filesystem come back in its result and are
// attached to the hub's task — scrubbed, under the hub's run id — and a file
// the result had no room for, or that the workload swapped for a link, is
// still recorded, saying where it is.
func TestARemoteRunsAttachmentsReachTheHub(t *testing.T) {
	isolateHome(t)
	const secret = "ghp_s3cretTokenValue0123456789"
	scrub := redact.New(secret).String
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Benchmark and chart", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)

	outside := filepath.Join(t.TempDir(), "device-secret")
	if err := os.WriteFile(outside, []byte("the agent's own credentials"), 0o600); err != nil {
		t.Fatal(err)
	}
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		deviceAttach(t, dir, 1, "report.txt", []byte("pushed with "+secret+"\n"))
		deviceAttach(t, dir, 1, "big.bin", randomBytes(t, attachmentCarryBytes+1))
		linked := deviceAttach(t, dir, 1, "linked.txt", []byte("27 bytes of ordinary text.\n"))
		// The workload swaps a stored file for a link to something only the
		// agent, outside the sandbox, could read.
		stored := filepath.Join(attachments.StoreDir(filepath.Join(dir, ".cloop", "state.db")), linked.ID)
		if err := os.Remove(stored); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, stored); err != nil {
			t.Fatal(err)
		}
	})

	data, err := Harvest(dev, seed, scrub)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	carried := map[string]Attachment{}
	for _, a := range r.Attachments {
		carried[a.Name] = a
	}
	if a := carried["report.txt"]; len(a.Data) == 0 || strings.Contains(string(a.Data), secret) || a.Left != "" {
		t.Errorf("report.txt in the result: %q, left %q — carried, and scrubbed", a.Data, a.Left)
	}
	if a := carried["big.bin"]; len(a.Data) != 0 || !strings.Contains(a.Left, "did not fit") || a.Size != attachmentCarryBytes+1 {
		t.Errorf("big.bin in the result: %d bytes, left %q", len(a.Data), a.Left)
	}
	if a := carried["linked.txt"]; len(a.Data) != 0 || a.Left == "" || strings.Contains(string(a.Data), "credentials") {
		t.Errorf("linked.txt in the result: %q, left %q — a link must not be read", a.Data, a.Left)
	}

	rep, err := Apply(hub, r, Provenance{RunID: "hub-run-7", ExecutorID: "edge-1"}, scrub)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rep.Attached != 1 || len(rep.LeftBehind) != 2 {
		t.Fatalf("merge report: attached %d, left behind %v", rep.Attached, rep.LeftBehind)
	}
	if s := rep.Summary(); !strings.Contains(s, "1 attached file") || !strings.Contains(s, "big.bin") {
		t.Errorf("Summary = %q", s)
	}
	rows := hubAttachments(t, hub, 1)
	report, ok := rows["report.txt"]
	if !ok || report.RunID != "hub-run-7" || report.Unavailable != "" {
		t.Fatalf("the hub's report.txt = %+v (all: %v)", report, rows)
	}
	f, _, err := attachments.Open(state.DBPath(hub), report)
	if err != nil {
		t.Fatalf("the hub cannot open the stored report: %v", err)
	}
	stored, _ := os.ReadFile(f.Name())
	f.Close()
	if strings.Contains(string(stored), secret) || !strings.HasPrefix(string(stored), "pushed with ") {
		t.Errorf("stored report = %q", stored)
	}
	for _, name := range []string{"big.bin", "linked.txt"} {
		if row := rows[name]; row.ID == "" || row.Unavailable == "" {
			t.Errorf("%s on the hub = %+v: recorded, without its file, saying why", name, row)
		}
	}
	if rows["big.bin"].MediaType != "application/octet-stream" || rows["big.bin"].Size != attachmentCarryBytes+1 {
		t.Errorf("big.bin is described as %+v", rows["big.bin"])
	}

	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Plan.TaskByID(1); got.AttachmentCount != 3 || got.Status != pm.TaskDone {
		t.Errorf("the hub's task 1: %d attachments, %s", got.AttachmentCount, got.Status)
	}
}

// TestApplyChecksWhatADeviceSends: the hub takes nothing about an attachment
// on the device's word — a digest that does not match keeps the bytes out, a
// task the device created is attached under the hub's number for it, a task
// the hub deleted or retitled while the run was out gets nothing, and a result
// that changed nothing else still lands its files.
func TestApplyChecksWhatADeviceSends(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskDone},
		{ID: 3, Title: "renamed on the hub", Status: pm.TaskDone},
		{ID: 5, Title: "the hub's own task 5", Status: pm.TaskDone},
	}}})
	r := &Result{Format: ResultFormat, Attachments: []Attachment{
		{TaskID: 1, TaskTitle: "one", Name: "tampered.txt", Data: []byte("payload"), SHA256: strings.Repeat("0", 64), Size: 7},
		{TaskID: 2, TaskTitle: "created on the device", Name: "../../renumbered.txt", Data: []byte("for task six"), Size: 12, CreatedAt: time.Now()},
		{TaskID: 3, TaskTitle: "what the run worked on", Name: "stale.txt", Data: []byte("x"), Size: 1},
		{TaskID: 9, TaskTitle: "gone", Name: "orphan.txt", Data: []byte("no such task"), Size: 12},
	}}
	// The device's task 2 was created by the run and renumbered to 6.
	rep := MergeReport{Renumbered: map[int]int{2: 6}}
	rep.markRunTask(6)
	st, err := state.LoadLite(hub)
	if err != nil {
		t.Fatal(err)
	}
	st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 6, Title: "created on the device", Status: pm.TaskDone})
	if err := st.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	if err := applyAttachments(hub, r.Attachments, rep.Renumbered, Provenance{RunID: "r"}, func(s string) string { return s }, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Attached != 1 {
		t.Fatalf("attached %d, want only the renumbered file: left %v, not recorded %v", rep.Attached, rep.LeftBehind, rep.NotRecorded)
	}
	if row := hubAttachments(t, hub, 6)["renumbered.txt"]; row.ID == "" || row.Unavailable != "" {
		t.Errorf("the created task's file, under the hub's number = %+v", row)
	}
	if row := hubAttachments(t, hub, 1)["tampered.txt"]; row.Unavailable == "" || !strings.Contains(row.Unavailable, "digest") {
		t.Errorf("a digest mismatch was stored: %+v", row)
	}
	if rows := hubAttachments(t, hub, 3); len(rows) != 0 {
		t.Errorf("a task retitled on the hub inherited the run's file: %v", rows)
	}
	notRecorded := strings.Join(rep.NotRecorded, " ")
	if !strings.Contains(notRecorded, "task #3 is not the task the run attached it to") ||
		!strings.Contains(notRecorded, "task #9 is not the task") {
		t.Errorf("not recorded = %v", rep.NotRecorded)
	}
	if s := rep.Summary(); !strings.Contains(s, "not recorded") {
		t.Errorf("Summary = %q", s)
	}

	// Through Apply: a result whose only news is a file still lands it.
	only := &Result{Format: ResultFormat, Attachments: []Attachment{{TaskID: 1, TaskTitle: "one", Name: "late.txt", Data: []byte("x"), Size: 1}}}
	got, err := Apply(hub, only, Provenance{RunID: "r2"}, nil)
	if err != nil || got.Attached != 1 {
		t.Fatalf("Apply of a files-only result: %+v, %v", got, err)
	}
}

// TestALeftBehindRowStillCountsAgainstTheTask: a run's files kept on its
// device take no room on the hub, but each is a row, and a task's rows are
// bounded however they arrive.
func TestALeftBehindRowStillCountsAgainstTheTask(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "one", Status: pm.TaskDone},
	}}})
	var in []Attachment
	for i := 0; i < attachments.MaxTaskFiles+5; i++ {
		in = append(in, Attachment{TaskID: 1, TaskTitle: "one", Name: "kept.bin", Size: 10, Left: "left on the device"})
	}
	rep := MergeReport{}
	if err := applyAttachments(hub, in, nil, Provenance{}, nil, &rep); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _ := db.TaskAttachments(1)
	if len(rows) != attachments.MaxTaskFiles || len(rep.NotRecorded) != 5 {
		t.Fatalf("recorded %d rows, refused %d; want %d and 5", len(rows), len(rep.NotRecorded), attachments.MaxTaskFiles)
	}
}

// TestAttachmentBytesGiveWayToFitTheTransport: a result over the transport's
// ceiling drops its attachments' bytes before the run's steps, and says so.
func TestAttachmentBytesGiveWayToFitTheTransport(t *testing.T) {
	r := &Result{Format: ResultFormat, Tasks: []TaskChange{{After: &pm.Task{ID: 1, Title: "x", Status: pm.TaskDone}}},
		Steps: []state.StepResult{{Step: 0, Output: "the transcript"}}}
	for i := 0; i < 3; i++ {
		r.Attachments = append(r.Attachments, Attachment{TaskID: 1, Name: "noise.bin", Data: randomBytes(t, 300<<10)})
	}
	data, err := encodeResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > executor.MaxProjectResultBytes {
		t.Fatalf("encoded %d bytes, over the ceiling", len(data))
	}
	got, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Attachments) != 3 || len(got.Steps) != 1 || got.Steps[0].Output != "the transcript" {
		t.Fatalf("decoded %d attachments, steps %+v", len(got.Attachments), got.Steps)
	}
	for _, a := range got.Attachments {
		if len(a.Data) != 0 || a.Left == "" {
			t.Errorf("an attachment kept its bytes, or lost them silently: %d bytes, left %q", len(a.Data), a.Left)
		}
	}
	if !strings.Contains(strings.Join(got.Omitted, " "), "3 files attached by the run were left") {
		t.Errorf("omitted = %v", got.Omitted)
	}
}

func TestDecodeResultBoundsAttachments(t *testing.T) {
	cases := map[string]*Result{
		"no task":         {Format: ResultFormat, Attachments: []Attachment{{Name: "x"}}},
		"too many":        {Format: ResultFormat, Attachments: make([]Attachment, maxResultAttachments+1)},
		"a size past any": {Format: ResultFormat, Attachments: []Attachment{{TaskID: 1, Name: "x", Size: 1 << 62}}},
		"a negative size": {Format: ResultFormat, Attachments: []Attachment{{TaskID: 1, Name: "x", Size: -1}}},
		"bytes and size disagree": {Format: ResultFormat, Attachments: []Attachment{
			{TaskID: 1, Name: "x", Data: []byte("four"), Size: 3}}},
		"an oversized name": {Format: ResultFormat, Attachments: []Attachment{
			{TaskID: 1, Name: strings.Repeat("n", maxAttachmentTextBytes+1)}}},
	}
	for i := range cases["too many"].Attachments {
		cases["too many"].Attachments[i] = Attachment{TaskID: 1, Name: "x"}
	}
	for name, r := range cases {
		data, err := compress(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeResult(data); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
