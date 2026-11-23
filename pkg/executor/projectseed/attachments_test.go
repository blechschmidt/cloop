package projectseed

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
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
		// Random bytes cost the frame what they weigh, and these weigh more
		// than the whole frame.
		deviceAttach(t, dir, 1, "big.bin", randomBytes(t, executor.MaxProjectResultBytes))
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
	if a := carried["big.bin"]; len(a.Data) != 0 || !strings.Contains(a.Left, "did not fit in what the run's result") ||
		a.Size != executor.MaxProjectResultBytes {
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
	if rows["big.bin"].MediaType != "application/octet-stream" || rows["big.bin"].Size != executor.MaxProjectResultBytes {
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
	if err := applyAttachments(hub, r.Attachments, nil, rep.Renumbered, Provenance{RunID: "r"}, func(s string) string { return s }, applyOptions{}, &rep); err != nil {
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
	if err := applyAttachments(hub, in, nil, nil, Provenance{}, nil, applyOptions{}, &rep); err != nil {
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
// ceiling drops its attachments' bytes before the run's steps — as few files,
// and as little of them, as it takes — and says so.
func TestAttachmentBytesGiveWayToFitTheTransport(t *testing.T) {
	cases := map[string]struct {
		sizes []int
		// kept are the files that keep their bytes.
		kept []string
		note string
	}{
		// A little over: the smallest file that makes the room goes.
		"one small file makes the room": {sizes: []int{300 << 10, 310 << 10, 120 << 10},
			kept: []string{"noise-0.bin", "noise-1.bin"}, note: "1 file attached by the run was left"},
		// No one file makes the room: the largest goes, then the smallest
		// that covers the rest.
		"no one file does": {sizes: []int{400 << 10, 420 << 10, 410 << 10},
			kept: []string{"noise-2.bin"}, note: "2 files attached by the run were left"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := &Result{Format: ResultFormat, Tasks: []TaskChange{{After: &pm.Task{ID: 1, Title: "x", Status: pm.TaskDone}}},
				Steps: []state.StepResult{{Step: 0, Output: "the transcript"}}}
			for i, n := range c.sizes {
				data := randomBytes(t, n)
				cost, _ := carryCost(data, math.MaxInt64)
				r.Attachments = append(r.Attachments, Attachment{TaskID: 1, Name: fmt.Sprintf("noise-%d.bin", i),
					Data: data, Size: int64(len(data)), SHA256: hexSHA(data), cost: cost})
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
			if len(got.Attachments) != len(c.sizes) || len(got.Steps) != 1 || got.Steps[0].Output != "the transcript" {
				t.Fatalf("decoded %d attachments, steps %+v", len(got.Attachments), got.Steps)
			}
			var kept []string
			for _, a := range got.Attachments {
				switch {
				case len(a.Data) > 0 && a.Left == "":
					kept = append(kept, a.Name)
				case len(a.Data) == 0 && a.Left == leftForRoom:
				default:
					t.Errorf("%s: %d bytes, left %q — carried whole, or left saying why", a.Name, len(a.Data), a.Left)
				}
			}
			if strings.Join(kept, ",") != strings.Join(c.kept, ",") {
				t.Errorf("kept %v, want %v", kept, c.kept)
			}
			if !strings.Contains(strings.Join(got.Omitted, " "), c.note) {
				t.Errorf("omitted = %v, want %q", got.Omitted, c.note)
			}
		})
	}
}

// TestARunsTextFilesComeBackWholeInItsResult is Task 20515's defect: a run on
// an edge device attached thirteen files — logs, Markdown, an SVG, a PNG,
// 726 KiB of them — and its result, which measured them by their own bytes
// against 384 KiB, left four of them in the executor's workspace. Compressed,
// as the frame carries them, they take less than half of it.
func TestARunsTextFilesComeBackWholeInItsResult(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 10, Title: "Compose integration and end-to-end test", Status: pm.TaskPending},
		{ID: 12, Title: "Documentation for the framework", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)
	files := map[string][]byte{
		"reproducibility-double-build.log": logLines(t, 329519),
		"offline-modified-source.log":      hexText(t, 168596),
		"THREAT_MODEL.md":                  logLines(t, 33297),
		"sequence.svg":                     hexText(t, 62993),
		"sequence.png":                     randomBytes(t, 114402),
	}
	var total, cost int64
	for _, data := range files {
		total += int64(len(data))
		c, _ := carryCost(data, math.MaxInt64)
		cost += c
	}
	if total <= attachmentCarryBytes || cost <= attachmentCarryBytes/2 {
		t.Fatalf("the files come to %d bytes, %d compressed; the case needs more than the old 384 KiB, and more "+
			"than half of it compressed", total, cost)
	}
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(10).Status = pm.TaskDone
		st.Plan.TaskByID(12).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"reproducibility-double-build.log", "offline-modified-source.log", "THREAT_MODEL.md"} {
			deviceAttach(t, dir, 10, name, files[name])
		}
		deviceAttach(t, dir, 12, "sequence.png", files["sequence.png"])
		deviceAttach(t, dir, 12, "sequence.svg", files["sequence.svg"])
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Attachments) != len(files) {
		t.Fatalf("the result describes %d files, want %d", len(r.Attachments), len(files))
	}
	for _, a := range r.Attachments {
		if a.Left != "" || !bytes.Equal(a.Data, files[a.Name]) {
			t.Errorf("%s: %d of %d bytes carried, left %q", a.Name, len(a.Data), len(files[a.Name]), a.Left)
		}
	}
	if len(r.Omitted) != 0 {
		t.Errorf("omitted = %v; nothing had to give way", r.Omitted)
	}
	rep, err := Apply(hub, r, Provenance{RunID: "hub-run", ExecutorID: "sgx"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rep.Attached != len(files) || len(rep.LeftBehind) != 0 {
		t.Fatalf("merge: attached %d, left behind %v", rep.Attached, rep.LeftBehind)
	}
	for task, names := range map[int][]string{10: {"THREAT_MODEL.md"}, 12: {"sequence.png", "sequence.svg"}} {
		rows := hubAttachments(t, hub, task)
		for _, name := range names {
			if row, ok := rows[name]; !ok || row.Unavailable != "" || row.Size != int64(len(files[name])) {
				t.Errorf("task %d's %s on the hub: %+v", task, name, row)
			}
		}
	}
}

// TestFilesDoNotCutTheRunsStepOutputMoreThanBefore: the room a result
// always keeps for files is measured by their own bytes, as it was before Task
// 20515, so a run with long step output and many logs keeps its step output
// whole, and carries the logs the frame has room left for besides.
func TestFilesDoNotCutTheRunsStepOutputMoreThanBefore(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Build", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)
	const steps = 24
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		for i := 0; i < steps; i++ {
			st.AddStep(state.StepResult{Task: "Build", Output: string(hexText(t, maxStepOutputBytes))})
		}
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 9; i++ {
			deviceAttach(t, dir, 1, fmt.Sprintf("build-%d.log", i), hexText(t, 200<<10))
			time.Sleep(time.Millisecond)
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Steps) != steps {
		t.Fatalf("the result has %d steps, want %d", len(r.Steps), steps)
	}
	for _, st := range r.Steps {
		if len(st.Output) != maxStepOutputBytes {
			t.Fatalf("step %d's output was cut to %d bytes (omitted %v); files may not cost the run more of it "+
				"than before", st.Step, len(st.Output), r.Omitted)
		}
	}
	carried := 0
	for _, a := range r.Attachments {
		if len(a.Data) > 0 {
			carried++
		} else if !strings.Contains(a.Left, "did not fit in what the run's result") {
			t.Errorf("%s: left %q", a.Name, a.Left)
		}
	}
	// The old room held one of these; the frame has room for one more.
	if carried < 1 || carried == 9 {
		t.Errorf("carried %d of the 9 logs", carried)
	}
}

// TestTooMuchReadOfFilesThatDidNotFitSkipsOnlyWhatCouldNot: once the run's
// result has read its fill of files that did not fit, a file is left unread
// only when it would have to shrink more than files do — a log that fits is
// still read and carried, and a large image is not read at all.
func TestTooMuchReadOfFilesThatDidNotFitSkipsOnlyWhatCouldNot(t *testing.T) {
	isolateHome(t)
	defer func(old int64) { maxWastedCarryBytes = old }(maxWastedCarryBytes)
	maxWastedCarryBytes = 1 << 20
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Images and a log", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)
	logData := logLines(t, 1<<20)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		for i, n := range []int{700 << 10, 700 << 10} {
			deviceAttach(t, dir, 1, fmt.Sprintf("image-%d.png", i), randomBytes(t, n))
			time.Sleep(time.Millisecond)
		}
		deviceAttach(t, dir, 1, "build.log", logData)
		time.Sleep(time.Millisecond)
		deviceAttach(t, dir, 1, "huge.png", randomBytes(t, 6<<20))
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Attachment{}
	for _, a := range r.Attachments {
		got[a.Name] = a
	}
	for _, name := range []string{"image-0.png", "image-1.png"} {
		if a := got[name]; len(a.Data) != 0 || !strings.Contains(a.Left, "did not fit") {
			t.Errorf("%s: %d bytes, left %q", name, len(a.Data), a.Left)
		}
	}
	if a := got["build.log"]; !bytes.Equal(a.Data, logData) {
		t.Errorf("build.log: %d bytes carried, left %q — it fits, and must still be read", len(a.Data), a.Left)
	}
	if a := got["huge.png"]; len(a.Data) != 0 || !strings.Contains(a.Left, "too large for the room") {
		t.Errorf("huge.png: %d bytes, left %q", len(a.Data), a.Left)
	}
}

// TestFilesFillTheFrameAndNoMore: files that do not compress take the room
// the result has for them in the order the run attached them, and one that
// does not fit what is left stays in the executor's workspace, saying so,
// while a later, smaller one still travels.
func TestFilesFillTheFrameAndNoMore(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Screenshots", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)
	sizes := []int{250 << 10, 250 << 10, 250 << 10, 20 << 10}
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		for i, n := range sizes {
			deviceAttach(t, dir, 1, fmt.Sprintf("shot-%d.png", i), randomBytes(t, n))
			time.Sleep(2 * time.Millisecond) // attached in this order
		}
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	if len(data) > executor.MaxProjectResultBytes {
		t.Fatalf("encoded %d bytes, over the ceiling", len(data))
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Attachment{}
	for _, a := range r.Attachments {
		got[a.Name] = a
	}
	for _, name := range []string{"shot-0.png", "shot-1.png", "shot-3.png"} {
		if a := got[name]; len(a.Data) == 0 || a.Left != "" {
			t.Errorf("%s: %d bytes, left %q — it fits", name, len(a.Data), a.Left)
		}
	}
	if a := got["shot-2.png"]; len(a.Data) != 0 || !strings.Contains(a.Left, "did not fit in what the run's result") {
		t.Errorf("shot-2.png: %d bytes, left %q — it does not fit beside the two before it", len(a.Data), a.Left)
	}
}

// TestTheCarryIsBoundedByTheFilesOwnBytes: a file that costs the frame almost
// nothing still counts by its own bytes against attachmentCarryRawBytes, so
// the hub never inflates a result past its ceiling.
func TestTheCarryIsBoundedByTheFilesOwnBytes(t *testing.T) {
	isolateHome(t)
	defer func(old int64) { attachmentCarryRawBytes = old }(attachmentCarryRawBytes)
	attachmentCarryRawBytes = 256 << 10
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Logs", Status: pm.TaskPending},
	}}})
	seed := seedFromHub(t, hub)
	dev := onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		deviceAttach(t, dir, 1, "first.log", bytes.Repeat([]byte("all quiet\n"), (200<<10)/10))
		time.Sleep(2 * time.Millisecond)
		deviceAttach(t, dir, 1, "second.log", bytes.Repeat([]byte("still quiet\n"), (100<<10)/12))
		time.Sleep(2 * time.Millisecond)
		deviceAttach(t, dir, 1, "third.log", []byte("small\n"))
	})
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Attachment{}
	for _, a := range r.Attachments {
		got[a.Name] = a
	}
	if a := got["first.log"]; len(a.Data) == 0 {
		t.Errorf("first.log was left: %q", a.Left)
	}
	if a := got["second.log"]; len(a.Data) != 0 || !strings.Contains(a.Left, "of files a run's result carries") {
		t.Errorf("second.log: %d bytes, left %q — past what is left of the files a result carries", len(a.Data), a.Left)
	}
	if a := got["third.log"]; string(a.Data) != "small\n" {
		t.Errorf("third.log: %q, left %q", a.Data, a.Left)
	}
}

// TestAResultNeverInflatesPastTheHubsCeiling: a document small on the wire and
// huge once inflated — which the hub would refuse whole, the run's outcomes
// with it — gives up its files until it fits.
func TestAResultNeverInflatesPastTheHubsCeiling(t *testing.T) {
	defer func(old int64) { resultInflatedLimit = old }(resultInflatedLimit)
	resultInflatedLimit = 1 << 20
	r := &Result{Format: ResultFormat, Tasks: []TaskChange{{After: &pm.Task{ID: 1, Title: "x", Status: pm.TaskDone}}}}
	for i := 0; i < 2; i++ {
		data := make([]byte, 600<<10)
		r.Attachments = append(r.Attachments, Attachment{TaskID: 1, Name: fmt.Sprintf("zeros-%d.bin", i),
			Data: data, Size: int64(len(data)), SHA256: hexSHA(data)})
	}
	data, err := encodeResult(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := inflateBounded(data, MaxResultInflatedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) > resultInflatedLimit {
		t.Fatalf("the result inflates to %d bytes, past %d", len(raw), resultInflatedLimit)
	}
	got, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("the hub refuses it: %v", err)
	}
	kept := 0
	for _, a := range got.Attachments {
		if len(a.Data) > 0 {
			kept++
		}
	}
	if kept != 1 || len(got.Tasks) != 1 {
		t.Errorf("kept %d files and %d tasks; want one file to give way, and the task", kept, len(got.Tasks))
	}
}

// hexText returns n bytes of hex digits: text that compresses to about half
// its size, as real prose and logs with numbers in them do.
func hexText(t *testing.T, n int) []byte {
	t.Helper()
	return []byte(hexOf(randomBytes(t, (n+1)/2))[:n])
}

// logLines returns n bytes of log text: lines that repeat in shape, not in
// content, as a build log's do.
func logLines(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "2026-11-23T14:%02d:%02d.%06dZ  INFO cargo: Compiling crate-%d v0.%d.%d (step %d of the build)\n",
			(i/60)%60, i%60, (i*7919)%1000000, i%97, i%13, i%7, i)
	}
	return b.Bytes()[:n]
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
