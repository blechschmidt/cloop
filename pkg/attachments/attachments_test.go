package attachments

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// pngHead is the start of a real PNG: enough for content sniffing.
var pngHead = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

// project is a project directory with a plan of tasks 1 and 2, its database
// open, and the path of that database.
func project(t *testing.T) (dir, dbPath string, db *statedb.DB) {
	t.Helper()
	dir = statedbtest.Dir(t)
	dbPath = filepath.Join(dir, ".cloop", "state.db")
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	plan := &pm.Plan{Goal: "g", Tasks: []*pm.Task{{ID: 1, Title: "one"}, {ID: 2, Title: "two"}}}
	if err := db.SaveState(&statedb.State{Goal: "g", Plan: plan}); err != nil {
		t.Fatal(err)
	}
	return dir, dbPath, db
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func refusedNames(rep Report) map[string]string {
	out := map[string]string{}
	for _, r := range rep.Refused {
		out[r.Name] = r.Reason
	}
	return out
}

func TestPrepareOutbox(t *testing.T) {
	dir, dbPath, _ := project(t)
	box, err := PrepareOutbox(dbPath, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, ".cloop", "attachments", "outbox", "7")
	if box != want || !filepath.IsAbs(box) {
		t.Fatalf("outbox = %q, want %q", box, want)
	}
	if info, err := os.Stat(box); err != nil || !info.IsDir() {
		t.Fatalf("outbox not created: %v", err)
	}
	gi, err := os.ReadFile(filepath.Join(dir, ".cloop", "attachments", ".gitignore"))
	if err != nil || !strings.Contains(string(gi), "\n*\n") {
		t.Fatalf("the store's .gitignore = %q, %v; want one that ignores everything", gi, err)
	}
	if _, err := PrepareOutbox(dbPath, 0); err == nil {
		t.Fatal("an outbox for task 0")
	}
	env := Env(7, box)
	if len(env) != 2 || env[0] != EnvOutbox+"="+box || env[1] != EnvTaskID+"=7" {
		t.Fatalf("Env = %q", env)
	}
	if s := PromptSection(7, box); !strings.Contains(s, box) || !strings.Contains(s, "task 7") || !strings.HasPrefix(s, "## ATTACHMENTS\n") {
		t.Fatalf("PromptSection = %q", s)
	}
}

func TestIngestAttachesWhatTheRunLeftAndEmptiesTheOutbox(t *testing.T) {
	dir, dbPath, db := project(t)
	box, err := PrepareOutbox(dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(box, "report.md"), []byte("# Report\nall good\n"))
	write(t, filepath.Join(box, "plots", "loss.png"), append(append([]byte{}, pngHead...), make([]byte, 64)...))
	write(t, filepath.Join(box, "a", "b", "c", "d", "e", "f", "g", "h", "deep.txt"), []byte("too deep"))
	outside := filepath.Join(dir, "secret.txt")
	write(t, outside, []byte("not for the dashboard"))
	if err := os.Symlink(outside, filepath.Join(box, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(box, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Ingest(db, dbPath, 1, IngestOptions{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != 2 {
		t.Fatalf("added %+v, want report.md and plots/loss.png", rep.Added)
	}
	byName := map[string]statedb.AttachmentRow{}
	for _, a := range rep.Added {
		byName[a.Name] = a
	}
	if a := byName["report.md"]; a.MediaType != "text/markdown" || a.RunID != "run-1" ||
		a.Source != statedb.AttachmentSourceRun || a.AddedBy != "agent" || a.Size != 18 {
		t.Errorf("report.md = %+v", a)
	}
	if a := byName["plots/loss.png"]; a.MediaType != "image/png" {
		t.Errorf("plots/loss.png = %+v", a)
	}
	refused := refusedNames(rep)
	for _, name := range []string{"link.txt", "pipe", "a/b/c/d/e/f/g/h/"} {
		if refused[name] == "" {
			t.Errorf("%s was not named as refused: %+v", name, rep.Refused)
		}
	}
	if !strings.Contains(refused["link.txt"], "symbolic link") {
		t.Errorf("the link's reason: %q", refused["link.txt"])
	}
	// Emptied, and left in place for an attempt still running; closing it is
	// the end of the attempt.
	if entries, err := os.ReadDir(box); err != nil || len(entries) != 0 {
		t.Fatalf("the outbox was not emptied: %v, %v", entries, err)
	}
	CloseOutbox(dbPath, 1)
	if _, err := os.Lstat(box); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CloseOutbox left the outbox: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "not for the dashboard" {
		t.Fatal("emptying the outbox touched what a link in it pointed at")
	}

	// The store holds what the rows describe, and the rows are the task's.
	rows, err := db.TaskAttachments(1)
	if err != nil || len(rows) != 2 {
		t.Fatalf("task 1's rows = %+v, %v", rows, err)
	}
	f, info, err := Open(dbPath, byName["report.md"])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil || buf.String() != "# Report\nall good\n" || info.Size() != 18 {
		t.Fatalf("stored bytes = %q, %v", buf.String(), err)
	}
	if s := Summary(1, rep); !strings.Contains(s, "Attached 2 files to task #1") || !strings.Contains(s, "not attached") {
		t.Fatalf("Summary = %q", s)
	}

	// Nothing there: nothing happens.
	again, err := Ingest(db, dbPath, 1, IngestOptions{})
	if err != nil || !again.Empty() {
		t.Fatalf("a second ingest of an emptied outbox: %+v, %v", again, err)
	}
}

func TestIngestRedactsLeasedCredentials(t *testing.T) {
	_, dbPath, db := project(t)
	box, err := PrepareOutbox(dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	secret := "ghp_" + strings.Repeat("Q7", 18)
	write(t, filepath.Join(box, "debug.log"), []byte("token="+secret+"\nok\n"))
	rep, err := Ingest(db, dbPath, 1, IngestOptions{Scrub: redact.New(secret)})
	if err != nil || len(rep.Added) != 1 {
		t.Fatalf("Ingest = %+v, %v", rep, err)
	}
	data, err := os.ReadFile(filepath.Join(StoreDir(dbPath), rep.Added[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("a leased credential reached the store: %q", data)
	}
	if rep.Added[0].Size != int64(len(data)) {
		t.Fatalf("recorded size %d, stored %d: the row must describe what was stored", rep.Added[0].Size, len(data))
	}
}

func TestIngestRespectsTheLimits(t *testing.T) {
	_, dbPath, db := project(t)
	// A project already at its limit, through another task.
	if err := db.AddTaskAttachment(statedb.AttachmentRow{ID: strings.Repeat("a", 32), TaskID: 2, Name: "huge",
		Size: MaxProjectBytes}); err != nil {
		t.Fatal(err)
	}
	box, err := PrepareOutbox(dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(box, "small.txt"), []byte("x"))
	rep, err := Ingest(db, dbPath, 1, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != 0 || !strings.Contains(refusedNames(rep)["small.txt"], "project") {
		t.Fatalf("a file past the project's limit: %+v", rep)
	}

	cases := []struct {
		u    statedb.AttachmentUsage
		size int64
		want string
	}{
		{statedb.AttachmentUsage{}, MaxFileBytes + 1, "a file may be"},
		{statedb.AttachmentUsage{TaskFiles: MaxTaskFiles}, 1, "most a task may have"},
		{statedb.AttachmentUsage{TaskBytes: MaxTaskBytes}, 1, "a task may hold"},
		{statedb.AttachmentUsage{ProjectBytes: MaxProjectBytes}, 1, "a project may hold"},
		{statedb.AttachmentUsage{}, MaxFileBytes, ""},
	}
	for _, c := range cases {
		if got := Room(c.u, c.size); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("Room(%+v, %d) = %q, want one mentioning %q", c.u, c.size, got, c.want)
		}
	}
}

func TestIngestRefusesAnOutboxThatIsALink(t *testing.T) {
	dir, dbPath, db := project(t)
	elsewhere := filepath.Join(dir, "elsewhere")
	write(t, filepath.Join(elsewhere, "x.txt"), []byte("x"))
	if err := os.MkdirAll(filepath.Join(StoreDir(dbPath), OutboxDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, OutboxDir(dbPath, 1)); err != nil {
		t.Fatal(err)
	}
	rep, err := Ingest(db, dbPath, 1, IngestOptions{})
	if err != nil || len(rep.Added) != 0 || len(rep.Refused) != 1 {
		t.Fatalf("Ingest through a linked outbox = %+v, %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "x.txt")); err != nil {
		t.Fatal("removing the linked outbox removed what it pointed at")
	}
}

func TestPutRefusesWhatIsTooLarge(t *testing.T) {
	_, dbPath, db := project(t)
	_, err := Put(db, dbPath, 1, Meta{Name: "big.bin"}, bytes.NewReader(make([]byte, 11)), 10, nil)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Put of 11 bytes under a 10-byte limit: %v, want ErrTooLarge", err)
	}
	entries, _ := os.ReadDir(StoreDir(dbPath))
	for _, e := range entries {
		if e.Name() != ".gitignore" {
			t.Errorf("a refused file left %q in the store", e.Name())
		}
	}
	if _, err := Put(db, dbPath, 9, Meta{Name: "x"}, strings.NewReader("x"), 10, nil); !errors.Is(err, statedb.ErrTaskNotFound) {
		t.Fatalf("Put for a task the plan does not have: %v", err)
	}
	if entries, _ := os.ReadDir(StoreDir(dbPath)); len(entries) != 1 {
		t.Fatalf("a file whose row was refused stayed in the store: %v", entries)
	}
}

func TestAddAttachesAFileByHand(t *testing.T) {
	dir, dbPath, db := project(t)
	src := filepath.Join(dir, "notes.txt")
	write(t, src, []byte("by hand"))
	row, err := Add(db, dbPath, 2, src, Meta{Source: statedb.AttachmentSourceCLI, Note: "from the bench", AddedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if row.Name != "notes.txt" || row.Note != "from the bench" || row.Source != statedb.AttachmentSourceCLI || row.MediaType != "text/plain" {
		t.Fatalf("row = %+v", row)
	}
	if _, err := Add(db, dbPath, 2, dir, Meta{}); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("attaching a directory: %v", err)
	}
}

// TestOpenServesOnlyTheStoredFile: what the hub reads to serve a download.
// The store is in a workload's reach, so each way it could be made to read
// something else is refused.
func TestOpenServesOnlyTheStoredFile(t *testing.T) {
	dir, dbPath, db := project(t)
	row, err := Put(db, dbPath, 1, Meta{Name: "a.txt"}, strings.NewReader("hello"), MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := Open(dbPath, row)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	store := StoreDir(dbPath)
	stored := filepath.Join(store, row.ID)
	replace := func(t *testing.T, fn func()) {
		t.Helper()
		if err := os.Remove(stored); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		fn()
	}

	t.Run("a link to a file in the project", func(t *testing.T) {
		write(t, filepath.Join(dir, "inside.txt"), []byte("hello"))
		replace(t, func() { _ = os.Symlink(filepath.Join(dir, "inside.txt"), stored) })
		if _, _, err := Open(dbPath, row); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("Open = %v, want ErrNotRegular", err)
		}
	})
	t.Run("a link out of the project", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "outside")
		write(t, out, []byte("hello"))
		replace(t, func() { _ = os.Symlink(out, stored) })
		if _, _, err := Open(dbPath, row); err == nil {
			t.Fatal("Open followed a link out of the project")
		}
	})
	t.Run("a FIFO", func(t *testing.T) {
		replace(t, func() { _ = syscall.Mkfifo(stored, 0o644) })
		done := make(chan error, 1)
		go func() { _, _, err := Open(dbPath, row); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Fatalf("Open = %v, want ErrNotRegular", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Open blocked on a FIFO")
		}
	})
	t.Run("a file of another size", func(t *testing.T) {
		replace(t, func() { write(t, stored, []byte("hello, world")) })
		if _, _, err := Open(dbPath, row); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Open = %v, want ErrUnavailable", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		replace(t, func() {})
		if _, _, err := Open(dbPath, row); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Open = %v, want ErrUnavailable", err)
		}
	})
	t.Run("a store replaced by a link", func(t *testing.T) {
		other := t.TempDir()
		write(t, filepath.Join(other, row.ID), []byte("hello"))
		if err := os.RemoveAll(store); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, store); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(dbPath, row); err == nil {
			t.Fatal("Open followed a store that is a link out of the project")
		}
	})
	t.Run("unavailable and malformed rows", func(t *testing.T) {
		gone := row
		gone.Unavailable = "left on the device"
		if _, _, err := Open(dbPath, gone); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Open of an unavailable attachment = %v", err)
		}
		bad := row
		bad.ID = "../state.db"
		if _, _, err := Open(dbPath, bad); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Open of a row naming a path = %v", err)
		}
	})
}

func TestSweepRemovesOnlyWhatNoRowNames(t *testing.T) {
	_, dbPath, db := project(t)
	row, err := Put(db, dbPath, 1, Meta{Name: "kept.txt"}, strings.NewReader("k"), MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := StoreDir(dbPath)
	old := time.Now().Add(-2 * time.Hour)
	orphan := filepath.Join(store, strings.Repeat("b", 32))
	young := filepath.Join(store, strings.Repeat("c", 32))
	tmp := filepath.Join(store, "."+strings.Repeat("d", 32)+".tmp")
	stray := filepath.Join(store, "notes.txt")
	for _, p := range []string{orphan, young, tmp, stray} {
		write(t, p, []byte("x"))
	}
	for _, p := range []string{orphan, tmp, stray, filepath.Join(store, row.ID)} {
		_ = os.Chtimes(p, old, old)
	}
	if _, err := PrepareOutbox(dbPath, 1); err != nil {
		t.Fatal(err)
	}
	n, err := Sweep(db, dbPath, time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("Sweep = %d, %v; want the orphan and the abandoned copy", n, err)
	}
	for p, want := range map[string]bool{orphan: false, tmp: false, young: true, stray: true,
		filepath.Join(store, row.ID): true, filepath.Join(store, ".gitignore"): true, OutboxDir(dbPath, 1): true} {
		if _, err := os.Lstat(p); (err == nil) != want {
			t.Errorf("%s present = %v, want %v", filepath.Base(p), err == nil, want)
		}
	}
}

func TestDetectAndInlineTypes(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><script>alert(1)</script></html>")
	cases := []struct {
		name      string
		head      []byte
		detected  string
		inline    string
		previewOK bool
	}{
		{"chart.png", pngHead, "image/png", "image/png", true},
		{"chart.png", html, "application/octet-stream", "", false},
		{"report.html", html, "text/html", "", false},
		{"logo.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "image/svg+xml", "", false},
		{"notes.txt", []byte("plain words\n"), "text/plain", "text/plain; charset=utf-8", true},
		{"data.csv", []byte("a,b\n1,2\n"), "text/csv", "text/plain; charset=utf-8", true},
		{"data.json", []byte(`{"a":1}`), "application/json", "text/plain; charset=utf-8", true},
		{"notes.txt", []byte("\x00\x01binary"), "application/octet-stream", "", false},
		{"noext", html, "application/octet-stream", "", false},
		{"noext", []byte("just text"), "text/plain", "text/plain; charset=utf-8", true},
		{"paper.pdf", []byte("%PDF-1.7\n"), "application/pdf", "", false},
	}
	for _, c := range cases {
		got := DetectType(c.name, c.head)
		if got != c.detected {
			t.Errorf("DetectType(%q) = %q, want %q", c.name, got, c.detected)
		}
		inline, ok := InlineType(got, c.head)
		if inline != c.inline || ok != (c.inline != "") {
			t.Errorf("InlineType(%q for %q) = %q, %v; want %q", got, c.name, inline, ok, c.inline)
		}
		if Previewable(got) != c.previewOK {
			t.Errorf("Previewable(%q) = %v, want %v", got, !c.previewOK, c.previewOK)
		}
	}
	// A recorded type is only a claim: the bytes in the store decide.
	if _, ok := InlineType("image/png", html); ok {
		t.Fatal("HTML stored where a PNG was recorded would be served inline")
	}
	if _, ok := InlineType("text/plain", []byte("\x00")); ok {
		t.Fatal("binary stored where text was recorded would be served inline")
	}
}

func TestCleanName(t *testing.T) {
	cases := map[string]string{
		"report.html":                     "report.html",
		"./plots/../loss.png":             "plots/loss.png",
		"../../etc/passwd":                "etc/passwd",
		"/abs/path.txt":                   "abs/path.txt",
		"win\\style\\name.txt":            "win/style/name.txt",
		"bell\a\x1b[31mred.txt":           "bell[31mred.txt",
		"evil\u202Etxt.exe":               "eviltxt.exe",
		"  spaced  /  out .txt ":          "spaced/out .txt",
		"":                                "file",
		"..":                              "file",
		"bad\xffbyte.txt":                 "bad\uFFFDbyte.txt",
		strings.Repeat("x", 300) + ".png": strings.Repeat("x", statedb.MaxAttachmentNameBytes-4) + ".png",
	}
	for in, want := range cases {
		if got := CleanName(in); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := BaseName("plots/loss.png"); got != "loss.png" {
		t.Errorf("BaseName = %q", got)
	}
}

// TestIngestKeepsWhatAPassingFailureStopped: a file the store could not take
// for a reason that may pass — the database busy, the disk full — stays in the
// outbox and is attached by the next ingest, rather than being thrown away
// with the refused ones.
func TestIngestKeepsWhatAPassingFailureStopped(t *testing.T) {
	_, dbPath, db := project(t)
	box, err := PrepareOutbox(dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(box, "keep", "results.csv"), []byte("a,b\n"))
	if err := os.Symlink("/etc/passwd", filepath.Join(box, "link")); err != nil {
		t.Fatal(err)
	}
	real := recordRow
	recordRow = func(*statedb.DB, statedb.AttachmentRow) error { return errors.New("database is locked") }
	rep, err := Ingest(db, dbPath, 1, IngestOptions{})
	recordRow = real
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != 0 || !strings.Contains(refusedNames(rep)["keep/results.csv"], "tried again") {
		t.Fatalf("a passing failure: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(box, "keep", "results.csv")); err != nil {
		t.Fatalf("the file a passing failure stopped was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(box, "link")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused link was kept with it")
	}
	if entries, _ := os.ReadDir(StoreDir(dbPath)); len(entries) != 2 { // .gitignore and outbox
		t.Fatalf("the failed attach left a file in the store: %v", entries)
	}
	again, err := Ingest(db, dbPath, 1, IngestOptions{})
	if err != nil || len(again.Added) != 1 || again.Added[0].Name != "keep/results.csv" {
		t.Fatalf("the next ingest: %+v, %v", again, err)
	}
}

// TestTheStoreIsReachedOnlyThroughItsDirectory: on a shared-filesystem
// executor the workload can replace the store, or the outbox, with a link.
// Nothing then writes, reads or removes through it.
func TestTheStoreIsReachedOnlyThroughItsDirectory(t *testing.T) {
	dir, dbPath, db := project(t)
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	store := StoreDir(dbPath)
	if err := os.Symlink(elsewhere, store); err != nil {
		t.Fatal(err)
	}
	if _, err := Put(db, dbPath, 1, Meta{Name: "x.txt"}, strings.NewReader("x"), MaxFileBytes, nil); err == nil {
		t.Error("Put wrote into a store that is a link")
	}
	if _, err := PrepareOutbox(dbPath, 1); err == nil {
		t.Error("PrepareOutbox made an outbox through a store that is a link")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("something was written where the link pointed: %v", entries)
	}
	if n, err := Sweep(db, dbPath, 0); err == nil || n != 0 {
		t.Errorf("Sweep through a linked store: %d, %v", n, err)
	}

	// A link out of the project, as the store, is not even opened.
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "inside")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../inside", store); err != nil {
		t.Fatal(err)
	}
	if _, err := Put(db, dbPath, 1, Meta{Name: "y.txt"}, strings.NewReader("y"), MaxFileBytes, nil); err == nil {
		t.Error("Put wrote through a store that is a link inside the project")
	}
}

func TestOutboxesAndTheirRemoval(t *testing.T) {
	_, dbPath, _ := project(t)
	for _, id := range []int{2, 7} {
		if _, err := PrepareOutbox(dbPath, id); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(OutboxDir(dbPath, 7), "a.txt"), []byte("a"))
	if err := os.MkdirAll(filepath.Join(StoreDir(dbPath), OutboxDirName, "not-a-task"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Outboxes(dbPath)
	if len(got) != 2 || got[0]+got[1] != 9 {
		t.Fatalf("Outboxes = %v, want 2 and 7", got)
	}
	CloseOutbox(dbPath, 7) // not empty: kept
	CloseOutbox(dbPath, 2) // empty: gone
	if _, err := os.Stat(OutboxDir(dbPath, 7)); err != nil {
		t.Error("CloseOutbox removed an outbox that still held a file")
	}
	if _, err := os.Stat(OutboxDir(dbPath, 2)); !errors.Is(err, os.ErrNotExist) {
		t.Error("CloseOutbox left an empty outbox")
	}
	RemoveOutbox(dbPath, 7)
	if _, err := os.Stat(OutboxDir(dbPath, 7)); !errors.Is(err, os.ErrNotExist) {
		t.Error("RemoveOutbox left the outbox")
	}
}
