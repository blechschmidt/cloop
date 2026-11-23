package attachments

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Task 20513: what a seeded run sends the hub while it runs is held under the
// run, checked as it arrives, attached under the run's own id, and swept only
// once its run is over.

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func heldFile(id string, task int, title, name string, data []byte) HeldFile {
	return HeldFile{ID: id, Task: task, TitleSHA256: digest([]byte(title)), Name: name, Size: int64(len(data)),
		SHA256: digest(data), CreatedAt: time.Now().Add(-time.Minute)}
}

const runA = "run-a"

func TestHoldChecksWhatArrivesAndKeepsItForTheRun(t *testing.T) {
	_, dbPath, db := project(t)
	data := bytes.Repeat([]byte("report line\n"), 50_000) // 600 KB: more than a result carries
	f := heldFile(strings.Repeat("a", 32), 1, "one", "out/report.txt", data)

	held, err := Hold(dbPath, runA, f, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if held.ReceivedAt.IsZero() || held.Name != "out/report.txt" {
		t.Fatalf("held = %+v", held)
	}
	list, err := Held(dbPath, runA)
	if err != nil || len(list) != 1 || list[0].ID != f.ID || list[0].Size != f.Size || list[0].SHA256 != f.SHA256 {
		t.Fatalf("Held = %+v, %v", list, err)
	}
	if other, _ := Held(dbPath, "run-b"); len(other) != 0 {
		t.Fatalf("another run sees this run's files: %+v", other)
	}
	if got, ok := HeldNow(dbPath, runA, f.ID); !ok || got.SHA256 != f.SHA256 {
		t.Fatalf("HeldNow = %+v, %v", got, ok)
	}
	if n := HeldCount(dbPath, runA); n != 1 {
		t.Fatalf("HeldCount = %d", n)
	}
	if n := HeldBytes(dbPath); n != f.Size {
		t.Fatalf("HeldBytes = %d, want %d", n, f.Size)
	}

	// Attached to the hub's task under the run's id, scrubbed on the way.
	secret := "s3cr3t-value-of-the-lease"
	withSecret := append([]byte("token="+secret+"\n"), data...)
	g := heldFile(strings.Repeat("b", 32), 1, "one", "leak.txt", withSecret)
	if _, err := Hold(dbPath, runA, g, bytes.NewReader(withSecret)); err != nil {
		t.Fatal(err)
	}
	row, err := AttachHeld(db, dbPath, runA, g, 1, Meta{Name: g.Name, Source: statedb.AttachmentSourceRun,
		RunID: runA, AddedBy: "agent"}, redact.New(secret))
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != g.ID || row.RunID != runA || row.TaskID != 1 {
		t.Fatalf("row = %+v", row)
	}
	fh, _, err := Open(dbPath, row)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := readAll(fh)
	if bytes.Contains(stored, []byte(secret)) || !bytes.Contains(stored, []byte("report line")) {
		t.Fatalf("stored bytes were not scrubbed of the run's credential (%d bytes)", len(stored))
	}
	// The held copy stays until the caller is sure of the attachment.
	if _, ok := HeldNow(dbPath, runA, g.ID); !ok {
		t.Fatal("the held copy went before the caller let go of it")
	}
	RemoveHeld(dbPath, runA, g.ID)
	if _, ok := HeldNow(dbPath, runA, g.ID); ok {
		t.Fatal("RemoveHeld kept the held copy")
	}

	RemoveHeldRun(dbPath, runA)
	if list, _ := Held(dbPath, runA); len(list) != 0 {
		t.Fatalf("RemoveHeldRun left %+v", list)
	}
}

func readAll(f *os.File) ([]byte, error) {
	defer f.Close()
	var b bytes.Buffer
	_, err := b.ReadFrom(f)
	return b.Bytes(), err
}

func TestHoldRefusesWhatDoesNotCheckOut(t *testing.T) {
	_, dbPath, _ := project(t)
	data := []byte("the real bytes")
	for _, tc := range []struct {
		name string
		f    HeldFile
		body []byte
		want error
	}{
		{"short body", heldFile(strings.Repeat("c", 32), 1, "one", "a.txt", data), data[:5], ErrUnavailable},
		{"long body", heldFile(strings.Repeat("c", 32), 1, "one", "a.txt", data), append(data, 'x'), ErrUnavailable},
		{"other bytes", heldFile(strings.Repeat("c", 32), 1, "one", "a.txt", data), []byte("the fake bytes"), ErrUnavailable},
		{"over the limit", HeldFile{ID: strings.Repeat("c", 32), Task: 1, TitleSHA256: digest(nil), Name: "big",
			Size: MaxFileBytes + 1, SHA256: digest(nil)}, nil, ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Hold(dbPath, runA, tc.f, bytes.NewReader(tc.body)); !errors.Is(err, tc.want) {
				t.Fatalf("Hold = %v, want %v", err, tc.want)
			}
			if list, _ := Held(dbPath, runA); len(list) != 0 {
				t.Fatalf("a refused file was kept: %+v", list)
			}
			if n := HeldBytes(dbPath); n != 0 {
				t.Fatalf("a refused file left %d bytes", n)
			}
		})
	}
	for _, bad := range []HeldFile{
		{ID: "not-an-id", Task: 1, TitleSHA256: digest(nil), Name: "x", SHA256: digest(nil)},
		{ID: strings.Repeat("d", 32), Task: 0, TitleSHA256: digest(nil), Name: "x", SHA256: digest(nil)},
		{ID: strings.Repeat("d", 32), Task: 1, TitleSHA256: "nope", Name: "x", SHA256: digest(nil)},
		{ID: strings.Repeat("d", 32), Task: 1, TitleSHA256: digest(nil), Name: "x", SHA256: "nope"},
	} {
		if _, err := Hold(dbPath, runA, bad, bytes.NewReader(nil)); err == nil {
			t.Errorf("Hold accepted %+v", bad)
		}
	}
	if _, err := Hold(dbPath, "", heldFile(strings.Repeat("e", 32), 1, "one", "a", data), bytes.NewReader(data)); err == nil {
		t.Error("Hold kept a file for no run")
	}
}

// A link where the hold, a run's directory or a held file should be is not
// followed: the hub is often root, and the store is in a workload's reach on
// a shared-filesystem executor.
func TestHeldFilesAreNotReachedThroughLinks(t *testing.T) {
	dir, dbPath, _ := project(t)
	outside := t.TempDir()
	data := []byte("held bytes")
	f := heldFile(strings.Repeat("f", 32), 1, "one", "a.txt", data)
	store := StoreDir(dbPath)
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store, HeldDirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Hold(dbPath, runA, f, bytes.NewReader(data)); err == nil {
		t.Fatal("Hold wrote through a held directory that is a link")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("Hold wrote outside the store: %v", entries)
	}
	if err := os.Remove(filepath.Join(store, HeldDirName)); err != nil {
		t.Fatal(err)
	}

	// A held file swapped for a link to a file outside the store is not read.
	if _, err := Hold(dbPath, runA, f, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "victim")
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatal(err)
	}
	heldPath := filepath.Join(store, HeldDirName, RunKey(runA), f.ID)
	if err := os.Remove(heldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, heldPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHeld(dbPath, runA, f); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("OpenHeld through a link = %v, want ErrNotRegular", err)
	}
	if list, _ := Held(dbPath, runA); len(list) != 0 {
		t.Fatalf("a held file that is a link is listed: %+v", list)
	}
	_ = dir
}

// An attach under an id the caller chose never touches what already holds the
// id: not another attachment's file, not its row.
func TestPutUnderAChosenIDNeverReplacesAnother(t *testing.T) {
	_, dbPath, db := project(t)
	first, err := Put(db, dbPath, 1, Meta{Name: "first.txt", Source: statedb.AttachmentSourceCLI}, strings.NewReader("first"), MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The row's id, on the same task and on another.
	for _, task := range []int{1, 2} {
		_, err := Put(db, dbPath, task, Meta{ID: first.ID, Name: "evil.txt", Source: statedb.AttachmentSourceRun},
			strings.NewReader("replacement"), MaxFileBytes, nil)
		if !errors.Is(err, ErrExists) {
			t.Fatalf("task %d: Put under an existing id = %v, want ErrExists", task, err)
		}
	}
	f, _, err := Open(dbPath, first)
	if err != nil {
		t.Fatalf("the first attachment's file is gone: %v", err)
	}
	if got, _ := readAll(f); string(got) != "first" {
		t.Fatalf("the first attachment's bytes became %q", got)
	}

	// A file in the store no row names yet (an attach in flight elsewhere).
	stray := strings.Repeat("9", 32)
	if err := os.WriteFile(filepath.Join(StoreDir(dbPath), stray), []byte("in flight"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Put(db, dbPath, 1, Meta{ID: stray, Name: "x"}, strings.NewReader("mine"), MaxFileBytes, nil); !errors.Is(err, ErrExists) {
		t.Fatalf("Put over a file in the store = %v, want ErrExists", err)
	}
	if got, _ := os.ReadFile(filepath.Join(StoreDir(dbPath), stray)); string(got) != "in flight" {
		t.Fatalf("the file in flight became %q", got)
	}

	// A fresh chosen id is recorded under that id.
	mine := strings.Repeat("7", 32)
	row, err := Put(db, dbPath, 2, Meta{ID: mine, Name: "mine.txt"}, strings.NewReader("mine"), MaxFileBytes, nil)
	if err != nil || row.ID != mine {
		t.Fatalf("Put under a fresh id = %+v, %v", row, err)
	}
	if _, err := Put(db, dbPath, 1, Meta{ID: "UPPER" + strings.Repeat("0", 27), Name: "x"}, strings.NewReader("x"), MaxFileBytes, nil); err == nil {
		t.Fatal("Put accepted an id that is not an attachment's")
	}
	// Record takes a chosen id too.
	left := strings.Repeat("6", 32)
	if r, err := Record(db, 1, Meta{ID: left, Name: "left.bin"}, 10, "", "left on the device"); err != nil || r.ID != left {
		t.Fatalf("Record under a chosen id = %+v, %v", r, err)
	}
	if _, err := Record(db, 1, Meta{ID: left, Name: "again.bin"}, 10, "", "x"); !errors.Is(err, statedb.ErrAttachmentExists) {
		t.Fatalf("Record under a recorded id = %v, want ErrAttachmentExists", err)
	}
}

func TestSweepHeldSparesRunsStillGoing(t *testing.T) {
	_, dbPath, _ := project(t)
	data := []byte("x")
	for _, run := range []string{"live-old", "dead-old", "dead-new"} {
		if _, err := Hold(dbPath, run, heldFile(strings.Repeat("a", 32), 1, "one", "a", data), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, run := range []string{"live-old", "dead-old"} {
		dir := filepath.Join(StoreDir(dbPath), HeldDirName, RunKey(run))
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.Chtimes(filepath.Join(dir, e.Name()), old, old)
		}
		_ = os.Chtimes(dir, old, old)
	}
	live := map[string]bool{RunKey("live-old"): true}
	if n := SweepHeld(dbPath, live, 24*time.Hour); n != 1 {
		t.Fatalf("SweepHeld removed %d runs, want 1", n)
	}
	for run, want := range map[string]int{"live-old": 1, "dead-old": 0, "dead-new": 1} {
		if got, _ := Held(dbPath, run); len(got) != want {
			t.Errorf("%s: %d held, want %d", run, len(got), want)
		}
	}
}

func TestSentMarks(t *testing.T) {
	_, dbPath, _ := project(t)
	id := strings.Repeat("a", 32)
	if WasSent(dbPath, id) {
		t.Fatal("unmarked file reads as sent")
	}
	if err := MarkSent(dbPath, id); err != nil {
		t.Fatal(err)
	}
	if err := MarkSent(dbPath, id); err != nil {
		t.Fatalf("marking twice: %v", err)
	}
	if !WasSent(dbPath, id) {
		t.Fatal("marked file does not read as sent")
	}
	if err := MarkSent(dbPath, "../../etc/passwd"); err == nil {
		t.Fatal("MarkSent took a path for an id")
	}
	// A link is not a mark.
	other := strings.Repeat("b", 32)
	if err := os.Symlink("/etc/hostname", filepath.Join(StoreDir(dbPath), SentDirName, other)); err != nil {
		t.Fatal(err)
	}
	if WasSent(dbPath, other) {
		t.Fatal("a link reads as a sent mark")
	}
	// The store's sweep leaves the marks alone: they are not attachments.
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Sweep(db, dbPath, 0); err != nil {
		t.Fatal(err)
	}
	if !WasSent(dbPath, id) {
		t.Fatal("the sweep removed a sent mark")
	}
}
