package attachments

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Task 20511: the files a person attaches to a task for its agent are copied
// into the task's inbox at the start of every attempt.

// attachInput attaches data to task as an input file, as an upload does.
func attachInput(t *testing.T, db *statedb.DB, dbPath string, task int, name, note string, data []byte) statedb.AttachmentRow {
	t.Helper()
	row, err := Put(db, dbPath, task, Meta{Name: name, Note: note, Source: statedb.AttachmentSourceUpload,
		Role: statedb.AttachmentRoleInput, AddedBy: "ada@example.com", CreatedAt: time.Now()},
		strings.NewReader(string(data)), MaxFileBytes, nil)
	if err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	return row
}

func TestPrepareInboxCopiesTheTasksInputFiles(t *testing.T) {
	dir, dbPath, db := project(t)
	attachInput(t, db, dbPath, 1, "spec.md", "The API to build", []byte("# Spec\nGET /hello\n"))
	attachInput(t, db, dbPath, 1, "data/rows.csv", "", []byte("a,b\n1,2\n"))
	attachInput(t, db, dbPath, 1, "ROWS.csv", "", []byte("c,d\n3,4\n"))
	attachInput(t, db, dbPath, 2, "other-task.txt", "", []byte("not task 1's"))
	// A result of task 1 is not one of its inputs.
	if _, err := Put(db, dbPath, 1, Meta{Name: "report.txt", Source: statedb.AttachmentSourceRun},
		strings.NewReader("a run made this"), MaxFileBytes, nil); err != nil {
		t.Fatal(err)
	}

	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1, Title: "one"}, LocalInputs(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, ".cloop", "attachments", "inbox", "1")
	if box == nil || box.Dir != want {
		t.Fatalf("inbox = %+v, want one at %s", box, want)
	}
	if box.Placed() != 3 || len(box.Files) != 3 {
		t.Fatalf("placed %d of %d files, want 3 of 3: %+v", box.Placed(), len(box.Files), box.Files)
	}
	entries, err := os.ReadDir(box.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// Each under its own name, without the directories it was attached
	// under, and a name two files share told apart whatever its case.
	if strings.Join(names, ",") != "rows (2).csv,rows.csv,spec.md" && strings.Join(names, ",") != "ROWS (2).csv,rows.csv,spec.md" {
		t.Fatalf("the inbox holds %v", names)
	}
	data, err := os.ReadFile(filepath.Join(box.Dir, "spec.md"))
	if err != nil || string(data) != "# Spec\nGET /hello\n" {
		t.Fatalf("spec.md in the inbox = %q, %v", data, err)
	}
	info, err := os.Stat(filepath.Join(box.Dir, "spec.md"))
	if err != nil || info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("the copy is writable (%v, %v): it is a copy for reading", info.Mode(), err)
	}
	if env := InboxEnv(box); len(env) != 1 || env[0] != EnvInbox+"="+box.Dir {
		t.Fatalf("InboxEnv = %q", env)
	}

	section := InboxPromptSection(box)
	for _, wantText := range []string{"## INPUT FILES", "attached 3 files", box.Dir, "$" + EnvInbox,
		"- spec.md (", "text/markdown", `"The API to build"`, "read-only copies"} {
		if !strings.Contains(section, wantText) {
			t.Errorf("the prompt section does not say %q:\n%s", wantText, section)
		}
	}
	if strings.Contains(section, "report.txt") || strings.Contains(section, "other-task.txt") {
		t.Fatalf("the prompt section names a file that is not an input of task 1:\n%s", section)
	}

	// The attempt is over: its copies go, and the store keeps the files.
	CloseInbox(dbPath, 1)
	if _, err := os.Lstat(box.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the inbox outlived its attempt: %v", err)
	}
	if rows, _ := db.TaskInputs(1); len(rows) != 3 {
		t.Fatalf("closing the inbox touched the stored input files: %d left", len(rows))
	}
}

func TestATaskWithoutInputFilesGetsNoInbox(t *testing.T) {
	dir, dbPath, _ := project(t)
	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 2, Title: "two"}, LocalInputs(dbPath))
	if err != nil || box != nil {
		t.Fatalf("PrepareInbox = %+v, %v; want no inbox", box, err)
	}
	if InboxPromptSection(box) != "" || InboxEnv(box) != nil {
		t.Fatal("an attempt without input files is told about some")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".cloop", "attachments", "inbox", "2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty inbox was made: %v", err)
	}
}

func TestEveryAttemptGetsFreshCopies(t *testing.T) {
	_, dbPath, db := project(t)
	attachInput(t, db, dbPath, 1, "spec.md", "", []byte("the spec"))
	ref := TaskRef{ID: 1, Title: "one"}
	box, err := PrepareInbox(context.Background(), dbPath, ref, LocalInputs(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	// The agent changes its copy and leaves a file of its own beside it.
	copyPath := filepath.Join(box.Dir, "spec.md")
	if err := os.Chmod(copyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, copyPath, []byte("edited by the agent"))
	write(t, filepath.Join(box.Dir, "scratch.txt"), []byte("left over"))

	box, err = PrepareInbox(context.Background(), dbPath, ref, LocalInputs(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(copyPath); string(data) != "the spec" {
		t.Fatalf("the next attempt's copy = %q, want the file as attached", data)
	}
	if _, err := os.Lstat(filepath.Join(box.Dir, "scratch.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the next attempt was given what the last one left in the inbox")
	}
}

func TestAnInputFileThatIsNotWhatWasAttachedIsNotGiven(t *testing.T) {
	dir, dbPath, db := project(t)
	good := attachInput(t, db, dbPath, 1, "good.txt", "", []byte("fine"))
	bad := attachInput(t, db, dbPath, 1, "bad.txt", "", []byte("original"))
	// Swapped in the store for bytes of the same length: only the digest
	// tells.
	stored := filepath.Join(dir, ".cloop", "attachments", bad.ID)
	if err := os.WriteFile(stored, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1}, LocalInputs(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if box.Placed() != 1 || box.Files[0].File != "good.txt" || box.Files[0].ID != good.ID {
		t.Fatalf("placed %+v, want good.txt only", box.Files)
	}
	if box.Files[1].File != "" || !strings.Contains(box.Files[1].Unavailable, "SHA-256") {
		t.Fatalf("the tampered file = %+v, want it refused for its digest", box.Files[1])
	}
	if _, err := os.Lstat(filepath.Join(box.Dir, "bad.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a copy of the tampered file was left in the inbox")
	}
	if s := InboxPromptSection(box); !strings.Contains(s, "bad.txt is not available to you") {
		t.Fatalf("the agent is not told which file it lacks:\n%s", s)
	}
}

func TestAnInboxSwappedForALinkWritesNothingOutsideTheStore(t *testing.T) {
	dir, dbPath, db := project(t)
	attachInput(t, db, dbPath, 1, "spec.md", "", []byte("the spec"))
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(outside, "keep.txt")
	write(t, keep, []byte("not the inbox's"))
	store := filepath.Join(dir, ".cloop", "attachments")

	// The workload made the task's inbox a link out of the store.
	if err := os.MkdirAll(filepath.Join(store, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store, "inbox", "1")); err != nil {
		t.Fatal(err)
	}
	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1}, LocalInputs(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if box.Placed() != 1 || box.Dir != filepath.Join(store, "inbox", "1") {
		t.Fatalf("inbox = %+v", box)
	}
	if info, err := os.Lstat(box.Dir); err != nil || !info.IsDir() {
		t.Fatalf("the inbox is not a directory of its own: %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Fatalf("the link's target was written: %v", entries)
	}
	if data, _ := os.ReadFile(keep); string(data) != "not the inbox's" {
		t.Fatal("the link's target was changed")
	}

	// And the whole inbox directory a link out of the store: nothing is
	// placed, and the agent is told why.
	CloseInbox(dbPath, 1)
	if err := os.RemoveAll(filepath.Join(store, "inbox")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store, "inbox")); err != nil {
		t.Fatal(err)
	}
	if box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1}, LocalInputs(dbPath)); err == nil {
		t.Fatalf("an inbox was made through a link out of the store: %+v", box)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Fatalf("the link's target was written: %v", entries)
	}
}

// fakeSource is an InputSource the test controls.
type fakeSource struct {
	inputs  []Input
	listErr error
	data    map[string]string
}

func (f fakeSource) Inputs(context.Context, TaskRef) ([]Input, error) { return f.inputs, f.listErr }

func (f fakeSource) Open(_ context.Context, _ TaskRef, in Input) (io.ReadCloser, error) {
	d, ok := f.data[in.ID]
	if !ok {
		return nil, errors.New("gone")
	}
	return io.NopCloser(strings.NewReader(d)), nil
}

func hexID(c byte) string { return strings.Repeat(string(c), 32) }

func TestAnInboxThatCouldNotBeListedSaysSo(t *testing.T) {
	_, dbPath, _ := project(t)
	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1},
		fakeSource{listErr: errors.New("asking the hub for them failed: connection refused")})
	if err != nil {
		t.Fatal(err)
	}
	s := InboxPromptSection(box)
	if !strings.Contains(s, "could not be fetched") || !strings.Contains(s, "connection refused") ||
		!strings.Contains(s, "instead of guessing") {
		t.Fatalf("the prompt section = %q", s)
	}
	if InboxEnv(box) != nil {
		t.Fatal("an attempt with no inbox was given its variable")
	}
}

func TestAnInboxIsBoundedByWhatAnAttachCouldHaveMade(t *testing.T) {
	_, dbPath, _ := project(t)
	src := fakeSource{data: map[string]string{hexID('a'): "short", hexID('b'): "fine"}, inputs: []Input{
		{ID: "../../etc/passwd", Name: "x", Size: 1},               // not an id: skipped
		{ID: hexID('a'), Name: "lies.txt", Size: 100},              // shorter than it says
		{ID: hexID('c'), Name: "huge.bin", Size: MaxFileBytes + 1}, // over the file limit
		{ID: hexID('b'), Name: "../../../escape.txt", Size: 4},     // a path for a name
		{ID: hexID('d'), Name: "missing.txt", Size: 3, Missing: "on the device"},
	}}
	box, err := PrepareInbox(context.Background(), dbPath, TaskRef{ID: 1}, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(box.Files) != 4 || box.Placed() != 1 {
		t.Fatalf("files = %+v", box.Files)
	}
	if box.Files[2].File != "escape.txt" {
		t.Fatalf("a name with a path became %q, want escape.txt in the inbox", box.Files[2].File)
	}
	for i, wantText := range map[int]string{0: "not the file that was attached", 1: "over the", 3: "on the device"} {
		if !strings.Contains(box.Files[i].Unavailable, wantText) {
			t.Errorf("file %d unavailable = %q, want %q", i, box.Files[i].Unavailable, wantText)
		}
	}
}

func TestInlineInputsGiveATextAgentTheText(t *testing.T) {
	src := fakeSource{
		data: map[string]string{
			hexID('a'): "first line\n```\nnot the end of the block\n```\n",
			hexID('b'): "\x89PNG...",
			hexID('c'): strings.Repeat("x", MaxInlineInputBytes+10),
			hexID('d'): "after the budget",
		},
		inputs: []Input{
			{ID: hexID('a'), Name: "notes.md", Size: 44, MediaType: "text/markdown", Note: "Read me first"},
			{ID: hexID('b'), Name: "chart.png", Size: 8, MediaType: "image/png"},
			{ID: hexID('c'), Name: "big.log", Size: MaxInlineInputBytes + 10, MediaType: "text/plain"},
			{ID: hexID('d'), Name: "late.txt", Size: 16, MediaType: "text/plain"},
		},
	}
	s := InlineInputs(context.Background(), TaskRef{ID: 1}, src)
	for _, want := range []string{"## INPUT FILES", "### notes.md", `Note: "Read me first"`, "not the end of the block",
		"````\nfirst line", "chart.png", "cannot open files", "### big.log", "(The first ", "late.txt",
		"used the 64.0 KiB"} {
		if !strings.Contains(s, want) {
			t.Errorf("the inline section does not hold %q", want)
		}
	}
	if strings.Contains(s, "PNG") || strings.Contains(s, "after the budget") {
		t.Error("the inline section carries what it should only name")
	}
	if len(s) > MaxInlineInputBytes+4096 {
		t.Errorf("the inline section is %d bytes, past its budget", len(s))
	}
	if InlineInputs(context.Background(), TaskRef{ID: 1}, fakeSource{}) != "" {
		t.Error("a task without input files gets an inline section")
	}
}

func TestUniqueName(t *testing.T) {
	taken := map[string]bool{}
	for _, c := range []struct{ in, want string }{
		{"a.txt", "a.txt"}, {"A.txt", "A (2).txt"}, {"a.txt", "a (3).txt"}, {".env", ".env"}, {".env", ".env (2)"},
		{"noext", "noext"}, {"noext", "noext (2)"},
	} {
		got := uniqueName(c.in, taken)
		if got != c.want {
			t.Errorf("uniqueName(%q) = %q, want %q", c.in, got, c.want)
		}
		taken[strings.ToLower(got)] = true
	}
}
