package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// `cloop task add --input-file` refuses a file before it adds the task, the
// project's limit included (Task 20511): a task added and then refused its
// file would run without it.
func TestTaskAddInputFilesAreCheckedAgainstTheProject(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	ps, err := state.Init(dir, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{{ID: 1, Title: "holds the project's files", Status: pm.TaskDone}}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(small, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkInputFiles(dir, []string{small, small}); err != nil {
		t.Fatalf("two small files for an empty project: %v", err)
	}
	if err := checkInputFiles(dir, []string{filepath.Join(dir, "missing.txt")}); err == nil {
		t.Fatal("a missing file passed")
	}
	if err := checkInputFiles(dir, []string{dir}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory: %v", err)
	}

	// The project holds all but 5 bytes of what it may.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddTaskAttachment(statedb.AttachmentRow{ID: strings.Repeat("e", 32), TaskID: 1, Name: "big.bin",
		Size: attachments.MaxProjectBytes - 5, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	err = checkInputFiles(dir, []string{small})
	if err == nil || !strings.Contains(err.Error(), "project's attachments would come to") {
		t.Fatalf("a file the project has no room for: %v", err)
	}
}
