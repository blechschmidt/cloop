package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/projectmove"
)

// runMoveStep runs `cloop workspace <step> --move <id>` in dir through the
// root command, as the hub's dispatch runs it on a device.
func runMoveStep(t *testing.T, dir, step, id string) (string, error) {
	t.Helper()
	t.Chdir(dir)
	workspaceMoveID = ""
	t.Cleanup(func() { workspaceMoveID = "" })
	var out bytes.Buffer
	rootCmd.SetArgs([]string{"workspace", step, "--move", id})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := rootCmd.ExecuteContextC(ctx)
	return out.String(), err
}

// The move's steps run in the project's working directory on a device, which
// must stay exactly as the move leaves it: the root command's reconcile —
// which opens, and so creates, .cloop/state.db — must not run for them.
func TestTheMoveStepsLeaveTheirDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	out, err := runMoveStep(t, dir, "move-probe", "0123456789abcdef")
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	rep, err := projectmove.ParseReport(out)
	if err != nil || !rep.Empty || rep.MoveID != "0123456789abcdef" {
		t.Fatalf("report = %+v, %v\n%s", rep, err, out)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("the probe left %v behind", entries)
	}
	// A verification of a directory no move seeded says so, and creates
	// nothing either.
	if out, err := runMoveStep(t, dir, "move-verify", "0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "records no move") {
		t.Errorf("verify of nothing = %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a .cloop appeared: %v", err)
	}
	if _, err := runMoveStep(t, dir, "move-seed", "not a move"); err == nil {
		t.Error("a seed ran with an id that is not a move's")
	}
}
