package cmd

// `cloop project readers` (Task 20498) against hubs in this process: one with
// single sign-on, reached with the session `cloop login` stored, and one on
// this machine without sign-in, reached with no credential at all.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectreaders"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// runReadersCLI runs `cloop project readers <args>` as a terminal would.
func runReadersCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(projectReadersCmd)
	t.Cleanup(func() { resetFlags(projectReadersCmd) })
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"project", "readers"}, args...))
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

// readerProject makes a project directory and registers it with the hub.
func readerProject(t *testing.T, name, goal string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, goal, 0); err != nil {
		t.Fatal(err)
	}
	if err := multiui.AddPaths([]string{dir}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// hubReaders reads the hub's lists from its control plane.
func hubReaders(t *testing.T, db *statedb.DB) *projectreaders.Resolver {
	t.Helper()
	r, err := projectreaders.Load(db)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProjectReadersOnAHubWithSignIn(t *testing.T) {
	clk := &movableClock{}
	credPath := credentialHome(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{
		SelfExe:     cliSelfExe(t),
		AdminEmails: []string{rootEmail},
		Clock:       clk.now,
	})
	w := &remoteWorld{hub: hub, credPath: credPath}
	shop := w.hub.Dir
	billing := readerProject(t, "billing", "reads the shop")
	db := w.hub.ControlPlane(t)
	// The command makes no database where it is run: it is the hub's client.
	cwd := t.TempDir()
	t.Chdir(cwd)

	// A viewer reads the list, and changes nothing.
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	out, err := runReadersCLI(t, "ls", "0")
	if err != nil || !strings.Contains(out, "No other project may read") || !strings.Contains(out, "Only the administrators") {
		t.Fatalf("a viewer lists the readers: %v\n%s", err, out)
	}
	if _, err := runReadersCLI(t, "add", "0", "billing"); err == nil || !strings.Contains(err.Error(), "project.readers") ||
		!strings.Contains(err.Error(), "only the administrators of") {
		t.Fatalf("a viewer's add: %v", err)
	}
	// So does a maintainer: the list is the administrators'.
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	if _, err := runReadersCLI(t, "add", "0", "billing"); err == nil || !strings.Contains(err.Error(), "project.readers") {
		t.Fatalf("a maintainer's add: %v", err)
	}
	if len(hubReaders(t, db).All()) != 0 {
		t.Fatal("a refused add changed the list")
	}

	// The administrator: add, see it from both sides, add again, remove.
	w.as(t, rootEmail)
	out, err = runReadersCLI(t, "add", "0", "billing")
	if err != nil || !strings.Contains(out, "billing may now read") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if !hubReaders(t, db).CanRead(billing, shop) {
		t.Fatal("the hub's list does not let billing read the shop")
	}
	out, err = runReadersCLI(t, "ls", "0")
	if err != nil || !strings.Contains(out, "Projects that may read") || !strings.Contains(out, billing) ||
		!strings.Contains(out, "added by "+rootEmail) || strings.Contains(out, "Only the administrators") {
		t.Fatalf("ls: %v\n%s", err, out)
	}
	out, err = runReadersCLI(t, "ls", "billing", "--json")
	var ans readersAnswer
	if err != nil || json.Unmarshal([]byte(out), &ans) != nil || len(ans.Readable) != 1 || ans.Readable[0].Path != shop {
		t.Fatalf("ls billing --json: %v\n%s", err, out)
	}
	if out, err := runReadersCLI(t, "add", "0", billing); err != nil || !strings.Contains(out, "could already read") {
		t.Fatalf("adding it again by path: %v\n%s", err, out)
	}
	if _, err := runReadersCLI(t, "add", "0", "0"); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Errorf("a project listing itself: %v", err)
	}
	if _, err := runReadersCLI(t, "add", "0", "no-such-project"); err == nil {
		t.Error("a project nobody can see was added")
	}
	out, err = runReadersCLI(t, "rm", "0", "billing")
	if err != nil || !strings.Contains(out, "billing may no longer read") {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	if _, err := runReadersCLI(t, "rm", "0", "billing"); err == nil || !strings.Contains(err.Error(), "no such entry") {
		t.Errorf("removing it again: %v", err)
	}
	if len(hubReaders(t, db).All()) != 0 {
		t.Fatal("the entry survived rm")
	}

	// A change asks for a recent sign-in, and says how to get one; listing
	// does not.
	clk.advance(3 * time.Hour)
	if _, err := runReadersCLI(t, "add", "0", "billing"); err == nil || !strings.Contains(err.Error(), "recent sign-in") ||
		!strings.Contains(err.Error(), "cloop login") {
		t.Errorf("a stale session's add: %v", err)
	}
	if _, err := runReadersCLI(t, "ls", "0"); err != nil {
		t.Errorf("a stale session's ls: %v", err)
	}
	if len(hubReaders(t, db).All()) != 0 {
		t.Error("a stale session changed the list")
	}
	if _, err := os.Stat(filepath.Join(cwd, ".cloop")); !os.IsNotExist(err) {
		t.Errorf("the command left a .cloop where it ran: %v", err)
	}
}

// TestProjectReadersOnALocalHub: a hub on this machine without sign-in answers
// a terminal that holds no session for it, as the static admin's.
func TestProjectReadersOnALocalHub(t *testing.T) {
	credentialHome(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := filepath.Join(t.TempDir(), "shop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "read from a terminal", 0); err != nil {
		t.Fatal(err)
	}
	billing := readerProject(t, "billing", "reads the shop")
	srv := ui.New(dir, 0, "")
	srv.RPS, srv.Burst = 10000, 10000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	out, err := runReadersCLI(t, "add", "shop", "billing", "--hub", ts.URL)
	if err != nil || !strings.Contains(out, "billing may now read shop") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	out, err = runReadersCLI(t, "ls", "shop", "--hub", ts.URL, "--json")
	var ans readersAnswer
	if err != nil || json.Unmarshal([]byte(out), &ans) != nil || !ans.CanManage || len(ans.Readers) != 1 ||
		ans.Readers[0].Path != billing {
		t.Fatalf("ls --json: %v\n%s", err, out)
	}
	// By the entry's id, as for a reader the terminal cannot see.
	out, err = runReadersCLI(t, "rm", "shop", ans.Readers[0].ID, "--hub", ts.URL)
	if err != nil || !strings.Contains(out, "may no longer read shop") {
		t.Fatalf("rm by id: %v\n%s", err, out)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(hubReaders(t, db).All()) != 0 {
		t.Fatal("the entry survived rm by id")
	}
}
