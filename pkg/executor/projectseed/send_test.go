package projectseed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeHub plays the hub's results endpoint for SendAttachments: it records
// what it is sent, and answers each send with what fail returns for it, if
// anything.
type fakeHub struct {
	mu    sync.Mutex
	got   map[string][]byte
	ups   []knowledgerun.ResultUpload
	tries map[string]int
	fail  func(u knowledgerun.ResultUpload, try int) error
}

func newFakeHub() *fakeHub { return &fakeHub{got: map[string][]byte{}, tries: map[string]int{}} }

func (h *fakeHub) SendResult(_ context.Context, u knowledgerun.ResultUpload, body io.Reader) (*knowledgerun.ResultResponse, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tries[u.Name]++
	if h.fail != nil {
		if err := h.fail(u, h.tries[u.Name]); err != nil {
			return nil, err
		}
	}
	h.got[u.Name] = data
	h.ups = append(h.ups, u)
	return &knowledgerun.ResultResponse{Outcome: knowledgerun.ResultAttached, ID: u.ID, Task: u.Task}, nil
}

// noRetryWaits makes SendAttachments retry without waiting.
func noRetryWaits(t *testing.T) {
	t.Helper()
	old := sendRetryWaits
	sendRetryWaits = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { sendRetryWaits = old })
}

// deviceWithFiles is a finished run on a device that attached files to the
// task it was given and to one it created, sent one of them itself, and was
// given an input file it must not send back.
func deviceWithFiles(t *testing.T) (dev string, seed []byte, rows map[string]statedb.AttachmentRow) {
	t.Helper()
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
		{ID: 1, Title: "Write the report", Status: pm.TaskPending},
	}}})
	seed = seedFromHub(t, hub)
	rows = map[string]statedb.AttachmentRow{}
	dev = onDevice(t, seed, func(dir string, st *state.ProjectState) {
		st.Plan.TaskByID(1).Status = pm.TaskDone
		st.Plan.Tasks = append(st.Plan.Tasks, &pm.Task{ID: 2, Title: "A task the run made", Status: pm.TaskDone})
		if err := st.SaveDirect(); err != nil {
			t.Fatal(err)
		}
		rows["sent-already.txt"] = deviceAttach(t, dir, 1, "sent-already.txt", []byte("the run sent this"))
		rows["report.md"] = deviceAttach(t, dir, 1, "report.md", []byte("# Report\n"))
		rows["chart.svg"] = deviceAttach(t, dir, 2, "chart.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
		dbPath := filepath.Join(dir, ".cloop", "state.db")
		if err := attachments.MarkSent(dbPath, rows["sent-already.txt"].ID); err != nil {
			t.Fatal(err)
		}
		db, err := statedb.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		in, err := attachments.Put(db, dbPath, 1, attachments.Meta{Name: "brief.pdf", Role: statedb.AttachmentRoleInput,
			Source: statedb.AttachmentSourceUpload}, bytes.NewReader([]byte("%PDF")), attachments.MaxFileBytes, nil)
		if err != nil {
			t.Fatal(err)
		}
		rows["brief.pdf"] = in
	})
	return dev, seed, rows
}

// TestSendAttachmentsSendsWhatTheRunDidNot: the files a finished run attached
// and did not send reach the hub under the run's own ids — a task the run
// created is said to be one — and are marked sent, so the result describes
// them without carrying them. What the run sent itself, and the input files
// the hub gave it, are not sent.
func TestSendAttachmentsSendsWhatTheRunDidNot(t *testing.T) {
	dev, seed, rows := deviceWithFiles(t)
	hub := newFakeHub()
	rep, err := SendAttachments(context.Background(), dev, seed, hub, nil)
	if err != nil {
		t.Fatalf("SendAttachments: %v", err)
	}
	if rep.Found != 2 || len(rep.Sent) != 2 || len(rep.NotSent) != 0 || rep.Stopped != "" {
		t.Fatalf("report = %+v; want the two files the run did not send, sent", rep)
	}
	if len(hub.got) != 2 || string(hub.got["report.md"]) != "# Report\n" || string(hub.got["chart.svg"]) != `<svg xmlns="http://www.w3.org/2000/svg"/>` {
		t.Fatalf("the hub got %v", hub.got)
	}
	for _, u := range hub.ups {
		row := rows[u.Name]
		if u.ID != row.ID || u.Task != row.TaskID || u.Size != row.Size || u.SHA256 != row.SHA256 {
			t.Errorf("%s was sent as %+v; its row is %+v", u.Name, u, row)
		}
		switch u.Name {
		case "report.md":
			if u.Created || u.TitleSHA256 != knowledgerun.TitleDigest("Write the report") {
				t.Errorf("report.md: created %v, title digest %s — its task is the one the run was given", u.Created, u.TitleSHA256)
			}
		case "chart.svg":
			if !u.Created || u.TitleSHA256 != knowledgerun.TitleDigest("A task the run made") {
				t.Errorf("chart.svg: created %v — its task is one the run made", u.Created)
			}
		}
	}

	// Nothing is sent twice, and the result carries none of the bytes.
	if rep, err := SendAttachments(context.Background(), dev, seed, hub, nil); err != nil || rep.Found != 0 {
		t.Fatalf("a second send found %d files (%v)", rep.Found, err)
	}
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResult(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Attachments {
		if !a.Sent || len(a.Data) != 0 || a.ID != rows[a.Name].ID {
			t.Errorf("%s in the result: sent %v, %d bytes, id %s", a.Name, a.Sent, len(a.Data), a.ID)
		}
	}
	if len(r.Attachments) != 3 {
		t.Errorf("the result describes %d files; want the run's three results, not its input", len(r.Attachments))
	}
}

// TestSendAttachmentsWhenTheHubDoesNotTakeAFile: a hub that is busy or
// restarting gets the file again; a session the hub refuses, or a hub that
// cannot be reached, ends the sending — every file goes to the same place with
// the same token — while a refusal of one file does not.
func TestSendAttachmentsWhenTheHubDoesNotTakeAFile(t *testing.T) {
	noRetryWaits(t)
	fixture, seed, _ := deviceWithFiles(t)
	cases := map[string]struct {
		err func(try int) error
		// sent and tries are what the hub ends up with, and how often
		// report.md was tried; stopped is part of why the rest were not.
		sent, tries int
		stopped     string
	}{
		"busy, then taken": {err: func(try int) error {
			if try < 3 {
				return &knowledgerun.APIError{Status: 503, Message: "restarting"}
			}
			return nil
		}, sent: 2, tries: 3},
		"session refused": {err: func(int) error {
			return &knowledgerun.APIError{Status: 401, Message: "the session is closed"}
		}, tries: 1, stopped: "refused the run's session"},
		"unreachable": {err: func(int) error {
			return errors.New("dial tcp 192.0.2.1:443: connect: connection refused")
		}, tries: len(sendRetryWaits) + 1, stopped: "could not be reached"},
		"one file refused": {err: func(int) error {
			return &knowledgerun.APIError{Status: 413, Message: "the project is full"}
		}, sent: 1, tries: 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dev := copyTree(t, fixture)
			hub := newFakeHub()
			hub.fail = func(u knowledgerun.ResultUpload, try int) error {
				if u.Name == "report.md" {
					return c.err(try)
				}
				return nil
			}
			rep, err := SendAttachments(context.Background(), dev, seed, hub, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Sent) != c.sent || hub.tries["report.md"] != c.tries {
				t.Fatalf("report %+v, report.md tried %d times; want %d sent and %d tries", rep,
					hub.tries["report.md"], c.sent, c.tries)
			}
			if c.sent == 2 {
				if len(rep.NotSent) != 0 || rep.Stopped != "" {
					t.Errorf("report %+v", rep)
				}
				return
			}
			if len(rep.NotSent) != 1 || !strings.Contains(rep.NotSent[0], "report.md") {
				t.Fatalf("not sent = %v", rep.NotSent)
			}
			switch {
			case c.stopped == "" && rep.Stopped != "":
				t.Errorf("stopped: %s; the next file goes elsewhere in the hub's eyes and must be tried", rep.Stopped)
			case c.stopped != "" && (!strings.Contains(rep.Stopped, c.stopped) || hub.tries["chart.svg"] != 0):
				t.Errorf("report %+v; want it stopped (%q) before chart.svg", rep, c.stopped)
			}
		})
	}
}

// copyTree copies the directory src — plain files and directories — to a new
// temporary directory, and returns it.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(to, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestSendAttachmentsSaysWhyItStopped: a sending whose time ran out says so,
// and one called off because the run was stopped says that.
func TestSendAttachmentsSaysWhyItStopped(t *testing.T) {
	dev, seed, _ := deviceWithFiles(t)
	called, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithTimeout(context.Background(), -time.Second)
	defer cancel2()
	for want, ctx := range map[string]context.Context{"called off": called, "no time left": expired} {
		hub := newFakeHub()
		rep, err := SendAttachments(ctx, dev, seed, hub, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Found != 2 || len(rep.Sent) != 0 || !strings.Contains(rep.Stopped, want) || len(hub.ups) != 0 {
			t.Errorf("report %+v, %d sent; want nothing sent and %q", rep, len(hub.ups), want)
		}
	}
}

// TestSendAttachmentsDoesNotFollowLinks: the agent sending these runs outside
// the workload's sandbox. A stored file the workload replaced with a link is
// not read — and the files after it still go — and a .cloop that is a link is
// refused outright, as Harvest refuses it.
func TestSendAttachmentsDoesNotFollowLinks(t *testing.T) {
	dev, seed, rows := deviceWithFiles(t)
	outside := filepath.Join(t.TempDir(), "agent-credential")
	if err := os.WriteFile(outside, []byte("only the agent can read this"), 0o600); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(attachments.StoreDir(filepath.Join(dev, ".cloop", "state.db")), rows["report.md"].ID)
	if err := os.Remove(stored); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stored); err != nil {
		t.Fatal(err)
	}
	hub := newFakeHub()
	rep, err := SendAttachments(context.Background(), dev, seed, hub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hub.got["report.md"]; ok || len(rep.Sent) != 1 || len(rep.NotSent) != 1 || rep.Stopped != "" {
		t.Fatalf("report %+v, the hub got %v", rep, hub.got)
	}
	if !strings.Contains(rep.NotSent[0], "could not be read") {
		t.Errorf("not sent = %v", rep.NotSent)
	}

	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(dev, ".cloop"), filepath.Join(linked, ".cloop")); err != nil {
		t.Fatal(err)
	}
	if _, err := SendAttachments(context.Background(), linked, seed, newFakeHub(), nil); err == nil ||
		!strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a linked .cloop: %v", err)
	}
}

// TestSendAttachmentsWithoutADatabaseSendsNothing: a run that never opened its
// project attached nothing — and looking must not create a database.
func TestSendAttachmentsWithoutADatabaseSendsNothing(t *testing.T) {
	isolateHome(t)
	hub := hubProject(t, &state.ProjectState{Goal: "g", Plan: &pm.Plan{Goal: "g"}})
	seed := seedFromHub(t, hub)
	dev := t.TempDir()
	if err := Write(dev, seed); err != nil {
		t.Fatal(err)
	}
	for _, name := range staleDatabaseFiles {
		_ = os.Remove(filepath.Join(dev, ".cloop", name))
	}
	rep, err := SendAttachments(context.Background(), dev, seed, newFakeHub(), nil)
	if err != nil || rep.Found != 0 {
		t.Fatalf("report %+v, %v", rep, err)
	}
	if _, err := os.Lstat(filepath.Join(dev, ".cloop", "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a database was created: %v", err)
	}
}
