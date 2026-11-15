package ui

// Browser gate for the Move dialog (Task 20496). See
// testdata/projectmove_browser.js for what it drives and why a browser; the
// hub's half is in projectmove_view_test.go. Skips when Chrome or node is
// missing, like the others.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/projectmove"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestProjectMoveDialog_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot press the buttons a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv(multiui.EnvRoot, t.TempDir())

	// A project in a git repository, with work no commit holds, bound to a
	// container that works in the hub's own tree: moving it onto the hub's
	// host runs every phase in this process, and isolates its runs less,
	// which the preflight warns about.
	dir := setupProjectDir(t, "moving in a browser", nil)
	db := hubWithControlPlane(t, dir)
	setProvider(t, dir, "ollama")
	moveWrite(t, filepath.Join(dir, "keep.txt"), "base\n")
	moveGit(t, dir, "init", "-q", "-b", "main")
	moveGit(t, dir, "add", "keep.txt")
	moveGit(t, dir, "commit", "-q", "-m", "base")
	moveWrite(t, filepath.Join(dir, "keep.txt"), "changed\n")
	moveWrite(t, filepath.Join(dir, "untracked.txt"), "untracked\n")
	box := newHarnessExec("mv-browser-box", executor.KindContainer, executor.IsolationContainer)
	registerMoveExec(t, box)
	recordExecutor(t, db, box.id, executor.KindContainer)
	recordExecutor(t, db, "local", executor.KindLocalProcess)
	if err := db.BindProjectExecutor(dir, box.id, "test"); err != nil {
		t.Fatal(err)
	}
	if err := executor.Bind(dir, box.id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })

	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	ts := newTestServerFor(t, srv)

	// What the dialog will show: something to accept, nothing blocking.
	if status, rep, raw := preflightOver(t, http.DefaultClient, ts.URL, "target=local&quiesce=1"); status != http.StatusOK ||
		rep.Blocked || rep.Counts.Warnings == 0 {
		t.Fatalf("the fixture's preflight onto the host = HTTP %d, want a warning and no blocker: %s", status, raw)
	}

	// The control server: a move the hub is not driving, started, moved on
	// and ended as the driver asks, each step announced as the engine's own
	// writes are.
	const seeded = "b20e5ee6b20e5ee6"
	var mu sync.Mutex
	at := time.Now().UTC()
	write := func(from projectmove.Move, to projectmove.Phase, detail projectmove.Detail, fail string) (projectmove.Move, error) {
		raw, err := json.Marshal(detail)
		if err != nil {
			return from, err
		}
		u := statedb.ProjectMoveUpdate{ID: from.ID, FromPhase: string(from.Phase), FromVersion: from.Version,
			Phase: string(to), DetailJSON: string(raw)}
		if fail != "" {
			u.FailedPhase, u.Error = string(from.Phase), fail
		}
		row, err := db.AdvanceProjectMove(u)
		if err != nil {
			return from, err
		}
		return projectmove.MoveFromRow(row)
	}
	step := func(p projectmove.Phase, i int) projectmove.Step {
		return projectmove.Step{Phase: p, Started: at.Add(time.Duration(i) * time.Second), Ended: at.Add(time.Duration(i)*time.Second + 500*time.Millisecond)}
	}
	var cur projectmove.Move
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var err error
		switch r.URL.Path {
		case "/seed":
			var row statedb.ProjectMoveRow
			row, err = db.CreateProjectMove(statedb.ProjectMoveRow{ID: seeded, ProjectPath: dir, ProjectName: filepath.Base(dir),
				SourceBinding: box.id, TargetBinding: "local", Phase: "capture", StartedBy: "someone@example.com",
				DetailJSON: mustJSON(t, projectmove.Detail{Timeline: []projectmove.Step{step(projectmove.PhasePreflight, 0), step(projectmove.PhaseQuiesce, 1)}})})
			if err == nil {
				cur, err = projectmove.MoveFromRow(row)
			}
		case "/advance":
			d := cur.Detail
			d.Timeline = append(d.Timeline, step(projectmove.PhaseCapture, 2), step(projectmove.PhaseSwitch, 3))
			if cur, err = write(cur, projectmove.PhaseSwitch, d, ""); err == nil {
				srv.moveChanged(cur)
				cur, err = write(cur, projectmove.PhaseSeed, d, "")
			}
		case "/finish":
			d := cur.Detail
			d.Timeline = append(d.Timeline, projectmove.Step{Phase: projectmove.PhaseSeed, Started: at.Add(4 * time.Second),
				Ended: at.Add(5 * time.Second), Error: "the target refused the seed"})
			cur, err = write(cur, projectmove.PhaseFailed, d, "the target refused the seed")
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		srv.moveChanged(cur)
		_, _ = io.WriteString(w, cur.ID)
	}))
	t.Cleanup(ctl.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	args := []string{mustAbs(t, "testdata/projectmove_browser.js"), chrome, ts.URL, ctl.URL}
	if shots := os.Getenv("CLOOP_PROJECTMOVE_SHOTS"); shots != "" {
		args = append(args, shots)
	}
	out, err := exec.CommandContext(ctx, node, args...).Output()
	var got struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		RunBefore       bool `json:"run_before"`
		RunWhileMoving  bool `json:"run_while_moving"`
		CardWhileMoving struct {
			Text        string `json:"text"`
			RunDisabled bool   `json:"run_disabled"`
		} `json:"card_while_moving"`
		ProgressTitle    string   `json:"progress_title"`
		FocusOnOpen      string   `json:"focus_on_open"`
		StepsDone        []string `json:"steps_done"`
		ReadsWhileMoving int      `json:"reads_while_moving"`
		Live             string   `json:"live"`
		EndedText        string   `json:"ended_text"`
		ReadsAfterEnd    int      `json:"reads_after_end"`
		RunAfter         bool     `json:"run_after"`
		FocusAfterClose  string   `json:"focus_after_close"`
		FramesSeeded     []string `json:"frames_seeded"`
		ChooseText       string   `json:"choose_text"`
		Review           struct {
			Groups       []string `json:"groups"`
			Acks         int      `json:"acks"`
			Remedies     int      `json:"remedies"`
			MoveDisabled bool     `json:"move_disabled"`
		} `json:"review"`
		TabEscapes         int      `json:"tab_escapes"`
		DisabledUntilLast  bool     `json:"disabled_until_last"`
		EnabledAfterTicks  bool     `json:"enabled_after_ticks"`
		ResultText         string   `json:"result_text"`
		FramesReal         []string `json:"frames_real"`
		CleanDisabledFirst bool     `json:"clean_disabled_first"`
		CleanedText        string   `json:"cleaned_text"`
		Errors             string   `json:"errors"`
	}
	if jerr := json.Unmarshal(out, &got); jerr != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v / %v\nstdout:\n%s\nstderr:\n%s", err, jerr, out, stderr)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s\nraw:\n%s", got.Error.Message, out)
	}

	t.Run("a move in progress holds the project's Run, and lets go when it ends", func(t *testing.T) {
		if got.RunBefore || !got.RunWhileMoving || got.RunAfter {
			t.Errorf("Run disabled before %v, while moving %v, after %v", got.RunBefore, got.RunWhileMoving, got.RunAfter)
		}
		if !strings.Contains(got.CardWhileMoving.Text, "Moving to") || !strings.Contains(got.CardWhileMoving.Text, "capture") ||
			!got.CardWhileMoving.RunDisabled {
			t.Errorf("the project card while moving = %+v", got.CardWhileMoving)
		}
	})

	t.Run("the dialog follows a move from the hub's pushes, without polling", func(t *testing.T) {
		if !strings.Contains(got.ProgressTitle, "Moving") || got.FocusOnOpen != "pm-title" {
			t.Errorf("progress face titled %q, focus on %q", got.ProgressTitle, got.FocusOnOpen)
		}
		for _, want := range []string{"Preflight", "Stop runs", "Capture", "Switch"} {
			if !slices.Contains(got.StepsDone, want) {
				t.Errorf("steps done once the push arrived = %v, want %s among them", got.StepsDone, want)
			}
		}
		// One read when the dialog opened; the steps after it came pushed.
		if got.ReadsWhileMoving != 1 {
			t.Errorf("the page read the move %d times while following it, want once: it polled", got.ReadsWhileMoving)
		}
		// And one more when it ended, for what cleaning up would remove.
		if got.ReadsAfterEnd != 2 {
			t.Errorf("reads by the end = %d, want 2", got.ReadsAfterEnd)
		}
		if !strings.Contains(got.Live, "Seed") {
			t.Errorf("the live region says %q", got.Live)
		}
		if !strings.Contains(got.EndedText, "the target refused the seed") {
			t.Errorf("the ended move's result: %q", got.EndedText)
		}
		if len(got.FramesSeeded) < 3 || got.FramesSeeded[len(got.FramesSeeded)-1] != "failed" {
			t.Errorf("project_move frames the page received = %v", got.FramesSeeded)
		}
		if got.FocusAfterClose != "moveBtn" {
			t.Errorf("focus after Escape = %q, want back on the Move to… button", got.FocusAfterClose)
		}
	})

	t.Run("Move waits for every warning to be accepted", func(t *testing.T) {
		if !strings.Contains(got.ChooseText, "local") || !strings.Contains(got.ChooseText, "where it is now") {
			t.Errorf("the targets: %q", got.ChooseText)
		}
		r := got.Review
		if !slices.Contains(r.Groups, "Lost or changed by the move ("+strconv.Itoa(r.Acks)+")") || r.Acks == 0 ||
			r.Remedies < r.Acks || !r.MoveDisabled {
			t.Errorf("review = %+v", r)
		}
		if slices.ContainsFunc(r.Groups, func(g string) bool { return strings.HasPrefix(g, "Blocks the move") }) {
			t.Errorf("the review shows blockers: %v", r.Groups)
		}
		if !got.DisabledUntilLast || !got.EnabledAfterTicks {
			t.Errorf("Move disabled until the last tick %v, enabled after %v", got.DisabledUntilLast, got.EnabledAfterTicks)
		}
	})

	t.Run("the dialog keeps the keyboard inside it", func(t *testing.T) {
		if got.TabEscapes != 0 {
			t.Errorf("Tab left the dialog %d times", got.TabEscapes)
		}
	})

	t.Run("the move ends verified, and cleanup waits for its tick", func(t *testing.T) {
		if !strings.Contains(got.ResultText, "Moved and verified") {
			t.Errorf("result: %q", got.ResultText)
		}
		if !slices.Contains(got.FramesReal, "done") || len(got.FramesReal) < 4 {
			t.Errorf("project_move frames during the real move = %v", got.FramesReal)
		}
		if !got.CleanDisabledFirst || !strings.Contains(got.CleanedText, "Cleaned up") || got.Errors != "" {
			t.Errorf("cleanup: disabled first %v, then %q (errors %q)", got.CleanDisabledFirst, got.CleanedText, got.Errors)
		}
		if b, _, _ := db.ProjectExecutor(dir); b != "local" {
			t.Errorf("binding after the move = %q", b)
		}
		moves, err := projectmove.ListMoves(db, statedb.ProjectMoveFilter{ProjectPath: dir})
		if err != nil || len(moves) != 2 {
			t.Fatalf("moves = %d, %v", len(moves), err)
		}
		m := moves[0]
		if m.Phase != projectmove.PhaseDone || m.Detail.Retained == nil || m.Detail.Retained.CleanedAt.IsZero() {
			t.Errorf("the real move = %s, retained %+v", m.Phase, m.Detail.Retained)
		}
		if _, err := os.Stat(m.Detail.Capture.Store); !os.IsNotExist(err) {
			t.Errorf("the move's store survived its cleanup: %v", err)
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
