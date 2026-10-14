package ui

// Browser gate for task attachments in the dashboard (Task 20428). See
// testdata/attachments_browser.js for what it drives. Skips when Chrome or
// node is missing, like the others; attachments_api_test.go holds the HTTP
// checks that run everywhere.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

type attachmentsBrowserResults struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Badge *struct {
		Task1 string `json:"task1"`
		Task2 string `json:"task2"`
	} `json:"badge"`
	Listed *struct {
		Names    []string `json:"names"`
		Previews []string `json:"previews"`
	} `json:"listed"`
	ImagePreview *struct {
		Width  float64 `json:"width"`
		Height float64 `json:"height"`
		Src    string  `json:"src"`
	} `json:"image_preview"`
	TextPreview *struct {
		Text string `json:"text"`
	} `json:"text_preview"`
	Download *struct {
		File  string `json:"file"`
		Bytes int    `json:"bytes"`
	} `json:"download"`
	Deleted *struct {
		Dialog string   `json:"dialog"`
		Left   []string `json:"left"`
		Badge  string   `json:"badge"`
	} `json:"deleted"`
	Phone *struct {
		OverflowPx  float64 `json:"overflow_px"`
		ModalFits   bool    `json:"modal_fits"`
		ButtonsShow bool    `json:"buttons_show"`
	} `json:"phone"`
}

func TestTaskAttachments_InBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot open the details a user sees")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}

	// A registry of its own: a single-project hub, whose first project is this.
	t.Setenv(multiui.EnvRoot, t.TempDir())
	dir := setupProjectDir(t, "files a run makes", []*pm.Task{
		{ID: 1, Title: "Benchmark the parser", Status: pm.TaskDone},
		{ID: 2, Title: "Nothing attached", Status: pm.TaskPending},
	})
	attachTo(t, dir, 1, "plots/latency.png", pngBytes)
	attachTo(t, dir, 1, "report.html", []byte("<html><body>results</body></html>"))
	attachTo(t, dir, 1, "bench.log", []byte("BenchmarkParse 1000 1234 ns/op\nok\n"))

	srv := New(dir, 0, "")
	// The driver loads the page twice and polls; the per-IP limiter would
	// measure itself instead of the dashboard.
	srv.RPS, srv.Burst = 1000, 1000
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	downloads := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, mustAbs(t, "testdata/attachments_browser.js"), chrome, ts.URL, downloads)
	out, err := cmd.Output()
	var got attachmentsBrowserResults
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
	if got.Badge == nil || got.Listed == nil || got.ImagePreview == nil || got.TextPreview == nil ||
		got.Download == nil || got.Deleted == nil || got.Phone == nil {
		t.Fatalf("a scenario did not run:\n%s", out)
	}

	t.Run("the task list marks a task with files", func(t *testing.T) {
		if !strings.Contains(got.Badge.Task1, "📎 3") || got.Badge.Task2 != "" {
			t.Errorf("badges: task 1 %q, task 2 %q", got.Badge.Task1, got.Badge.Task2)
		}
	})
	t.Run("the details list every file, previewing only what may be shown", func(t *testing.T) {
		names := strings.Join(got.Listed.Names, ",")
		if names != "plots/latency.png,report.html,bench.log" {
			t.Errorf("listed %q", names)
		}
		if p := strings.Join(got.Listed.Previews, ","); p != "plots/latency.png,bench.log" {
			t.Errorf("offered a preview for %q; HTML must only be downloaded", p)
		}
	})
	t.Run("an image previews as pixels", func(t *testing.T) {
		if got.ImagePreview.Width != 1 || got.ImagePreview.Height != 1 || !strings.HasPrefix(got.ImagePreview.Src, "data:image/png;base64,") {
			t.Errorf("image preview = %+v", got.ImagePreview)
		}
	})
	t.Run("text previews as text", func(t *testing.T) {
		if got.TextPreview.Text != "BenchmarkParse 1000 1234 ns/op\nok\n" {
			t.Errorf("text preview = %q", got.TextPreview.Text)
		}
	})
	t.Run("a download saves the file under its name", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(downloads, "bench.log"))
		if got.Download.File != "bench.log" || err != nil || string(data) != "BenchmarkParse 1000 1234 ns/op\nok\n" {
			t.Errorf("download = %+v; saved %q, %v", got.Download, data, err)
		}
	})
	t.Run("delete asks first, then the list and the badge follow", func(t *testing.T) {
		if !strings.Contains(got.Deleted.Dialog, "latency.png") {
			t.Errorf("the confirmation asked %q", got.Deleted.Dialog)
		}
		if strings.Join(got.Deleted.Left, ",") != "report.html,bench.log" || !strings.Contains(got.Deleted.Badge, "📎 2") {
			t.Errorf("after the delete: listed %v, badge %q", got.Deleted.Left, got.Deleted.Badge)
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, _ := db.TaskAttachments(1)
		if len(rows) != 2 {
			t.Errorf("the hub holds %d attachments for task 1 after the delete, want 2", len(rows))
		}
	})
	t.Run("a phone shows the section without widening the page", func(t *testing.T) {
		if got.Phone.OverflowPx > 0 || !got.Phone.ModalFits || !got.Phone.ButtonsShow {
			t.Errorf("at 360px: %+v", got.Phone)
		}
	})
}
