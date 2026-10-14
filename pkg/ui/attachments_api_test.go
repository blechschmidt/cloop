package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// pngBytes is a complete 1×1 PNG.
var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89" +
	"\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")

// attachTo stores a file as an attachment of a task in the project at dir.
func attachTo(t *testing.T, dir string, taskID int, name string, data []byte) statedb.AttachmentRow {
	t.Helper()
	dbPath := state.DBPath(dir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row, err := attachments.Put(db, dbPath, taskID, attachments.Meta{Name: name, Source: statedb.AttachmentSourceRun, RunID: "r1"},
		bytes.NewReader(data), attachments.MaxFileBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// rawGET fetches path without letting the client undo a Content-Encoding.
func rawGET(t *testing.T, url string, header map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestTaskAttachmentsAPI(t *testing.T) {
	dir := setupProjectWithTasks(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "makes files", Status: pm.TaskDone},
		{ID: 2, Title: "another", Status: pm.TaskPending},
	})
	chart := attachTo(t, dir, 1, "plots/chart.png", pngBytes)
	report := attachTo(t, dir, 1, "report.html", []byte("<html><script>alert(document.cookie)</script></html>"))
	log := attachTo(t, dir, 1, "run.log", []byte(strings.Repeat("line\n", 400)))
	other := attachTo(t, dir, 2, "other.txt", []byte("task two"))
	ts := newTestServer(t, dir, nil)

	t.Run("the list", func(t *testing.T) {
		body := apiGET(t, ts, "/api/tasks/1/attachments")
		list, _ := body["attachments"].([]any)
		if body["ok"] != true || len(list) != 3 {
			t.Fatalf("GET /api/tasks/1/attachments = %v", body)
		}
		preview := map[string]bool{}
		for _, a := range list {
			m := a.(map[string]any)
			preview[m["name"].(string)] = m["previewable"] == true
		}
		if !preview["plots/chart.png"] || preview["report.html"] || !preview["run.log"] {
			t.Errorf("previewable = %v: the chart and the log, never the HTML", preview)
		}
		if body["limits"] == nil || body["usage"] == nil {
			t.Errorf("the list carries no limits or usage: %v", body)
		}
	})

	t.Run("a download is a download, whatever it claims", func(t *testing.T) {
		resp, body := rawGET(t, ts.URL+"/api/tasks/1/attachments/"+report.ID+"?inline=1", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
		h := resp.Header
		if h.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") {
			t.Errorf("HTML asked for inline: type %q, disposition %q — it must only ever be downloaded",
				h.Get("Content-Type"), h.Get("Content-Disposition"))
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("CSP = %q", h.Get("Content-Security-Policy"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
		}
		if cd := h.Get("Content-Disposition"); !strings.Contains(cd, `filename=report.html`) && !strings.Contains(cd, `filename="report.html"`) {
			t.Errorf("Content-Disposition = %q", h.Get("Content-Disposition"))
		}
		if string(body) != "<html><script>alert(document.cookie)</script></html>" {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("an image and text may be shown in place", func(t *testing.T) {
		resp, body := rawGET(t, ts.URL+"/api/tasks/1/attachments/"+chart.ID+"?inline=1", nil)
		if resp.Header.Get("Content-Type") != "image/png" || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "inline") ||
			!bytes.Equal(body, pngBytes) {
			t.Errorf("chart: type %q, disposition %q", resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"))
		}
		resp, body = rawGET(t, ts.URL+"/api/tasks/1/attachments/"+log.ID+"?inline=1", nil)
		if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || len(body) != 2000 {
			t.Errorf("log: type %q, %d bytes", resp.Header.Get("Content-Type"), len(body))
		}
		// Not compressed by the API's gzip layer, so its length and ranges
		// describe the file.
		if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "2000" {
			t.Errorf("log: encoding %q, length %q", resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Length"))
		}
	})

	t.Run("ranges and revalidation", func(t *testing.T) {
		resp, body := rawGET(t, ts.URL+"/api/tasks/1/attachments/"+log.ID, map[string]string{"Range": "bytes=0-9"})
		if resp.StatusCode != http.StatusPartialContent || string(body) != "line\nline\n" {
			t.Errorf("a range: %d %q", resp.StatusCode, body)
		}
		resp, _ = rawGET(t, ts.URL+"/api/tasks/1/attachments/"+log.ID, map[string]string{"If-None-Match": `"` + log.SHA256 + `"`})
		if resp.StatusCode != http.StatusNotModified {
			t.Errorf("a revalidation with the current ETag: %d", resp.StatusCode)
		}
	})

	t.Run("another task's attachment is not reachable through this one", func(t *testing.T) {
		resp, _ := rawGET(t, ts.URL+"/api/tasks/1/attachments/"+other.ID, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("task 2's file through task 1: %d, want 404", resp.StatusCode)
		}
		for _, path := range []string{"/api/tasks/9/attachments", "/api/tasks/x/attachments", "/api/tasks/1/attachments/..%2Fstate.db"} {
			if resp, _ := rawGET(t, ts.URL+path, nil); resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadRequest {
				t.Errorf("GET %s = %d", path, resp.StatusCode)
			}
		}
	})

	t.Run("a store the sandbox tampered with is not served", func(t *testing.T) {
		stored := filepath.Join(attachments.StoreDir(state.DBPath(dir)), other.ID)
		if err := os.Remove(stored); err != nil {
			t.Fatal(err)
		}
		secret := filepath.Join(dir, ".cloop", "config.yaml")
		if err := os.Symlink(secret, stored); err != nil {
			t.Fatal(err)
		}
		resp, body := rawGET(t, ts.URL+"/api/tasks/2/attachments/"+other.ID, nil)
		if resp.StatusCode != http.StatusConflict || strings.Contains(string(body), "provider") {
			t.Errorf("a link in the store: %d %q", resp.StatusCode, body)
		}
		if err := os.Remove(stored); err != nil {
			t.Fatal(err)
		}
		if resp, _ := rawGET(t, ts.URL+"/api/tasks/2/attachments/"+other.ID, nil); resp.StatusCode != http.StatusGone {
			t.Errorf("a file missing from the store: %d, want 410", resp.StatusCode)
		}
	})

	t.Run("the task list counts them", func(t *testing.T) {
		st := apiGET(t, ts, "/api/state")
		tasks := st["plan"].(map[string]any)["tasks"].([]any)
		counts := map[float64]any{}
		for _, raw := range tasks {
			m := raw.(map[string]any)
			counts[m["id"].(float64)] = m["attachment_count"]
		}
		if counts[1] != float64(3) || counts[2] != float64(1) {
			t.Errorf("attachment_count in /api/state = %v", counts)
		}
	})

	t.Run("delete", func(t *testing.T) {
		body := apiDELETE(t, ts, "/api/tasks/1/attachments/"+chart.ID)
		if body["ok"] != true {
			t.Fatalf("DELETE = %v", body)
		}
		if _, err := os.Lstat(filepath.Join(attachments.StoreDir(state.DBPath(dir)), chart.ID)); !os.IsNotExist(err) {
			t.Errorf("the deleted attachment's file is still in the store: %v", err)
		}
		if again := apiDELETE(t, ts, "/api/tasks/1/attachments/"+chart.ID); again["error"] == nil {
			t.Errorf("deleting it twice = %v", again)
		}
		if wrong := apiDELETE(t, ts, "/api/tasks/2/attachments/"+log.ID); wrong["error"] == nil {
			t.Errorf("deleting task 1's file through task 2 = %v", wrong)
		}
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "task.attachment_delete"})
		if err != nil || len(evs) != 1 {
			t.Fatalf("audit rows for the deletion = %d, %v", len(evs), err)
		}
		var payload map[string]any
		_ = json.Unmarshal([]byte(evs[0].Payload), &payload)
		if payload["attachment_id"] != chart.ID || payload["name"] != "plots/chart.png" {
			t.Errorf("audit payload = %v", payload)
		}
	})
}
