package apiserver

// Regression tests for boundedread caps on handleMetrics and handleArtifact.
//
// Both handlers serve the contents of files written elsewhere on the host
// (.cloop/metrics.json, .cloop/tasks/<id>-*.md). A corrupted, runaway, or
// hostile file would otherwise be loaded fully into memory before the
// response is written — and for the JSON branch of either handler, the
// content is re-encoded into a JSON envelope, doubling allocation. The
// bounded read returns 413 Payload Too Large instead of OOM-ing the daemon.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBigFile creates a path of exactly size bytes filled with 'x'.
func writeBigFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = 'x'
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestHandleMetrics_OversizeReturns413 confirms that pointing the API server
// at a metrics.json larger than maxMetricsFileBytes results in a 413 response
// rather than the file being loaded into memory and re-encoded.
func TestHandleMetrics_OversizeReturns413(t *testing.T) {
	dir := t.TempDir()
	metricsPath := filepath.Join(dir, ".cloop", "metrics.json")
	// Write maxMetricsFileBytes+1 so the size check fails strictly.
	writeBigFile(t, metricsPath, int(maxMetricsFileBytes)+1)

	s := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversize metrics file, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

// TestHandleMetrics_HappyPath confirms the handler still serves a
// well-formed JSON metrics file with a 200 OK and the original bytes intact.
func TestHandleMetrics_HappyPath(t *testing.T) {
	dir := t.TempDir()
	metricsPath := filepath.Join(dir, ".cloop", "metrics.json")
	if err := os.MkdirAll(filepath.Dir(metricsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := `{"counter":{"foo":42}}`
	if err := os.WriteFile(metricsPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"foo":42`) {
		t.Fatalf("expected metrics body to be served verbatim, got %q", rr.Body.String())
	}
}

// TestHandleMetrics_MissingFileReturns200Empty confirms a missing metrics
// file is treated as "no data yet" rather than an error — preserves the
// pre-fix behaviour for the common case of an empty project.
func TestHandleMetrics_MissingFileReturns200Empty(t *testing.T) {
	dir := t.TempDir() // no .cloop/metrics.json written

	s := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for missing metrics file, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "no metrics data yet") {
		t.Fatalf("expected 'no metrics data yet' message, got %q", rr.Body.String())
	}
}

// TestHandleArtifact_OversizeReturns413 confirms a runaway task artifact
// (e.g. an AI that wrote a 50 MiB markdown file) is rejected at the bounded
// read rather than loaded into memory and JSON-escaped.
func TestHandleArtifact_OversizeReturns413(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, ".cloop", "tasks", "7-some-task.md")
	writeBigFile(t, artifactPath, int(maxArtifactFileBytes)+1)

	s := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/artifacts/7", nil)
	req.SetPathValue("taskId", "7")
	rr := httptest.NewRecorder()
	s.handleArtifact(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversize artifact, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

// TestHandleArtifact_HappyPath confirms a normally-sized artifact is still
// served verbatim with a 200.
func TestHandleArtifact_HappyPath(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, ".cloop", "tasks", "12-foo.md")
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "# Task 12\n\nWork report.\n"
	if err := os.WriteFile(artifactPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := &Server{WorkDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/artifacts/12", nil)
	req.SetPathValue("taskId", "12")
	rr := httptest.NewRecorder()
	s.handleArtifact(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Work report.") {
		t.Fatalf("expected artifact body to be served verbatim, got %q", rr.Body.String())
	}
}
