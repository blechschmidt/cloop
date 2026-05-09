package flow

// Regression tests: flow YAML Load reads workspace-relative files
// (.cloop/flows/*.yaml) through a size cap.
//
// Without a cap, a runaway file under .cloop/flows/ — or a user-supplied
// path pointing flow.Load at a multi-GB artifact — would be slurped into
// memory in full before the YAML parser ever sees it. boundedread.ReadFile
// stats the file first and refuses to load any payload that exceeds
// maxFlowYAMLBytes; the *boundedread.SizeError matches errors.Is(err,
// boundedread.ErrTooLarge).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/boundedread"
)

// validFlowYAML returns a minimal but valid flow YAML payload.
func validFlowYAML() []byte {
	return []byte(`name: bound-test
description: regression test flow
steps:
  - name: noop
    command: lint
`)
}

// TestLoad_OversizeRejected confirms an oversize flow file is rejected
// with *boundedread.SizeError before any payload is loaded.
func TestLoad_OversizeRejected(t *testing.T) {
	prev := maxFlowYAMLBytes
	maxFlowYAMLBytes = 256
	t.Cleanup(func() { maxFlowYAMLBytes = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	body := append(validFlowYAML(), make([]byte, 4096)...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load: want error, got nil")
	}
	if !errors.Is(err, boundedread.ErrTooLarge) {
		t.Fatalf("Load: want boundedread.ErrTooLarge, got %v", err)
	}
}

// TestLoad_UnderCapParses confirms a normally sized flow YAML parses
// correctly under the cap.
func TestLoad_UnderCapParses(t *testing.T) {
	prev := maxFlowYAMLBytes
	maxFlowYAMLBytes = 1 << 20
	t.Cleanup(func() { maxFlowYAMLBytes = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(path, validFlowYAML(), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Name != "bound-test" {
		t.Fatalf("Name mismatch: got %q", f.Name)
	}
	if len(f.Steps) != 1 || f.Steps[0].Command != "lint" {
		t.Fatalf("Steps mismatch: %+v", f.Steps)
	}
}

// TestLoad_MissingFile confirms that a missing flow file still produces a
// reasonable os.ErrNotExist-matching error rather than a generic
// boundedread complaint.
func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-such.yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load: want error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load: want os.ErrNotExist, got %v", err)
	}
}
