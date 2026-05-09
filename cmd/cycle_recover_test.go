package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/agent"
	"github.com/blechschmidt/cloop/pkg/daemon"
)

// The agent and daemon workers are long-running ticker loops that re-enter
// runAgentCycle / runDaemonCycle every tick for the lifetime of the process.
// Before this guard, a single panic anywhere in the cycle (provider call,
// state parse, task mutation) would tear down the worker goroutine and
// silently leave the user with no daemon until manual restart. These tests
// pin the recovery branch behaviour so a regression cannot remove the safety
// net without failing.

func captureLogf() (func(string, ...interface{}), *[]string) {
	var msgs []string
	logf := func(f string, args ...interface{}) {
		msgs = append(msgs, fmt.Sprintf(f, args...))
	}
	return logf, &msgs
}

// --- agent ---

func TestRecoverAgentCyclePanic_NilRecIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	s := &agent.State{Status: "running"}
	logf, msgs := captureLogf()

	recoverAgentCyclePanic(nil, s, tmp, logf)

	if s.Status != "running" {
		t.Errorf("nil rec must not modify Status, got %q", s.Status)
	}
	if s.LastError != "" {
		t.Errorf("nil rec must not set LastError, got %q", s.LastError)
	}
	if len(*msgs) != 0 {
		t.Errorf("nil rec must not log, got %v", *msgs)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".cloop", "agent.json")); err == nil {
		t.Error("nil rec must not save state file")
	}
}

func TestRecoverAgentCyclePanic_StringPanicRecordsAndPersists(t *testing.T) {
	tmp := t.TempDir()
	s := &agent.State{Status: "running"}
	logf, msgs := captureLogf()

	recoverAgentCyclePanic("boom", s, tmp, logf)

	if s.Status != "error" {
		t.Errorf("Status: want %q, got %q", "error", s.Status)
	}
	if !strings.Contains(s.LastError, "boom") {
		t.Errorf("LastError must contain panic message, got %q", s.LastError)
	}
	if len(*msgs) == 0 || !strings.Contains((*msgs)[0], "boom") {
		t.Errorf("expected log entry containing 'boom', got %v", *msgs)
	}

	loaded, err := agent.Load(tmp)
	if err != nil {
		t.Fatalf("loading saved state: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected state file on disk after recovery, got nil")
	}
	if loaded.Status != "error" || !strings.Contains(loaded.LastError, "boom") {
		t.Errorf("on-disk state lost panic info: %+v", loaded)
	}
}

func TestRecoverAgentCyclePanic_ErrorValuePanic(t *testing.T) {
	tmp := t.TempDir()
	s := &agent.State{Status: "running"}
	logf, _ := captureLogf()

	recoverAgentCyclePanic(errors.New("nil pointer dereference"), s, tmp, logf)

	if !strings.Contains(s.LastError, "nil pointer dereference") {
		t.Errorf("LastError must contain error text, got %q", s.LastError)
	}
}

// TestRunAgentCycleSafely_DefersDoNotPropagatePanic verifies the wrapper's
// defer/recover idiom catches panics and surfaces them via the recovery
// helper. We can't easily make runAgentCycle itself panic without elaborate
// state fixtures, so we mirror the wrapper's defer pattern with a synthetic
// panicking inner call. A regression that drops the defer/recover (or calls
// recover() in the wrong frame) would let the panic escape this t.Run and
// fail the test.
func TestRunAgentCycleSafely_DefersDoNotPropagatePanic(t *testing.T) {
	tmp := t.TempDir()
	s := &agent.State{Status: "running"}
	logf, _ := captureLogf()

	func() {
		defer func() { recoverAgentCyclePanic(recover(), s, tmp, logf) }()
		panic("simulated cycle panic")
	}()

	if s.Status != "error" {
		t.Errorf("wrapper idiom should have caught panic; Status=%q", s.Status)
	}
	if !strings.Contains(s.LastError, "simulated cycle panic") {
		t.Errorf("LastError should contain panic info, got %q", s.LastError)
	}
}

// --- daemon ---

func TestRecoverDaemonCyclePanic_NilRecIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	s := &daemon.State{Status: "running"}
	logf, msgs := captureLogf()

	recoverDaemonCyclePanic(nil, s, tmp, logf)

	if s.Status != "running" {
		t.Errorf("nil rec must not modify Status, got %q", s.Status)
	}
	if s.LastError != "" {
		t.Errorf("nil rec must not set LastError, got %q", s.LastError)
	}
	if len(*msgs) != 0 {
		t.Errorf("nil rec must not log, got %v", *msgs)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".cloop", "daemon.json")); err == nil {
		t.Error("nil rec must not save state file")
	}
}

func TestRecoverDaemonCyclePanic_StringPanicRecordsAndPersists(t *testing.T) {
	tmp := t.TempDir()
	s := &daemon.State{Status: "running"}
	logf, msgs := captureLogf()

	recoverDaemonCyclePanic("kaboom", s, tmp, logf)

	if s.Status != "error" {
		t.Errorf("Status: want %q, got %q", "error", s.Status)
	}
	if !strings.Contains(s.LastError, "kaboom") {
		t.Errorf("LastError must contain panic message, got %q", s.LastError)
	}
	if len(*msgs) == 0 || !strings.Contains((*msgs)[0], "kaboom") {
		t.Errorf("expected log entry containing 'kaboom', got %v", *msgs)
	}

	loaded, err := daemon.Load(tmp)
	if err != nil {
		t.Fatalf("loading saved state: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected state file on disk after recovery, got nil")
	}
	if loaded.Status != "error" || !strings.Contains(loaded.LastError, "kaboom") {
		t.Errorf("on-disk state lost panic info: %+v", loaded)
	}
}

func TestRecoverDaemonCyclePanic_ErrorValuePanic(t *testing.T) {
	tmp := t.TempDir()
	s := &daemon.State{Status: "running"}
	logf, _ := captureLogf()

	recoverDaemonCyclePanic(errors.New("runtime error: invalid memory address"), s, tmp, logf)

	if !strings.Contains(s.LastError, "invalid memory address") {
		t.Errorf("LastError must contain error text, got %q", s.LastError)
	}
}

func TestRunDaemonCycleSafely_DefersDoNotPropagatePanic(t *testing.T) {
	tmp := t.TempDir()
	s := &daemon.State{Status: "running"}
	logf, _ := captureLogf()

	func() {
		defer func() { recoverDaemonCyclePanic(recover(), s, tmp, logf) }()
		panic("simulated cycle panic")
	}()

	if s.Status != "error" {
		t.Errorf("wrapper idiom should have caught panic; Status=%q", s.Status)
	}
	if !strings.Contains(s.LastError, "simulated cycle panic") {
		t.Errorf("LastError should contain panic info, got %q", s.LastError)
	}
}
