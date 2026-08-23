package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain redirects the per-user state directory at a temporary one for the
// whole pkg/ui test binary, and replaces the binary its handlers fork with a
// stub.
//
// This package is where the leak that motivated it lived. POST
// /api/projects/new registers the created project in the global
// ~/.cloop/projects.json, and TestProjectNewDoesNotGrantWhatTheCallerMayNotGrant
// exercises that route without an isolated HOME — so every run appended an
// entry to the developer's real registry and left it there. At 99 entries,
// project index 99 resolved to a deleted /tmp directory and
// TestScopeForNeverSilentlyWidens, TestProjectExecutorBind_RejectsBadIndex and
// TestUnresolvableProjectIdxDoesNotFallBackToGlobalScope all began failing —
// on a developer's machine only, since CI runners start from an empty HOME.
//
// The exec stub closes the second half of the same hole. Under `go test`,
// os.Executable() is the compiled test binary, so every handler that shells out
// to a cloop subcommand — that same /api/projects/new running `init`, the run
// endpoints running `run`, plus reset, chat, voice and suggest — was re-running
// this package's entire test suite as a child process, with argv like
// `ui.test init ordinary project --skip-clarify`. The child eventually exits and
// the parent subtest passes either way, so nothing ever pointed at it; the only
// symptom was pkg/ui taking ten minutes, which is over `go test`'s default
// per-package timeout and was failing CI outright.
//
// Both live here rather than in the one test that tripped them: 50 test files in
// this package reach handlers that touch the registry or fork, and the next one
// to be added should not have to know that.
func TestMain(m *testing.M) {
	stub, cleanup, err := writeExecStub()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pkg/ui tests: cannot create the exec stub: %v\n", err)
		os.Exit(1)
	}
	defaultSelfExe = stub

	code := hometest.Isolate(m)
	cleanup()
	os.Exit(code)
}

// writeExecStub creates an executable that succeeds silently, standing in for
// the cloop binary. It gets its own temp dir rather than t.TempDir() because
// TestMain has no *testing.T, and removes it explicitly so the suite leaves
// nothing behind.
func writeExecStub() (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "cloop-ui-exec-stub")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	path = filepath.Join(dir, "cloop-stub")
	if runtime.GOOS == "windows" {
		path += ".bat"
		err = os.WriteFile(path, []byte("@echo off\r\nexit /b 0\r\n"), 0o700)
	} else {
		err = os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700)
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
