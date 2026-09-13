package cmd

// Tests for readMintPayload's source precedence.
//
// The case that motivated them is `--file -`. It is the conventional spelling
// for stdin and the natural way to feed in a multi-line host_device inventory,
// and reading it literally turned the documented command into
// "open -: no such file or directory" — an error naming neither the mistake nor
// the fix. These pin the behaviour so it cannot regress into a filename again.

import (
	"os"
	"strings"
	"testing"
)

// withMintFlags isolates the package-level flag variables, which persist
// between tests because cobra binds them once at init.
func withMintFlags(t *testing.T, file, value string) {
	t.Helper()
	origFile, origValue := mintFileFlag, mintValueFlag
	mintFileFlag, mintValueFlag = file, value
	t.Cleanup(func() { mintFileFlag, mintValueFlag = origFile, origValue })
}

// withStdin replaces os.Stdin with a pipe carrying payload. A pipe rather than a
// file because the production check is `ModeCharDevice`, and only a pipe
// exercises the branch a shell heredoc actually takes.
func withStdin(t *testing.T, payload string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		defer w.Close()
		_, _ = w.WriteString(payload)
	}()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig; r.Close() })
}

const inventory = "serial0=/dev/ttyUSB0\nanalyser=/dev/ttyACM0:r\n"

func TestMintFileDashReadsStdin(t *testing.T) {
	withMintFlags(t, "-", "")
	withStdin(t, inventory)

	got, err := readMintPayload(nil)
	if err != nil {
		t.Fatalf("--file - rejected the payload on stdin: %v", err)
	}
	if string(got) != inventory {
		t.Errorf("--file - returned %q, want the inventory piped in", got)
	}
}

// TestMintFileDashBeatsValue guards the precedence. --file was passed
// explicitly, so falling through to --value would seal a different credential
// than the one the operator piped in — the worst outcome available here, and
// silent.
func TestMintFileDashBeatsValue(t *testing.T) {
	withMintFlags(t, "-", "a-different-secret")
	withStdin(t, inventory)

	got, err := readMintPayload(nil)
	if err != nil {
		t.Fatalf("readMintPayload: %v", err)
	}
	if string(got) != inventory {
		t.Errorf("an explicit --file - was overridden by --value; got %q", got)
	}
}

// TestMintFileDashOnATerminalExplainsItself covers the operator who types
// `--file -` and forgets to pipe anything. /dev/null is a character device, so
// it reaches the same branch an interactive terminal would.
func TestMintFileDashOnATerminalExplainsItself(t *testing.T) {
	withMintFlags(t, "-", "")
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	orig := os.Stdin
	os.Stdin = devNull
	t.Cleanup(func() { os.Stdin = orig })

	_, err = readMintPayload(nil)
	if err == nil {
		t.Fatal("--file - with no payload on stdin succeeded")
	}
	if !strings.Contains(err.Error(), "stdin") {
		t.Errorf("error %q does not mention stdin, so it does not name the fix", err)
	}
}

// TestMintRealFileStillWins keeps the ordinary path intact: only the exact
// string "-" is special, and a real path must not be diverted to stdin.
func TestMintRealFileStillWins(t *testing.T) {
	path := t.TempDir() + "/bench-hw.txt"
	if err := os.WriteFile(path, []byte(inventory), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	withMintFlags(t, path, "")
	withStdin(t, "this must not be read")

	got, err := readMintPayload(nil)
	if err != nil {
		t.Fatalf("readMintPayload: %v", err)
	}
	if string(got) != inventory {
		t.Errorf("a real --file path read %q; stdin shadowed the file", got)
	}
}

func TestMintValueStillWorks(t *testing.T) {
	withMintFlags(t, "", "/srv/git")
	got, err := readMintPayload(nil)
	if err != nil {
		t.Fatalf("readMintPayload: %v", err)
	}
	if string(got) != "/srv/git" {
		t.Errorf("--value returned %q", got)
	}
}
