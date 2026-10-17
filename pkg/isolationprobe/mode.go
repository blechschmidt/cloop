package isolationprobe

import (
	"fmt"
	"io"
)

// IsInvocation reports whether args — os.Args — ask for probe mode: exactly
// `cloop isolation-probe`, nothing before or after it.
//
// Exact on purpose. The mode is entered before the CLI parses anything, so it
// must not swallow an invocation meant for a command: anything more than the
// bare argument goes to the CLI, which knows no such command and says so.
func IsInvocation(args []string) bool {
	return len(args) == 2 && args[1] == Arg
}

// Main is probe mode: collect the evidence the kernel gives this process and
// write it to stdout as one line. It returns the process's exit code.
//
// It touches nothing but the kernel interfaces Collect reads. A sandbox runs it
// with a read-only root filesystem, no network, no capabilities and an unknown
// user — and as a binary bound in from outside an image whose own files it
// never opens.
func Main(stdout, stderr io.Writer) int {
	out, err := Encode(Collect())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "isolationprobe: write evidence:", err)
		return 1
	}
	return 0
}
