package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

// TestMain lets this test binary serve as its own isolation probe.
//
// RunIsolationProbe binds the running executable into the sandbox, and under
// `go test` that is this binary rather than cloop. Answering probe mode here,
// before anything else, is what lets the probe's tests run the real probe under
// a real runtime without building cloop first.
//
// Anything else that reaches this binary under another name is refused rather
// than handed to m.Run: a copy of a test binary that falls through to the
// suite runs every test inside the sandbox, and every test there starts more
// sandboxes.
func TestMain(m *testing.M) {
	if isolationprobe.IsInvocation(os.Args) {
		os.Exit(isolationprobe.Main(os.Stdout, os.Stderr))
	}
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") {
		// The smoke tests run this binary bound in as `cloop version`, and
		// what they check is that the sandbox ran a host binary and heard back.
		// Before this guard the copy ran the whole suite inside the sandbox to
		// answer them.
		if len(os.Args) == 2 && os.Args[1] == "version" {
			fmt.Println("cloop version: this package's test binary, standing in for cloop")
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "refusing to run the test suite as %q: not a test binary\n", os.Args[0])
		os.Exit(2)
	}
	os.Exit(m.Run())
}
