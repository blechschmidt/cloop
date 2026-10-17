package main

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/cmd"
	// Before bubbletea's init can query the terminal and wait five seconds
	// for an answer that, under a script's pty, never comes.
	_ "github.com/blechschmidt/cloop/internal/termquery"
	"github.com/blechschmidt/cloop/pkg/caps"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

func main() {
	// The isolation probe (Task 20439) runs inside a sandbox, bound in from
	// outside its image, with no configuration, home or writable filesystem to
	// rely on: it leaves before anything else in the binary runs.
	if isolationprobe.IsInvocation(os.Args) {
		os.Exit(isolationprobe.Main(os.Stdout, os.Stderr))
	}
	// Before anything can start a child process: a capability this process
	// was started with — the executor agent's CAP_NET_ADMIN — stays with it
	// and never reaches a workload. See pkg/caps.
	if err := caps.Confine(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	cmd.Execute()
}
