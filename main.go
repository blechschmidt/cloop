package main

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/cmd"
	"github.com/blechschmidt/cloop/pkg/caps"
)

func main() {
	// Before anything can start a child process: a capability this process
	// was started with — the executor agent's CAP_NET_ADMIN — stays with it
	// and never reaches a workload. See pkg/caps.
	if err := caps.Confine(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	cmd.Execute()
}
