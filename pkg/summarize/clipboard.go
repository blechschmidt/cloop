package summarize

import (
	"os/exec"
	"strings"
)

// lookPath is a thin wrapper around exec.LookPath for testability.
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// runWithStdin runs a command, piping content to its stdin.
func runWithStdin(path string, args []string, content string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}
