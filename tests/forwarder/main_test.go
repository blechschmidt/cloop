//go:build linux

package forwarder_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain isolates $HOME before anything runs. The hubs, agents and
// forwarders this test starts get homes of their own, but docker, ip, usbip
// and the build of cloop inherit this process's environment, and nothing they
// do belongs in the real one. tests/hermetic enforces it.
func TestMain(m *testing.M) {
	// Read before Isolate moves HOME: Go's build and module caches default to
	// directories under it, and a build of cloop against empty ones is a cold
	// compile that also needs the network for every module.
	goEnv = captureGoEnv()
	os.Exit(hometest.Isolate(m))
}

// goEnv carries GOCACHE, GOMODCACHE and GOPATH from the invoking environment
// into the build of cloop.
var goEnv []string

func captureGoEnv() []string {
	names := []string{"GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return nil
	}
	var env []string
	for i, v := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if i < len(names) && v != "" {
			env = append(env, names[i]+"="+v)
		}
	}
	return env
}
