package imagepolicy

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestMain isolates $HOME: DockerConfigCredential reads ~/.docker/config.json,
// and a test must find the logins it set up, never the developer's.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}
