package offboard

// This package imports pkg/multiui, which owns ~/.cloop/projects.json, so its
// tests could otherwise read and write the registry of the machine they run
// on. Isolating $HOME keeps the suite hermetic — see tests/hermetic.

import (
	"os"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }
