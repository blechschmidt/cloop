// Package exits passes every test and still fails: its TestMain exits 3
// after them. No test is to blame. A fixture; see ../failing.
package exits

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	m.Run()
	fmt.Println("the fixture's server did not shut down")
	os.Exit(3)
}

func TestPasses(t *testing.T) {}
