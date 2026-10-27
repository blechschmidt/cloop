// Package passing passes, the noisy way: logs, subtests, a skip, parallel
// tests. Its output is what a green step looks like. A fixture; see
// ../failing.
package passing

import "testing"

func TestLogs(t *testing.T) {
	t.Log("FAIL is only a word here, and so is panic: and --- FAIL")
}

func TestSubtests(t *testing.T) {
	t.Run("one", func(t *testing.T) {})
	t.Run("two", func(t *testing.T) { t.Skip("skipped on purpose") })
}

func TestParallelA(t *testing.T) { t.Parallel() }

func TestParallelB(t *testing.T) { t.Parallel() }
