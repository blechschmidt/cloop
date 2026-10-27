// Package panicking crashes its test binary: a method called on a nil
// pointer, a few frames below the test. A fixture; see ../failing.
package panicking

import "testing"

type config struct{ limits map[string]int }

func (c *config) limit(name string) int { return c.limits[name] }

func cpuLimit(c *config) int { return c.limit("cpu") }

func TestBeforeThePanic(t *testing.T) {}

func TestPanics(t *testing.T) {
	var c *config
	if cpuLimit(c) > 0 {
		t.Log("unreachable")
	}
}

// TestNeverRuns is named so a reader can see it was not reported: the binary
// died before it started.
func TestNeverRuns(t *testing.T) {}
