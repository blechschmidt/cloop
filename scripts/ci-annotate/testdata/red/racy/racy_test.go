// Package racy has a data race under -race: two goroutines increment one
// counter unguarded. Without -race it passes. A fixture; see ../failing.
package racy

import (
	"sync"
	"testing"
)

type counter struct{ n int }

func (c *counter) inc() { c.n++ }

func TestRace(t *testing.T) {
	var c counter
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.inc()
		}()
	}
	wg.Wait()
	if c.n == 0 {
		t.Fatal("nothing was counted")
	}
}
