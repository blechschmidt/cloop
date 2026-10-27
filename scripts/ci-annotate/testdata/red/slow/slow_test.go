// Package slow outlives any short -timeout: a subtest sleeps for an hour
// while a parallel test waits on it. A fixture; see ../failing.
package slow

import (
	"testing"
	"time"
)

func TestHangs(t *testing.T) {
	t.Run("waiting on the store", func(t *testing.T) {
		time.Sleep(time.Hour)
	})
}

func TestFinishes(t *testing.T) {}
