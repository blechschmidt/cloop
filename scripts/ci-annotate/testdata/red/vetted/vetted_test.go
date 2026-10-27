// Package vetted compiles and fails the vet checks go test runs before it
// tests: a format verb that does not match its argument. A fixture; see
// ../failing.
package vetted

import (
	"fmt"
	"testing"
)

func TestFormat(t *testing.T) {
	fmt.Printf("%d tasks\n", "seven")
}
