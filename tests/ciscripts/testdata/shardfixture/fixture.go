// Package shardfixture is what tests/ciscripts shards: tests whose names are
// prefixes of one another, a fuzz target, an example and a benchmark, and a
// little code for their coverage profiles to cover. It is under testdata so
// that `go test ./...` never runs it; the scripts name it explicitly.
package shardfixture

// Sign says whether n is negative, zero or positive.
func Sign(n int) string {
	switch {
	case n < 0:
		return "negative"
	case n == 0:
		return "zero"
	}
	return "positive"
}

// Double returns 2n.
func Double(n int) int { return 2 * n }

// Triple returns 3n. No test calls it, so no profile covers it.
func Triple(n int) int { return 3 * n }
