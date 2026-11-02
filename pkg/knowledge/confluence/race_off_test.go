//go:build !race

package confluence

// raceDetector reports whether this test binary was built with -race.
const raceDetector = false
