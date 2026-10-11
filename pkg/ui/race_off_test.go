//go:build !race

package ui

// raceDetector reports whether this test binary was built with -race.
const raceDetector = false
