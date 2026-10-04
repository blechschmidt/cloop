// Package termquery keeps cloop from questioning the terminal as it starts
// (Task 20374). It has no API: importing it is the whole effect, and main
// imports it.
//
// bubbletea v1's tea_init.go calls lipgloss.HasDarkBackground in a package
// init, so that the answer is cached before a Program takes over the terminal.
// Asking means writing an OSC 11 background-colour query and a cursor-position
// request (ESC ]11;? and ESC [6n) to the terminal and reading the reply — and
// termenv waits up to five seconds for one. Every cloop command links
// bubbletea, for its five TUIs, so every command whose stdout is a terminal
// asked, whatever it was going to do. Under a pseudo-terminal that never
// answers — expect, `docker exec -t` or `kubectl exec -t` from a script, a CI
// job with a tty — each `cloop status` took 5.05 s instead of 0.03 s, and the
// query bytes led its output.
//
// cloop never uses the answer: it has no AdaptiveColor, the only thing lipgloss
// consults the background for. So the answer is given instead of asked for, in
// an init that Go runs before bubbletea's. Go initialises, at each step, the
// first package in import-path order whose imports are all initialised, and
// this package imports nothing but lipgloss, which bubbletea imports too: the
// moment bubbletea could be initialised so could this package, and
// "github.com/blechschmidt/..." sorts before "github.com/charmbracelet/...".
// GODEBUG=inittrace=1 shows the order, and tests/e2e checks it.
//
// The answer given is "dark", which is also what termenv concludes when a
// terminal does not reply. bubbletea's own comment calls its init a workaround
// to be dropped in v2; when it goes, so can this.
package termquery

import "github.com/charmbracelet/lipgloss"

func init() {
	lipgloss.SetHasDarkBackground(true)
}
