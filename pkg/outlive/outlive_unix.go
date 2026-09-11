//go:build unix

package outlive

import (
	"os"
	"os/signal"
	"syscall"
)

// keepStdioWritesNonFatal demotes SIGPIPE from a fatal signal to an ordinary
// EPIPE error return on writes to file descriptors 1 and 2.
//
// The mechanism is os/signal's documented special case: the runtime only makes
// SIGPIPE fatal for a program that has *not* asked to receive it. Asking is
// therefore the whole fix, and the channel is a formality — it exists because
// Notify requires one, not because anything acts on what arrives.
//
// Which is why nothing drains it. Notify sends non-blockingly and drops when
// the buffer is full, so an undrained channel costs one buffered value and no
// goroutine; a drain loop here would be a goroutine living for the life of the
// process to discard every value it received. Verified behaviourally rather
// than assumed: see TestControlPlaneSurvivesABrokenStdoutPipe, which kills the
// reader and asserts the child finishes its work.
func keepStdioWritesNonFatal() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}
