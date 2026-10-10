package diskwatch

import (
	"fmt"
	"runtime"
)

// LowPriority runs fn on an OS thread of its own whose CPU and I/O priority
// were lowered first — nice 19 and the idle I/O class on Linux — and waits for
// it to return. A panic in fn comes back as an error.
//
// The thread is never unlocked. A goroutine that exits still locked to its
// thread takes the thread with it (runtime.LockOSThread), so the lowered
// priority ends with the walk instead of returning to the scheduler's pool and
// slowing whatever goroutine lands there next; and the runtime starts new
// threads from a template thread rather than cloning a locked one, so it does
// not spread to them either.
//
// Lowering is best effort and its failure is not reported: a walk at normal
// priority is still bounded by its deadline, and refusing to measure would be
// the weaker outcome.
func LowPriority(fn func()) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("diskwatch: the walk panicked: %v", r)
				return
			}
			done <- nil
		}()
		_ = lowerThreadPriority()
		fn()
	}()
	return <-done
}
