//go:build unix

package attachments

import "syscall"

// nonBlock keeps an open from waiting on a FIFO put where a file was: the
// store and the outbox are in a workload's reach.
const nonBlock = syscall.O_NONBLOCK
