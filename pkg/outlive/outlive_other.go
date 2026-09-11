//go:build !unix

package outlive

// keepStdioWritesNonFatal is a no-op off Unix. SIGPIPE is a POSIX signal and
// the fatal-on-descriptors-1-and-2 rule it triggers is specific to the Go
// runtime's Unix implementation, so there is nothing here to demote: a write to
// a broken pipe already surfaces as an error to the caller.
func keepStdioWritesNonFatal() {}
