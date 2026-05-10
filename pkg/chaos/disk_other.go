//go:build !unix

package chaos

// isENOSPC stub for non-unix platforms. We never compile cloop for Windows in
// CI, but we keep the door open with a benign no-op.
func isENOSPC(error) bool { return false }
