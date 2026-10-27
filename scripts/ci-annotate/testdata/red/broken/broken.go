// Package broken does not compile: Total calls a function nobody wrote, and
// returns the wrong type besides. A fixture; see ../failing.
package broken

// Total adds xs up.
func Total(xs []int) string { return sum(xs) }
