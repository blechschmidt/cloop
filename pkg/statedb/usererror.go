// usererror.go: errors with two audiences (Task 20294).
//
// The sentinels in errors.go are written for code. Their text names a Go
// variable — "statedb: project not found" — which is the right thing for a
// reader of a stack trace and the wrong thing for a person who has just typed
// their first cloop command.
//
// fmt.Errorf cannot serve both, because %w concatenates. Wrapping a helpful
// sentence around ErrProjectNotFound produced
//
//	no cloop project found (run 'cloop init' first): statedb: project not found
//
// where the half before the colon tells the reader exactly what to do and the
// half after it is noise that makes the whole line read like a crash. Dropping
// the wrap is not an option either: errors.Is on these sentinels is how the
// HTTP layer picks a status code and how callers tell "there is no project
// here" apart from a genuine storage failure.
//
// So the two audiences are separated rather than concatenated.

package statedb

import "fmt"

// userError reports a message written for a person while remaining, to
// errors.Is and errors.As, the sentinel it carries.
//
// Error and Unwrap deliberately disagree about what this error "is": that
// disagreement is the whole point. Unwrap keeps the sentinel reachable, so
// nothing about error matching changes; Error omits it, so nothing about the
// sentinel reaches the terminal.
type userError struct {
	msg      string
	sentinel error
}

func (e *userError) Error() string { return e.msg }

// Unwrap returns the sentinel, which is what makes errors.Is(err, ErrXxx)
// continue to hold even though Error never mentions it.
func (e *userError) Unwrap() error { return e.sentinel }

// UserErrorf returns an error that prints as the formatted message and matches
// sentinel under errors.Is.
//
// Use it wherever a sentinel would otherwise be wrapped in prose the user is
// meant to read:
//
//	return statedb.UserErrorf(statedb.ErrProjectNotFound,
//		"no cloop project found (run 'cloop init' first)")
//
// prints "no cloop project found (run 'cloop init' first)" and still satisfies
// errors.Is(err, statedb.ErrProjectNotFound).
//
// format is rendered with fmt.Sprintf, so it takes ordinary verbs but not %w —
// this constructor already owns the wrapping. A nil sentinel degrades to a
// plain fmt.Errorf rather than producing an error that matches nothing, so a
// caller that passes one by mistake still gets a usable message.
func UserErrorf(sentinel error, format string, args ...any) error {
	if sentinel == nil {
		return fmt.Errorf(format, args...)
	}
	return &userError{msg: fmt.Sprintf(format, args...), sentinel: sentinel}
}
