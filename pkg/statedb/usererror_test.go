package statedb

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// TestUserErrorfShowsProseAndMatchesSentinel is the contract in one test: the
// message is what a person reads, the sentinel is what code matches. Both at
// once is the whole reason the type exists.
func TestUserErrorfShowsProseAndMatchesSentinel(t *testing.T) {
	err := UserErrorf(ErrProjectNotFound, "no cloop project found (run 'cloop init' first)")

	const want = "no cloop project found (run 'cloop init' first)"
	if got := err.Error(); got != want {
		t.Errorf("Error() must be the prose alone:\nwant: %q\ngot:  %q", want, got)
	}
	if !errors.Is(err, ErrProjectNotFound) {
		t.Error("errors.Is must still match the sentinel")
	}
	// The regression this guards: fmt.Errorf("%w") appended the sentinel's own
	// text, which is how "statedb: project not found" reached the terminal.
	if got := err.Error(); got != want {
		t.Errorf("the sentinel's text must not appear in the message, got %q", got)
	}
}

// TestUserErrorfSurvivesFurtherWrapping matters because these errors do not go
// straight to the terminal — they pass back through callers that add their own
// context, and the sentinel has to survive that.
func TestUserErrorfSurvivesFurtherWrapping(t *testing.T) {
	base := UserErrorf(ErrTaskNotFound, "no task plan found")
	wrapped := fmt.Errorf("replay: %w", base)

	if !errors.Is(wrapped, ErrTaskNotFound) {
		t.Error("the sentinel must survive an outer %w wrap")
	}
	if got, want := wrapped.Error(), "replay: no task plan found"; got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// TestUserErrorfDoesNotMatchOtherSentinels: carrying one sentinel must not make
// an error match its neighbours, or every 404 would also be a 409.
func TestUserErrorfDoesNotMatchOtherSentinels(t *testing.T) {
	err := UserErrorf(ErrProjectNotFound, "no cloop project found")
	for _, other := range []error{ErrTaskNotFound, ErrStaleVersion, ErrDBLocked, ErrSchemaMismatch} {
		if errors.Is(err, other) {
			t.Errorf("must not match %v", other)
		}
	}
}

// TestUserErrorfFeedsHTTPStatus closes the loop on the reason the sentinel had
// to be kept at all: the HTTP layer picks a status code by matching it.
func TestUserErrorfFeedsHTTPStatus(t *testing.T) {
	if got := HTTPStatus(UserErrorf(ErrProjectNotFound, "no cloop project found")); got != http.StatusNotFound {
		t.Errorf("want 404, got %d", got)
	}
	if got := HTTPStatus(UserErrorf(ErrStaleVersion, "the plan changed under you")); got != http.StatusConflict {
		t.Errorf("want 409, got %d", got)
	}
}

// TestUserErrorfFormats: the constructor takes a format string, so a message
// can name the thing it could not find.
func TestUserErrorfFormats(t *testing.T) {
	err := UserErrorf(ErrTaskNotFound, "no task with id %d in this plan", 42)
	if got, want := err.Error(), "no task with id 42 in this plan"; got != want {
		t.Errorf("want %q, got %q", want, got)
	}
	if !errors.Is(err, ErrTaskNotFound) {
		t.Error("formatting must not cost the sentinel")
	}
}

// TestUserErrorfNilSentinelDegradesGracefully: a caller that forgets the
// sentinel should still get a usable error rather than one that silently
// matches nothing and, worse, panics on Unwrap.
func TestUserErrorfNilSentinelDegradesGracefully(t *testing.T) {
	err := UserErrorf(nil, "something went wrong with %s", "the thing")
	if err == nil {
		t.Fatal("want an error even without a sentinel")
	}
	if got, want := err.Error(), "something went wrong with the thing"; got != want {
		t.Errorf("want %q, got %q", want, got)
	}
	if errors.Unwrap(err) != nil {
		t.Error("a nil sentinel must not produce a non-nil unwrap")
	}
}
