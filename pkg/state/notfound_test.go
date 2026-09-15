package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The message Load and LoadLite produce outside a project is the first thing a
// new user sees, and the sentinel behind it is how the HTTP layer picks a
// status code. Task 20294 separated the two; these tests hold both halves
// together, because it is easy to "simplify" either one into breaking the
// other.

// TestLoadOutsideProjectKeepsTheSentinel: the text changed, the matching must
// not have.
func TestLoadOutsideProjectKeepsTheSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func(string) (*ProjectState, error)
	}{
		{"Load", Load},
		{"LoadLite", LoadLite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.load(t.TempDir())
			if err == nil {
				t.Fatal("loading a directory with no project must fail")
			}
			if !errors.Is(err, statedb.ErrProjectNotFound) {
				t.Errorf("errors.Is(err, ErrProjectNotFound) must hold, got %#v", err)
			}

			const want = "no cloop project found (run 'cloop init' first)"
			if got := err.Error(); got != want {
				t.Errorf("the message must be the prose alone:\nwant: %q\ngot:  %q", want, got)
			}
			// The specific regression: %w used to append the sentinel's own
			// text, so the line ended "...: statedb: project not found".
			if strings.Contains(err.Error(), "statedb:") {
				t.Errorf("an internal sentinel's text must not reach the user: %q", err.Error())
			}
		})
	}
}

// TestLoadOutsideProjectMapsTo404 is why the sentinel had to be preserved at
// all rather than simply dropped along with the wrap.
func TestLoadOutsideProjectMapsTo404(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("loading a directory with no project must fail")
	}
	if got := statedb.HTTPStatus(err); got != 404 {
		t.Errorf("want 404 for a missing project, got %d", got)
	}
}
