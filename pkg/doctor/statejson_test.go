package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

// stateJSONResults runs checkStateJSON against dir and returns what it added.
func stateJSONResults(t *testing.T, dir string) []Result {
	t.Helper()
	var got []Result
	checkStateJSON(dir, func(r Result) { got = append(got, r) })
	return got
}

// TestStateJSONAbsentReportsNothing: project state lives in state.db, so a
// project without a legacy state.json is the normal case. A warning for it
// would never clear, however many runs the project had.
func TestStateJSONAbsentReportsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := stateJSONResults(t, dir); len(got) != 0 {
		t.Fatalf("a project with no state.json got %d result(s), want none: %+v", len(got), got)
	}
}

// TestStateJSONPresentIsValidated: a state.json that is there (an older
// cloop's, or a project seed waiting to be migrated) is still checked.
func TestStateJSONPresentIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want Level
	}{
		{"valid", `{"goal":"g","tasks":[]}`, Pass},
		{"invalid", `{"goal":`, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := stateJSONResults(t, dir)
			if len(got) != 1 || got[0].Level != tc.want {
				t.Fatalf("got %+v, want one result at level %v", got, tc.want)
			}
		})
	}
}
