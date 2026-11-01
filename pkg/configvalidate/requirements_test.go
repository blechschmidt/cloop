package configvalidate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRefusesAnUnknownRequirementsGate is the `cloop config validate`
// leg of the requirements gate's rule (Task 20461): Load drops a mode it does
// not know and keeps running, so this is where the file's own text is judged.
func TestValidateRefusesAnUnknownRequirementsGate(t *testing.T) {
	for body, wantError := range map[string]bool{
		"requirements:\n  gate: sometimes\n":   true,
		"requirements:\n  gate: linked+must\n": false,
		"requirements:\n  assess: true\n":      false,
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := Run(context.Background(), dir, ValidateOptions{})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		found := false
		for _, f := range rep.Findings {
			if f.Field == "config.requirements.gate" && f.Severity == SeverityError && strings.Contains(f.Message, "linked+must") {
				found = true
			}
		}
		if found != wantError {
			t.Errorf("%q: error finding = %v, want %v (%+v)", body, found, wantError, rep.Findings)
		}
	}
}
