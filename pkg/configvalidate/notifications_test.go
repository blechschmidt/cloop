package configvalidate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRefusesAPlaintextWebhook is the `cloop config validate` leg of
// the notifications rule (Task 20427): Load drops the webhook and keeps
// running, so this is where the operator's own text is judged.
func TestValidateRefusesAPlaintextWebhook(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "notifications:\n  webhooks:\n    - name: plain\n      type: json\n      url: http://collector.internal/hook\n"
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), dir, ValidateOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Field == "config.notifications" && f.Severity == SeverityError && strings.Contains(f.Message, "https") {
			return
		}
	}
	t.Fatalf("no error finding for the plaintext webhook: %+v", rep.Findings)
}
