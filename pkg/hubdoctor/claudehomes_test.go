package hubdoctor

// offboard.claude_homes (Task 20422): fail while the Claude Code home of an
// identity the control plane denies is still on this host, naming it; pass
// once it is gone; leave a held identity's and an admitted one's alone.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func seedDoctorClaudeHome(t *testing.T, root, key string) string {
	t.Helper()
	dir, err := claudecodeauth.HomePathIn(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudecodeauth.CredentialsPath(dir), []byte(`{"claudeAiOauth":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func claudeHomeFindings(t *testing.T, dir, root string) []Finding {
	t.Helper()
	return findingsFor(t, dir, hubCfg(), Options{Offline: true, ClaudeHomesRoot: root})["offboard.claude_homes"]
}

func TestClaudeLeftoversAreReported(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	db := openDoctorDB(t, dir)
	for _, email := range []string{"alice@example.com", "carol@example.com"} {
		if _, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectDeny, Claim: "email",
			Value: email, Reason: "left"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PutLegalHold(statedb.LegalHoldRow{Identity: "carol@example.com", Reason: "LH-2", PlacedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	alices := seedDoctorClaudeHome(t, root, "alice@example.com")
	seedDoctorClaudeHome(t, root, "bob@example.com")
	carols := seedDoctorClaudeHome(t, root, "carol@example.com")

	got := claudeHomeFindings(t, dir, root)
	if len(got) != 1 {
		t.Fatalf("%d findings: %+v", len(got), got)
	}
	f := got[0]
	wantSeverity(t, f, SeverityFail)
	for _, want := range []string{"1 Claude Code home", alices, "alice@example.com", "holding a login", "plaintext"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message does not say %q: %q", want, f.Message)
		}
	}
	if strings.Contains(f.Message, "bob@example.com") || strings.Contains(f.Message, carols) {
		t.Errorf("message names a home no sweep removes: %q", f.Message)
	}
	if !strings.Contains(f.Remediation, "rm -rf "+alices) {
		t.Errorf("remediation does not name the directory: %q", f.Remediation)
	}

	if err := os.RemoveAll(alices); err != nil {
		t.Fatal(err)
	}
	got = claudeHomeFindings(t, dir, root)
	if len(got) != 1 || got[0].Severity != SeverityPass {
		t.Fatalf("after removal: %+v, want one pass", got)
	}
}

func TestClaudeLeftoversWithNobodyDeniedPass(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	openDoctorDB(t, dir)
	seedDoctorClaudeHome(t, root, "bob@example.com")
	got := claudeHomeFindings(t, dir, root)
	if len(got) != 1 || got[0].Severity != SeverityPass || !strings.Contains(got[0].Message, "denies no identity") {
		t.Fatalf("%+v, want one pass saying nobody is denied", got)
	}
}
