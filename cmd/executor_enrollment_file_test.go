package cmd

// An installed agent passes --token-file on every start, but the token behind
// it is single-use and the agent deletes it the moment enrollment succeeds. So
// "the file is gone" is the steady state of a working device, and the startup
// path has to tell that apart from "the path is wrong".
//
// Getting it backwards is not a cosmetic bug: the unit restarts on failure, so
// a device that refuses to start without the spent token restarts forever, with
// a perfectly good credential sitting unread next to the file it is missing.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestEnrollmentFileAbsentIsNotAnError is the regression. A device enrolled
// yesterday has no enrollment file today; that must not stop it starting.
func TestEnrollmentFileAbsentIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.tok")

	b, warning, present, err := loadEnrollmentFile(path)
	if err != nil {
		t.Fatalf("a spent enrollment file must not be an error, got %v", err)
	}
	if present {
		t.Error("present = true for a file that does not exist")
	}
	if warning != "" {
		t.Errorf("warning = %q, want empty", warning)
	}
	if b.Token != "" || b.Server != "" {
		t.Errorf("absent file yielded material: %+v", b)
	}
}

// TestEnrollmentFilePresentIsRead keeps the first-boot path working: the file
// the installer wrote is still what the device enrolls with.
func TestEnrollmentFilePresentIsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.tok")
	if err := os.WriteFile(path, []byte("tok_abc123\n"), remote.TokenFileMode); err != nil {
		t.Fatal(err)
	}

	b, _, present, err := loadEnrollmentFile(path)
	if err != nil {
		t.Fatalf("loadEnrollmentFile: %v", err)
	}
	if !present {
		t.Error("present = false for a file that exists")
	}
	if b.Token != "tok_abc123" {
		t.Errorf("Token = %q, want tok_abc123", b.Token)
	}
}

// TestEnrollmentFileMalformedStaysFatal draws the other edge of the line. Only
// absence means "already enrolled"; a file that exists but cannot be used is a
// provisioning mistake, and swallowing it would strand a device that never
// enrolled in the first place.
func TestEnrollmentFileMalformedStaysFatal(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty", "   \n"},
		{"not a token", "this is prose, not a token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.body), remote.TokenFileMode); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := loadEnrollmentFile(path); err == nil {
				t.Fatal("a malformed enrollment file must stay fatal")
			} else if errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("malformed file reported as absent: %v", err)
			}
		})
	}
}

// TestEnrollmentFileUnsetIsNotAnError covers the operator who passes --token
// directly and never names a file.
func TestEnrollmentFileUnsetIsNotAnError(t *testing.T) {
	if _, _, present, err := loadEnrollmentFile("  "); err != nil || present {
		t.Fatalf("unset --token-file: present=%v err=%v, want false/nil", present, err)
	}
}

// TestEnrolledAgentStartsAfterItsTokenIsRetired is the end-to-end shape of the
// bug, across both halves of the fix: the agent retires the token on enrolling,
// and the next start has to succeed on the credential alone.
//
// It drives agent.New rather than the cobra command because that is where the
// "can this device authenticate" decision actually lives — the command's job is
// only to stop short-circuiting it.
func TestEnrolledAgentStartsAfterItsTokenIsRetired(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "agent.json")
	tokenPath := filepath.Join(dir, "enroll.tok")

	// Stand in for a completed enrollment: a durable credential on disk, and
	// the spent token already deleted.
	if err := agent.SaveCredential(credPath, agent.Credential{
		Server:      "wss://hub.example:8888/api/executors/connect",
		AgentID:     "exec-sgx",
		Name:        "sgx",
		Credential:  "cred-secret-value",
		WorkDirRoot: filepath.Join(dir, "work"),
	}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if _, err := os.Stat(tokenPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("precondition: token file should be absent, stat gave %v", err)
	}

	// Exactly what the installed unit re-executes on restart.
	_, warning, _, err := loadEnrollmentFile(tokenPath)
	if err != nil {
		t.Fatalf("restart must tolerate the retired token file: %v", err)
	}
	if warning != "" {
		t.Errorf("unexpected warning: %q", warning)
	}

	a, err := agent.New(agent.Config{
		Server:         "wss://hub.example:8888/api/executors/connect",
		TokenFile:      tokenPath,
		CredentialPath: credPath,
		WorkDirRoot:    filepath.Join(dir, "work"),
		Logf:           func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("an enrolled device must start without its spent token: %v", err)
	}
	if a == nil {
		t.Fatal("agent.New returned nil without an error")
	}
}

// TestUnenrolledAgentNamesTheEnrollmentFile: the tolerance above must not cost
// a genuinely unenrolled device its diagnosis. Saying "no --token was given" to
// an operator who passed --token-file sends them looking in the wrong place.
func TestUnenrolledAgentNamesTheEnrollmentFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "enroll.tok")

	_, err := agent.New(agent.Config{
		Server:         "wss://hub.example:8888/api/executors/connect",
		TokenFile:      tokenPath,
		CredentialPath: filepath.Join(dir, "agent.json"),
		WorkDirRoot:    filepath.Join(dir, "work"),
		Logf:           func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("an unenrolled device with no token must still refuse to start")
	}
	if !strings.Contains(err.Error(), tokenPath) {
		t.Errorf("error must name the enrollment file %s, got: %v", tokenPath, err)
	}
}
