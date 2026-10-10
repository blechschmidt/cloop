package cmd

// `cloop hub user offboard` and what the departed person keeps on the hub
// (Task 20400): personal secrets, the grants over them, Claude Code logins.
//
// Run from a shell without CLOOP_SECRET_KEY — the emergency the command is
// for — with a stand-in `claude` on PATH, so the logout it runs is observed
// rather than sent to Anthropic.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// offboardWorld is a hub directory where alice keeps a personal PAT granted
// to a shared project and a Claude login, and the log a fake `claude` writes.
type offboardWorld struct {
	dir, secretID, grantID, home, claudeLog string
}

func newOffboardWorld(t *testing.T) offboardWorld {
	t.Helper()
	w := offboardWorld{dir: hubDir(t)}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// Seeding needs the key — the session store seals with it, and minting
	// does — and the offboarding below runs without one. Set before the first
	// seal, so an ambient key in the test's environment cannot create a key
	// this test cannot derive.
	t.Setenv(secretbroker.EnvPassphraseKey, "cmd-offboard-test-passphrase")
	seedSessions(t, w.dir, map[string]string{"sess-alice": "alice@example.com"})
	db, err := statedb.Open(state.DBPath(w.dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{Name: "alice-pat",
		Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_ALICEALICEALICEALICEALICEALICE0000"),
		Actor: "alice@example.com", Owner: "alice@example.com", Personal: true})
	if err != nil {
		t.Fatal(err)
	}
	g, err := broker.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/shared"},
		Constraints: secretbroker.Constraints{Repos: []string{"corp/app"}}, TTL: time.Hour,
		Actor: "alice@example.com", Viewer: secretbroker.Viewer{Identity: "alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	w.secretID, w.grantID = sec.ID, g.ID

	w.home, err = claudecodeauth.HomeFor("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudecodeauth.CredentialsPath(w.home), []byte(`{"claudeAiOauth":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// A `claude` that records how it was called.
	bin := t.TempDir()
	w.claudeLog = filepath.Join(t.TempDir(), "claude.log")
	script := "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR $*\" >> '" + w.claudeLog + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return w
}

func (w offboardWorld) run(t *testing.T, extra ...string) error {
	t.Helper()
	args := append([]string{"alice@example.com", "--workdir", w.dir, "--reason", "left the company, HR-882", "--json"}, extra...)
	return runHubSub(t, hubUserOffboardCmd, func(c *cobra.Command) {
		c.Flags().String("workdir", "", "")
		c.Flags().Bool("dry-run", false, "")
		c.Flags().Bool("json", false, "")
		c.Flags().String("reason", "", "")
		c.Flags().Bool("keep-credentials", false, "")
	}, args...)
}

func (w offboardWorld) secretAndGrant(t *testing.T) (secretPresent, grantLive bool) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(w.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.GetBrokerSecret(w.secretID)
	secretPresent = err == nil
	g, err := db.GetBrokerGrant(w.grantID)
	if err != nil {
		t.Fatal(err)
	}
	return secretPresent, g.RevokedAt == ""
}

// TestOffboardCLIDestroysStoredCredentialsWithoutTheSealingKey: the secret is
// gone, its grant revoked, and the Claude home logged out — the CLI scoped to
// alice's directory, never the host's — and removed.
func TestOffboardCLIDestroysStoredCredentialsWithoutTheSealingKey(t *testing.T) {
	w := newOffboardWorld(t)
	if err := w.run(t); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	present, live := w.secretAndGrant(t)
	if present || live {
		t.Fatalf("secret present=%v grant live=%v after offboarding, want destroyed and revoked", present, live)
	}
	if _, err := os.Stat(w.home); !os.IsNotExist(err) {
		t.Fatalf("the Claude home survived: %v", err)
	}
	log, err := os.ReadFile(w.claudeLog)
	if err != nil {
		t.Fatalf("claude was never run to log the home out: %v", err)
	}
	if got := strings.TrimSpace(string(log)); got != w.home+" auth logout" {
		t.Fatalf("claude ran as %q, want a logout scoped to %s", got, w.home)
	}
}

// TestOffboardCLIKeepCredentialsKeepsThemAndStillSevers: under a legal hold the
// secret and the login stay; the grant does not, and neither does the session.
func TestOffboardCLIKeepCredentialsKeepsThemAndStillSevers(t *testing.T) {
	w := newOffboardWorld(t)
	if err := w.run(t, "--keep-credentials"); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	present, live := w.secretAndGrant(t)
	if !present || live {
		t.Fatalf("secret present=%v grant live=%v under a hold, want kept and revoked", present, live)
	}
	if !claudecodeauth.HasCredential(w.home) {
		t.Fatal("the Claude login was not kept under the hold")
	}
	if _, err := os.Stat(w.claudeLog); !os.IsNotExist(err) {
		t.Fatal("a hold ran claude auth logout")
	}
	db, err := statedb.Open(state.DBPath(w.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, err := db.ListSessions(); err != nil || len(rows) != 0 {
		t.Fatalf("sessions left %d (%v), want alice's ended", len(rows), err)
	}
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "user.offboard_hold"})
	if err != nil || len(evs) != 1 || !strings.Contains(evs[0].Payload, "alice-pat") {
		t.Fatalf("hold rows %+v (%v), want one naming what was kept", evs, err)
	}
}
