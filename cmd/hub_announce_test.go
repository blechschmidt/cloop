package cmd

// The incident commands write the session and token tables directly, behind
// every running hub's back — so they announce what they ended on the hub bus,
// which is what makes a running hub drop the session from its cache and close
// the dashboard streams and sandbox terminals it opened within a bus poll
// (Task 20398). These pin that each command announces exactly what it ended.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// announced reads every invalidation on the hub bus as (key, payload).
func announced(t *testing.T, dir string) [][2]string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.HubEventsAfter(0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out [][2]string
	for _, r := range rows {
		if r.Topic == "invalidate" {
			out = append(out, [2]string{r.Key, r.Payload})
		}
	}
	return out
}

// seedSessions writes sessions for the given (id, email) pairs.
func seedSessions(t *testing.T, dir string, sessions map[string]string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := sessionstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for id, email := range sessions {
		if err := store.Put(oidcauth.SessionRecord{
			ID: id, Identity: oidcauth.Identity{Sub: "sub-" + email, Email: email},
			IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
}

func payloadField(t *testing.T, payload, field string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		t.Fatalf("payload %q: %v", payload, err)
	}
	return m[field]
}

// TestSessionRevokeAnnouncesWhatItEnded: one event per session ended — and
// none for a session it did not select — or one naming every session for
// --all.
func TestSessionRevokeAnnouncesWhatItEnded(t *testing.T) {
	dir := hubDir(t)
	seedSessions(t, dir, map[string]string{
		"sess-alice-1": "alice@example.com", "sess-alice-2": "alice@example.com", "sess-carol": "carol@example.com",
	})
	if err := sessionRevoke(t, "--workdir", dir, "--identity", "alice@example.com",
		"--reason", "credential compromise INC-4412"); err != nil {
		t.Fatalf("session revoke: %v", err)
	}
	events := announced(t, dir)
	got := map[string]bool{}
	for _, ev := range events {
		if ev[0] != "session" {
			t.Errorf("announced %q, want only session invalidations", ev[0])
			continue
		}
		hash, _ := payloadField(t, ev[1], "session_hash").(string)
		got[hash] = true
	}
	if len(got) != 2 || !got["sess-alice-1"] || !got["sess-alice-2"] {
		t.Fatalf("announced %v, want exactly alice's two sessions", got)
	}

	if err := sessionRevoke(t, "--workdir", dir, "--all", "--reason", "rotating the IdP client secret"); err != nil {
		t.Fatalf("session revoke --all: %v", err)
	}
	events = announced(t, dir)
	last := events[len(events)-1]
	if len(events) != 3 || last[0] != "session" || payloadField(t, last[1], "all") != true {
		t.Fatalf("--all announced %v, want one event naming every session", events[2:])
	}
}

// TestTokenRevokeAnnouncesTheToken: the next request presenting a revoked
// token is refused on its own; a stream it already opened is not a request.
func TestTokenRevokeAnnouncesTheToken(t *testing.T) {
	dir := hubDir(t)
	mgr, closer, err := openHubTokenManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{Name: "ci", Roles: []string{"viewer"}, CreatedBy: "root"})
	closer()
	if err != nil {
		t.Fatal(err)
	}
	if err := runHubSub(t, hubTokenRevokeCmd, func(c *cobra.Command) {
		c.Flags().String("workdir", "", "")
	}, minted.Token.ID, "--workdir", dir); err != nil {
		t.Fatalf("token revoke: %v", err)
	}
	events := announced(t, dir)
	if len(events) != 1 || events[0][0] != "token" || payloadField(t, events[0][1], "token_id") != minted.Token.ID {
		t.Fatalf("announced %v, want the revoked token", events)
	}
}

// TestOffboardAnnouncesTheSessionsAndTokensItEnded: offboarding ends a
// person's sessions and tokens in one transaction, and a running hub learns of
// each from the bus.
func TestOffboardAnnouncesTheSessionsAndTokensItEnded(t *testing.T) {
	dir := hubDir(t)
	seedSessions(t, dir, map[string]string{"sess-alice": "alice@example.com", "sess-carol": "carol@example.com"})
	mgr, closer, err := openHubTokenManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := mgr.Mint(apitoken.MintOptions{Name: "alice-ci", Roles: []string{"viewer"}, CreatedBy: "root",
		Owner: &apitoken.Owner{Sub: "sub-alice@example.com", Email: "alice@example.com"}})
	closer()
	if err != nil {
		t.Fatal(err)
	}

	if err := runHubSub(t, hubUserOffboardCmd, func(c *cobra.Command) {
		c.Flags().String("workdir", "", "")
		c.Flags().Bool("dry-run", false, "")
		c.Flags().Bool("json", false, "")
		c.Flags().String("reason", "", "")
	}, "alice@example.com", "--workdir", dir, "--reason", "left the company, HR-882", "--json"); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	sessions, tokens := map[string]bool{}, map[string]bool{}
	for _, ev := range announced(t, dir) {
		switch ev[0] {
		case "session":
			h, _ := payloadField(t, ev[1], "session_hash").(string)
			sessions[h] = true
		case "token":
			id, _ := payloadField(t, ev[1], "token_id").(string)
			tokens[id] = true
		}
	}
	if len(sessions) != 1 || !sessions["sess-alice"] {
		t.Errorf("announced sessions %v, want alice's alone", sessions)
	}
	if len(tokens) != 1 || !tokens[minted.Token.ID] {
		t.Errorf("announced tokens %v, want alice's token", tokens)
	}
}
