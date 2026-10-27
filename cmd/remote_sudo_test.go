package cmd

// A terminal session held to the sudo window (Task 20448): `cloop login`'s
// session counts from its approval, and a privileged action asked of one
// approved longer ago than ui.oidc.sudo_max_age_minutes is refused — the
// terminal says why, and names `cloop login` as the way back.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

// movableClock is the hub's session clock, moved forward by a test.
type movableClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *movableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *movableClock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

func TestRemoteStaleTerminalIsToldToRunCloopLogin(t *testing.T) {
	clk := &movableClock{}
	credPath := credentialHome(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{
		SelfExe:     cliSelfExe(t),
		AdminEmails: []string{rootEmail},
		Clock:       clk.now,
	})
	w := &remoteWorld{hub: hub, credPath: credPath}

	path := rootProject(t, w)
	storeSecret(t, w, "org-token", "github_pat", patPayload, false)
	share(t, w, path, oliveEmail, "operator")
	w.as(t, oliveEmail, ssohubtest.GroupOperators)
	out, err := runRemoteCLI(t, "grants", "request", "org-token", "--project", "widgets", "--repo", "acme/widgets",
		"--justification", "Release work (API-7)", "--json")
	if err != nil {
		t.Fatalf("grants request: %v\n%s", err, out)
	}
	id := jsonField(t, out, "id")

	// Root's terminal session, approved now, then three hours pass.
	w.as(t, rootEmail)
	clk.advance(3 * time.Hour)
	_, err = runRemoteCLI(t, "approvals", "approve", id)
	if err == nil {
		t.Fatal("a terminal session approved three hours ago approved a grant request")
	}
	if !hubclient.IsReauthRequired(err) {
		t.Fatalf("the refusal is not the hub's REAUTH_REQUIRED: %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "run `cloop login "+mustNormalize(t, hub.URL)+"` again") ||
		!strings.Contains(msg, "approved more than 2 hours ago") {
		t.Fatalf("the terminal did not say why and name `cloop login` as the remedy: %v", err)
	}

	// A fresh `cloop login` is the remedy, and it works.
	w.as(t, rootEmail)
	if out, err := runRemoteCLI(t, "approvals", "approve", id); err != nil {
		t.Fatalf("after `cloop login`, approvals approve = %v\n%s", err, out)
	}
}

// jsonField reads one string field out of a command's --json output.
func jsonField(t *testing.T, out, field string) string {
	t.Helper()
	i := strings.Index(out, `"`+field+`":"`)
	if i < 0 {
		t.Fatalf("no %q in %s", field, out)
	}
	rest := out[i+len(field)+4:]
	return rest[:strings.Index(rest, `"`)]
}
