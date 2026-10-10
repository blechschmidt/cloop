package ui

// Ending a departed identity's Claude Code logins on every hub member (Task
// 20400).
//
// Two members in one test process share one environment, so each is given its
// own Claude home root (Server.claudeHomesRoot) — the separate trees two
// processes under different users or container filesystems would have. What
// crosses between them crosses as it does in production: the signed peer
// channel from the dashboard's side, the bus from the CLI's.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedClaudeHome writes a logged-in Claude home for key under root.
func seedClaudeHome(t *testing.T, root, key string) string {
	t.Helper()
	dir, err := claudecodeauth.HomePathIn(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudecodeauth.CredentialsPath(dir), []byte(`{"claudeAiOauth":{"refreshToken":"x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// denyIdentity writes the global deny bindings an offboarding writes.
func denyIdentity(t *testing.T, dir string, claims map[string]string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for claim, value := range claims {
		if _, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectDeny,
			Claim: claim, Value: value, Reason: "offboarded"}); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeLogouts replaces `claude auth logout` for the test and records which
// directories were logged out.
func fakeLogouts(t *testing.T) func() []string {
	t.Helper()
	var (
		mu   sync.Mutex
		dirs []string
	)
	prev := testClaudeLogout
	testClaudeLogout = func(_ context.Context, dir string) error {
		mu.Lock()
		defer mu.Unlock()
		dirs = append(dirs, dir)
		return nil
	}
	t.Cleanup(func() { testClaudeLogout = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), dirs...)
	}
}

func dirGone(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Lstat(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return os.IsNotExist(err)
}

// TestOffboardReachesEveryMembersClaudeHome: the member serving an offboarding
// removes its own copy and asks the other member, over the peer channel, to
// remove the one in its tree. Both copies are logged out first, and the plan
// lists both before anything happens.
func TestOffboardReachesEveryMembersClaudeHome(t *testing.T) {
	dir, a, b := clusterPair(t)
	a.srv.claudeHomesRoot, b.srv.claudeHomesRoot = t.TempDir(), t.TempDir()
	homeA := seedClaudeHome(t, a.srv.claudeHomesRoot, "alice@example.com")
	homeB := seedClaudeHome(t, b.srv.claudeHomesRoot, "alice@example.com")
	bobs := seedClaudeHome(t, b.srv.claudeHomesRoot, "bob@example.com")
	denyIdentity(t, dir, map[string]string{"email": "alice@example.com"})
	logouts := fakeLogouts(t)

	surface := a.srv.offboardClaude()
	homes, unreached, err := surface.Inspect([]string{"alice@example.com"})
	if err != nil || len(unreached) != 0 {
		t.Fatalf("inspect: %v %+v", err, unreached)
	}
	members := map[string]bool{}
	for _, h := range homes {
		if h.Exists && h.Credential {
			members[h.Member] = true
		}
	}
	if !members[a.node.ID()] || !members[b.node.ID()] {
		t.Fatalf("the plan found copies on %v, want both members (%s, %s): %+v",
			members, a.node.ID(), b.node.ID(), homes)
	}

	results, unreached, err := surface.Sever([]string{"alice@example.com"}, false, "admin@example.com", "left")
	if err != nil || len(unreached) != 0 {
		t.Fatalf("sever: %v %+v", err, unreached)
	}
	removed := map[string]bool{}
	for _, r := range results {
		if r.Removed && r.LoggedOut {
			removed[r.Member] = true
		}
	}
	if !removed[a.node.ID()] || !removed[b.node.ID()] {
		t.Fatalf("removed on %v, want both members: %+v", removed, results)
	}
	if !dirGone(t, homeA) || !dirGone(t, homeB) {
		t.Fatal("a member's copy survived the offboarding")
	}
	if dirGone(t, bobs) {
		t.Fatal("bob's login on the other member went with alice's")
	}
	if got := logouts(); len(got) != 2 {
		t.Fatalf("logged out %v, want both members' copies", got)
	}
}

// TestAMemberEndsLoginsOnlyForADeniedIdentity: a member acts on another
// process's word only for an identity the control plane denies, so a request
// for somebody still admitted — a bug, a forged bus row — removes nothing.
func TestAMemberEndsLoginsOnlyForADeniedIdentity(t *testing.T) {
	_, a, b := clusterPair(t)
	a.srv.claudeHomesRoot, b.srv.claudeHomesRoot = t.TempDir(), t.TempDir()
	homeB := seedClaudeHome(t, b.srv.claudeHomesRoot, "carol@example.com")
	fakeLogouts(t)

	_, unreached, err := a.srv.offboardClaude().Sever([]string{"carol@example.com"}, false, "admin@example.com", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(unreached) != 1 || unreached[0].Member != b.node.ID() ||
		!strings.Contains(unreached[0].Detail, "does not deny") {
		t.Fatalf("unreached = %+v, want the other member's refusal named", unreached)
	}
	if dirGone(t, homeB) {
		t.Fatal("a member removed the login of an identity the control plane still admits")
	}
}

// TestTheCLIReachesMembersOverTheBus: `cloop hub user offboard` is no member
// and cannot sign a peer call. It writes its request on the bus, each member
// answers there, addressed back to it, and the copies in the members' trees
// are gone when it reports.
func TestTheCLIReachesMembersOverTheBus(t *testing.T) {
	dir, a, b := clusterPair(t)
	a.srv.claudeHomesRoot, b.srv.claudeHomesRoot = t.TempDir(), t.TempDir()
	homeA := seedClaudeHome(t, a.srv.claudeHomesRoot, "sub:u-alice")
	homeB := seedClaudeHome(t, b.srv.claudeHomesRoot, "sub:u-alice")
	cliRoot := t.TempDir()
	homeCLI := seedClaudeHome(t, cliRoot, "sub:u-alice")
	denyIdentity(t, dir, map[string]string{"sub": "u-alice"})
	fakeLogouts(t)

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cli := busClaude{db: db, origin: "cli-test", inspectWait: 10 * time.Second, severWait: 10 * time.Second,
		local: offboard.LocalClaude{Root: cliRoot, Logout: func(context.Context, string) error { return nil }}}

	homes, unreached, err := cli.Inspect([]string{"sub:u-alice"})
	if err != nil || len(unreached) != 0 {
		t.Fatalf("inspect over the bus: %v %+v", err, unreached)
	}
	if len(homes) != 3 {
		t.Fatalf("found %d copies over the bus, want the CLI's and both members': %+v", len(homes), homes)
	}

	results, unreached, err := cli.Sever([]string{"sub:u-alice"}, false, "cli:root", "left")
	if err != nil || len(unreached) != 0 {
		t.Fatalf("sever over the bus: %v %+v", err, unreached)
	}
	byMember := map[string]bool{}
	for _, r := range results {
		if r.Removed {
			byMember[r.Member] = true
		}
	}
	if !byMember[""] || !byMember[a.node.ID()] || !byMember[b.node.ID()] {
		t.Fatalf("removed on %v, want the CLI's own copy and both members': %+v", byMember, results)
	}
	for _, d := range []string{homeA, homeB, homeCLI} {
		if !dirGone(t, d) {
			t.Fatalf("%s survived", d)
		}
	}
}

// TestAMemberThatDoesNotAnswerIsNamed: a live member that never answers the
// bus — a build older than this one — is reported by id, with what to remove
// by hand, rather than taken to hold nothing.
func TestAMemberThatDoesNotAnswerIsNamed(t *testing.T) {
	dir := setupProjectDir(t, "a member that does not answer", nil)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: "m-old", Hostname: "elsewhere", PID: 1,
		BootID: "other-boot", Address: ":8080", AdvertiseURL: "http://192.0.2.1:8080", Version: "v0.0.1",
		Meta: "{}", StartedAt: now, HeartbeatAt: now}); err != nil {
		t.Fatal(err)
	}
	cli := busClaude{db: db, origin: "cli-test", inspectWait: 300 * time.Millisecond, severWait: 300 * time.Millisecond,
		local: offboard.LocalClaude{Root: t.TempDir()}}
	_, unreached, err := cli.Sever([]string{"alice@example.com"}, false, "cli:root", "left")
	if err != nil {
		t.Fatal(err)
	}
	if len(unreached) != 1 || unreached[0].Member != "m-old" ||
		!strings.Contains(unreached[0].Detail, "did not answer") ||
		!strings.Contains(unreached[0].Detail, claudecodeauth.IdentitySlug("alice@example.com")) {
		t.Fatalf("unreached = %+v, want m-old named with the directory to remove", unreached)
	}
}

// TestAStoppedMembersTreeOnAReachedHostIsNamed: a stopped member that kept its
// homes in a tree nobody reached, on a host the run did reach, still has them
// on disk; one on a host the run cannot see is most likely gone with its
// container, and one sharing a reached tree was covered.
func TestAStoppedMembersTreeOnAReachedHostIsNamed(t *testing.T) {
	reached := []claudeTree{{host: "hub-1", root: "/var/lib/cloop/.config/cloop/claude-identities"}}
	stopped := []claudeTree{
		{member: "m-shared", host: "hub-1", root: "/var/lib/cloop/.config/cloop/claude-identities"},
		{member: "m-other-user", host: "hub-1", root: "/home/svc/.config/cloop/claude-identities"},
		{member: "m-gone-pod", host: "pod-7f9c", root: "/var/lib/cloop/.config/cloop/claude-identities"},
		{member: "m-no-root", host: "hub-1"},
	}
	got := strandedTrees([]string{"alice@example.com"}, reached, stopped)
	if len(got) != 1 || got[0].Member != "m-other-user" ||
		!strings.Contains(got[0].Detail, filepath.Join("/home/svc/.config/cloop/claude-identities",
			claudecodeauth.IdentitySlug("alice@example.com"))) {
		t.Fatalf("stranded = %+v, want only m-other-user, naming the directory", got)
	}
}

// TestARefusedCredentialIsJournaledOncePerProcess: the project that lost a
// credential is told on its first run after, not on every run — the revoked
// grant stays forever, and so would the row.
func TestARefusedCredentialIsJournaledOncePerProcess(t *testing.T) {
	dir := setupProjectDir(t, "lost a colleague's credential", nil)
	refused := []secretbroker.RefusedCredential{{GrantID: "grant_x", SecretID: "sec_x", SecretName: "alice-pat",
		Kind: secretbroker.KindGitHubPAT, Owner: "alice@example.com",
		Reason: `grant revoked at T: github_pat "alice-pat", a personal credential of alice@example.com, was destroyed on 2026-10-10 when its owner was offboarded`}}
	journalRefusedCredentials(dir, refused)
	journalRefusedCredentials(dir, refused)

	rows, _, err := state.ListEvents(dir, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var found []statedb.EventRow
	for _, r := range rows {
		if r.Type == state.EventCredentialRefused {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d credential_refused rows, want one: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Message, `github_pat "alice-pat"`) || !strings.Contains(found[0].Message, "offboarded") {
		t.Fatalf("row %q does not name the lost credential", found[0].Message)
	}
}
