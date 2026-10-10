package offboard

// What a departed identity keeps on the hub (Task 20400): personal secrets and
// the grants over them, requests left pending, Claude Code login homes.
//
// The fixture is a real broker over secretbrokertest's in-memory store and a
// real Claude home tree under a temporary XDG_CONFIG_HOME, so "gone" is
// asserted against the store and the filesystem, not against the report.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// credWorld is alice — who is leaving — and bob, who is not, with everything
// each of them keeps on the hub.
type credWorld struct {
	db     *statedb.DB
	store  *secretbrokertest.Store
	broker *secretbroker.Broker
	audit  *secretbrokertest.Recorder

	alicePAT, aliceEnv, bobPAT, fleet secretbroker.Secret
	// aliceToOwn and aliceToShared spend alice's PAT; aliceEnvGrant her env
	// secret; bobGrant and fleetGrant are the grants that must survive.
	aliceToOwn, aliceToShared, aliceEnvGrant, bobGrant, fleetGrant secretbroker.Grant
	// aliceReq was filed from her browser, aliceTokReq through her PAT.
	aliceReq, aliceTokReq, bobReq secretbroker.AccessRequest

	// Claude homes, by owner key.
	homes map[string]string

	mu      sync.Mutex
	logouts []string
}

const credKey = "0123456789abcdef0123456789abcdef"

func newCredWorld(t *testing.T) *credWorld {
	t.Helper()
	// tests/hermetic: a Claude home is per-user state, and the real one must
	// never be touched.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	w := &credWorld{db: testDB(t), store: secretbrokertest.NewStore(),
		audit: &secretbrokertest.Recorder{}, homes: map[string]string{}}
	putSession(t, w.db, "s-alice", "u-alice", "alice@example.com")
	putSession(t, w.db, "s-bob", "u-bob", "bob@example.com")
	putToken(t, w.db, "tok-alice", "", "u-alice", "alice@example.com")

	cipher, err := secretbroker.NewCipherWithKey([]byte(credKey))
	if err != nil {
		t.Fatal(err)
	}
	w.broker, err = secretbroker.New(w.store, secretbroker.WithCipher(cipher), secretbroker.WithAuditor(w.audit))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mint := func(name string, kind secretbroker.Kind, payload, owner string) secretbroker.Secret {
		t.Helper()
		s, err := w.broker.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: kind, Payload: []byte(payload),
			Actor: "seed", Owner: owner, Personal: owner != ""})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		return s
	}
	w.alicePAT = mint("alice-pat", secretbroker.KindGitHubPAT, "ghp_ALICEALICEALICEALICEALICEALICE0000", "alice@example.com")
	// Owned under her subject: the spelling a secret minted while the IdP
	// withheld her email carries, and the one an email-only sweep misses.
	w.aliceEnv = mint("alice-env", secretbroker.KindEnv, `{"TOKEN":"alice-value"}`, "sub:u-alice")
	w.bobPAT = mint("bob-pat", secretbroker.KindGitHubPAT, "ghp_BOBBOBBOBBOBBOBBOBBOBBOBBOBBOB0000", "bob@example.com")
	w.fleet = mint("fleet-deploy", secretbroker.KindGitHubPAT, "ghp_FLEETFLEETFLEETFLEETFLEETFLEET00", "")

	grant := func(sec secretbroker.Secret, project, as string) secretbroker.Grant {
		t.Helper()
		c := secretbroker.Constraints{Repos: []string{"corp/app"}}
		if sec.Kind == secretbroker.KindEnv {
			c = secretbroker.Constraints{EnvKeys: []string{"TOKEN"}}
		}
		g, err := w.broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project},
			Constraints: c, TTL: 24 * time.Hour, Actor: as, Viewer: secretbroker.Viewer{Identity: as}})
		if err != nil {
			t.Fatalf("grant %s to %s: %v", sec.Name, project, err)
		}
		return g
	}
	w.aliceToOwn = grant(w.alicePAT, "/srv/alice", "alice@example.com")
	w.aliceToShared = grant(w.alicePAT, "/srv/shared", "alice@example.com")
	w.aliceEnvGrant = grant(w.aliceEnv, "/srv/alice", "sub:u-alice")
	w.bobGrant = grant(w.bobPAT, "/srv/shared", "bob@example.com")
	w.fleetGrant = grant(w.fleet, "/srv/shared", "ops@example.com")

	request := func(actor, project string) secretbroker.AccessRequest {
		t.Helper()
		r, err := w.broker.RequestAccess(ctx, secretbroker.AccessRequestInput{SecretRef: "fleet-deploy",
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project},
			Constraints: secretbroker.Constraints{Repos: []string{"corp/app"}}, Justification: "deploys",
			Actor: actor})
		if err != nil {
			t.Fatalf("request for %s: %v", actor, err)
		}
		return r
	}
	w.aliceReq = request("alice@example.com", "/srv/alice")
	w.aliceTokReq = request("token:token-tok-alice (cloop_pat_tok-alice)", "/srv/alice-ci")
	w.bobReq = request("bob@example.com", "/srv/bob")

	for _, key := range []string{"alice@example.com", "sub:u-alice", "bob@example.com"} {
		dir, err := claudecodeauth.HomeFor(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(claudecodeauth.CredentialsPath(dir),
			[]byte(`{"claudeAiOauth":{"refreshToken":"sk-ant-ort01-`+key+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "projects"), 0o700); err != nil {
			t.Fatal(err)
		}
		w.homes[key] = dir
	}
	return w
}

// logout stands in for `claude auth logout`, which talks to Anthropic.
func (w *credWorld) logout(_ context.Context, dir string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logouts = append(w.logouts, dir)
	return nil
}

func (w *credWorld) options(identity string) Options {
	o := baseOptions(w.db, identity)
	o.Secrets = BrokerSecrets(w.broker)
	o.Claude = LocalClaude{Logout: w.logout}
	return o
}

func (w *credWorld) secretExists(t *testing.T, s secretbroker.Secret) bool {
	t.Helper()
	_, err := w.store.GetSecret(s.ID)
	if err != nil && !errors.Is(err, secretbroker.ErrSecretNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (w *credWorld) grantLive(t *testing.T, g secretbroker.Grant) bool {
	t.Helper()
	got, err := w.store.GetGrant(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got.RevokedAt.IsZero()
}

func (w *credWorld) requestState(t *testing.T, r secretbroker.AccessRequest) secretbroker.RequestState {
	t.Helper()
	got, err := w.store.GetAccessRequest(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got.State
}

func homeExists(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Lstat(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func auditCounts(t *testing.T, db *statedb.DB) map[string]int {
	t.Helper()
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, ev := range evs {
		seen[ev.EventType]++
	}
	return seen
}

// failingSecrets wraps the broker surface and fails the named operations, to
// prove one refusal neither stops the rest nor passes for a clean run.
type failingSecrets struct {
	Secrets
	failDelete map[string]bool
	failRevoke map[string]bool
}

var errStoreDown = errors.New("store is down")

func (f failingSecrets) DeleteSecret(id, actor, reason string) error {
	if f.failDelete[id] {
		return errStoreDown
	}
	return f.Secrets.DeleteSecret(id, actor, reason)
}

func (f failingSecrets) RevokeGrant(id, actor, reason string) error {
	if f.failRevoke[id] {
		return errStoreDown
	}
	return f.Secrets.RevokeGrant(id, actor, reason)
}

// unreachableMember wraps a Claude surface with a member that never answers.
type unreachableMember struct{ ClaudeHomes }

func (u unreachableMember) Inspect(keys []string) ([]ClaudeHomeRef, []ClaudeUnreached, error) {
	homes, missed, err := u.ClaudeHomes.Inspect(keys)
	return homes, append(missed, ClaudeUnreached{Member: "m-2", Detail: "did not answer"}), err
}

func (u unreachableMember) Sever(keys []string, keep bool, actor, reason string) ([]ClaudeHomeResult, []ClaudeUnreached, error) {
	res, missed, err := u.ClaudeHomes.Sever(keys, keep, actor, reason)
	return res, append(missed, ClaudeUnreached{Member: "m-2", Detail: "did not answer"}), err
}

// TestOffboardingStoredCredentials is the table: the default destroys, a
// legal hold keeps and still severs, a dry run changes nothing, and a run that
// cannot finish says which part it could not.
func TestOffboardingStoredCredentials(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(w *credWorld, o *Options)
		check func(t *testing.T, w *credWorld, rep Report)
	}{
		{
			name:  "destroys the departed user's secrets, grants, requests and Claude homes",
			setup: func(*credWorld, *Options) {},
			check: func(t *testing.T, w *credWorld, rep Report) {
				if !rep.OK() {
					t.Fatalf("failures: %+v", rep.Failures)
				}
				// Both of alice's secrets — including the one owned by her
				// subject alone — are gone, through the broker.
				for _, s := range []secretbroker.Secret{w.alicePAT, w.aliceEnv} {
					if w.secretExists(t, s) {
						t.Errorf("%s survived the offboarding", s.Name)
					}
					if tomb, ok := w.broker.Tombstone(s.ID); !ok || tomb.Cause != secretbroker.CauseOffboarded {
						t.Errorf("%s left no offboarding tombstone: %+v", s.Name, tomb)
					}
				}
				if len(rep.SecretsDeleted) != 2 || len(rep.SecretsKept) != 0 {
					t.Errorf("deleted %+v kept %+v, want both deleted", rep.SecretsDeleted, rep.SecretsKept)
				}
				for _, g := range []secretbroker.Grant{w.aliceToOwn, w.aliceToShared, w.aliceEnvGrant} {
					if w.grantLive(t, g) {
						t.Errorf("grant %s over a departed user's secret is still live", g.ID)
					}
				}
				if len(rep.GrantsRevoked) != 3 {
					t.Errorf("grants revoked = %+v, want 3", rep.GrantsRevoked)
				}
				// Her requests, both spellings of the requester, withdrawn.
				for _, r := range []secretbroker.AccessRequest{w.aliceReq, w.aliceTokReq} {
					if st := w.requestState(t, r); st != secretbroker.RequestWithdrawn {
						t.Errorf("request %s (%s) is %s, want withdrawn", r.ID, r.RequestedBy, st)
					}
				}
				// Every spelling's Claude home, logged out and removed.
				for _, key := range []string{"alice@example.com", "sub:u-alice"} {
					if homeExists(t, w.homes[key]) {
						t.Errorf("the Claude home of %s survived", key)
					}
				}
				if len(w.logouts) != 2 {
					t.Errorf("logged out %v, want alice's two homes", w.logouts)
				}
				for _, d := range w.logouts {
					if d == w.homes["bob@example.com"] {
						t.Error("bob's home was logged out by alice's offboarding")
					}
				}
				seen := auditCounts(t, w.db)
				for _, a := range []string{"user.offboard_grant", "user.offboard_secret",
					"user.offboard_request", "user.offboard_claude"} {
					if seen[a] != 1 {
						t.Errorf("audit %v: want exactly one %s", seen, a)
					}
				}
				if seen["user.offboard_hold"] != 0 {
					t.Error("a run with no hold wrote a hold row")
				}
				if dels := w.audit.Events(secretbroker.ActionDeleteSec); len(dels) != 2 {
					t.Errorf("broker secret.delete rows = %d, want 2 — the deletions must go through the broker", len(dels))
				}
			},
		},
		{
			name:  "leaves shared secrets and other users' personal secrets alone",
			setup: func(*credWorld, *Options) {},
			check: func(t *testing.T, w *credWorld, rep Report) {
				for _, s := range []secretbroker.Secret{w.bobPAT, w.fleet} {
					if !w.secretExists(t, s) {
						t.Errorf("%s was destroyed by alice's offboarding", s.Name)
					}
				}
				for _, g := range []secretbroker.Grant{w.bobGrant, w.fleetGrant} {
					if !w.grantLive(t, g) {
						t.Errorf("grant %s was revoked by alice's offboarding", g.ID)
					}
				}
				if st := w.requestState(t, w.bobReq); st != secretbroker.RequestPending {
					t.Errorf("bob's request is %s, want still pending", st)
				}
				if !homeExists(t, w.homes["bob@example.com"]) ||
					!claudecodeauth.HasCredential(w.homes["bob@example.com"]) {
					t.Error("bob's Claude login went with alice's")
				}
			},
		},
		{
			name: "a legal hold keeps the credentials and still severs access",
			setup: func(w *credWorld, o *Options) {
				o.KeepCredentials = true
			},
			check: func(t *testing.T, w *credWorld, rep Report) {
				if !rep.OK() {
					t.Fatalf("failures: %+v", rep.Failures)
				}
				for _, s := range []secretbroker.Secret{w.alicePAT, w.aliceEnv} {
					if !w.secretExists(t, s) {
						t.Errorf("%s was destroyed under a legal hold", s.Name)
					}
				}
				if len(rep.SecretsKept) != 2 || len(rep.SecretsDeleted) != 0 || !rep.Credentials.Keep {
					t.Errorf("kept %+v deleted %+v, want both kept", rep.SecretsKept, rep.SecretsDeleted)
				}
				for _, key := range []string{"alice@example.com", "sub:u-alice"} {
					if !claudecodeauth.HasCredential(w.homes[key]) {
						t.Errorf("the Claude login of %s was not kept", key)
					}
				}
				if len(w.logouts) != 0 {
					t.Errorf("a hold logged %v out", w.logouts)
				}
				kept := 0
				for _, r := range rep.ClaudeResults {
					if r.Kept && !r.Removed {
						kept++
					}
				}
				if kept != 2 {
					t.Errorf("claude results %+v, want two kept copies", rep.ClaudeResults)
				}
				// Access is severed regardless.
				for _, g := range []secretbroker.Grant{w.aliceToOwn, w.aliceToShared, w.aliceEnvGrant} {
					if w.grantLive(t, g) {
						t.Errorf("grant %s still live under a hold — a hold keeps evidence, not access", g.ID)
					}
				}
				if st := w.requestState(t, w.aliceReq); st != secretbroker.RequestWithdrawn {
					t.Errorf("request is %s under a hold, want withdrawn", st)
				}
				if len(rep.SessionsRevoked) != 1 || len(rep.TokensRevoked) != 1 || len(rep.DeniesWritten) != 2 {
					t.Errorf("sessions %v tokens %v denies %v, want alice severed",
						rep.SessionsRevoked, rep.TokensRevoked, rep.DeniesWritten)
				}
				seen := auditCounts(t, w.db)
				if seen["user.offboard_hold"] != 1 || seen["user.offboard_secret"] != 0 {
					t.Errorf("audit %v: want one hold row and no destruction row", seen)
				}
			},
		},
		{
			name: "a dry run lists what it would destroy and changes nothing",
			setup: func(w *credWorld, o *Options) {
				o.DryRun = true
			},
			check: func(t *testing.T, w *credWorld, rep Report) {
				c := rep.Credentials
				if len(c.Secrets) != 2 || len(c.Grants) != 3 || len(c.Requests) != 2 || c.ClaudeCopies() != 2 {
					t.Fatalf("plan lists secrets %d grants %d requests %d claude %d, want 2/3/2/2",
						len(c.Secrets), len(c.Grants), len(c.Requests), c.ClaudeCopies())
				}
				var shared bool
				for _, g := range c.Grants {
					if g.Subject == "project:/srv/shared" && g.SecretName == "alice-pat" {
						shared = true
					}
				}
				if !shared {
					t.Errorf("the plan does not name the shared project that loses alice-pat: %+v", c.Grants)
				}
				for _, s := range []secretbroker.Secret{w.alicePAT, w.aliceEnv} {
					if !w.secretExists(t, s) {
						t.Errorf("a dry run destroyed %s", s.Name)
					}
				}
				if !w.grantLive(t, w.aliceToShared) || w.requestState(t, w.aliceReq) != secretbroker.RequestPending {
					t.Error("a dry run revoked or withdrew something")
				}
				if !homeExists(t, w.homes["alice@example.com"]) || len(w.logouts) != 0 {
					t.Error("a dry run touched a Claude home")
				}
				if seen := auditCounts(t, w.db); len(seen) != 0 {
					t.Errorf("a dry run wrote audit rows: %v", seen)
				}
			},
		},
		{
			name: "a part that cannot be destroyed is reported and the rest is not held back",
			setup: func(w *credWorld, o *Options) {
				o.Secrets = failingSecrets{Secrets: o.Secrets,
					failDelete: map[string]bool{w.aliceEnv.ID: true},
					failRevoke: map[string]bool{w.aliceToShared.ID: true}}
				o.Claude = unreachableMember{o.Claude}
			},
			check: func(t *testing.T, w *credWorld, rep Report) {
				if rep.OK() {
					t.Fatal("a run that could not destroy everything reported itself clean")
				}
				surfaces := map[string]int{}
				for _, f := range rep.Failures {
					surfaces[f.Surface]++
				}
				for _, want := range []string{"secret", "grant", "claude"} {
					if surfaces[want] == 0 {
						t.Errorf("failures %+v name no %s", rep.Failures, want)
					}
				}
				var unreachedNamed bool
				for _, f := range rep.Failures {
					if f.Surface == "claude" && strings.Contains(f.Detail, "m-2") {
						unreachedNamed = true
					}
				}
				if !unreachedNamed {
					t.Errorf("the unreached member is not named: %+v", rep.Failures)
				}
				// The parts that could go, went.
				if w.secretExists(t, w.alicePAT) {
					t.Error("alice-pat survived because a different secret failed")
				}
				if !w.secretExists(t, w.aliceEnv) {
					t.Error("the secret whose delete failed is reported gone")
				}
				if homeExists(t, w.homes["alice@example.com"]) {
					t.Error("the local Claude home survived because a member was unreachable")
				}
				// And the severing did not roll back.
				if len(rep.TokensRevoked) != 1 || len(rep.DeniesWritten) != 2 {
					t.Errorf("tokens %v denies %v, want alice still severed", rep.TokensRevoked, rep.DeniesWritten)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newCredWorld(t)
			o := w.options("alice@example.com")
			tc.setup(w, &o)
			rep, err := Run(o)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, w, rep)
		})
	}
}

// TestTheSharedProjectIsToldWhichCredentialItLost: bob's project held a grant
// over alice's PAT. On its next run after she is offboarded the lease refuses
// that grant naming the secret and whose it was — not "secret not found".
func TestTheSharedProjectIsToldWhichCredentialItLost(t *testing.T) {
	w := newCredWorld(t)
	if rep, err := Run(w.options("alice@example.com")); err != nil || !rep.OK() {
		t.Fatalf("offboard: %v %+v", err, rep.Failures)
	}
	lease, err := w.broker.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	var lost *secretbroker.RefusedCredential
	for i := range lease.Refused {
		if lease.Refused[i].GrantID == w.aliceToShared.ID {
			lost = &lease.Refused[i]
		}
	}
	if lost == nil {
		t.Fatalf("the shared project's next lease does not mention alice-pat: %+v", lease.Refused)
	}
	for _, want := range []string{"alice-pat", "alice@example.com", "offboarded"} {
		if !strings.Contains(lost.Reason, want) {
			t.Errorf("refusal %q lacks %q", lost.Reason, want)
		}
	}
	if strings.Contains(lost.Reason, "secret not found") || strings.Contains(lost.Reason, "left the company") {
		t.Errorf("refusal %q is bare, or carries the offboarding reason", lost.Reason)
	}
	// bob's own credentials still reach the project.
	if len(lease.Materials) != 2 {
		t.Errorf("materials = %d, want bob's PAT and the fleet key", len(lease.Materials))
	}
}

// TestStrictModeSkipsLogoutButStillRemovesTheHome: on a hub that runs no
// program on a request's behalf, the upstream revocation is skipped, said so,
// and the credential on disk is destroyed regardless.
func TestStrictModeSkipsLogoutButStillRemovesTheHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := claudecodeauth.HomeFor("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudecodeauth.CredentialsPath(dir), []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := executor.SetAllowHostExecution(false)
	t.Cleanup(func() { executor.SetAllowHostExecution(prev) })
	called := false
	c := LocalClaude{Logout: func(context.Context, string) error { called = true; return nil }}
	res, _, err := c.Sever([]string{"alice@example.com"}, false, "admin", "left")
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("logout ran on a hub that forbids host execution")
	}
	if len(res) != 1 || !res[0].Removed || !strings.Contains(res[0].Logout, "allow_host_process") {
		t.Fatalf("result %+v, want the home removed and the skipped logout explained", res)
	}
	if homeExists(t, dir) {
		t.Fatal("the home survived")
	}
}

// TestInspectingCreatesNothing: a dry run on a hub that never kept a Claude
// home — including one whose config directory is read-only — must not create
// the tree it is looking for.
func TestInspectingCreatesNothing(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	homes, _, err := LocalClaude{}.Inspect([]string{"alice@example.com", "sub:u-alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(homes) != 0 {
		t.Fatalf("found %+v in an empty tree", homes)
	}
	if res, _, err := (LocalClaude{}).Sever([]string{"alice@example.com"}, false, "a", "r"); err != nil || len(res) != 0 {
		t.Fatalf("sever on an empty tree: %+v %v", res, err)
	}
	entries, err := os.ReadDir(xdg)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("looking created %v", entries)
	}
}

// TestMissingCredentialCollaboratorsAreWarnedAbout: a run with no secret store
// or no Claude surface must say those parts were not checked.
func TestMissingCredentialCollaboratorsAreWarnedAbout(t *testing.T) {
	plan, err := BuildPlan(baseOptions(testDB(t), "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"personal secrets, the grants over them and pending grant requests were not checked",
		"Claude Code logins were not checked"} {
		if !warnsAbout(plan.Warnings, want) {
			t.Errorf("warnings %v, want one mentioning %q", plan.Warnings, want)
		}
	}
}

// TestASymlinkedHomeIsRemovedWithoutBeingFollowed: something planted where a
// home belongs — a link to another directory, the host's own login at worst —
// is taken away, and logout is never run through it, which would sign out
// whatever credential the link points at.
func TestASymlinkedHomeIsRemovedWithoutBeingFollowed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	elsewhere := t.TempDir()
	if err := os.WriteFile(claudecodeauth.CredentialsPath(elsewhere), []byte(`{"host":"login"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	home, err := claudecodeauth.HomePath("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, home); err != nil {
		t.Fatal(err)
	}
	called := false
	res, _, err := LocalClaude{Logout: func(context.Context, string) error { called = true; return nil }}.
		Sever([]string{"alice@example.com"}, false, "admin", "left")
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("logout ran through a symbolic link")
	}
	if len(res) != 1 || !res[0].Removed || !strings.Contains(res[0].Logout, "symbolic link") {
		t.Fatalf("result %+v, want the link removed and the skipped logout explained", res)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatal("the link survived")
	}
	if !claudecodeauth.HasCredential(elsewhere) {
		t.Fatal("the link's target was touched")
	}
}

// TestALegalHoldStillTellsTheSharedProject: under a hold the secret is kept and
// the grant over it is revoked with its cause, so bob's project is told which
// credential went with its departed owner, without the offboarding's reason —
// and the request alice left is withdrawn with a note that does not carry it
// either.
func TestALegalHoldStillTellsTheSharedProject(t *testing.T) {
	w := newCredWorld(t)
	o := w.options("alice@example.com")
	o.KeepCredentials = true
	if rep, err := Run(o); err != nil || !rep.OK() {
		t.Fatalf("offboard: %v %+v", err, rep.Failures)
	}
	lease, err := w.broker.Lease(context.Background(), "edge-1", "/srv/shared")
	if err != nil {
		t.Fatal(err)
	}
	var lost *secretbroker.RefusedCredential
	for i := range lease.Refused {
		if lease.Refused[i].GrantID == w.aliceToShared.ID {
			lost = &lease.Refused[i]
		}
	}
	if lost == nil || lost.SecretName != "alice-pat" || !strings.Contains(lost.Reason, "withdrawn") {
		t.Fatalf("refused = %+v, want alice-pat named as withdrawn", lease.Refused)
	}
	if strings.Contains(lost.Reason, "HR-882") {
		t.Errorf("refusal %q carries the offboarding reason", lost.Reason)
	}
	req, err := w.store.GetAccessRequest(w.aliceReq.ID)
	if err != nil {
		t.Fatal(err)
	}
	if req.State != secretbroker.RequestWithdrawn || strings.Contains(req.DecisionNote, "HR-882") {
		t.Fatalf("request %s note %q, want withdrawn without the reason", req.State, req.DecisionNote)
	}
}
