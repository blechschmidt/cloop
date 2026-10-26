package ui

// A run the hub carries on by itself acts on its starter's Claude account
// (Task 20443): the automatic resume after a usage cap, the legacy pause an
// older build recorded, and a failover's replacement — on a hub with single
// sign-on whose own process carries a different login, as :8888's did, in its
// HOME and in an ambient CLAUDE_CODE_OAUTH_TOKEN.
//
// The resume tests dispatch for real: the hub's own project runs on the host
// driver, with a stand-in for `cloop run` that runs `claude` the way a harness
// does, and a stub `claude` first on PATH records whose account it ran on.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/runbuild"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	resumeAlice = "alice@example.com"
	resumeBob   = "bob@example.com"
	resumeRoot  = "root@example.com"
	// The hub process's own login: what a run that inherits its environment
	// would spend.
	hubAmbientToken = "hub-ambient-token"
)

// resumeHub is a hub with single sign-on, a role policy, alice and bob as
// operators and root as an admin, whose own project runs on the host.
type resumeHub struct {
	srv       *Server
	base      string
	dir       string
	clients   map[string]*http.Client
	claudeLog string
}

func newResumeHub(t *testing.T) *resumeHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "resume-account-passphrase")
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"),
		[]byte(`{"claudeAiOauth":{"accessToken":"hub-own-login"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", hubAmbientToken)

	// The stub claude, and a stand-in for the hub's binary whose `run` runs it
	// as a harness would: from the project, with the environment it was given.
	bin := t.TempDir()
	claudeLog := filepath.Join(t.TempDir(), "claude.log")
	stub := "#!/bin/sh\ncat >/dev/null\n" +
		`echo "${CLAUDE_CONFIG_DIR-<unset>}|${CLAUDE_CODE_OAUTH_TOKEN-<unset>}" >> ` + shellQuote(claudeLog) + "\n" +
		"echo TASK_DONE\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	standIn := filepath.Join(bin, "cloop-run-stand-in")
	if err := os.WriteFile(standIn, []byte("#!/bin/sh\n[ \"$1\" = run ] || exit 0\nexec claude --print </dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Authz = resolver
	srv.RPS, srv.Burst = 1000, 1000
	srv.SelfExe = standIn
	setProvider(t, srv.WorkDir, "claudecode")

	loginAs := func(sub, email string, groups ...string) *http.Client {
		idp.sub, idp.email, idp.groups = sub, email, groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	h := &resumeHub{srv: srv, base: ts.URL, dir: srv.WorkDir, claudeLog: claudeLog, clients: map[string]*http.Client{
		"alice": loginAs("sub-alice", resumeAlice, "engineers"),
		"bob":   loginAs("sub-bob", resumeBob, "engineers"),
		"root":  loginAs("sub-root", resumeRoot, "owners"),
	}}
	t.Cleanup(func() { h.settle(t) })
	return h
}

func (h *resumeHub) do(t *testing.T, who, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, h.base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.clients[who].Do(req)
	if err != nil {
		t.Fatalf("%s %s %s: %v", who, method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// run has who start the project's run, and waits for it to end.
func (h *resumeHub) run(t *testing.T, who string) {
	t.Helper()
	if code, body := h.do(t, who, "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("%s's run = %d %v", who, code, body)
	}
	h.settle(t)
}

// settle waits until no run of the project is executing and its database is
// quiet.
func (h *resumeHub) settle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for h.srv.projectExecuting(h.dir) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if h.srv.projectExecuting(h.dir) {
		t.Errorf("the project still executes 15 s on")
	}
	awaitQuietProject(t, h.dir)
}

// capPause parks the project on a usage cap whose window reopened an hour ago,
// and returns a clock past it.
func (h *resumeHub) capPause(t *testing.T) time.Time {
	t.Helper()
	reset := time.Now().Add(-time.Hour)
	setPauseReason(t, h.dir, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour window exhausted", reset))
	return time.Now()
}

func setPauseReason(t *testing.T, dir string, r pausereason.Reason) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.SetPaused(r)
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
}

// claudeRun is one line of the stub claude's log.
type claudeRun struct{ configDir, oauthToken string }

func (h *resumeHub) claudeRuns(t *testing.T) []claudeRun {
	t.Helper()
	raw, err := os.ReadFile(h.claudeLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []claudeRun
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		dir, tok, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("unreadable stub log line %q", line)
		}
		out = append(out, claudeRun{dir, tok})
	}
	return out
}

// lastRanFor asserts the last claude the project ran was on who's own Claude
// home and nothing ambient.
func (h *resumeHub) lastRanFor(t *testing.T, who, what string) {
	t.Helper()
	runs := h.claudeRuns(t)
	if len(runs) == 0 {
		t.Fatalf("%s: claude never ran", what)
	}
	got := runs[len(runs)-1]
	home, err := claudecodeauth.HomePath(who)
	if err != nil {
		t.Fatal(err)
	}
	if got.configDir != home {
		t.Errorf("%s ran claude on CLAUDE_CONFIG_DIR %q, want %s's own %q", what, got.configDir, who, home)
	}
	if got.oauthToken != "" {
		t.Errorf("%s ran claude with CLAUDE_CODE_OAUTH_TOKEN %q, want it cleared", what, got.oauthToken)
	}
}

func (h *resumeHub) pause(t *testing.T) *pausereason.Reason {
	t.Helper()
	st, err := state.LoadLite(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" {
		t.Fatalf("the project is %q, want paused", st.Status)
	}
	return st.PauseReason
}

// The core guarantee. alice starts a run on the host; it pauses at a usage
// cap; the sweep resumes it on her Claude home with the hub's ambient token
// cleared — never on the hub's own login — and the trail says it acted for
// her. Then bob's run resumes on his.
func TestAutoResumeActsOnTheStartersClaudeAccount(t *testing.T) {
	h := newResumeHub(t)

	for _, who := range []string{resumeAlice, resumeBob} {
		client := strings.TrimSuffix(who, "@example.com")
		h.run(t, client)
		h.lastRanFor(t, who, client+"'s own run")

		now := h.capPause(t)
		h.srv.nowFn = func() time.Time { return now }
		before := len(h.claudeRuns(t))
		if !h.srv.maybeAutoResume(h.dir) {
			t.Fatalf("the sweep did not resume %s's cap-paused run", client)
		}
		h.settle(t)
		if got := len(h.claudeRuns(t)); got != before+1 {
			t.Fatalf("the resume ran claude %d time(s), want once", got-before)
		}
		h.lastRanFor(t, who, "the resume of "+client+"'s run")

		rows := auditRowsOf(t, h.dir, auditaction.ActionRunCapResumed)
		if len(rows) == 0 {
			t.Fatal("no run.cap_resumed row")
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(rows[len(rows)-1].Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["acted_for"] != who || payload["acted_for_basis"] != actedForStarter {
			t.Errorf("run.cap_resumed for %s's run records %v", client, payload)
		}
	}
}

// An older build's extra-usage pause is judged by the starter's own usage
// windows, read under her home — not the hub's own login's.
func TestLegacyPauseClearsByTheStartersUsage(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	aliceHome, err := claudecodeauth.HomePath(resumeAlice)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 26, 23, 35, 0, 0, time.UTC)
	exhausted := &ratelimit.ClaudeUsage{FiveHour: &ratelimit.UsageDetail{Utilization: 100, ResetsAt: now.Add(2 * time.Hour)}}
	open := &ratelimit.ClaudeUsage{FiveHour: &ratelimit.UsageDetail{Utilization: 4, ResetsAt: now.Add(5 * time.Hour)}}

	for _, tt := range []struct {
		name        string
		alice, hubs *ratelimit.ClaudeUsage
		want        bool
	}{
		{"alice's window reopened, the hub's still exhausted", open, exhausted, true},
		{"alice's window still exhausted, the hub's open", exhausted, open, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setPauseReason(t, h.dir, pausereason.New(pausereason.CodeBudget, legacyExtraUsageDetail))
			h.srv.nowFn = func() time.Time { return now }
			var asked []string
			h.srv.autoResumeUsage = func(dir string) (*ratelimit.ClaudeUsage, error) {
				asked = append(asked, dir)
				if dir == aliceHome {
					return tt.alice, nil
				}
				return tt.hubs, nil
			}
			var resumed []string
			h.srv.autoResumeStart = func(workDir string) error {
				resumed = append(resumed, workDir)
				return nil
			}
			if got := h.srv.maybeAutoResume(h.dir); got != tt.want {
				t.Fatalf("maybeAutoResume = %v, want %v (usage asked of %q)", got, tt.want, asked)
			}
			if len(asked) != 1 || asked[0] != aliceHome {
				t.Errorf("the usage was read under %q, want only alice's home %q", asked, aliceHome)
			}
			if tt.want != (len(resumed) == 1) {
				t.Errorf("resumed %v", resumed)
			}
		})
	}
}

// alice is offboarded while her run waits at a cap: her home is removed and
// she is denied. The sweep does not resume it on anyone else's login; it
// stays paused, saying who and why, and the journal says so.
func TestAnOffboardedStartersRunStaysPaused(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	home, err := claudecodeauth.HomePath(resumeAlice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("alice's run left no home to remove: %v", err)
	}
	h.offboard(t, resumeAlice)
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("offboarding left alice's home in place: %v", err)
	}

	now := h.capPause(t)
	h.srv.nowFn = func() time.Time { return now }
	before := len(h.claudeRuns(t))
	if h.srv.maybeAutoResume(h.dir) {
		t.Fatal("the sweep resumed the run of an offboarded starter")
	}
	h.settle(t)
	if got := len(h.claudeRuns(t)); got != before {
		t.Fatalf("claude ran %d time(s) for an offboarded starter's run", got-before)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("the sweep created a home for the offboarded starter: %v", err)
	}
	pr := h.pause(t)
	if pr.Code != pausereason.CodeStarterUnavailable || !strings.Contains(pr.Detail, resumeAlice) ||
		!strings.Contains(pr.Detail, "press Run") {
		t.Fatalf("the pause is %s %q, want starter_unavailable naming alice and the remedy", pr.Code, pr.Detail)
	}
	// Every reader of the project sees the pause: it says neither why the
	// hub denies her nor that it does.
	for _, secret := range []string{"left the company", "denied", "not allowed", "suspended", "offboarded on"} {
		if strings.Contains(pr.Detail, secret) {
			t.Errorf("the pause tells every reader of the project %q: %q", secret, pr.Detail)
		}
	}
	if pr.AutoResumable(now.Add(24 * time.Hour)) {
		t.Error("the hold is auto-resumable: the next sweep would try again")
	}
	rows, _, err := state.ListEvents(h.dir, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	journaled := false
	for _, e := range rows {
		if e.Type == state.EventSessionPaused && strings.Contains(e.Message, "Auto-resume held") &&
			strings.Contains(e.Message, resumeAlice) {
			journaled = true
			if strings.Contains(e.Message, "left the company") {
				t.Errorf("the journal shows the offboarding's reason: %q", e.Message)
			}
		}
	}
	if !journaled {
		t.Error("the journal does not say the resume was held for alice")
	}
	// Held, not retried: a second sweep leaves it as it is.
	if h.srv.maybeAutoResume(h.dir) {
		t.Fatal("a second sweep resumed the held run")
	}
	if again := h.pause(t); again.Code != pausereason.CodeStarterUnavailable || again.Detail != pr.Detail {
		t.Errorf("a second sweep rewrote the hold: %s %q", again.Code, again.Detail)
	}
}

// offboard has root offboard who, for real: sessions ended, deny bindings
// written, their Claude home removed.
func (h *resumeHub) offboard(t *testing.T, who string) {
	t.Helper()
	if code, body := h.do(t, "root", "POST", "/api/users/offboard",
		map[string]any{"identity": who, "reason": "left the company"}); code != http.StatusOK {
		t.Fatalf("offboard %s = %d %v", who, code, body)
	}
}

// The pause an older build recorded for an exhausted window is judged by the
// starter's own usage, which an offboarded starter no longer has. Rather than
// sit forever as a budget pause nobody can clear by waiting, it is held as
// what it is — before any usage is asked for.
func TestALegacyPauseOfAnOffboardedStarterIsHeld(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	h.offboard(t, resumeAlice)
	setPauseReason(t, h.dir, pausereason.New(pausereason.CodeBudget, legacyExtraUsageDetail))
	h.srv.autoResumeUsage = func(dir string) (*ratelimit.ClaudeUsage, error) {
		t.Errorf("the usage of %q was asked for an offboarded starter's run", dir)
		return &ratelimit.ClaudeUsage{}, nil
	}
	if h.srv.maybeAutoResume(h.dir) {
		t.Fatal("resumed the legacy pause of an offboarded starter")
	}
	if pr := h.pause(t); pr.Code != pausereason.CodeStarterUnavailable || !strings.Contains(pr.Detail, resumeAlice) {
		t.Fatalf("the pause is %s %q, want starter_unavailable naming alice", pr.Code, pr.Detail)
	}
}

// A starter whose home is gone is held on the host, where the home is what the
// run would use, but not on an isolating executor, where the broker supplies
// the credential as before. A denied starter is held on both.
func TestResumeAccountRefusesByExecutor(t *testing.T) {
	h := newResumeHub(t)
	recordHarnessInitiator(h.dir, harnessInitiator{Identity: "carol@example.com"}) // never signed in here
	acct := h.srv.resumeAccountFor(h.dir)
	if acct.unavailable == nil || acct.unavailable.AnyExecutor {
		t.Fatalf("a starter with no home resolved to %+v", acct.unavailable)
	}
	if _, err := os.Stat(mustHomePath(t, "carol@example.com")); !os.IsNotExist(err) {
		t.Fatalf("resolving the account created carol a home: %v", err)
	}
	if err := acct.check(hostExecutor()); err == nil {
		t.Error("a host dispatch acting for a starter with no home was not refused")
	}
	if err := acct.check(containerExec()); err != nil {
		t.Errorf("an isolating dispatch was refused for a missing home it does not use: %v", err)
	}
	// Should the clearance ever be bypassed, the pin still names no login —
	// not the hub's own.
	if env := specEnv(executor.Spec{Env: acct.envFor(hostExecutor())}); env["CLAUDE_CONFIG_DIR"] != unavailableHomePath ||
		env["CLAUDE_CODE_OAUTH_TOKEN"] != "" {
		t.Errorf("a starter with no home pinned %v", env)
	}
	if env := acct.envFor(containerExec()); len(env) != 0 {
		t.Errorf("an isolating dispatch for a starter with no home got %v", env)
	}

	// Denied: refused wherever the run would go.
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutRoleBinding(statedb.RoleBindingRow{
		Effect: statedb.RoleEffectDeny, Claim: "email", Value: "dana@example.com", Reason: "on leave",
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := claudecodeauth.HomeFor("dana@example.com"); err != nil {
		t.Fatal(err)
	}
	recordHarnessInitiator(h.dir, harnessInitiator{Identity: "dana@example.com"})
	acct = h.srv.resumeAccountFor(h.dir)
	if acct.unavailable == nil || !acct.unavailable.AnyExecutor {
		t.Fatalf("a denied starter resolved to %+v", acct.unavailable)
	}
	// That and why they are denied is the operators' to read, never the
	// project's: an offboarding writes its reason on the deny binding.
	if su := acct.unavailable; strings.Contains(su.Error(), "on leave") || strings.Contains(su.Error(), "denied") ||
		!strings.Contains(su.logDetail(), "on leave") {
		t.Errorf("the refusal shows the project %q and the hub log %q", su.Error(), su.logDetail())
	}
	if err := acct.check(containerExec()); err == nil {
		t.Error("an isolating dispatch acting for a denied starter was not refused")
	}

	// Started acting for no one — the static token: the hub's own login, as
	// it started, with nobody to refuse.
	recordHarnessInitiator(h.dir, harnessInitiator{})
	acct = h.srv.resumeAccountFor(h.dir)
	if acct.unavailable != nil || acct.scope.PerUser() || acct.basis != actedForStarter || acct.actedFor() != "" {
		t.Errorf("a run started for no one resolved to %+v", acct)
	}
}

func mustHomePath(t *testing.T, owner string) string {
	t.Helper()
	p, err := claudecodeauth.HomePath(owner)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With no record of the starter — a run older than it — the project's owner,
// as before; with neither, nobody, which is refused on the host.
func TestResumeAccountFallsBackToTheProjectsOwner(t *testing.T) {
	h := newResumeHub(t)
	owned := setupProjectDir(t, "an owned project", nil)
	if err := multiui.AddPathsOwned([]string{owned}, "Carol@Example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := claudecodeauth.HomeFor("carol@example.com"); err != nil {
		t.Fatal(err)
	}
	acct := h.srv.resumeAccountFor(owned)
	if acct.unavailable != nil || acct.basis != actedForOwner || acct.actedFor() != "carol@example.com" ||
		acct.scope.ConfigDir != mustHomePath(t, "carol@example.com") {
		t.Fatalf("an unrecorded run of carol's project resolved to %+v (%+v)", acct, acct.unavailable)
	}

	acct = h.srv.resumeAccountFor(h.dir) // the hub's own project: no owner, no record
	if acct.unavailable == nil || !strings.Contains(acct.unavailable.Error(), "no owner") {
		t.Fatalf("a run nobody can be named for resolved to %+v", acct)
	}
	if err := acct.check(hostExecutor()); err == nil {
		t.Error("a host dispatch acting for nobody nameable was not refused")
	}
}

// A hub without single sign-on has one operator and one login: the resume
// runs on the host's own, as before, and the legacy pause is judged by it.
func TestSingleUserHubResumesAsBefore(t *testing.T) {
	dir := pausedProject(t, pausereason.New(pausereason.CodeBudget, legacyExtraUsageDetail))
	now := time.Now()
	srv, resumed := resumeProbe(t, dir, now)
	acct := srv.resumeAccountFor(dir)
	if acct.unavailable != nil || acct.scope.PerUser() || acct.basis != "" || acct.auditFields() != nil {
		t.Fatalf("a single-user hub resolved %+v", acct)
	}
	if env := acct.envFor(hostExecutor()); len(env) != 0 {
		t.Errorf("a single-user resume pinned %v", env)
	}
	var asked []string
	srv.autoResumeUsage = func(dir string) (*ratelimit.ClaudeUsage, error) {
		asked = append(asked, dir)
		return &ratelimit.ClaudeUsage{FiveHour: &ratelimit.UsageDetail{Utilization: 1, ResetsAt: now.Add(time.Hour)}}, nil
	}
	if !srv.maybeAutoResume(dir) || len(*resumed) != 1 {
		t.Fatalf("a single-user hub did not resume a reopened legacy pause (resumed %v)", *resumed)
	}
	if len(asked) != 1 || asked[0] != "" {
		t.Errorf("a single-user hub read usage under %q, want the hub's own login", asked)
	}
}

// ── failover ────────────────────────────────────────────────────────────────

// enableOIDC turns single sign-on on for a rig's hub, as newOIDCTestServer
// wires it, so whom a failover acts for is a person.
func enableOIDC(t *testing.T, srv *Server, base string) {
	t.Helper()
	idp := newUIFakeIdP(t)
	cfg := oidcauth.Config{
		Enabled: true, Issuer: idp.server.URL, ClientID: "cloop-dashboard", ClientSecret: "test-secret",
		RedirectURL: base + "/auth/callback",
	}
	srv.InstallOIDCHooks(&cfg)
	auth, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.OIDC = auth
}

// newHostFailoverRig is the failed-over-run rig on two devices that share the
// hub's filesystem — so the replacement runs where a Claude home means
// something — on a hub with single sign-on, with alice recorded as the
// starter of the run.
func newHostFailoverRig(t *testing.T) *trackRig {
	t.Helper()
	r := newTrackRig(t, 2, []*pm.Task{{ID: 1, Title: "only", Status: pm.TaskPending}})
	for _, n := range r.nodes {
		n.mu.Lock()
		n.host = true
		n.mu.Unlock()
	}
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", hubAmbientToken)
	enableOIDC(t, r.srv, r.ts.URL)
	recordHarnessInitiator(r.dir, harnessInitiator{Identity: resumeAlice})
	return r
}

// specEnv is the environment a spec's process would see: the last assignment
// of each key, as exec keeps it.
func specEnv(spec executor.Spec) map[string]string {
	out := map[string]string{}
	for _, kv := range spec.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

func TestFailoverOntoAHostSharingExecutorCarriesTheStartersHome(t *testing.T) {
	r := newHostFailoverRig(t)
	home, err := claudecodeauth.HomeFor(resumeAlice)
	if err != nil {
		t.Fatal(err)
	}
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/1: only ━━━")
	r.killAndProbe(r.nodes[0])

	if r.nodes[1].startCount() != 1 {
		t.Fatalf("the second device started %d workloads, want the replacement", r.nodes[1].startCount())
	}
	env := specEnv(r.nodes[1].last(t).spec)
	// The device runs on the hub's tree: no project went out as a copy.
	if w := r.nodes[1].last(t); w.dir != "" {
		t.Errorf("a host-sharing replacement was sent the project as a seed")
	}
	if env["CLAUDE_CONFIG_DIR"] != home {
		t.Errorf("the replacement runs on CLAUDE_CONFIG_DIR %q, want alice's %q", env["CLAUDE_CONFIG_DIR"], home)
	}
	if tok, ok := env["CLAUDE_CODE_OAUTH_TOKEN"]; !ok || tok != "" {
		t.Errorf("the replacement carries CLAUDE_CODE_OAUTH_TOKEN %q (set %v), want it cleared", tok, ok)
	}
	if !r.journalSays(t, state.EventFailover, "continues on "+r.nodes[1].id, "acting for "+resumeAlice) {
		t.Error("the failover journal does not say whom the replacement acts for")
	}
	var placed map[string]any
	for _, row := range auditRowsOf(t, r.dir, auditaction.ActionExecutorFailover) {
		var p map[string]any
		if json.Unmarshal([]byte(row.Payload), &p) == nil && p["placed"] == true {
			placed = p
		}
	}
	if placed == nil || placed["acted_for"] != resumeAlice {
		t.Errorf("the executor.failover row = %v, want acted_for %s", placed, resumeAlice)
	}
}

// The starter's home is gone: the replacement is not started on the hub's
// login in its place, and the project is paused naming them.
func TestFailoverForAStarterWithNoHomeStaysPaused(t *testing.T) {
	r := newHostFailoverRig(t)
	if _, err := claudecodeauth.HomeFor(resumeAlice); err != nil {
		t.Fatal(err)
	}
	h1 := r.dispatch(t)
	r.nodes[0].say(t, h1, "━━━ Task 1/1: only ━━━")
	if err := claudecodeauth.ForgetHome(resumeAlice); err != nil {
		t.Fatal(err)
	}
	r.killAndProbe(r.nodes[0])

	if n := r.nodes[1].startCount(); n != 0 {
		t.Fatalf("the second device started %d workloads for a starter with no home", n)
	}
	r.waitUntil(t, "the lost run to be settled", func() bool {
		_, _, ok := r.tracked()
		return !ok
	})
	st, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeStarterUnavailable ||
		!strings.Contains(st.PauseReason.Detail, resumeAlice) {
		t.Fatalf("the project is %s %+v, want paused starter_unavailable naming alice", st.Status, st.PauseReason)
	}
	if !r.journalSays(t, state.EventFailover, "not re-dispatched to "+r.nodes[1].id, resumeAlice) {
		t.Error("the failover journal does not say the replacement was refused for alice")
	}
	if _, err := os.Stat(mustHomePath(t, resumeAlice)); !os.IsNotExist(err) {
		t.Errorf("the failover created alice a home: %v", err)
	}
}

// ── the record names the run it was written for ─────────────────────────────

func readRecord(t *testing.T, workDir string) harnessInitiator {
	t.Helper()
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, ok, err := readHarnessInitiator(db, workDir)
	if err != nil || !ok {
		t.Fatalf("no record of whom %s's run was started for (%v)", workDir, err)
	}
	return rec
}

func saveRunOwner(t *testing.T, dir string, o *runbuild.Owner) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SaveRunOwner(o); err != nil {
		t.Fatal(err)
	}
}

func putDeny(t *testing.T, row statedb.RoleBindingRow) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	row.Effect = statedb.RoleEffectDeny
	if _, err := db.PutRoleBinding(row); err != nil {
		t.Fatal(err)
	}
}

// A run the hub did not dispatch — `cloop run` from a shell — records itself
// when it starts, and that is well after the dispatch the record describes,
// whatever run id it took up. Its cap pause is not carried on as whoever last
// pressed Run on the hub: on the hub's host that would be their account, spent
// for somebody else's run. The run alice did start is carried on as her.
func TestARunStartedOutsideTheHubIsNotCarriedOnAsTheLastStarter(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	rec := readRecord(t, h.dir)
	if rec.Identity != resumeAlice || rec.Basis != actedForStarter || rec.RunID == "" || rec.At.IsZero() {
		t.Fatalf("alice's run left the record %+v", rec)
	}

	for _, shell := range []struct {
		name  string
		runID string
	}{
		{"with a run id of its own", "run_from_a_shell"},
		// A shell's run takes up the hub's run id from the placement record
		// the hub left, for ten minutes: the id alone proves nothing.
		{"with the hub's run id taken up", rec.RunID},
	} {
		saveRunOwner(t, h.dir, &runbuild.Owner{RunID: shell.runID, StartedAt: rec.At.Add(5 * time.Minute)})
		now := h.capPause(t)
		h.srv.nowFn = func() time.Time { return now }
		before := len(h.claudeRuns(t))
		if h.srv.maybeAutoResume(h.dir) {
			t.Fatalf("a run started from a shell %s was resumed as the hub's last starter", shell.name)
		}
		if got := len(h.claudeRuns(t)); got != before {
			t.Fatalf("claude ran %d time(s)", got-before)
		}
		if pr := h.pause(t); pr.Code != pausereason.CodeStarterUnavailable ||
			!strings.Contains(pr.Detail, "not started from this hub") || strings.Contains(pr.Detail, resumeAlice) {
			t.Fatalf("%s: the pause is %s %q, want starter_unavailable saying the run was not the hub's",
				shell.name, pr.Code, pr.Detail)
		}
	}

	// The run alice's dispatch started recorded itself as it started — even
	// one that missed the placement record and minted an id of its own.
	saveRunOwner(t, h.dir, &runbuild.Owner{RunID: "run_minted_by_the_child", StartedAt: rec.At.Add(2 * time.Second)})
	h.capPause(t)
	if !h.srv.maybeAutoResume(h.dir) {
		t.Fatal("the run alice started was not resumed")
	}
	h.settle(t)
	h.lastRanFor(t, resumeAlice, "the resume of the run alice started")

	// A run owner older than the record — a device's run records its own on
	// the device — says nothing against it.
	rec = readRecord(t, h.dir)
	saveRunOwner(t, h.dir, &runbuild.Owner{RunID: "run_before", StartedAt: rec.At.Add(-time.Hour)})
	h.capPause(t)
	if !h.srv.maybeAutoResume(h.dir) {
		t.Fatal("a record newer than the run owner was not honoured")
	}
	h.settle(t)
	h.lastRanFor(t, resumeAlice, "a resume after a device run")
}

// The bare identity beside the record names somebody else: an older hub
// build dispatched a run since and rewrote only that key. Neither record can
// then be trusted to name the run's starter.
func TestARecordAnOlderBuildOverwroteIsNotTrusted(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	db, err := statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetHubMeta(harnessInitiatorKey(h.dir), resumeBob); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	acct := h.srv.resumeAccountFor(h.dir)
	if acct.unavailable == nil || acct.basis != actedForUnknown || acct.unavailable.Transient {
		t.Fatalf("disagreeing records resolved to %+v (%+v)", acct, acct.unavailable)
	}
	if err := acct.check(hostExecutor()); err == nil {
		t.Error("a host dispatch acting on disagreeing records was not refused")
	}

	// And a record that cannot be decoded is held, not retried for ever.
	db, err = statedb.Open(state.DBPath(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetHubMeta(harnessInitiatorRunKey(h.dir), "{not json"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	acct = h.srv.resumeAccountFor(h.dir)
	if acct.unavailable == nil || acct.unavailable.Transient || !acct.unavailable.AnyExecutor {
		t.Fatalf("an unreadable record resolved to %+v", acct.unavailable)
	}
}

// A resume leaves the record it acted on, never more: an owner fallback stays
// one, and a run nobody could be named for stays unknown — never laundered into
// "started for no one", which would run on the hub's own login.
func TestAResumeRecordsTheBasisItActedOn(t *testing.T) {
	h := newResumeHub(t)
	owned := setupProjectDir(t, "an owned project", nil)
	if err := multiui.AddPathsOwned([]string{owned}, "carol@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := claudecodeauth.HomeFor("carol@example.com"); err != nil {
		t.Fatal(err)
	}
	newResumeClearance(h.srv.resumeAccountFor(owned)).started("run_resumed")
	if rec := readRecord(t, owned); rec.Identity != "carol@example.com" || rec.Basis != actedForOwner || rec.RunID != "run_resumed" {
		t.Fatalf("the resume recorded %+v, want carol on the owner's basis", rec)
	}
	if again := h.srv.resumeAccountFor(owned); again.basis != actedForOwner || again.unavailable != nil {
		t.Errorf("the next resume acts on basis %q (%v)", again.basis, again.unavailable)
	}

	acct := h.srv.resumeAccountFor(h.dir) // the hub's own project: no record, no owner
	if acct.basis != actedForUnknown {
		t.Fatalf("basis %q, want unknown", acct.basis)
	}
	newResumeClearance(acct).started("run_unknown") // as a dispatch to an isolating executor would
	again := h.srv.resumeAccountFor(h.dir)
	if again.unavailable == nil || again.basis != actedForUnknown {
		t.Fatalf("a run nobody could be named for became %+v", again)
	}
	if err := again.check(hostExecutor()); err == nil {
		t.Error("it may now run on the hub's own login")
	}
}

// A control plane that cannot be read just now refuses the resume but does
// not hold the run: the next sweep asks again.
func TestATransientControlPlaneErrorDoesNotHoldTheRun(t *testing.T) {
	h := newResumeHub(t)
	h.run(t, "alice")
	now := h.capPause(t)
	h.srv.nowFn = func() time.Time { return now }
	resumed := 0
	h.srv.autoResumeStart = func(string) error { resumed++; return nil }

	withControlPlaneDir(t, "/dev/null")
	if h.srv.maybeAutoResume(h.dir) || resumed != 0 {
		t.Fatal("resumed with a control plane that could not be read")
	}
	if pr := h.pause(t); pr.Code != pausereason.CodeUsageCap {
		t.Fatalf("an unreadable control plane held the run: %s %q", pr.Code, pr.Detail)
	}
	withControlPlaneDir(t, h.dir)
	if !h.srv.maybeAutoResume(h.dir) || resumed != 1 {
		t.Fatal("the next sweep did not resume the run")
	}
}

// A deny binding on the project refuses the resume on every executor. One on
// an executor does not — authz applies those to managing the executor, never
// to a project's run — but the executor's access list does, where its user
// entries show the starter is not on it.
func TestProjectDeniesAndExecutorAccessListsRefuseTheResume(t *testing.T) {
	h := newResumeHub(t)
	if _, err := claudecodeauth.HomeFor("erin@example.com"); err != nil {
		t.Fatal(err)
	}
	recordHarnessInitiator(h.dir, harnessInitiator{Identity: "erin@example.com"})
	box := containerExec()
	putDeny(t, statedb.RoleBindingRow{Claim: "email", Value: "erin@example.com", Executor: box.ID(), Reason: "no admin of the box"})
	acct := h.srv.resumeAccountFor(h.dir)
	if acct.unavailable != nil {
		t.Fatalf("an executor-scoped deny refused the resume: %v", acct.unavailable)
	}
	if err := acct.check(box); err != nil {
		t.Errorf("a deny on managing the box refused a run on it: %v", err)
	}

	audience := func(kind, value string) {
		t.Helper()
		db, err := statedb.Open(state.DBPath(controlPlaneDir()))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := db.AddExecutorAudience(box.ID(), kind, value, "test"); err != nil {
			t.Fatal(err)
		}
	}
	audience("user", "frank@example.com")
	if err := acct.check(box); err == nil {
		t.Error("a run on an executor whose access list does not name erin was not refused")
	}
	audience("user", "Erin@Example.com")
	if err := acct.check(box); err != nil {
		t.Errorf("a run on an executor whose list names erin was refused: %v", err)
	}
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ClearExecutorAudience(box.ID()); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	// A group may admit her: which groups she is in is a claim of her
	// sign-in, which a resume does not have. So may an entry for a subject —
	// hers, for all a resume that knows her by email can tell.
	for _, other := range [][2]string{{"group", "engineers"}, {"user", "sub-erin-at-the-idp"}} {
		audience("user", "frank@example.com")
		audience(other[0], other[1])
		if err := acct.check(box); err != nil {
			t.Errorf("a run on an executor open to %s %q was refused: %v", other[0], other[1], err)
		}
		db, err := statedb.Open(state.DBPath(controlPlaneDir()))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.ClearExecutorAudience(box.ID()); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}

	putDeny(t, statedb.RoleBindingRow{Claim: "email", Value: "erin@example.com", Project: h.dir, Reason: "left the team"})
	acct = h.srv.resumeAccountFor(h.dir)
	if acct.unavailable == nil || !acct.unavailable.AnyExecutor {
		t.Fatalf("a project-scoped deny resolved to %+v", acct.unavailable)
	}
	if strings.Contains(acct.unavailable.Error(), "left the team") || !strings.Contains(acct.unavailable.logDetail(), "left the team") {
		t.Errorf("the refusal shows the project %q and the hub log %q", acct.unavailable.Error(), acct.unavailable.logDetail())
	}
}

// A member that was handed a resume and declined it — the state moved, or it
// held the run — resumed nothing, and the trail says nothing.
func TestADeclinedHandOffIsNotAResume(t *testing.T) {
	dir, a, b := clusterPair(t)
	bm, ok := a.node.Member(b.node.ID())
	if !ok {
		t.Fatal("A does not know B")
	}
	if err := a.srv.handOffAutoResume(bm, dir); !errors.Is(err, errResumeDeclined) {
		t.Fatalf("a member's refusal to restart a run that is not paused read as %v", err)
	}

	setPauseReason(t, dir, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour window exhausted", time.Now().Add(-time.Hour)))
	a.srv.autoResumeStart = func(string) error { return errResumeDeclined }
	if a.srv.maybeAutoResume(dir) {
		t.Fatal("a declined hand-off counted as a resume")
	}
	if rows := auditRowsOf(t, dir, auditaction.ActionRunCapResumed); len(rows) != 0 {
		t.Errorf("a declined hand-off was recorded as %d run.cap_resumed row(s)", len(rows))
	}
	if st, err := state.LoadLite(dir); err != nil || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeUsageCap {
		t.Errorf("the leader rewrote the member's answer into the pause: %+v (%v)", st.PauseReason, err)
	}
}

// An older build's pause for a starter with no home here, on an executor that
// would not have used one: nothing could ever read the starter's windows, so
// it is held, saying so, rather than left looking like a budget nobody raises.
func TestALegacyPauseWithNoUsageToReadIsHeld(t *testing.T) {
	h := newResumeHub(t)
	box := containerExec()
	registerStub(t, box)
	if err := executor.Bind(h.dir, box.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(h.dir) })
	recordHarnessInitiator(h.dir, harnessInitiator{Identity: "frank@example.com"})
	setPauseReason(t, h.dir, pausereason.New(pausereason.CodeBudget, legacyExtraUsageDetail))
	h.srv.autoResumeUsage = func(dir string) (*ratelimit.ClaudeUsage, error) {
		t.Errorf("usage was read under %q for a starter with no home", dir)
		return nil, errors.New("no")
	}
	if h.srv.maybeAutoResume(h.dir) {
		t.Fatal("resumed a pause nothing could judge")
	}
	if pr := h.pause(t); pr.Code != pausereason.CodeStarterUnavailable || !strings.Contains(pr.Detail, "frank@example.com") ||
		!strings.Contains(pr.Detail, "usage") {
		t.Fatalf("the pause is %s %q, want starter_unavailable naming frank and the usage it cannot read", pr.Code, pr.Detail)
	}
}
