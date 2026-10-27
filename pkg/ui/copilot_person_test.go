package ui

// A copilot project on the hub's own host acts for its person on a hub with
// single sign-on (Task 20449): every run, model call, resume and failover
// there signs the Copilot CLI in with a credential granted to the project that
// counts for that person — never the hub's own `copilot login`, GH_TOKEN or
// GITHUB_TOKEN — and keeps its sessions in their own Copilot home.
//
// The hub's process carries the Copilot and GitHub credentials a service might
// hold for something else; the executors here are stubs that share the hub's
// host and record what they were asked to start, so each test reads the very
// environment the `cloop run` or helper subcommand would have inherited.
// pkg/provider/copilot's tests take it from there to the CLI, and
// cmd/hub_copilot_test.go runs the whole chain.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/copilotauth"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// hubCopilotEnv is the hub process's own: what a run that inherits it would
// sign in with, and where it would send a token.
var hubCopilotEnv = map[string]string{
	"COPILOT_GITHUB_TOKEN": "hub-copilot-token",
	"GH_TOKEN":             "hub-gh-token",
	"GITHUB_TOKEN":         "hub-github-token",
	"GH_HOST":              "ghe.hub.example",
	"COPILOT_API_URL":      "https://collector.hub.example",
}

func setHubCopilotEnv(t *testing.T) {
	t.Helper()
	for k, v := range hubCopilotEnv {
		t.Setenv(k, v)
	}
}

// personToken is a fine-grained GitHub token shaped as the paste classifier
// recognises one, distinct per tag (six characters); built at run time so no
// realistic-looking token sits in the source.
func personToken(tag string) string {
	return "github" + "_pat_" + "11AB2CD3" + strings.Repeat(tag, 12)
}

// newCopilotHub is the harness hub with its own project a copilot one on an
// executor that shares the hub's host.
func newCopilotHub(t *testing.T) *harnessHub {
	t.Helper()
	setHubCopilotEnv(t)
	h := newHarnessHub(t)
	host := newHarnessExec("copilot-hub-host", executor.KindLocalProcess, executor.IsolationNone)
	registerStub(t, host)
	executor.DefaultRegistry.Unbind(h.srv.WorkDir)
	if err := executor.Bind(h.srv.WorkDir, host.ID()); err != nil {
		t.Fatal(err)
	}
	h.ex = host
	setProvider(t, h.srv.WorkDir, "copilot")
	ps, err := state.Load(h.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending, Priority: 1},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	return h
}

// paste has who store token as their personal Copilot credential and grant it
// to the project, returning the grant's id.
func pasteCopilot(t *testing.T, h *harnessHub, who, token string) string {
	t.Helper()
	code, out := h.do(t, who, "POST", harnessPath, map[string]any{"token": token})
	if code != http.StatusOK {
		t.Fatalf("%s's paste = %d %v", who, code, out)
	}
	return out["granted"].(map[string]any)["grant_id"].(string)
}

// settleRuns waits until the project executes nothing.
func settleRuns(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for srv.projectExecuting(srv.WorkDir) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	awaitQuietProject(t, srv.WorkDir)
}

// actedFor asserts env signs the Copilot CLI in as owner with token, in
// owner's Copilot home, with the hub's own Copilot variables blanked. The
// hub's GitHub tokens and host stay in the run, for its other tools: the
// provider removes them from the CLI's environment (pkg/provider/copilot).
func actedFor(t *testing.T, env map[string]string, owner, token, what string) {
	t.Helper()
	pinnedTo(t, env, owner, what)
	if got := env[envCopilotGitHubToken]; got != token {
		t.Errorf("%s: COPILOT_GITHUB_TOKEN is %.24q…, want %s's own", what, got, owner)
	}
}

// pinnedTo asserts env pins the Copilot CLI to owner's Copilot home, with the
// hub's own Copilot variables blanked.
func pinnedTo(t *testing.T, env map[string]string, owner, what string) {
	t.Helper()
	home, err := copilotauth.HomePath(owner)
	if err != nil {
		t.Fatal(err)
	}
	if got := env[copilotauth.EnvHome]; got != home {
		t.Errorf("%s: %s = %q, want %s's own Copilot home %q", what, copilotauth.EnvHome, got, owner, home)
	}
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %s's Copilot home is %v (%v), want a 0700 directory", what, owner, fi, err)
	}
	if v, ok := env["COPILOT_API_URL"]; !ok || v != "" {
		t.Errorf("%s: the hub's COPILOT_API_URL reaches the run as %q (set %v), want it blanked", what, v, ok)
	}
	if v := env[envCopilotGitHubToken]; v == hubCopilotEnv[envCopilotGitHubToken] {
		t.Errorf("%s: the hub's own COPILOT_GITHUB_TOKEN reaches the run", what)
	}
}

// A run on the hub's host, for alice and for bob: each refused until they
// grant a credential of their own, each then started on it and in their own
// Copilot home, never on the hub's — and neither ever on the other's.
func TestCopilotHostRunActsForItsPerson(t *testing.T) {
	h := newCopilotHub(t)

	code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{})
	if code != http.StatusConflict || body["code"] != codeHarnessCredentialMissing || body["per_person"] != true {
		t.Fatalf("alice's run with no credential = %d %v, want the 409 the dialog opens on", code, body)
	}
	if s, _ := body["summary"].(string); !strings.Contains(s, "Copilot credential") {
		t.Errorf("summary = %q", body["summary"])
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "never with the hub's own Copilot sign-in") {
		t.Errorf("the refusal does not say why: %q", msg)
	}
	if n := len(h.ex.started()); n != 0 {
		t.Fatalf("a refused run started %d workload(s) — on the hub's own sign-in", n)
	}

	aliceToken, bobToken := personToken("aL1cE2"), personToken("bO3bB4")
	pasteCopilot(t, h, "alice", aliceToken)
	if code, body := h.do(t, "bob", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusConflict ||
		body["per_person"] != true {
		t.Fatalf("bob's run on alice's personal grant = %d %v", code, body)
	}
	if code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's run once granted = %d %v", code, body)
	}
	settleRuns(t, h.srv)
	specs := h.ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads, want alice's", len(specs))
	}
	aliceEnv := specEnv(specs[0])
	actedFor(t, aliceEnv, "alice@corp.example", aliceToken, "alice's run")
	if !strings.HasSuffix(strings.Join(specs[0].Env, "\n"), copilotauth.Pin(aliceEnv[copilotauth.EnvHome])) {
		t.Error("the pin is not the last word of the run's environment, after the lease's grants")
	}

	pasteCopilot(t, h, "bob", bobToken)
	if code, body := h.do(t, "bob", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("bob's run once granted = %d %v", code, body)
	}
	settleRuns(t, h.srv)
	specs = h.ex.started()
	actedFor(t, specEnv(specs[len(specs)-1]), "bob@corp.example", bobToken, "bob's run")
	for _, kv := range specs[len(specs)-1].Env {
		if strings.Contains(kv, aliceToken) {
			t.Fatal("bob's run carries alice's token")
		}
	}

	// The card is each viewer's own.
	_, view := h.do(t, "bob", "GET", harnessPath, nil)
	if view["applies"] != true || view["per_person"] != true || view["state"] != "ok" ||
		view["satisfied_by"].(map[string]any)["owner"] != "bob@corp.example" {
		t.Errorf("bob's card = %v", view)
	}
	_, view = h.do(t, "lead", "GET", harnessPath, nil)
	if view["state"] != "missing" || view["satisfied_by"] != nil {
		t.Errorf("the lead, who granted nothing, sees %v", view)
	}
	for _, body := range h.bodies {
		if strings.Contains(body, aliceToken) || strings.Contains(body, bobToken) || strings.Contains(body, "hub-copilot-token") {
			t.Fatal("a response repeated a credential")
		}
	}
}

// A credential an administrator shared with the project counts for every
// person's runs, each still in their own Copilot home.
func TestCopilotHostRunOnASharedCredential(t *testing.T) {
	h := newCopilotHub(t)
	shared := personToken("sH5rE6")
	sec := h.seedSharedEnv(t, "team-copilot", envCopilotGitHubToken, shared)
	if code, out := h.do(t, "root", "POST", "/api/grants", map[string]any{
		"secret_ref": sec.ID, "subject": "project:" + h.srv.WorkDir, "ttl_minutes": 600,
		"env_keys": []string{envCopilotGitHubToken},
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("grant the shared credential = %d %v", code, out)
	}
	for i, who := range []string{"alice", "bob"} {
		if code, body := h.do(t, who, "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
			t.Fatalf("%s's run on the shared credential = %d %v", who, code, body)
		}
		settleRuns(t, h.srv)
		specs := h.ex.started()
		if len(specs) != i+1 {
			t.Fatalf("started %d workloads", len(specs))
		}
		actedFor(t, specEnv(specs[i]), who+"@corp.example", shared, who+"'s run")
	}
}

// The dashboard's model calls on a copilot project are dispatched acting for
// the caller exactly as a run is: refused without a credential of theirs,
// started on it otherwise.
func TestCopilotModelCallsActForTheCaller(t *testing.T) {
	h := newCopilotHub(t)
	for _, call := range []struct{ path, what string }{
		{"/api/tasks/1/decompose", "the split preview"},
		{"/api/tasks/1/blocker", "the blocker analysis"},
	} {
		code, body := h.do(t, "bob", "POST", call.path, map[string]any{})
		if code != http.StatusConflict || body["code"] != codeHarnessCredentialMissing || body["per_person"] != true {
			t.Errorf("%s with no credential = %d %v, want the 409 the dialog opens on", call.what, code, body)
		}
	}
	if n := len(h.ex.started()); n != 0 {
		t.Fatalf("a refused model call started %d workload(s)", n)
	}
	token := personToken("bO3bB4")
	pasteCopilot(t, h, "bob", token)
	code, body := h.do(t, "bob", "POST", "/api/tasks/1/decompose", map[string]any{})
	if code == http.StatusConflict {
		t.Fatalf("bob's split preview once granted = %d %v", code, body)
	}
	specs := h.ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads, want the split preview's", len(specs))
	}
	if argv := strings.Join(specs[0].Argv, " "); !strings.Contains(argv, "task decompose") {
		t.Fatalf("the dispatched call is %q", argv)
	}
	actedFor(t, specEnv(specs[0]), "bob@corp.example", token, "bob's split preview")
}

// The automatic resume acts for the run's starter: on her credential and her
// home; and once her credential is gone the run waits paused
// starter_unavailable rather than being carried on on anyone else's.
func TestCopilotResumeActsForItsStarter(t *testing.T) {
	h := newCopilotHub(t)
	token := personToken("aL1cE2")
	grant := pasteCopilot(t, h, "alice", token)
	if code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's run = %d %v", code, body)
	}
	settleRuns(t, h.srv)

	reset := time.Now().Add(-time.Hour)
	setPauseReason(t, h.srv.WorkDir, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour window exhausted", reset))
	now := time.Now()
	h.srv.nowFn = func() time.Time { return now }
	if !h.srv.maybeAutoResume(h.srv.WorkDir) {
		t.Fatal("the sweep did not resume alice's run")
	}
	settleRuns(t, h.srv)
	specs := h.ex.started()
	if len(specs) != 2 {
		t.Fatalf("started %d workloads, want alice's run and its resume", len(specs))
	}
	actedFor(t, specEnv(specs[1]), "alice@corp.example", token, "the resume of alice's run")

	if code, out := h.do(t, "alice", "DELETE", "/api/grants/"+grant, nil); code != http.StatusOK {
		t.Fatalf("alice revokes her grant = %d %v", code, out)
	}
	setPauseReason(t, h.srv.WorkDir, pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour window exhausted", reset))
	if h.srv.maybeAutoResume(h.srv.WorkDir) {
		t.Fatal("the sweep resumed a run whose starter has no Copilot credential")
	}
	if n := len(h.ex.started()); n != 2 {
		t.Fatalf("started %d workloads; a resume with no credential of the starter's ran", n)
	}
	st, err := state.LoadLite(h.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeStarterUnavailable ||
		!strings.Contains(st.PauseReason.Detail, "alice@corp.example") ||
		!strings.Contains(st.PauseReason.Detail, reasonNoCopilot) {
		t.Fatalf("the project is %s %+v, want paused starter_unavailable for alice's Copilot credential",
			st.Status, st.PauseReason)
	}
}

// The preflight's rules, one by one.
func TestPreflightCopilotOnTheHubsHost(t *testing.T) {
	f := newHarnessFixture(t)
	project := t.TempDir()
	setProvider(t, project, "copilot")
	host := newHarnessExec("pf-host", executor.KindLocalProcess, executor.IsolationNone)
	alice := harnessWho{identity: "alice@corp.example", personal: true}
	bob := harnessWho{identity: "bob@corp.example", personal: true}

	rep := harnessPreflight(project, host, alice, "", true)
	if !rep.PerPerson || !rep.Applies || rep.State != "missing" || rep.refusal() == nil {
		t.Fatalf("a copilot run on the hub's host, nothing granted: %+v", rep)
	}
	if e, ok := asHarnessRefusal(rep.refusal()); !ok || !e.PerPerson || e.Code != codeHarnessCredentialMissing {
		t.Fatalf("refusal = %v", rep.refusal())
	}
	// Not checked: a single-user hub, a lease clearance, another provider.
	for what, r := range map[string]harnessReport{
		"single-user":     harnessPreflight(project, host, harnessWho{}, "", true),
		"lease clearance": harnessPreflight(project, host, alice, "", false),
		"claudecode":      harnessPreflight(project, host, alice, "claudecode", true),
	} {
		if r.PerPerson || r.Applies || r.refusal() != nil {
			t.Errorf("%s: %+v, want nothing checked", what, r)
		}
	}

	aliceGrant := f.grant(t, f.env(t, "alice-copilot", map[string]string{envCopilotGitHubToken: personToken("aL1cE2")},
		"alice@corp.example"), "project:"+project, time.Hour)
	if rep := harnessPreflight(project, host, alice, "", true); rep.State != "ok" || rep.Satisfied[0].GrantID != aliceGrant.ID {
		t.Errorf("alice with her own grant: %+v", rep)
	}
	rep = harnessPreflight(project, host, bob, "", true)
	if rep.State != "missing" || rep.Foreign != 1 || rep.Withhold[aliceGrant.ID] == "" {
		t.Errorf("bob, with only alice's grant: state %q foreign %d withhold %v", rep.State, rep.Foreign, rep.Withhold)
	}
	if cause, _ := rep.explain(); strings.Contains(cause, "alice") {
		t.Errorf("bob's refusal names alice's credential: %s", cause)
	}
	nobody := harnessWho{personal: true}
	rep = harnessPreflight(project, host, nobody, "", true)
	if rep.State != "missing" || !rep.Nobody {
		t.Errorf("acting for no one with only a personal grant: %+v", rep)
	}
	if cause, remedy := rep.explain(); !strings.Contains(cause, "acts for no one") || !strings.Contains(remedy, "shared") {
		t.Errorf("acting for no one: %s / %s", cause, remedy)
	}
	f.grant(t, f.env(t, "team-copilot", map[string]string{envCopilotGitHubToken: personToken("sH5rE6")}, ""),
		"project:"+project, time.Hour)
	for _, w := range []harnessWho{bob, nobody} {
		if rep := harnessPreflight(project, host, w, "", true); rep.State != "ok" {
			t.Errorf("%+v with a shared grant: state %q", w, rep.State)
		}
	}

	// A personal grant carrying only what travels beside a provider's URL —
	// its headers, which may hold its key — is bob's credential too, and is
	// withheld from alice's lease like his token would be.
	headers := f.grant(t, f.env(t, "bob-gateway-headers",
		map[string]string{"COPILOT_PROVIDER_HEADERS": `{"Authorization":"Bearer bob-gateway-key"}`}, "bob@corp.example"),
		"project:"+project, time.Hour)
	if rep := harnessPreflight(project, host, alice, "", true); rep.Withhold[headers.ID] == "" {
		t.Errorf("bob's personal provider headers reach alice's lease: withhold %v", rep.Withhold)
	}

	// The provider factory reads names without regard to case, and so does
	// the preflight: a project that recorded "Copilot" runs the Copilot CLI.
	shouty := t.TempDir()
	setProvider(t, shouty, "Copilot")
	if rep := harnessPreflight(shouty, host, alice, "", true); !rep.PerPerson || rep.Provider != "copilot" || rep.State != "missing" {
		t.Errorf("a project naming \"Copilot\": %+v", rep)
	}
}

// A clearance never settled against the executor it is asked about — no
// primitive does that — pins a would-be pinned dispatch to nobody's home
// rather than to nothing.
func TestAnUnsettledClearancePinsNobodysHome(t *testing.T) {
	setHubCopilotEnv(t)
	host := newHarnessExec("unsettled-host", executor.KindLocalProcess, executor.IsolationNone)
	c := newHarnessClearance(t.TempDir(), harnessWho{identity: "alice@corp.example", personal: true}, "")
	blanks, pin := c.copilotEnv(host)
	if len(blanks) == 0 || len(pin) != 1 || pin[0] != copilotauth.Pin(noCopilotHomePath) {
		t.Errorf("copilotEnv = %v / %v, want the hub's Copilot variables blanked and a home that never exists", blanks, pin)
	}
	sandbox := newHarnessExec("unsettled-sandbox", executor.KindContainer, executor.IsolationContainer)
	if b, p := c.copilotEnv(sandbox); b != nil || p != nil {
		t.Errorf("a sandbox got %v / %v", b, p)
	}
	single := newHarnessClearance(t.TempDir(), harnessWho{}, "")
	if b, p := single.copilotEnv(host); b != nil || p != nil {
		t.Errorf("a single-user hub's dispatch got %v / %v", b, p)
	}
}

// A dispatch the hub makes by itself — a resume, a failover — finds the
// starter's Copilot home; it never makes their identity home, and one that is
// gone holds the run for a person.
func TestResumeClearanceFindsTheStartersCopilotHome(t *testing.T) {
	setHubCopilotEnv(t)
	f := newHarnessFixture(t)
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	setProvider(t, project, "copilot")
	host := newHarnessExec("rc-host", executor.KindLocalProcess, executor.IsolationNone)
	const owner = "alice@corp.example"
	f.grant(t, f.env(t, "alice-copilot", map[string]string{envCopilotGitHubToken: personToken("aL1cE2")}, owner),
		"project:"+project, time.Hour)
	acct := &resumeAccount{workDir: project, who: harnessWho{identity: owner, personal: true}, basis: actedForStarter}

	// No identity home: offboarded, or never here.
	if _, err := newResumeClearance(acct).settle(host, project); err == nil {
		t.Fatal("a resume for a starter with no identity home was not refused")
	} else if su, ok := errStarterUnavailable(err); !ok || !su.Copilot || su.Transient {
		t.Fatalf("refusal = %v, want a held starter_unavailable for Copilot", err)
	}
	identity, err := claudecodeauth.HomePath(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(identity); !os.IsNotExist(err) {
		t.Fatalf("the refused resume made alice an identity home: %v", err)
	}

	if _, err := claudecodeauth.HomeFor(owner); err != nil {
		t.Fatal(err)
	}
	c := newResumeClearance(acct)
	if _, err := c.settle(host, project); err != nil {
		t.Fatalf("settle: %v", err)
	}
	blanks, pin := c.copilotEnv(host)
	if len(blanks) == 0 || len(pin) != 1 || pin[0] != copilotauth.Pin(filepath.Join(identity, "copilot")) {
		t.Fatalf("copilotEnv = %v / %v", blanks, pin)
	}
	other := newHarnessExec("rc-sandbox", executor.KindContainer, executor.IsolationContainer)
	if b, p := c.copilotEnv(other); b != nil || p != nil {
		t.Errorf("a clearance settled for one executor pinned another: %v %v", b, p)
	}
}

// One person's grant never names another person's home: the pin outranks an
// env grant of the variable it pins.
func TestAGrantCannotRepointACopilotRunsHome(t *testing.T) {
	h := newCopilotHub(t)
	token := personToken("mA7lL8")
	victim, err := copilotauth.HomeFor("bob@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{envCopilotGitHubToken: token, copilotauth.EnvHome: victim})
	code, out := h.do(t, "alice", "POST", "/api/secrets", map[string]any{
		"name": "alice-copilot-and-more", "kind": "env", "payload": string(payload), "personal": true,
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("alice's secret = %d %v", code, out)
	}
	secID := fmt.Sprint(out["id"])
	if secID == "" || secID == "<nil>" {
		if s, ok := out["secret"].(map[string]any); ok {
			secID = fmt.Sprint(s["id"])
		}
	}
	if code, out := h.do(t, "alice", "POST", "/api/grants", map[string]any{
		"secret_ref": secID, "subject": "project:" + h.srv.WorkDir, "ttl_minutes": 600,
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("alice's grant = %d %v", code, out)
	}
	if code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's run = %d %v", code, body)
	}
	settleRuns(t, h.srv)
	specs := h.ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads", len(specs))
	}
	if !strings.Contains(strings.Join(specs[0].Env, "\n"), copilotauth.EnvHome+"="+victim) {
		t.Fatal("the lease did not deliver the grant's home at all; this test proves nothing")
	}
	if got := specEnv(specs[0])[copilotauth.EnvHome]; got == victim {
		t.Fatalf("alice's grant pointed her run at bob's Copilot home %s", got)
	}
	actedFor(t, specEnv(specs[0]), "alice@corp.example", token, "alice's run")
}

// A run of a project whose own provider is another may still start the
// Copilot CLI — as its review gate's reviewer — so every harness dispatch to
// the hub's host on a hub with single sign-on is pinned to its person,
// whatever the provider; only a copilot project needs a Copilot credential to
// be dispatched at all.
func TestEveryHostRunIsPinnedWhateverItsProvider(t *testing.T) {
	h := newCopilotHub(t)
	setProvider(t, h.srv.WorkDir, "claudecode")
	ps, err := state.Load(h.srv.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	ps.ReviewGate = &pm.ReviewGate{Enabled: true, Provider: "copilot"}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if code, body := h.do(t, "alice", "POST", "/api/projects/0/run", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's claudecode run = %d %v; it needs no Copilot credential to start", code, body)
	}
	settleRuns(t, h.srv)
	specs := h.ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads", len(specs))
	}
	pinnedTo(t, specEnv(specs[0]), "alice@corp.example", "alice's claudecode run with a Copilot reviewer")
}

// A hub without single sign-on keeps today's behaviour: nothing is checked,
// blanked or pinned.
func TestSingleUserHubCopilotHostRunIsUnchanged(t *testing.T) {
	setHubCopilotEnv(t)
	f := newHarnessFixture(t)
	setProvider(t, f.dir, "copilot")
	host := newHarnessExec("su-host", executor.KindLocalProcess, executor.IsolationNone)
	registerStub(t, host)
	if err := executor.Bind(f.dir, host.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(f.dir) })
	ex, _, err := startWorkloadAs(nil, newHarnessClearance(f.dir, harnessWho{}, ""), "", f.dir,
		[]string{"cloop", "run"}, map[string]string{"handler": "run"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The dispatch's watchers write to the project as the run ends; let them
	// finish before its directory is removed.
	t.Cleanup(func() { awaitQuietProject(t, f.dir) })
	if ex.ID() != host.ID() {
		t.Fatalf("dispatched to %s", ex.ID())
	}
	specs := host.started()
	if len(specs) != 1 {
		t.Fatalf("started %d", len(specs))
	}
	env := specEnv(specs[0])
	if _, ok := env[copilotauth.EnvHome]; ok {
		t.Error("a single-user hub pinned a Copilot home")
	}
	for k := range hubCopilotEnv {
		if v, ok := env[k]; ok && v == "" {
			t.Errorf("a single-user hub blanked %s", k)
		}
	}
}

// The identity provider reaches a person's Copilot credential as it reaches
// their other personal ones (Task 20415): a deactivation suspends it — their
// runs on the hub's host are refused, and it stays sealed in case the provider
// reactivates them — and a deletion destroys it, with the Copilot home inside
// their identity home.
func TestSCIMReachesACopilotCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(secretbroker.EnvPassphraseKey, "scim-copilot-passphrase")
	f := newSCIMFixture(t, authz.Config{})
	id := f.provisionAlice(t)
	project := f.srv.WorkDir
	setProvider(t, project, "copilot")
	useControlPlaneDir(t, project)
	host := newHarnessExec("scim-host", executor.KindLocalProcess, executor.IsolationNone)
	who := harnessWho{identity: aliceEmail, personal: true}

	home, err := copilotauth.HomeFor(aliceEmail)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "session-store.db"), []byte("conversations"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := openTestBroker(t, project)
	payload, _ := json.Marshal(map[string]string{envCopilotGitHubToken: personToken("aL1cE2")})
	sec, err := b.Mint(t.Context(), secretbroker.MintRequest{Name: "alice-copilot", Kind: secretbroker.KindEnv,
		Payload: payload, Actor: aliceEmail, Owner: aliceEmail, Personal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(t.Context(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project}, TTL: time.Hour,
		Actor: aliceEmail, Viewer: secretbroker.Viewer{Identity: aliceEmail}}); err != nil {
		t.Fatal(err)
	}
	if rep := harnessPreflight(project, host, who, "", true); rep.State != "ok" {
		t.Fatalf("before the deactivation alice's run would be %q", rep.State)
	}

	status, out := f.scim(t, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if status != http.StatusOK || out["active"] != false {
		t.Fatalf("the deactivation answered %d %v", status, out)
	}
	if rep := harnessPreflight(project, host, who, "", true); rep.State != "missing" || rep.refusal() == nil {
		t.Fatalf("after the deactivation alice's run would be %q: her Copilot credential is still spendable", rep.State)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("a deactivation, which the provider may lift, destroyed alice's Copilot home: %v", err)
	}

	if status, out := f.scim(t, "DELETE", "/scim/v2/Users/"+id, ""); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("the deletion answered %d %v", status, out)
	}
	if _, err := openTestBroker(t, project).DescribeSecret(sec.ID); err == nil {
		t.Error("alice's Copilot credential survived her deletion at the identity provider")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("alice's Copilot home, with her conversations, survived her deletion: %v", err)
	}
}

// openTestBroker opens the secret broker over dir's control plane.
func openTestBroker(t *testing.T, dir string) *secretbroker.Broker {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.AsControlPlane()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
