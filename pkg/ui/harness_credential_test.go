package ui

// Tests for the harness-credential preflight (Task 20379): which dispatches it
// refuses, which it leaves alone, and that a refused dispatch starts nothing
// while a granted one starts with the credential it was promised.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeAnthropicToken builds a token of the given lead out of parts, so no
// literal in this file has the shape a secret scanner refuses a push over.
func fakeAnthropicToken(lead, tag string) string {
	body := strings.Repeat(tag, 1+40/len(tag))[:40]
	return "sk-" + "ant-" + lead + "-" + body + "Qx7_Lm2-Pz9"
}

// harnessFixture is a control plane with a working broker, pointed at by the
// package, plus helpers to put grants in it.
type harnessFixture struct {
	dir string
	db  *statedb.DB
	b   *secretbroker.Broker
}

func newHarnessFixture(t *testing.T) *harnessFixture {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "harness-credential-unit-passphrase")
	dir := statedbtest.Dir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.AsControlPlane()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	useControlPlaneDir(t, dir)
	return &harnessFixture{dir: dir, db: db, b: b}
}

// env mints an env secret; owner "" mints a shared one.
func (f *harnessFixture) env(t *testing.T, name string, kv map[string]string, owner string) secretbroker.Secret {
	t.Helper()
	parts := make([]string, 0, len(kv))
	for k, v := range kv {
		parts = append(parts, fmt.Sprintf("%q:%q", k, v))
	}
	sec, err := f.b.Mint(t.Context(), secretbroker.MintRequest{
		Name: name, Kind: secretbroker.KindEnv, Payload: []byte("{" + strings.Join(parts, ",") + "}"),
		Actor: "test", Owner: owner, Personal: owner != "",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return sec
}

// grant grants sec to project (or the subject spec given) for ttl, on behalf
// of sec's owner so a personal secret may be spent.
func (f *harnessFixture) grant(t *testing.T, sec secretbroker.Secret, subject string, ttl time.Duration, envKeys ...string) secretbroker.Grant {
	t.Helper()
	return f.grantWith(t, f.b, sec, subject, ttl, envKeys...)
}

func (f *harnessFixture) grantWith(t *testing.T, b *secretbroker.Broker, sec secretbroker.Secret, subject string, ttl time.Duration, envKeys ...string) secretbroker.Grant {
	t.Helper()
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	g, err := b.Grant(t.Context(), secretbroker.GrantRequest{
		SecretRef: sec.ID, Subject: sub, TTL: ttl, Actor: "test",
		Viewer:      secretbroker.Viewer{Identity: sec.Owner},
		Constraints: secretbroker.Constraints{EnvKeys: envKeys},
	})
	if err != nil {
		t.Fatalf("grant %s to %s: %v", sec.Name, subject, err)
	}
	return g
}

// grantLapsed creates a grant that expired an hour ago, through a broker whose
// clock stands two hours back.
func (f *harnessFixture) grantLapsed(t *testing.T, sec secretbroker.Secret, subject string) secretbroker.Grant {
	t.Helper()
	store, err := secretstore.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	past, err := secretbroker.New(store, secretbroker.WithClock(func() time.Time { return time.Now().Add(-2 * time.Hour) }))
	if err != nil {
		t.Fatal(err)
	}
	return f.grantWith(t, past, sec, subject, time.Hour)
}

// harnessExec is an executor that records what it was asked to start. It
// shares the hub's filesystem, so a dispatch has no source tree to fetch, and
// it can take a credential back, so a dispatch may hand it one.
type harnessExec struct {
	id   string
	kind string
	iso  executor.Isolation
	// shares says the executor works on the hub's own tree, as the container
	// driver does. A dispatch needs it here to start without fetching a source
	// tree; the preflight reads it to judge which provider the sandbox runs.
	shares bool

	mu    sync.Mutex
	specs []executor.Spec
}

func newHarnessExec(id, kind string, iso executor.Isolation) *harnessExec {
	return &harnessExec{id: id, kind: kind, iso: iso, shares: true}
}

func (e *harnessExec) ID() string   { return e.id }
func (e *harnessExec) Kind() string { return e.kind }
func (e *harnessExec) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: e.iso, SharesHostFilesystem: e.shares}
}
func (e *harnessExec) HealthCheck(context.Context) error { return nil }
func (e *harnessExec) Start(_ context.Context, spec executor.Spec) (executor.Handle, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.specs = append(e.specs, spec)
	return executor.Handle{ID: fmt.Sprintf("%s-%d", e.id, len(e.specs)), ExecutorID: e.id, StartedAt: time.Now()}, nil
}
func (e *harnessExec) Status(_ context.Context, id string) (executor.Status, error) {
	return executor.Status{HandleID: id, ExecutorID: e.id, State: executor.StateExited}, nil
}
func (e *harnessExec) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	ch := make(chan executor.LogLine)
	close(ch)
	return ch, nil
}
func (e *harnessExec) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *harnessExec) SupportsRevocation() bool                              { return true }
func (e *harnessExec) HoldsLease(string) bool                                { return false }
func (e *harnessExec) Leases() []string                                      { return nil }
func (e *harnessExec) RevokeLease(_ context.Context, req executor.RevokeRequest) executor.RevokeOutcome {
	return executor.RevokeOutcome{LeaseID: req.LeaseID, State: executor.RevokeStateRevoked}
}
func (e *harnessExec) Revocations() []executor.RevokeOutcome { return nil }

func (e *harnessExec) started() []executor.Spec {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]executor.Spec(nil), e.specs...)
}

// setProvider writes an explicit provider into a project's config.yaml.
func setProvider(t *testing.T, dir, provider string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: "+provider+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// remoteExec is a stub for an executor that works on a tree of its own — a
// Pod, a device — fetched, with the project's state seeded into it.
func remoteExec(id, kind string) *harnessExec {
	e := newHarnessExec(id, kind, executor.IsolationRemote)
	e.shares = false
	return e
}

var (
	containerExec = func() *harnessExec { return newHarnessExec("box", executor.KindContainer, executor.IsolationContainer) }
	kataExec      = func() *harnessExec { return newHarnessExec("kata", executor.KindContainer, executor.IsolationVM) }
	podExec       = func() *harnessExec { return remoteExec("pod", executor.KindKubernetes) }
	deviceExec    = func() *harnessExec { return remoteExec("sgx", executor.KindRemoteAgent) }
	// A virtual executor (Task 20345) is a sandbox on an enrolled device: it
	// isolates exactly as the device does.
	virtualExec = func() *harnessExec { return remoteExec("sgx.yubihsm", executor.KindRemoteAgent) }
	hostExec    = func() *harnessExec { return newHarnessExec("local", executor.KindLocalProcess, executor.IsolationNone) }
)

// setStateProvider records provider in a project's state, which decides where
// the project has no config.
func setStateProvider(t *testing.T, dir, provider string) {
	t.Helper()
	st, err := state.Init(dir, "provider "+provider, 0)
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	st.Provider = provider
	if err := st.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}
}

func refusalCode(t *testing.T, rep harnessReport) string {
	t.Helper()
	err := rep.refusal()
	if err == nil {
		return ""
	}
	e, ok := asHarnessRefusal(err)
	if !ok {
		t.Fatalf("refusal is a %T, not a harness refusal: %v", err, err)
	}
	return e.Code
}

func TestPreflightRefusesEveryIsolatingExecutorWithoutACredential(t *testing.T) {
	newHarnessFixture(t)
	project := t.TempDir()
	for _, ex := range []*harnessExec{containerExec(), kataExec(), podExec(), deviceExec(), virtualExec()} {
		t.Run(ex.id, func(t *testing.T) {
			rep := harnessPreflight(project, ex, harnessWho{}, "", true)
			if !rep.Applies || rep.State != "missing" {
				t.Fatalf("report = applies %v, state %q; want a refusal", rep.Applies, rep.State)
			}
			err := rep.refusal()
			e, ok := asHarnessRefusal(err)
			if !ok || e.Code != codeHarnessCredentialMissing || e.ExecutorID != ex.id {
				t.Fatalf("refusal = %v; want harness_credential_missing naming %s", err, ex.id)
			}
			if !strings.Contains(e.Remediation(), "Claude credential") || !strings.Contains(e.Remediation(), "--env-keys") {
				t.Errorf("remedy names neither the dialog nor the CLI: %s", e.Remediation())
			}
		})
	}
}

func TestPreflightLeavesTheHostAndOtherProvidersAlone(t *testing.T) {
	newHarnessFixture(t)
	project := t.TempDir()

	// The host executor runs the harness under the hub's or the user's own
	// login; nothing is checked, whatever the provider.
	if rep := harnessPreflight(project, hostExec(), harnessWho{personal: true}, "", true); rep.Applies || rep.refusal() != nil {
		t.Errorf("host executor: applies %v, refusal %v", rep.Applies, rep.refusal())
	}
	for _, provider := range []string{"mock", "openai", "ollama"} {
		dir := t.TempDir()
		setProvider(t, dir, provider)
		if rep := harnessPreflight(dir, containerExec(), harnessWho{}, "", true); rep.Applies || rep.refusal() != nil {
			t.Errorf("%s in a container: applies %v, refusal %v", provider, rep.Applies, rep.refusal())
		}
		dir = t.TempDir()
		setStateProvider(t, dir, provider)
		if rep := harnessPreflight(dir, deviceExec(), harnessWho{}, "", true); rep.Applies || rep.refusal() != nil {
			t.Errorf("%s on a device: applies %v, refusal %v", provider, rep.Applies, rep.refusal())
		}
	}
	// A workload that runs no harness is never refused, wherever it goes.
	if rep := harnessPreflight(project, deviceExec(), harnessWho{}, "", false); rep.Applies || rep.refusal() != nil {
		t.Errorf("a lease clearance was checked: applies %v, refusal %v", rep.Applies, rep.refusal())
	}
	// No executor resolved is the dispatch's to report, not the preflight's.
	if rep := harnessPreflight(project, nil, harnessWho{}, "", true); rep.Applies {
		t.Error("a nil executor was checked")
	}
}

func TestPreflightAcceptsWhatEachProviderAuthenticatesWith(t *testing.T) {
	f := newHarnessFixture(t)
	token := fakeAnthropicToken("oat01", "oauth")
	key := fakeAnthropicToken("api03", "apikey")

	cases := []struct {
		name     string
		provider string
		grants   []map[string]string // one env secret per entry, granted whole
		want     string
	}{
		{"claude oauth token", "", []map[string]string{{envClaudeOAuthToken: token}}, "ok"},
		{"claude api key", "", []map[string]string{{envAnthropicAPIKey: key}}, "ok"},
		{"relay in one secret", "", []map[string]string{{envAnthropicAuth: key, envAnthropicBaseURL: "https://relay.example"}}, "ok"},
		{"relay split across two grants", "", []map[string]string{{envAnthropicAuth: key}, {envAnthropicBaseURL: "https://relay.example"}}, "ok"},
		{"relay token without its base URL", "", []map[string]string{{envAnthropicAuth: key}}, "missing"},
		{"something else entirely", "", []map[string]string{{"GITHUB_TOKEN": "x"}}, "missing"},
		{"anthropic provider, api key", "anthropic", []map[string]string{{envAnthropicAPIKey: key}}, "ok"},
		{"anthropic provider, cloop's own spelling", "anthropic", []map[string]string{{envCloopAnthropicKey: key}}, "ok"},
		{"anthropic provider, oauth token only", "anthropic", []map[string]string{{envClaudeOAuthToken: token}}, "missing"},
		// The cloud platforms: the flag is the hub's to see, the rest the
		// platform's to check.
		{"bedrock", "", []map[string]string{{envClaudeUseBedrock: "1", "AWS_REGION": "eu-central-1"}}, "ok"},
		{"vertex", "", []map[string]string{{envClaudeUseVertex: "1"}}, "ok"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			if tc.provider != "" {
				setProvider(t, project, tc.provider)
			}
			for j, kv := range tc.grants {
				sec := f.env(t, fmt.Sprintf("case-%d-%d", i, j), kv, "")
				f.grant(t, sec, "project:"+project, time.Hour)
			}
			rep := harnessPreflight(project, containerExec(), harnessWho{}, "", true)
			if rep.State != tc.want {
				t.Fatalf("state = %q, want %q (report %+v)", rep.State, tc.want, rep)
			}
			if tc.want == "ok" && len(rep.Satisfied) == 0 {
				t.Error("an ok report names no grant it relies on")
			}
		})
	}
}

// The grant's env_keys allowlist and the project's sandbox.yaml env list both
// narrow what the sandbox receives, after the lease; the preflight has to see
// the same narrowing or it would wave a run through that reaches claude
// logged out.
func TestPreflightSeesTheNarrowingTheLeaseApplies(t *testing.T) {
	f := newHarnessFixture(t)
	token := fakeAnthropicToken("oat01", "narrow")

	project := t.TempDir()
	sec := f.env(t, "narrowed", map[string]string{envClaudeOAuthToken: token, "OTHER": "x"}, "")
	f.grant(t, sec, "project:"+project, time.Hour, "OTHER")
	if rep := harnessPreflight(project, deviceExec(), harnessWho{}, "", true); rep.State != "missing" {
		t.Errorf("a grant whose env_keys exclude the token: state %q, want missing", rep.State)
	}

	filtered := t.TempDir()
	f.grant(t, f.env(t, "filtered", map[string]string{envClaudeOAuthToken: token}, ""), "project:"+filtered, time.Hour)
	if err := os.MkdirAll(filepath.Join(filtered, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filtered, ".cloop", "sandbox.yaml"), []byte("env: [GITHUB_TOKEN]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := harnessPreflight(filtered, deviceExec(), harnessWho{}, "", true)
	if rep.State != "missing" || len(rep.Filtered) != 1 || rep.Filtered[0] != envClaudeOAuthToken {
		t.Fatalf("sandbox.yaml env list without the token: state %q filtered %v", rep.State, rep.Filtered)
	}
	if _, remedy := rep.explain(); !strings.Contains(remedy, "sandbox.yaml") {
		t.Errorf("remedy does not point at sandbox.yaml: %s", remedy)
	}
}

func TestPreflightFeatureUsesItsParentsGrant(t *testing.T) {
	f := newHarnessFixture(t)
	parent := t.TempDir()
	feature := filepath.Join(parent, ".cloop", "features", "login")
	if err := os.MkdirAll(feature, 0o755); err != nil {
		t.Fatal(err)
	}
	if rep := harnessPreflight(feature, deviceExec(), harnessWho{}, "", true); rep.State != "missing" {
		t.Fatalf("before any grant: state %q", rep.State)
	}
	f.grant(t, f.env(t, "parent-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "parent")}, ""),
		"project:"+parent, time.Hour)
	rep := harnessPreflight(feature, deviceExec(), harnessWho{}, "", true)
	if rep.State != "ok" || rep.Satisfied[0].SecretName != "parent-claude" {
		t.Fatalf("feature after its parent's grant: state %q satisfied %+v", rep.State, rep.Satisfied)
	}
	// And a grant to the feature's own path, which no lease ever names, is not
	// mistaken for one.
	other := t.TempDir()
	otherFeature := filepath.Join(other, ".cloop", "features", "beta")
	if err := os.MkdirAll(otherFeature, 0o755); err != nil {
		t.Fatal(err)
	}
	f.grant(t, f.env(t, "feature-path", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "featr")}, ""),
		"project:"+otherFeature, time.Hour)
	if rep := harnessPreflight(otherFeature, deviceExec(), harnessWho{}, "", true); rep.State != "missing" {
		t.Errorf("a grant to the feature's own path counted: state %q", rep.State)
	}
}

func TestPreflightNeverCountsAnotherUsersPersonalSecret(t *testing.T) {
	f := newHarnessFixture(t)
	project := t.TempDir()
	alice := f.env(t, "alice-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "alice")}, "alice@corp.example")
	aliceGrant := f.grant(t, alice, "project:"+project, time.Hour)

	bob := harnessWho{identity: "bob@corp.example", personal: true}
	rep := harnessPreflight(project, deviceExec(), bob, "", true)
	if rep.State != "missing" || rep.Foreign != 1 {
		t.Fatalf("bob's run with only alice's personal token: state %q foreign %d", rep.State, rep.Foreign)
	}
	if why, ok := rep.Withhold[aliceGrant.ID]; !ok || !strings.Contains(why, "alice@corp.example") {
		t.Errorf("alice's grant is not withheld from bob's lease: %v", rep.Withhold)
	}
	cause, _ := rep.explain()
	if strings.Contains(cause, "alice-claude") {
		t.Errorf("the refusal names another user's secret: %s", cause)
	}

	// Nobody at all — a static token's run — fares no better.
	if rep := harnessPreflight(project, deviceExec(), harnessWho{personal: true}, "", true); rep.State != "missing" {
		t.Errorf("an anonymous run counted alice's token: state %q", rep.State)
	}
	// Alice's own run does count it, whatever the case of her address.
	if rep := harnessPreflight(project, deviceExec(), harnessWho{identity: "alice@corp.example", personal: true}, "", true); rep.State != "ok" || len(rep.Withhold) != 0 {
		t.Errorf("alice's own run: state %q withhold %v", rep.State, rep.Withhold)
	}
	// Without single sign-on there is one person and every grant is theirs.
	if rep := harnessPreflight(project, deviceExec(), harnessWho{}, "", true); rep.State != "ok" {
		t.Errorf("single-user hub: state %q", rep.State)
	}
	// A shared credential satisfies bob, and alice's stays withheld.
	f.grant(t, f.env(t, "team-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "teamx")}, ""),
		"project:"+project, time.Hour)
	rep = harnessPreflight(project, deviceExec(), bob, "", true)
	if rep.State != "ok" || rep.Satisfied[0].SecretName != "team-claude" || rep.Withhold[aliceGrant.ID] == "" {
		t.Errorf("bob with a shared grant: state %q satisfied %+v withhold %v", rep.State, rep.Satisfied, rep.Withhold)
	}
}

func TestPreflightRefusesExpiredAndExpiringGrants(t *testing.T) {
	f := newHarnessFixture(t)

	lapsed := t.TempDir()
	sec := f.env(t, "lapsed", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "lapse")}, "")
	g := f.grantLapsed(t, sec, "project:"+lapsed)
	rep := harnessPreflight(lapsed, deviceExec(), harnessWho{}, "", true)
	if refusalCode(t, rep) != codeHarnessCredentialMissing || len(rep.Lapsed) != 1 || rep.Lapsed[0].GrantID != g.ID {
		t.Fatalf("expired grant: code %q lapsed %+v", refusalCode(t, rep), rep.Lapsed)
	}
	if cause, _ := rep.explain(); !strings.Contains(cause, "expired") {
		t.Errorf("the refusal does not say the grant expired: %s", cause)
	}

	soon := t.TempDir()
	f.grant(t, f.env(t, "soon", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "soonx")}, ""),
		"project:"+soon, 5*time.Minute)
	rep = harnessPreflight(soon, deviceExec(), harnessWho{}, "", true)
	if refusalCode(t, rep) != codeHarnessCredentialExpiring {
		t.Fatalf("grant expiring in 5 minutes: code %q state %q", refusalCode(t, rep), rep.State)
	}
	e, _ := asHarnessRefusal(rep.refusal())
	if e.ExpiresAt.IsZero() {
		t.Error("an expiring refusal carries no expiry")
	}

	// A longer grant beside it is the credential the answer relies on, since
	// any one is enough — but the lease still ends with the five-minute grant,
	// the first of its grants to lapse, and takes the longer one with it.
	f.grant(t, f.env(t, "later", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "later")}, ""),
		"project:"+soon, 20*time.Minute)
	rep = harnessPreflight(soon, deviceExec(), harnessWho{}, "", true)
	if refusalCode(t, rep) != codeHarnessCredentialExpiring || rep.Satisfied[0].SecretName != "later" ||
		rep.EndedBy == nil || rep.EndedBy.SecretName != "soon" {
		t.Fatalf("with a 20-minute grant beside a 5-minute one: state %q satisfied %+v ended by %+v",
			rep.State, rep.Satisfied, rep.EndedBy)
	}
	if cause, remedy := rep.explain(); !strings.Contains(cause, "soon") || !strings.Contains(remedy, rep.EndedBy.GrantID) {
		t.Errorf("the refusal does not name the grant that ends the lease: %s / %s", cause, remedy)
	}
	// Once the short grant is gone, the long one is what the sandbox has.
	if err := f.b.Revoke(t.Context(), rep.EndedBy.GrantID, "test"); err != nil {
		t.Fatal(err)
	}
	rep = harnessPreflight(soon, deviceExec(), harnessWho{}, "", true)
	if rep.State != "ok" || rep.Satisfied[0].SecretName != "later" || rep.EndedBy != nil {
		t.Errorf("after revoking the short grant: state %q satisfied %+v ended by %+v", rep.State, rep.Satisfied, rep.EndedBy)
	}

	// A grant of another kind ends the lease just the same.
	gh := t.TempDir()
	f.grant(t, f.env(t, "gh-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "ghclaude")}, ""),
		"project:"+gh, time.Hour)
	pat, err := f.b.Mint(t.Context(), secretbroker.MintRequest{
		Name: "gh-pat", Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_" + strings.Repeat("Ab3d", 9)), Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := secretbroker.ParseSubject("project:" + gh)
	if _, err := f.b.Grant(t.Context(), secretbroker.GrantRequest{
		SecretRef: pat.ID, Subject: sub, TTL: 3 * time.Minute, Actor: "test",
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
	}); err != nil {
		t.Fatal(err)
	}
	rep = harnessPreflight(gh, deviceExec(), harnessWho{}, "", true)
	if refusalCode(t, rep) != codeHarnessCredentialExpiring || rep.EndedBy == nil || rep.EndedBy.SecretName != "gh-pat" {
		t.Errorf("a 3-minute GitHub grant beside an hour's Claude one: state %q ended by %+v", rep.State, rep.EndedBy)
	}
}

func TestPreflightNamesAnUnconfiguredBroker(t *testing.T) {
	newHarnessFixture(t)
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	rep := harnessPreflight(t.TempDir(), deviceExec(), harnessWho{}, "", true)
	if rep.State != "missing" || !rep.BrokerUnset {
		t.Fatalf("no CLOOP_SECRET_KEY: state %q unset %v", rep.State, rep.BrokerUnset)
	}
	if _, remedy := rep.explain(); !strings.Contains(remedy, "CLOOP_SECRET_KEY") {
		t.Errorf("remedy does not say what to set: %s", remedy)
	}
}

// The dispatch itself: a refused run starts nothing and mints no lease; a
// granted one starts with the token in its environment; and another user's
// personal token never reaches the run of someone it does not belong to.
func TestDispatchStartsNothingWithoutACredentialAndWithholdsOthersTokens(t *testing.T) {
	f := newHarnessFixture(t)
	project := statedbtest.Dir(t)
	ex := deviceExec()
	ex.id = "harness-dispatch-device"
	ex.shares = true // so the dispatch binds the tree rather than fetching one
	registerStub(t, ex)
	if err := executor.Bind(project, ex.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(project) })

	bob := newHarnessClearance(project, harnessWho{identity: "bob@corp.example", personal: true}, "")
	_, _, err := startWorkloadAs(nil, bob, "bob@corp.example", project, []string{"cloop", "run"}, nil)
	if e, ok := asHarnessRefusal(err); !ok || e.Code != codeHarnessCredentialMissing {
		t.Fatalf("dispatch with no grant: err = %v, want harness_credential_missing", err)
	}
	if n := len(ex.started()); n != 0 {
		t.Fatalf("a refused dispatch started %d workload(s)", n)
	}
	if rows, _, err := f.db.ListAuditEvents(statedb.AuditFilter{EventType: string(secretbroker.ActionLease)}); err != nil {
		t.Fatalf("list lease rows: %v", err)
	} else if len(rows) != 0 {
		t.Errorf("a refused dispatch wrote %d secret.lease row(s); it must lease nothing", len(rows))
	}

	aliceToken := fakeAnthropicToken("oat01", "alicetok")
	sharedToken := fakeAnthropicToken("oat01", "sharedtk")
	// The shared grant first: whichever grant renders last wins a key both
	// set, so alice's being last is the order in which only withholding keeps
	// her token out of bob's environment.
	f.grant(t, f.env(t, "team-claude", map[string]string{envClaudeOAuthToken: sharedToken}, ""),
		"project:"+project, time.Hour)
	aliceGrant := f.grant(t, f.env(t, "alice-claude", map[string]string{envClaudeOAuthToken: aliceToken}, "alice@corp.example"),
		"project:"+project, time.Hour)

	bob = newHarnessClearance(project, harnessWho{identity: "bob@corp.example", personal: true}, "")
	if _, _, err := startWorkloadAs(nil, bob, "bob@corp.example", project, []string{"cloop", "run"}, nil); err != nil {
		t.Fatalf("dispatch with a shared grant: %v", err)
	}
	specs := ex.started()
	if len(specs) != 1 {
		t.Fatalf("started %d workloads, want 1", len(specs))
	}
	env := strings.Join(specs[0].Env, "\n")
	if !strings.Contains(env, envClaudeOAuthToken+"="+sharedToken) {
		t.Error("the run did not receive the shared token it was cleared on")
	}
	if strings.Contains(env, aliceToken) {
		t.Fatal("alice's personal token reached bob's run")
	}
	for _, b := range specs[0].Secrets {
		if b.GrantID == aliceGrant.ID {
			t.Fatalf("bob's run carries a binding for alice's grant: %+v", b)
		}
	}
	denied := false
	rows, _, err := f.db.ListAuditEvents(statedb.AuditFilter{EventType: string(secretbroker.ActionLease)})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.Payload, aliceGrant.ID) && strings.Contains(r.Payload, "deny") &&
			strings.Contains(r.Payload, "spent only on runs its owner starts") {
			denied = true
		}
	}
	if !denied {
		t.Error("no secret.lease denial records why bob's run went without alice's grant")
	}
}

func TestClearanceSettlesOncePerExecutor(t *testing.T) {
	newHarnessFixture(t)
	project := t.TempDir()
	c := newHarnessClearance(project, harnessWho{}, "")
	if _, err := c.settle(deviceExec(), project); err == nil {
		t.Fatal("no refusal for a device with no grant")
	}
	first := c.report
	if _, err := c.settle(deviceExec(), project); err == nil || c.report != first {
		t.Error("settling for the same executor recomputed the report")
	}
	if _, err := c.settle(hostExec(), project); err != nil || c.report == first {
		t.Errorf("a different executor reused the device's answer: %v", err)
	}
	var nilClear *harnessClearance
	if w, err := nilClear.settle(deviceExec(), ""); w != nil || err != nil {
		t.Error("a nil clearance is not a no-op")
	}
}

// The provider is judged from what reaches the sandbox: a container reads the
// project's config.yaml through its bind mount, a device or a Pod is sent the
// state and never the config, and neither gets the hub's CLOOP_PROVIDER.
func TestPreflightJudgesTheProviderTheSandboxRuns(t *testing.T) {
	newHarnessFixture(t)

	sandboxes := []*harnessExec{containerExec(), deviceExec(), podExec()}
	judge := func(dir, want string, applies bool, why string) {
		t.Helper()
		for _, ex := range sandboxes {
			if rep := harnessPreflight(dir, ex, harnessWho{}, "", true); rep.Provider != want || rep.Applies != applies {
				t.Errorf("%s, %s: provider %q applies %v, want %q applies %v", why, ex.kind, rep.Provider, rep.Applies, want, applies)
			}
		}
	}

	// A config that names mock and a state that names nothing — the eval
	// stack's project (deploy/eval/seed-project.sh). A container reads the
	// config from the hub's tree; a device reads it committed in the tree it
	// fetched, or as the provider its seed carries, the hub's own resolution.
	configMock := t.TempDir()
	setProvider(t, configMock, "mock")
	judge(configMock, "mock", false, "config says mock")

	// The config outranks the state (preferProjectChoice), and the seed
	// carries the config's choice, not the state's.
	configClaude := t.TempDir()
	setStateProvider(t, configClaude, "mock")
	setProvider(t, configClaude, "claudecode")
	judge(configClaude, "claudecode", true, "config says claudecode, state mock")

	// Without a config the state decides, and the seed carries it.
	stateMock := t.TempDir()
	setStateProvider(t, stateMock, "mock")
	judge(stateMock, "mock", false, "state says mock")

	// The hub's CLOOP_PROVIDER: a container on the hub's tree gets none of
	// the hub's environment, while a device's seed carries the hub's
	// resolution, variable included.
	stateClaude := t.TempDir()
	setStateProvider(t, stateClaude, "claudecode")
	t.Setenv("CLOOP_PROVIDER", "mock")
	if rep := harnessPreflight(stateClaude, containerExec(), harnessWho{}, "", true); !rep.Applies || rep.Provider != "claudecode" {
		t.Errorf("hub CLOOP_PROVIDER=mock, container: provider %q applies %v", rep.Provider, rep.Applies)
	}
	if rep := harnessPreflight(stateClaude, deviceExec(), harnessWho{}, "", true); rep.Applies || rep.Provider != "mock" {
		t.Errorf("hub CLOOP_PROVIDER=mock, device: provider %q applies %v", rep.Provider, rep.Applies)
	}
	// Where a config.yaml says otherwise, a device reads the file if the
	// repository commits it and the seed if not. The hub cannot tell which,
	// and refuses on neither guess.
	if rep := harnessPreflight(configClaude, deviceExec(), harnessWho{}, "", true); rep.Applies || rep.Provider != "mock" {
		t.Errorf("hub CLOOP_PROVIDER=mock, config claudecode, device: provider %q applies %v", rep.Provider, rep.Applies)
	}
	t.Setenv("CLOOP_PROVIDER", "claudecode")
	if rep := harnessPreflight(configMock, deviceExec(), harnessWho{}, "", true); rep.Applies || rep.Provider != "mock" {
		t.Errorf("hub CLOOP_PROVIDER=claudecode, config mock, device: provider %q applies %v", rep.Provider, rep.Applies)
	}
	if rep := harnessPreflight(configMock, containerExec(), harnessWho{}, "", true); rep.Applies || rep.Provider != "mock" {
		t.Errorf("hub CLOOP_PROVIDER=claudecode, config mock, container: provider %q applies %v", rep.Provider, rep.Applies)
	}
}

// The seed is what makes a device's provider the hub's resolution: this pins
// the two together, so the preflight cannot drift from what projectSeedFor
// sends.
func TestPreflightJudgesADeviceByTheProviderItsSeedCarries(t *testing.T) {
	newHarnessFixture(t)
	for _, tc := range []struct {
		name   string
		config string // "" for no config.yaml
		state  string
	}{
		{"config mock, empty state", "mock", ""},
		{"config claudecode, state mock", "claudecode", "mock"},
		{"no config, state mock", "", "mock"},
		{"no config, state anthropic", "", "anthropic"},
		{"no config, state empty", "", ""},
	} {
		dir := t.TempDir()
		setStateProvider(t, dir, tc.state)
		if tc.config != "" {
			setProvider(t, dir, tc.config)
		}
		seed, err := projectSeedFor(dir)
		if err != nil || len(seed) == 0 {
			t.Fatalf("%s: projectSeedFor: %d bytes, %v", tc.name, len(seed), err)
		}
		// Placed as a device places it, in a tree that commits no config.
		device := t.TempDir()
		if err := projectseed.Write(device, seed); err != nil {
			t.Fatalf("%s: place the seed: %v", tc.name, err)
		}
		sent, err := state.LoadLite(device)
		if err != nil {
			t.Fatalf("%s: read the seeded state: %v", tc.name, err)
		}
		if rep := harnessPreflight(dir, deviceExec(), harnessWho{}, "", true); rep.Provider != sent.Provider {
			t.Errorf("%s: preflight judged %q, the seed carries %q", tc.name, rep.Provider, sent.Provider)
		}
	}
}

func TestPreflightHonoursTheHubsExemption(t *testing.T) {
	f := newHarnessFixture(t)
	if err := os.WriteFile(filepath.Join(f.dir, ".cloop", "config.yaml"),
		[]byte("executors:\n  harness_credential_exempt: [sgx]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	rep := harnessPreflight(project, deviceExec(), harnessWho{}, "", true)
	if !rep.Exempt || rep.Applies || rep.refusal() != nil {
		t.Fatalf("an exempt device: exempt %v applies %v refusal %v", rep.Exempt, rep.Applies, rep.refusal())
	}
	other := remoteExec("edge-2", executor.KindRemoteAgent)
	if rep := harnessPreflight(project, other, harnessWho{}, "", true); refusalCode(t, rep) != codeHarnessCredentialMissing {
		t.Errorf("a device the list does not name: %+v", rep)
	}
	// An exemption waives the check, never the withholding.
	alice := f.env(t, "alice-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "exempt")}, "alice@corp.example")
	g := f.grant(t, alice, "project:"+project, time.Hour)
	rep = harnessPreflight(project, deviceExec(), harnessWho{identity: "bob@corp.example", personal: true}, "", true)
	if rep.Applies || rep.Withhold[g.ID] == "" {
		t.Errorf("exempt device, bob's run: applies %v withhold %v", rep.Applies, rep.Withhold)
	}
	// And a project's own config.yaml cannot grant itself the exemption.
	selfExempt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(selfExempt, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selfExempt, ".cloop", "config.yaml"),
		[]byte("executors:\n  harness_credential_exempt: [edge-2]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := harnessPreflight(selfExempt, other, harnessWho{}, "", true); rep.Exempt || !rep.Applies {
		t.Error("a project's config.yaml waived the check for itself")
	}
}

// Withholding is not a property of the refusal: a colleague's personal Claude
// token stays out of a run on the host and out of a workload that runs no
// harness at all.
func TestWithholdingReachesEveryDispatch(t *testing.T) {
	f := newHarnessFixture(t)
	aliceToken := fakeAnthropicToken("oat01", "alicehost")
	bob := harnessWho{identity: "bob@corp.example", personal: true}
	noAlice := func(t *testing.T, spec executor.Spec, grantID string) {
		t.Helper()
		if strings.Contains(strings.Join(spec.Env, "\n"), aliceToken) {
			t.Fatal("alice's personal token reached bob's workload")
		}
		for _, b := range spec.Secrets {
			if b.GrantID == grantID {
				t.Fatalf("bob's workload carries a binding for alice's grant: %+v", b)
			}
		}
	}

	hostProject := statedbtest.Dir(t)
	host := newHarnessExec("harness-host-stub", executor.KindLocalProcess, executor.IsolationNone)
	registerStub(t, host)
	if err := executor.Bind(hostProject, host.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(hostProject) })
	g := f.grant(t, f.env(t, "alice-host", map[string]string{envClaudeOAuthToken: aliceToken}, "alice@corp.example"),
		"project:"+hostProject, time.Hour)
	if _, _, err := startWorkloadAs(nil, newHarnessClearance(hostProject, bob, ""), "bob@corp.example",
		hostProject, []string{"cloop", "run"}, nil); err != nil {
		t.Fatalf("a run on the host is never refused here: %v", err)
	}
	if specs := host.started(); len(specs) != 1 {
		t.Fatalf("host started %d workloads", len(specs))
	} else {
		noAlice(t, specs[0], g.ID)
	}

	boxProject := statedbtest.Dir(t)
	box := newHarnessExec("harness-box-stub", executor.KindContainer, executor.IsolationContainer)
	registerStub(t, box)
	if err := executor.Bind(boxProject, box.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(boxProject) })
	g = f.grant(t, f.env(t, "alice-box", map[string]string{envClaudeOAuthToken: aliceToken}, "alice@corp.example"),
		"project:"+boxProject, time.Hour)
	// A subcommand that runs no harness is not refused for having no
	// credential of its own, and still does not get alice's.
	if _, err := runWorkloadEnvFor(t.Context(), boxProject, []string{"cloop", "reset"}, nil,
		newLeaseClearance(boxProject, bob), nil); err != nil {
		t.Fatalf("a lease clearance refused a dispatch: %v", err)
	}
	if specs := box.started(); len(specs) != 1 {
		t.Fatalf("box started %d workloads", len(specs))
	} else {
		noAlice(t, specs[0], g.ID)
	}
}

func TestClearanceRecordsWhomARunWasStartedFor(t *testing.T) {
	newHarnessFixture(t)
	project := t.TempDir()
	if _, ok := recordedHarnessInitiator(project); ok {
		t.Fatal("a record before any run")
	}
	newLeaseClearance(project, harnessWho{identity: "bob@corp.example", personal: true}).started()
	newHarnessClearance(project, harnessWho{identity: "bob@corp.example"}, "").started()
	if _, ok := recordedHarnessInitiator(project); ok {
		t.Fatal("a workload that runs no harness, or a hub without sign-on, recorded an initiator")
	}
	newHarnessClearance(project, harnessWho{identity: "alice@corp.example", personal: true}, "").started()
	if id, ok := recordedHarnessInitiator(project); !ok || id != "alice@corp.example" {
		t.Fatalf("recorded initiator = %q, %v", id, ok)
	}
	// A clearance is for the dispatch it was built for.
	c := newHarnessClearance(project, harnessWho{}, "")
	if _, err := c.settle(deviceExec(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "settled for") {
		t.Errorf("a clearance settled for another project: %v", err)
	}
}
