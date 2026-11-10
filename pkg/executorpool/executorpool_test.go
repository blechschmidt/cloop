package executorpool_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStore(t *testing.T) (*executorpool.Store, *statedb.DB, *clock) {
	t.Helper()
	db := statedbtest.Open(t)
	db.AsControlPlane()
	c := &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	return executorpool.NewStore(db).WithClock(c.now), db, c
}

func mustCreate(t *testing.T, s *executorpool.Store, spec executorpool.Spec) executorpool.Pool {
	t.Helper()
	p, err := s.Create(spec, "admin@example.com")
	if err != nil {
		t.Fatalf("create pool %q: %v", spec.Name, err)
	}
	return p
}

var runnerOpts = executorpool.RunnerOptions{Server: "wss://hub.example.com/api/executors/connect", Pin: "sha256:AAAA", Actor: "pool:test/cred"}

func TestSpecValidation(t *testing.T) {
	s, _, _ := newStore(t)
	for _, tc := range []struct {
		name string
		spec executorpool.Spec
		want string
	}{
		{"no name", executorpool.Spec{MaxRunners: 1}, "needs a name"},
		{"bad name", executorpool.Spec{Name: "GPU pool!", MaxRunners: 1}, "lowercase"},
		{"zero max", executorpool.Spec{Name: "k8s", MaxRunners: 0}, "max_runners"},
		{"huge max", executorpool.Spec{Name: "k8s", MaxRunners: executorpool.MaxRunnersCeiling + 1}, "max_runners"},
		{"relative root", executorpool.Spec{Name: "k8s", MaxRunners: 2, WorkDirRoot: "work"}, "absolute"},
		{"negative memory", executorpool.Spec{Name: "k8s", MaxRunners: 2, Capabilities: executorpool.Capabilities{MemoryMB: -1}}, "negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Create(tc.spec, "admin")
			if !errors.Is(err, executorpool.ErrInvalidSpec) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Create(%+v) = %v, want ErrInvalidSpec mentioning %q", tc.spec, err, tc.want)
			}
		})
	}
	p := mustCreate(t, s, executorpool.Spec{Name: " K8S-Gpu ", MaxRunners: 3, Owner: "Alice@Example.com",
		Capabilities: executorpool.Capabilities{Harnesses: []string{"git", "Claude", "git"}}})
	if p.Name != "k8s-gpu" || p.Owner != "alice@example.com" || strings.Join(p.Capabilities.Harnesses, ",") != "claude,git" {
		t.Fatalf("normalized pool = %+v", p)
	}
	if !strings.HasPrefix(p.ID, executorpool.IDPrefix) || p.Binding() != "pool:"+p.ID {
		t.Fatalf("pool id %q / binding %q", p.ID, p.Binding())
	}
	if _, err := s.Create(executorpool.Spec{Name: "k8s-gpu", MaxRunners: 1}, "admin"); !errors.Is(err, statedb.ErrExecutorPoolNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
}

func TestCredentialAuthentication(t *testing.T) {
	s, _, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 2})
	token, cred, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, executorpool.CredentialPrefix) || !strings.Contains(token, cred.ID+".") {
		t.Fatalf("credential %q does not carry its prefix and id %s", token, cred.ID)
	}
	got, gotCred, err := s.Authenticate(token)
	if err != nil || got.ID != p.ID || gotCred.ID != cred.ID {
		t.Fatalf("Authenticate = %+v, %+v, %v", got, gotCred, err)
	}

	id, secret, _ := executorpool.ParseCredential(token)
	for name, bad := range map[string]string{
		"wrong secret": executorpool.CredentialPrefix + id + "." + strings.Repeat("A", len(secret)),
		"unknown id":   executorpool.CredentialPrefix + "nosuchcredential." + secret,
		"no prefix":    id + "." + secret,
		"no secret":    executorpool.CredentialPrefix + id + ".",
		"enroll token": "clet1.abc.def.ghi",
	} {
		if _, _, err := s.Authenticate(bad); !errors.Is(err, executorpool.ErrCredentialInvalid) {
			t.Errorf("%s: Authenticate = %v, want ErrCredentialInvalid", name, err)
		}
	}

	// Stored only as a hash.
	creds, err := s.Credentials(p.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials = %v, %v", creds, err)
	}
	row, err := s.DB().GetExecutorPoolCredential(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row.SecretHash, secret) || len(row.SecretHash) != 64 {
		t.Fatalf("stored hash %q is not a SHA-256 of the secret", row.SecretHash)
	}

	// Revoking one credential refuses it and nothing else.
	second, _, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	c.advance(time.Second)
	if _, err := s.RevokeCredential(p.ID, cred.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate(token); !errors.Is(err, executorpool.ErrCredentialRevoked) {
		t.Fatalf("revoked credential: %v", err)
	}
	if _, _, err := s.Authenticate(second); err != nil {
		t.Fatalf("the other credential stopped working: %v", err)
	}
	// A credential is revoked only through its own pool's route.
	other := mustCreate(t, s, executorpool.Spec{Name: "other", MaxRunners: 1})
	_, otherCred, _ := s.MintCredential(other.ID, "admin")
	if _, err := s.RevokeCredential(p.ID, otherCred.ID, "admin"); !errors.Is(err, statedb.ErrPoolCredentialNotFound) {
		t.Fatalf("revoking another pool's credential through this one: %v", err)
	}
}

func TestMintRunnersRefusesPastMaxRunners(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 3, Labels: map[string]string{"gpu": "a100"}})

	cfgs, err := s.MintRunners(p, 2, runnerOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("got %d configs", len(cfgs))
	}
	for _, cfg := range cfgs {
		if !remote.IsRunnerToken(cfg.Token) || !cfg.Ephemeral || cfg.Labels["gpu"] != "a100" {
			t.Fatalf("runner config %+v", cfg)
		}
		if ttl := cfg.ExpiresAt.Sub(c.now()); ttl <= 0 || ttl > remote.MaxRunnerTTL {
			t.Fatalf("token valid for %s, want (0, %s]", ttl, remote.MaxRunnerTTL)
		}
		b, err := remote.DecodeBundle(cfg.Bundle)
		if err != nil || b.Token != cfg.Token || b.Server != runnerOpts.Server || b.Pin != runnerOpts.Pin {
			t.Fatalf("bundle %+v, %v", b, err)
		}
	}

	// 2 live + 2 more > 3.
	_, err = s.MintRunners(p, 2, runnerOpts)
	var capErr *statedb.PoolAtCapacityError
	if !errors.As(err, &capErr) || !errors.Is(err, executorpool.ErrAtCapacity) || capErr.Live != 2 || capErr.Max != 3 {
		t.Fatalf("mint past max_runners = %v, want a PoolAtCapacityError with 2 of 3", err)
	}
	// Nothing of the refused request was stored.
	if rows, _ := db.ListExecutorPoolRunners(p.ID); len(rows) != 2 {
		t.Fatalf("%d runner rows after a refused mint, want 2", len(rows))
	}
	if _, err := s.MintRunners(p, 1, runnerOpts); err != nil {
		t.Fatalf("the third runner: %v", err)
	}
	for _, n := range []int{0, -1, executorpool.MaxRunnersPerRequest + 1} {
		if _, err := s.MintRunners(p, n, runnerOpts); !errors.Is(err, executorpool.ErrInvalidSpec) {
			t.Errorf("MintRunners(%d) = %v, want ErrInvalidSpec", n, err)
		}
	}

	// Expired tokens give their places back.
	c.advance(remote.MaxRunnerTTL + time.Second)
	if _, err := s.MintRunners(p, 3, runnerOpts); err != nil {
		t.Fatalf("after every token expired: %v", err)
	}
}

func TestConcurrentMintsHoldMaxRunners(t *testing.T) {
	s, db, _ := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 5})
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfgs, err := s.MintRunners(p, 1, runnerOpts)
			if err == nil {
				mu.Lock()
				granted += len(cfgs)
				mu.Unlock()
			} else if !errors.Is(err, executorpool.ErrAtCapacity) {
				t.Errorf("mint: %v", err)
			}
		}()
	}
	wg.Wait()
	rows, _ := db.ListExecutorPoolRunners(p.ID)
	if granted != 5 || len(rows) != 5 {
		t.Fatalf("granted %d runners, stored %d, want exactly max_runners = 5", granted, len(rows))
	}
}

// redeemer redeems runner tokens the way the hub does, through the pools'
// admission.
func redeem(t *testing.T, s *executorpool.Store, db *statedb.DB, token string, now func() time.Time) (remote.AgentRecord, error) {
	t.Helper()
	store, err := executorstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	_, agent, err := remote.RedeemRunner(store, token, remote.RedeemOptions{Now: now,
		Admit: func(rec remote.EnrollmentRecord) error { return s.AdmitRunner(rec.ID) }})
	if err != nil {
		return agent, err
	}
	_, err = s.RunnerEnrolled(agent.EnrollmentID, agent.AgentID, agent.Name, "member-a")
	return agent, err
}

func TestRunnerTokensAreSingleUseAndExpire(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 4})
	cfgs, err := s.MintRunners(p, 2, executorpool.RunnerOptions{Server: runnerOpts.Server, TTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	agent, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	r, err := s.RunnerByExecutor(agent.AgentID)
	if err != nil || r.State != statedb.PoolRunnerIdle || r.PoolID != p.ID {
		t.Fatalf("runner after enrollment = %+v, %v", r, err)
	}
	if _, err := redeem(t, s, db, cfgs[0].Token, c.now); !errors.Is(err, remote.ErrTokenAlreadyUsed) {
		t.Fatalf("second redemption = %v, want ErrTokenAlreadyUsed", err)
	}

	// An enrollment token is not a runner token, and a runner token is not
	// an enrollment token.
	store, _ := executorstore.New(db)
	if _, _, err := remote.Redeem(store, cfgs[1].Token, remote.RedeemOptions{Now: c.now}); !errors.Is(err, remote.ErrTokenInvalid) {
		t.Fatalf("a runner token redeemed as an enrollment token: %v", err)
	}
	if _, _, err := remote.RedeemRunner(store, cfgs[1].Token, remote.RedeemOptions{Now: c.now}); !errors.Is(err, remote.ErrTokenInvalid) {
		t.Fatalf("a runner token redeemed with no pool to admit it: %v", err)
	}

	c.advance(5*time.Minute + time.Second)
	if _, err := redeem(t, s, db, cfgs[1].Token, c.now); !errors.Is(err, remote.ErrTokenExpired) {
		t.Fatalf("expired token = %v, want ErrTokenExpired", err)
	}
	expired, err := db.ExpireExecutorPoolRunners(c.now())
	if err != nil || len(expired) != 1 || expired[0].EnrollmentID != cfgs[1].EnrollmentID {
		t.Fatalf("expired = %+v, %v", expired, err)
	}

	if _, err := s.MintRunners(p, 1, executorpool.RunnerOptions{Server: runnerOpts.Server, TTL: remote.MaxRunnerTTL + time.Second}); err == nil {
		t.Fatal("a runner token valid for longer than ten minutes was minted")
	}
}

func TestRevokingAPoolRefusesEverything(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 4})
	token, _, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfgs, err := s.MintRunners(p, 3, runnerOpts)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	q := statedb.PoolQueueRow{ID: "q1", PoolID: p.ID, ProjectPath: "/srv/a", Starter: "alice@example.com"}
	if err := db.EnqueuePoolRun(q); err != nil {
		t.Fatal(err)
	}

	rev, err := s.Revoke(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Credentials != 1 || len(rev.Tokens) != 2 || len(rev.Runners) != 1 || rev.Runners[0].ExecutorID != agent.AgentID ||
		len(rev.Cancelled) != 1 || rev.Cancelled[0].ID != "q1" {
		t.Fatalf("revocation took back %+v", rev)
	}
	if _, _, err := s.Authenticate(token); !errors.Is(err, executorpool.ErrCredentialRevoked) {
		t.Fatalf("credential after revocation: %v", err)
	}
	if _, err := redeem(t, s, db, cfgs[1].Token, c.now); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("unredeemed token after revocation: %v", err)
	}
	store, _ := executorstore.New(db)
	if rec, err := store.GetAgent(agent.AgentID); err != nil || !rec.Revoked() {
		t.Fatalf("live runner's credential after revocation: %+v, %v", rec, err)
	}
	if _, err := s.MintRunners(p, 1, runnerOpts); !errors.Is(err, executorpool.ErrRevoked) {
		t.Fatalf("mint after revocation: %v", err)
	}
	if _, _, err := s.MintCredential(p.ID, "admin"); !errors.Is(err, statedb.ErrExecutorPoolRevoked) {
		t.Fatalf("credential mint after revocation: %v", err)
	}
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "q2", PoolID: p.ID, ProjectPath: "/srv/b"}); !errors.Is(err, statedb.ErrExecutorPoolRevoked) {
		t.Fatalf("queue after revocation: %v", err)
	}
	if _, err := s.Revoke(p.ID, "admin"); !errors.Is(err, statedb.ErrExecutorPoolRevoked) {
		t.Fatalf("second revocation: %v", err)
	}
	if got, _ := db.GetPoolQueueEntry("q1"); got.State != statedb.PoolQueueCancelled {
		t.Fatalf("queued run after revocation is %s", got.State)
	}
}

// access is a fake of the hub's answers.
type access struct {
	bindings map[string]string
	readable map[string]map[string]bool // owner → project → may read
	broken   bool                       // every binding read fails
	owners   map[string]string          // project → owner key
	parents  map[string]string          // feature → its project
	barred   map[string]bool            // starters who may not read their projects
}

func (a access) StarterMayRead(starter, _ string) (bool, error) {
	if a.broken {
		return false, errors.New("database is locked")
	}
	return !a.barred[starter], nil
}

func (a access) Project(p string) (string, string, error) {
	if a.broken {
		return "", "", errors.New("database is locked")
	}
	if parent, ok := a.parents[p]; ok {
		p = parent
	}
	return p, a.owners[p], nil
}

func (a access) Binding(p string) (string, error) {
	if a.broken {
		return "", errors.New("database is locked")
	}
	return a.bindings[p], nil
}
func (a access) OwnerMayRead(owner, p string) (bool, error) {
	return a.readable[owner][p], nil
}

// TestDemandIsWhatThePoolMaySee is the cross-tenant property: a pool's demand
// counts only runs queued for it that it may see.
func TestDemandIsWhatThePoolMaySee(t *testing.T) {
	s, db, c := newStore(t)
	teamA := mustCreate(t, s, executorpool.Spec{Name: "team-a", MaxRunners: 10, Owner: "alice@example.com",
		Labels: map[string]string{"site": "a"}})
	teamB := mustCreate(t, s, executorpool.Spec{Name: "team-b", MaxRunners: 10, Owner: "bob@example.com"})
	org := mustCreate(t, s, executorpool.Spec{Name: "org", MaxRunners: 10,
		Capabilities: executorpool.Capabilities{ContainerRuntimes: nil}})

	acc := access{
		bindings: map[string]string{
			"/srv/a1": teamA.Binding(), "/srv/a2": teamA.Binding(), "/srv/a-secret": teamA.Binding(),
			"/srv/b1": teamB.Binding(), "/srv/b2": teamB.Binding(),
			"/srv/org": org.Binding(), "/srv/org-container": org.Binding(), "/srv/moved": org.Binding(),
		},
		readable: map[string]map[string]bool{
			"alice@example.com": {"/srv/a1": true, "/srv/a2": true},
			"bob@example.com":   {"/srv/b1": true, "/srv/b2": true},
		},
	}
	req, _ := executorpool.EncodeRequirements(executor.Requirements{RequireIsolation: true})
	needsContainers, _ := executorpool.EncodeRequirements(executor.Requirements{RequireContainerRuntime: true})
	needsLabel, _ := executorpool.EncodeRequirements(executor.Requirements{Labels: map[string]string{"site": "a"}})
	enqueue := func(id string, pool executorpool.Pool, project, requirements string) {
		t.Helper()
		if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: id, PoolID: pool.ID, ProjectPath: project,
			Starter: "someone", Requirements: requirements}); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Millisecond)
	}
	enqueue("a1", teamA, "/srv/a1", req)
	enqueue("a2", teamA, "/srv/a2", needsLabel)
	// Queued for team A's pool, but alice may not read it: an administrator
	// bound bob's private project there. Team A's controller must not learn
	// of it.
	enqueue("a-secret", teamA, "/srv/a-secret", req)
	enqueue("b1", teamB, "/srv/b1", req)
	enqueue("b2", teamB, "/srv/b2", req)
	enqueue("org", org, "/srv/org", req)
	// The org pool's runners advertise no container runtime.
	enqueue("org-container", org, "/srv/org-container", needsContainers)
	// Queued for the org pool, then rebound elsewhere.
	enqueue("moved", org, "/srv/moved", req)
	acc.bindings["/srv/moved"] = teamB.Binding()

	snap := func(p executorpool.Pool) (executorpool.Snapshot, map[string]executorpool.Verdict) {
		t.Helper()
		got, verdicts, err := s.Snapshot(p, acc)
		if err != nil {
			t.Fatal(err)
		}
		return got, verdicts
	}
	a, va := snap(teamA)
	if a.Demand != 2 || !va["a1"].Visible || !va["a2"].Visible || va["a-secret"].Visible || !va["a-secret"].Final {
		t.Fatalf("team A sees demand %d, verdicts %+v; want 2 (a1, a2), never a-secret", a.Demand, va)
	}
	for id := range va {
		if strings.HasPrefix(id, "b") || strings.HasPrefix(id, "org") || id == "moved" {
			t.Fatalf("team A's snapshot judged %s, another pool's run", id)
		}
	}
	b, _ := snap(teamB)
	if b.Demand != 2 {
		t.Fatalf("team B demand %d, want 2", b.Demand)
	}
	o, vo := snap(org)
	if o.Demand != 1 || !vo["org"].Visible || vo["org-container"].Visible || vo["moved"].Visible {
		t.Fatalf("org demand %d, verdicts %+v; want only org", o.Demand, vo)
	}
	if !strings.Contains(vo["org-container"].Reason, "container") {
		t.Fatalf("a run the runners cannot run should say why: %q", vo["org-container"].Reason)
	}

	// Restricting a pool's access list after runs were queued hides them
	// until they are started again under the new list.
	if err := s.Admit(teamB.ID, "group", "team-b", "admin"); err != nil {
		t.Fatal(err)
	}
	if b, vb := snap(teamB); b.Demand != 0 || vb["b1"].Visible || !vb["b1"].Final {
		t.Fatalf("after the access list changed: demand %d, verdicts %+v", b.Demand, vb)
	}
	fp, _ := s.AudienceFingerprint(teamB.ID)
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "b3", PoolID: teamB.ID, ProjectPath: "/srv/b3",
		AudienceFP: fp, Requirements: req}); err != nil {
		t.Fatal(err)
	}
	acc.bindings["/srv/b3"] = teamB.Binding()
	acc.readable["bob@example.com"]["/srv/b3"] = true
	if b, _ := snap(teamB); b.Demand != 1 {
		t.Fatalf("a run queued under the new list: demand %d, want 1", b.Demand)
	}

	// A binding that cannot be read decides nothing: the run is not counted,
	// and not taken out of the queue either.
	acc.broken = true
	if b, vb := snap(teamB); b.Demand != 0 || vb["b3"].Visible || vb["b3"].Final {
		t.Fatalf("with bindings unreadable: demand %d, verdict %+v", b.Demand, vb["b3"])
	}
}

func TestOwnerKeysKeepASubjectsCase(t *testing.T) {
	s, _, _ := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "subject-owned", MaxRunners: 1, Owner: " SUB:AbC-123 "})
	if p.Owner != "sub:AbC-123" {
		t.Fatalf("owner %q, want sub:AbC-123 — a subject is case-sensitive", p.Owner)
	}
	p = mustCreate(t, s, executorpool.Spec{Name: "email-owned", MaxRunners: 1, Owner: "Alice@Example.COM"})
	if p.Owner != "alice@example.com" {
		t.Fatalf("owner %q, want the email folded", p.Owner)
	}
}

// A credential that leaked and was revoked takes back what it minted: its
// unredeemed tokens no longer redeem, and its runners are retired with their
// credentials revoked. Another credential's runners are untouched.
func TestRevokingACredentialTakesBackWhatItMinted(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 6})
	_, leaked, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := s.MintCredential(p.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	mint := func(credID string, n int) []executorpool.RunnerConfig {
		t.Helper()
		cfgs, err := s.MintRunners(p, n, executorpool.RunnerOptions{Server: runnerOpts.Server, CredentialID: credID})
		if err != nil {
			t.Fatal(err)
		}
		return cfgs
	}
	byLeaked := mint(leaked.ID, 2)
	byOther := mint(other.ID, 1)
	enrolled, err := redeem(t, s, db, byLeaked[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := redeem(t, s, db, byOther[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}

	rev, err := s.RevokeCredential(p.ID, leaked.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !rev.Revoked || len(rev.Tokens) != 1 || rev.Tokens[0] != byLeaked[1].EnrollmentID ||
		len(rev.Runners) != 1 || rev.Runners[0].ExecutorID != enrolled.AgentID {
		t.Fatalf("revocation took back %+v", rev)
	}
	if _, err := redeem(t, s, db, byLeaked[1].Token, c.now); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("a token the revoked credential minted: %v", err)
	}
	store, _ := executorstore.New(db)
	if rec, _ := store.GetAgent(enrolled.AgentID); !rec.Revoked() {
		t.Fatal("a runner the revoked credential minted is still live")
	}
	if r, _ := s.RunnerByExecutor(enrolled.AgentID); r.State != statedb.PoolRunnerRetired {
		t.Fatalf("its runner is %s", r.State)
	}
	if rec, _ := store.GetAgent(otherAgent.AgentID); rec.Revoked() {
		t.Fatal("another credential's runner was revoked")
	}
	if _, err := s.Get(p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCountsRunnersAndWanted(t *testing.T) {
	s, db, c := newStore(t)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 3})
	acc := access{bindings: map[string]string{}}
	for i, project := range []string{"/srv/1", "/srv/2", "/srv/3", "/srv/4", "/srv/5"} {
		acc.bindings[project] = p.Binding()
		if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: string(rune('a' + i)), PoolID: p.ID, ProjectPath: project}); err != nil {
			t.Fatal(err)
		}
	}
	snap, _, err := s.Snapshot(p, acc)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Demand != 5 || snap.Spare != 3 || snap.Wanted != 3 {
		t.Fatalf("snapshot %+v: want demand 5, spare 3, wanted 3", snap)
	}
	cfgs, err := s.MintRunners(p, 2, runnerOpts)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := redeem(t, s, db, cfgs[0].Token, c.now)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := db.AssignPoolQueueEntry("a", agent.AgentID, "member-a", c.now())
	if err != nil || !ok {
		t.Fatalf("assign: %v, %v", ok, err)
	}
	// The runner is busy, and the run it took left the waiting queue.
	if ok, _ := db.AssignPoolQueueEntry("b", agent.AgentID, "member-a", c.now()); ok {
		t.Fatal("a busy runner was handed a second run")
	}
	snap, _, _ = s.Snapshot(p, acc)
	if snap.Demand != 4 || snap.Busy != 1 || snap.Pending != 1 || snap.Runners != 2 || snap.Spare != 1 || snap.Wanted != 1 {
		t.Fatalf("snapshot %+v: want demand 4, busy 1, pending 1, spare 1, wanted 1", snap)
	}
	before := snap.Revision
	if retired, err := s.RetireRunner(agent.AgentID, "its run settled"); err != nil || !retired {
		t.Fatalf("retire: %v, %v", retired, err)
	}
	if again, _ := s.RetireRunner(agent.AgentID, "again"); again {
		t.Fatal("a runner was retired twice")
	}
	snap, _, _ = s.Snapshot(p, acc)
	if snap.Busy != 0 || snap.Revision == before {
		t.Fatalf("after retirement %+v (revision %s, was %s)", snap, snap.Revision, before)
	}
}

func TestQueueHandsOffExactlyOnce(t *testing.T) {
	_, db, _ := newStore(t)
	s := executorpool.NewStore(db)
	p := mustCreate(t, s, executorpool.Spec{Name: "k8s", MaxRunners: 2})
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "q1", PoolID: p.ID, ProjectPath: "/srv/a"}); err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "q2", PoolID: p.ID, ProjectPath: "/srv/a"}); !errors.Is(err, statedb.ErrPoolRunAlreadyQueued) {
		t.Fatalf("a second open run of one project: %v", err)
	}
	var wins int
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			moved, err := db.MovePoolQueueEntry("q1", []string{statedb.PoolQueueWaiting}, statedb.PoolQueueCancelled, "stopped", time.Now())
			if err != nil {
				t.Error(err)
			}
			if moved {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d cancellations won, want exactly 1", wins)
	}
	// Closed, so the project may queue again.
	if err := db.EnqueuePoolRun(statedb.PoolQueueRow{ID: "q3", PoolID: p.ID, ProjectPath: "/srv/a"}); err != nil {
		t.Fatalf("queue again after the first closed: %v", err)
	}
}
