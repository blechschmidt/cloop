package remote_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// fakeRunners is the pools' side of runner tokens, for these tests.
type fakeRunners struct {
	mu        sync.Mutex
	admit     map[string]bool // enrollment id → may redeem
	enrolled  map[string]string
	refuseRec bool
	broken    bool // IsRunner cannot be answered
}

func (f *fakeRunners) AdmitRunner(rec remote.EnrollmentRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.admit[rec.ID] {
		return errors.New("the pool was revoked")
	}
	return nil
}

func (f *fakeRunners) RunnerEnrolled(agent remote.AgentRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuseRec {
		return errors.New("the pool's database is read-only")
	}
	f.enrolled[agent.AgentID] = agent.EnrollmentID
	return nil
}

func (f *fakeRunners) IsRunner(agentID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.broken {
		return false, errors.New("database is locked")
	}
	_, ok := f.enrolled[agentID]
	return ok, nil
}

type runnerRig struct {
	t      *testing.T
	store  *memStore
	hub    *remote.Hub
	reg    *executor.Registry
	pools  *fakeRunners
	server *httptest.Server
}

func newRunnerRig(t *testing.T, withPools bool) *runnerRig {
	t.Helper()
	r := &runnerRig{t: t, store: newMemStore(), reg: executor.NewRegistry(),
		pools: &fakeRunners{admit: map[string]bool{}, enrolled: map[string]string{}}}
	opts := remote.HubOptions{Store: r.store, Registry: r.reg, Logf: func(string, ...any) {}}
	if withPools {
		opts.Runners = r.pools
	}
	hub, err := remote.NewHub(opts)
	if err != nil {
		t.Fatal(err)
	}
	r.hub = hub
	r.server = httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	t.Cleanup(r.server.Close)
	return r
}

// mint prepares a runner token and stores its record, as a pool would.
func (r *runnerRig) mint(admit bool) (string, remote.EnrollmentRecord) {
	r.t.Helper()
	token, rec, err := remote.PrepareRunnerToken(remote.MintOptions{Name: "pool-runner", WorkDirRoot: r.t.TempDir(),
		Labels: map[string]string{"site": "lab"}})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.store.PutEnrollment(rec); err != nil {
		r.t.Fatal(err)
	}
	r.pools.mu.Lock()
	r.pools.admit[rec.ID] = admit
	r.pools.mu.Unlock()
	return token, rec
}

// connect dials with token and completes the handshake, returning the welcome
// and the connection; status is the HTTP status of a refused dial.
func (r *runnerRig) connect(token string) (remote.WelcomePayload, remote.Conn, int) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.server.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		if resp != nil {
			return remote.WelcomePayload{}, nil, resp.StatusCode
		}
		r.t.Fatalf("dial: %v", err)
	}
	conn := remote.NewWSConn(ws)
	hello, _ := remote.NewFrame(remote.TypeHello, "hello", "", remote.HelloPayload{ProtocolVersion: remote.ProtocolVersion})
	if err := conn.WriteFrame(ctx, hello); err != nil {
		r.t.Fatal(err)
	}
	for {
		f, err := conn.ReadFrame(ctx)
		if err != nil {
			r.t.Fatalf("read welcome: %v", err)
		}
		if f.Type == remote.TypeWelcome {
			w, err := remote.DecodeWelcome(f)
			if err != nil {
				r.t.Fatal(err)
			}
			r.t.Cleanup(func() { _ = conn.Close("test done") })
			return w, conn, http.StatusSwitchingProtocols
		}
	}
}

func TestRunnerTokenEnrollsAnEphemeralExecutorAndRetireEndsIt(t *testing.T) {
	r := newRunnerRig(t, true)
	token, rec := r.mint(true)

	w, conn, _ := r.connect(token)
	if w.Credential == "" || !w.Ephemeral {
		t.Fatalf("welcome %+v: want a credential and the ephemeral flag", w)
	}
	// A runner's credential has a shape of its own, which a hub build that
	// predates pools refuses rather than taking for a device's.
	if !remote.IsRunnerCredential(w.Credential) || strings.HasPrefix(w.Credential, "clac1.") {
		t.Fatalf("runner credential %q is not a clrc1 credential", w.Credential)
	}
	if _, err := remote.Authenticate(r.store, w.Credential, time.Now()); err != nil {
		t.Fatalf("this hub refuses the runner credential it issued: %v", err)
	}
	if got := r.pools.enrolled[w.ExecutorID]; got != rec.ID {
		t.Fatalf("the pools were told %q enrolled from %q, want %q", w.ExecutorID, got, rec.ID)
	}
	ex, ok := r.hub.Executor(w.ExecutorID)
	if !ok || !ex.Ephemeral() || !executor.IsEphemeral(ex) {
		t.Fatalf("the runner's executor is not ephemeral (%v, %v)", ok, ex)
	}
	if agent, err := r.store.GetAgent(w.ExecutorID); err != nil || agent.Labels["site"] != "lab" {
		t.Fatalf("the runner's record %+v, %v: want the pool's labels", agent, err)
	}

	// The token is single-use.
	if _, _, st := r.connect(token); st != http.StatusUnauthorized {
		t.Fatalf("a runner token redeemed twice: %d", st)
	}

	if err := r.hub.Retire(w.ExecutorID, "its run settled"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var bye remote.ByePayload
	for {
		f, err := conn.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read bye: %v", err)
		}
		if f.Type == remote.TypeBye {
			bye, _ = remote.DecodeBye(f)
			break
		}
	}
	if !bye.Retired || bye.Reconnect {
		t.Fatalf("bye %+v: want retired, and no reconnect", bye)
	}
	if _, ok := r.hub.Executor(w.ExecutorID); ok {
		t.Fatal("the retired runner is still the hub's executor")
	}
	if _, err := r.reg.Get(w.ExecutorID); err == nil {
		t.Fatal("the retired runner is still registered")
	}
	if _, err := remote.Authenticate(r.store, w.Credential, time.Now()); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("the retired runner's credential: %v, want revoked", err)
	}
	// Retiring it again, or retiring an agent nothing holds, is harmless.
	if err := r.hub.Retire(w.ExecutorID, "again"); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerTokensAreRefusedUnlessTheirPoolAdmitsThem(t *testing.T) {
	// The pool refuses: the token stays unredeemed and no agent exists.
	r := newRunnerRig(t, true)
	token, rec := r.mint(false)
	if _, _, st := r.connect(token); st != http.StatusUnauthorized {
		t.Fatalf("a runner token its pool refuses: %d, want 401", st)
	}
	if got, _ := r.store.GetEnrollment(rec.ID); got.Redeemed() {
		t.Fatal("a refused runner token was spent")
	}
	if agents, _ := r.store.ListAgents(); len(agents) != 0 {
		t.Fatalf("a refused runner token left %d agents", len(agents))
	}

	// A hub with no pools refuses every runner token.
	r = newRunnerRig(t, false)
	token, _ = r.mint(true)
	if _, _, st := r.connect(token); st != http.StatusUnauthorized {
		t.Fatalf("a runner token on a hub with no pools: %d, want 401", st)
	}

	// A runner the pools cannot record is not left a permanent device.
	r = newRunnerRig(t, true)
	r.pools.refuseRec = true
	token, _ = r.mint(true)
	if _, _, st := r.connect(token); st != http.StatusUnauthorized {
		t.Fatalf("an unrecordable runner: %d, want 401", st)
	}
	agents, _ := r.store.ListAgents()
	for _, a := range agents {
		if !a.Revoked() {
			t.Fatalf("an unrecordable runner's agent %s is live", a.AgentID)
		}
	}

	// An enrollment token is never a runner, and makes no ephemeral executor.
	r = newRunnerRig(t, true)
	enroll, _, err := remote.Mint(r.store, remote.MintOptions{Name: "edge-1", WorkDirRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	w, _, _ := r.connect(enroll)
	if w.Ephemeral {
		t.Fatal("an enrolled device was told it is ephemeral")
	}
	if ex, ok := r.hub.Executor(w.ExecutorID); !ok || ex.Ephemeral() {
		t.Fatal("an enrolled device's executor is ephemeral")
	}
}

// Whether an agent is a runner is never guessed: when the pools cannot say,
// a reconnecting agent is refused rather than made a permanent device, and a
// runner credential whose runner the pools no longer know is refused outright.
func TestRunnerReconnectsFailClosed(t *testing.T) {
	r := newRunnerRig(t, true)
	token, _ := r.mint(true)
	w, conn, _ := r.connect(token)
	_ = conn.Close("reconnect")
	r.hub.Deregister(w.ExecutorID)

	r.pools.mu.Lock()
	r.pools.broken = true
	r.pools.mu.Unlock()
	if _, _, st := r.connect(w.Credential); st != http.StatusServiceUnavailable {
		t.Fatalf("a reconnect the pools cannot vouch for: %d, want 503", st)
	}

	r.pools.mu.Lock()
	r.pools.broken = false
	delete(r.pools.enrolled, w.ExecutorID)
	r.pools.mu.Unlock()
	if _, _, st := r.connect(w.Credential); st != http.StatusUnauthorized {
		t.Fatalf("a runner credential the pools do not know: %d, want 401", st)
	}
}

func TestRunnerTokenTTLIsBounded(t *testing.T) {
	if _, _, err := remote.PrepareRunnerToken(remote.MintOptions{Name: "r", TTL: remote.MaxRunnerTTL + time.Second}); err == nil {
		t.Fatal("a runner token past MaxRunnerTTL was prepared")
	}
	_, rec, err := remote.PrepareRunnerToken(remote.MintOptions{Name: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if ttl := rec.ExpiresAt.Sub(rec.CreatedAt); ttl != remote.MaxRunnerTTL {
		t.Fatalf("default runner token TTL %s, want %s", ttl, remote.MaxRunnerTTL)
	}
	token, rec, _ := remote.PrepareRunnerToken(remote.MintOptions{Name: "r"})
	if !remote.IsRunnerToken(token) || remote.RunnerTokenID(token) != rec.ID || remote.IsRunnerToken("clet1.a.b.c") {
		t.Fatal("runner token shape")
	}
}
