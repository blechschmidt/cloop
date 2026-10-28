package ui

// A run adopted after the hub process that dispatched it was killed keeps full
// push-scan and output-redaction coverage (Task 20454): every credential its
// grants delivered is re-derived from them, and every token its dispatcher
// minted — App installation tokens, and the git proxy, Kubernetes monitor,
// egress and model relay session tokens — is found by its prefix and confirmed
// against the hash its dispatcher recorded. These run the kill in one process,
// as the restore rig does: the dispatcher's memory dropped, its records kept.
// tests/cluster runs it with a second member adopting.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// carried is one credential a run was given and what a refusal must name it by.
type carried struct {
	name   string
	value  string
	grant  string
	secret string
}

// fullRun is the restore rig's run with one grant of every kind besides the
// rig's App and kubeconfig, an egress session from the hosted egress proxy,
// and a model relay session.
type fullRun struct {
	d       dispatched
	egress  *egressbroker.Redemption
	relay   string
	carried []carried
}

// randomHexValue is a credential with no shape any detector knows: only an
// exact-value match can catch it.
func randomHexValue(t *testing.T, label string) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return label + "-" + hex.EncodeToString(b)
}

// dispatchFull grants the run's other credentials, starts the hosted egress
// proxy, dispatches the run as the rig does, and mints the egress and relay
// sessions the dispatching process would hand the workload.
func dispatchFull(t *testing.T, r *restoreRig) fullRun {
	t.Helper()
	broker, closeDB, err := openUIBroker(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	ctx := context.Background()
	subject := secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: r.ex.ID()}
	grant := func(name string, kind secretbroker.Kind, payload string, c secretbroker.Constraints) secretbroker.Grant {
		t.Helper()
		sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: kind, Payload: []byte(payload), Actor: "test"})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		g, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID, Subject: subject, Constraints: c,
			TTL: 24 * time.Hour, Actor: "test"})
		if err != nil {
			t.Fatalf("grant %s: %v", name, err)
		}
		return g
	}
	apiKey := randomHexValue(t, "acme-api-key")
	envGrant := grant("acme-api", secretbroker.KindEnv, `{"ACME_API_KEY":"`+apiKey+`"}`, secretbroker.Constraints{})
	regPassword := randomHexValue(t, "registry-password")
	regAuth := base64Std("robot:" + regPassword)
	regGrant := grant("acme-registry", secretbroker.KindRegistry, `{"auths":{"ghcr.io":{"auth":"`+regAuth+`"}}}`,
		secretbroker.Constraints{Registries: []string{"ghcr.io"}})
	proxyPassword := randomHexValue(t, "proxy-password")
	proxyGrant := grant("acme-proxy", secretbroker.KindEgressProxy,
		"http://proxyuser:"+proxyPassword+"@proxy.example.invalid:3128", secretbroker.Constraints{Hosts: []string{"example.com"}})

	cfg := &config.Config{}
	cfg.Executors.Egress = config.EgressConfig{Enabled: true, ListenAddr: "127.0.0.1:0", MaxSessionMinutes: 10}
	ensureEgressProxy(cfg, r.dir, 0)
	t.Cleanup(func() { closeEgressProxy(r.dir) })
	svc := activeEgressProxy()
	if svc == nil {
		t.Fatalf("the egress proxy did not start: %s", egressProxyUnavailable())
	}
	eg := grantEgress(t, svc, "executor:"+r.ex.ID(), nil)

	run := fullRun{d: r.dispatch()}
	run.egress, err = svc.broker.Redeem(ctx, egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: r.ex.ID(), ProjectID: r.dir, RunID: "run_restore"},
		RunID:     "run_restore", Actor: "test", Durable: true,
	})
	if err != nil {
		t.Fatalf("redeem the run's egress session: %v", err)
	}

	// The model relay session, as the relay's registry mints and records it:
	// standing on the run's lease and the grant of the credential it relays.
	reg := claudeproxy.NewRegistryWithPrefix("", modelRelayTokenPrefix)
	reg.Store = sessionrecord.NewModelStore(r.db, sessionHolderID, nil, logSessionStoreErr)
	m, err := reg.Mint(claudeproxy.MintRequest{
		Policy: claudeproxy.Policy{Models: []string{"claude-sonnet-5"}, MaxRequests: 10},
		RunID:  "run_restore", LeaseID: run.d.lease.lease.ID, GrantID: envGrant.ID, ExecutorID: r.ex.ID(),
		TTL: 30 * time.Minute,
	})
	if err != nil || !m.Session.Durable() {
		t.Fatalf("mint the run's relay session: durable %v, %v", m != nil && m.Session.Durable(), err)
	}
	run.relay = m.Token

	for _, tok := range []string{run.d.gitToken, run.d.kubeToken, run.egress.Token, run.relay, run.d.firstAppToken} {
		if redact.MintedPrefix(tok) == "" {
			t.Fatalf("a minted token carries no prefix a stream can find it by: %.16s…", tok)
		}
	}
	run.carried = []carried{
		{"an env secret's value", apiKey, envGrant.ID, "acme-api"},
		{"a registry secret's auth", regAuth, regGrant.ID, "acme-registry"},
		{"the password inside the registry auth", regPassword, regGrant.ID, "acme-registry"},
		{"an egress proxy secret's password", proxyPassword, proxyGrant.ID, "acme-proxy"},
		{"the kubeconfig's cluster token", restoreClusterToken, r.kubeGrant.ID, "restore-kube"},
		{"the GitHub App installation token", run.d.firstAppToken, r.appGrant.ID, "restore-app"},
		{"the git proxy session token", run.d.gitToken, r.appGrant.ID, "restore-app"},
		{"the Kubernetes monitor session token", run.d.kubeToken, r.kubeGrant.ID, "restore-kube"},
		{"the egress proxy session's password", run.egress.Token, eg.ID, "the run's egress proxy session"},
		{"the model relay session token", run.relay, envGrant.ID, "the run's model relay session"},
	}
	return run
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// pushCarrying commits a file holding value in work and pushes it to its own
// ref through the git proxy session d holds.
func (r *restoreRig) pushCarrying(d dispatched, work string, n int, value string) (string, error) {
	r.t.Helper()
	name := fmt.Sprintf("leak-%d.txt", n)
	if err := os.WriteFile(filepath.Join(work, name), []byte("config = "+value+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", name},
		{"-c", "user.email=a@b.invalid", "-c", "user.name=t", "commit", "-qm", "add " + name},
	} {
		if out, err := r.git(d, work, args...); err != nil {
			r.t.Fatalf("git %s: %v\n%s", args[0], err, out)
		}
	}
	out, err := r.git(d, work, "push", "origin", fmt.Sprintf("HEAD:refs/heads/cloop/leak-%d", n))
	// The next commit starts from the forge's tip again, so a refused commit
	// does not ride along with every later push.
	if _, rerr := r.git(d, work, "reset", "-q", "--hard", "HEAD~1"); rerr != nil {
		r.t.Fatalf("git reset: %v", rerr)
	}
	return out, err
}

// assertRefused holds a push carrying c to the task's terms: refused, naming
// c's grant and secret, never c's value, and no ref moved.
func (r *restoreRig) assertRefused(c carried, n int, out string, err error) {
	r.t.Helper()
	if err == nil {
		r.t.Errorf("a push carrying %s was accepted:\n%s", c.name, out)
		return
	}
	if !strings.Contains(out, "cloop git proxy refused this push") {
		r.t.Errorf("a push carrying %s failed, but not by the push scan:\n%s", c.name, out)
	}
	if !strings.Contains(out, "grant "+c.grant) || !strings.Contains(out, fmt.Sprintf("secret %q", c.secret)) {
		r.t.Errorf("the refusal of %s does not name grant %s and secret %q:\n%s", c.name, c.grant, c.secret, out)
	}
	if strings.Contains(out, c.value) {
		r.t.Errorf("the refusal of %s carries the value", c.name)
	}
	if ref := r.forge.Ref(r.t, restoreRepo, fmt.Sprintf("refs/heads/cloop/leak-%d", n)); ref != "" {
		r.t.Errorf("the push carrying %s updated a ref on the forge", c.name)
	}
}

// TestAnAdoptedRunIsHeldToEveryCredentialItWasGiven is the task: the process
// that dispatched the run is killed, a new one adopts the run as adoptRun
// does, and for every kind of credential the run holds — re-derived or known
// only by its recorded hash — a push carrying it through the restored git
// session is refused, named by its grant and secret and never by its value,
// and the run's streamed output carrying it is scrubbed. A token of the same
// shape that is not the run's is neither refused nor scrubbed. A run the new
// process dispatches after the restart is covered by its exact values alone.
func TestAnAdoptedRunIsHeldToEveryCredentialItWasGiven(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	r := newRestoreRig(t)
	run := dispatchFull(t, r)
	d := run.d
	work := filepath.Join(t.TempDir(), "work")
	if out, err := r.git(d, "", "clone", r.gitSrv.URL+"/"+restoreRepo, work); err != nil {
		t.Fatalf("clone before the restart: %v\n%s", err, out)
	}

	// SIGKILL: the dispatcher's memory goes — its lease registry entry, its
	// proxies' registries, its egress and relay sessions — and its records
	// stay.
	r.clock.Advance(2 * time.Minute)
	r.restart(d, "hub_new")
	pushScans.Lock()
	delete(pushScans.runs, "run_restore")
	pushScans.Unlock()

	srv := &Server{WorkDir: r.dir}
	meta := runOwnerMeta{Executor: r.ex.ID(), Handle: "h-1", Leases: []string{d.lease.lease.ID},
		Egress: []string{run.egress.Session.ID}, Provenance: &projectseed.Provenance{RunID: "run_restore"}}
	srv.adoptRunTokens(r.dir, r.ex, meta)
	if r.takeOver(d) == nil {
		t.Fatal("the adopting process does not hold the run's lease")
	}

	n := 0
	for _, c := range run.carried {
		n++
		out, err := r.pushCarrying(d, work, n, c.value)
		r.assertRefused(c, n, out, err)
		line := "the workload printed " + c.value + " on its way\n"
		if got := r.ex.scrub("h-1", line); strings.Contains(got, c.value) || !strings.Contains(got, redact.Marker) {
			t.Errorf("the adopted run's stream carries %s: %q", c.name, got)
		}
	}
	if journal := pushRefusalsFor(t, r.dir); journal < len(run.carried) {
		t.Errorf("the run's history files %d refused pushes, want %d", journal, len(run.carried))
	}

	// Precision: tokens of the same shapes that are not the run's pass.
	for _, prefix := range []string{redact.GitProxyTokenPrefix, redact.KubeGuardTokenPrefix, redact.EgressTokenPrefix,
		redact.RelayTokenPrefix, redact.GitHubAppTokenPrefix} {
		var own string
		for _, c := range run.carried {
			if strings.HasPrefix(c.value, prefix) {
				own = c.value
			}
		}
		stranger := lookAlike(t, own)
		n++
		if out, err := r.pushCarrying(d, work, n, stranger); err != nil {
			t.Errorf("a push carrying a %s token that is not the run's was refused: %v\n%s", prefix, err, out)
		}
		if got := r.ex.scrub("h-1", "fixture "+stranger); !strings.Contains(got, stranger) {
			t.Errorf("a %s token that is not the run's was scrubbed from its stream: %q", prefix, got)
		}
	}

	// A run the new process dispatches is covered by what it handed out: its
	// exact values, registered at dispatch, and no token hashes to search for.
	after := acquireSecretLease(r.dir, r.dir, r.ex, "run_after", nil)
	if after == nil {
		t.Fatal("no lease was issued after the restart")
	}
	stopKeepaliveForTest(after)
	after.bindHandle(r.ex.ID(), "h-2")
	t.Cleanup(after.Close)
	spec, err := applyLease(executor.Spec{Argv: []string{"cloop", "run"}}, r.ex, after)
	if err != nil {
		t.Fatal(err)
	}
	end := registerRunPushScan("run_after", r.dir, after, spec)
	t.Cleanup(end)
	pushScans.Lock()
	if e := pushScans.runs["run_after"]; e == nil || len(e.tokens) != 0 {
		pushScans.Unlock()
		t.Fatalf("a run dispatched here searches for token hashes: %+v", e)
	}
	pushScans.Unlock()
	afterRun := dispatched{}
	for _, f := range after.SecretFiles() {
		if f.Name != "git-proxy-credential" {
			continue
		}
		for _, line := range strings.Split(string(f.Content), "\n") {
			if v, ok := strings.CutPrefix(line, "username="); ok {
				afterRun.gitID = v
			}
			if v, ok := strings.CutPrefix(line, "password="); ok {
				afterRun.gitToken = v
			}
		}
	}
	if afterRun.gitToken == "" || !strings.HasPrefix(afterRun.gitToken, redact.GitProxyTokenPrefix) {
		t.Fatalf("the run dispatched after the restart holds no prefixed git session token")
	}
	work2 := filepath.Join(t.TempDir(), "work2")
	if out, err := r.git(afterRun, "", "clone", r.gitSrv.URL+"/"+restoreRepo, work2); err != nil {
		t.Fatalf("clone after the restart: %v\n%s", err, out)
	}
	for _, c := range []carried{
		{"the new run's git proxy session token", afterRun.gitToken, r.appGrant.ID, "restore-app"},
		{"the new run's env secret value", run.carried[0].value, run.carried[0].grant, run.carried[0].secret},
	} {
		n++
		out, err := r.pushCarrying(afterRun, work2, n, c.value)
		r.assertRefused(c, n, out, err)
		if got := spec.Redactor().String("printed " + c.value); strings.Contains(got, c.value) {
			t.Errorf("the new run's own redaction leaves %s: %q", c.name, got)
		}
	}
}

// lookAlike returns a token of tok's shape that is not tok: the same prefix
// and length, a different body.
func lookAlike(t *testing.T, tok string) string {
	t.Helper()
	prefix := redact.MintedPrefix(tok)
	if prefix == "" {
		t.Fatalf("no minted prefix on %.12s…", tok)
	}
	body := []byte(tok[len(prefix):])
	for i, c := range body {
		switch {
		case c >= '0' && c <= '8', c >= 'a' && c <= 'y', c >= 'A' && c <= 'Y':
			body[i] = c + 1
		case c == '9':
			body[i] = '0'
		case c == 'z':
			body[i] = 'a'
		case c == 'Z':
			body[i] = 'A'
		}
	}
	return prefix + string(body)
}

// pushRefusalsFor counts the refused pushes the project's history files.
func pushRefusalsFor(t *testing.T, dir string) int {
	t.Helper()
	rows, err := state.ListEventsOfType(dir, state.EventGitPushRefused, 200)
	if err != nil {
		t.Fatalf("read the run's history: %v", err)
	}
	return len(rows)
}

// TestAnAdoptedRunWithNothingMintedSearchesForNoTokens: a run whose grants are
// all re-derivable, and whose dispatcher minted nothing, is adopted at the
// exact-value cost it always had — nothing is handed to its driver or its push
// scan to search for.
func TestAnAdoptedRunWithNothingMintedSearchesForNoTokens(t *testing.T) {
	ex := newTakeoverExecutor("edge-plain")
	h := newTakeoverHub(t, ex.ID())
	sl := h.dispatch(t, ex, "h-1")
	liveLeases.removeIf(sl)
	h.holder = "hub_adopter"
	srv := &Server{WorkDir: h.dir}
	srv.adoptRunTokens(h.dir, ex, runOwnerMeta{Executor: ex.ID(), Handle: "h-1", Leases: []string{sl.lease.ID}})
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if len(ex.tokens["h-1"]) != 0 {
		t.Fatalf("a run whose dispatcher minted nothing was handed %d token hashes", len(ex.tokens["h-1"]))
	}
}

// attachingExecutor is a container driver's stand-in: like the real one it
// knows an adopted handle only once the store has been read again
// (AttachHandleStore), and refuses what it is handed for a handle it does not
// know.
type attachingExecutor struct {
	*takeoverExecutor
	attached bool
	refused  int
}

func (e *attachingExecutor) Kind() string { return executor.KindContainer }

func (e *attachingExecutor) AttachHandleStore(executor.HandleStore) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attached = true
}

func (e *attachingExecutor) AddHandleTokens(handleID string, hs ...redact.TokenHash) bool {
	e.mu.Lock()
	known := e.attached
	if !known {
		e.refused++
	}
	e.mu.Unlock()
	if !known {
		return false
	}
	return e.takeoverExecutor.AddHandleTokens(handleID, hs...)
}

// TestAnAdoptedContainerRunsDriverIsHandedItsTokensOnceItKnowsTheHandle: a
// container or Pod run adopted from a member that died is known to its driver
// only after adoptRun has the driver read the handle store again, so the token
// hashes go to the driver after that — through adoptRun itself, not a call
// made beside it. Handed over before, they were refused and the run's minted
// tokens streamed unscrubbed.
func TestAnAdoptedContainerRunsDriverIsHandedItsTokensOnceItKnowsTheHandle(t *testing.T) {
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "tokens follow the handle", 0); err != nil {
		t.Fatal(err)
	}
	withControlPlaneDir(t, dir)
	ex := &attachingExecutor{takeoverExecutor: newTakeoverExecutor("ctr-adopt")}
	if err := executor.DefaultRegistry.Register(ex); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()); ex.finish() })

	// What the dead member recorded of the git proxy session it minted for
	// the run: the token's hash, beside the lease it fed.
	token := redact.GitProxyTokenPrefix + strings.Repeat("Ab1-", 10) + "xyz"
	h := redact.HashToken(token)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutProxySession(statedb.ProxySessionRow{Kind: statedb.ProxySessionGit, SessionID: "sess-adopt",
		TokenSHA256: hex.EncodeToString(h.Sum[:]), LeaseID: "lease-adopt", Holder: "hub_dead", RunID: "run-adopt",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	dispatcher, adopter := slotMember(t, dir), slotMember(t, dir)
	waitCluster(t, "the members to see each other", func() bool {
		return dispatcher.Cluster.HasPeers() && adopter.Cluster.HasPeers()
	})
	asProcess(t, dispatcher.Cluster)
	if _, err := dispatcher.claimRun(dir, "run"); err != nil {
		t.Fatalf("claim the run: %v", err)
	}
	if err := dispatcher.recordRunDispatch(dir, "run", ex, "h-adopt"); err != nil {
		t.Fatalf("record the run: %v", err)
	}
	meta := runOwnerOf(t, dispatcher.Cluster, dir)
	meta.Leases = []string{"lease-adopt"}
	o, found, err := adopter.Cluster.Lookup(ownerRun, dir)
	if err != nil || !found {
		t.Fatalf("the run's owner row: %v, %v", found, err)
	}
	if adopter.clusterHandleStoreFor() == nil {
		t.Fatal("no handle store for the driver to read: the test proves nothing")
	}
	asProcess(t, adopter.Cluster)
	adopter.adoptRun(o, meta, "test: the member that dispatched the run died")

	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.refused != 0 {
		t.Fatalf("the token hashes were handed to the driver %d time(s) before it knew the handle", ex.refused)
	}
	if got := ex.tokens["h-adopt"]; len(got) != 1 || got[0] != h {
		t.Fatalf("the driver was handed %v, want the session token's recorded hash", got)
	}
}
