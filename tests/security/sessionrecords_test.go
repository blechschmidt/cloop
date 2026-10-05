package security

// Guarantee: what a restarted hub restores a session from is never a
// credential (Task 20383).
//
// A run's git proxy, Kubernetes monitor and egress sessions are recorded in
// proxy_sessions, and the GitHub App tokens behind them in app_token_slots, so
// the hub process that adopts the run after the one serving it stops can bring
// them back. Those rows outlive the process, the run and every revocation, and
// are copied into every backup of the control plane — exactly where a token
// must not be. The restore re-derives every upstream credential from the
// lease's grants; the rows hold token hashes and scopes only.
//
// The check is on the bytes that reach SQLite after a realistic run, not on the
// record structs: a guarded PAT, a guarded GitHub App token, an App token
// delivered as a file, a guarded kubeconfig and an egress session, through the
// real broker, registries and the stores the hub writes with. Every credential
// any of them involves — the PAT, the App's private key, every installation
// token GitHub minted, the cluster token and kubeconfig, every session token
// the sandbox holds, the egress proxy URL — is then looked for in every column
// of every row, verbatim and base64-encoded.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionrecord"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// recordSubject parses a grant subject or fails the test.
func recordSubject(t *testing.T, spec string) secretbroker.Subject {
	t.Helper()
	s, err := secretbroker.ParseSubject(spec)
	if err != nil {
		t.Fatalf("subject %q: %v", spec, err)
	}
	return s
}

const (
	recordPAT          = "ghp_RecordCanary0000000000000000000000001"
	recordClusterToken = "record-canary-cluster-token-0123456789"
)

// recordGuards mint durable sessions on real registries, as the hub's guards
// do, and remember every token they hand a sandbox.
type recordGuards struct {
	git    *gitproxy.Registry
	kube   *kubeguard.Registry
	tokens []string
	hashes map[string]string // session id → sha256 hex of its token
}

func (g *recordGuards) GuardGitHub(_ context.Context, req secretbroker.GitGuardRequest) (secretbroker.GitGuardResult, error) {
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m, err := g.git.Mint(gitproxy.MintRequest{
		Upstream: "https://github.com", RepoPatterns: req.Repos,
		Credential:          gitproxy.Credential{Username: "x-access-token", Password: req.Token, GrantID: req.GrantID, LeaseID: req.LeaseID},
		CredentialExpiresAt: req.TokenExpiresAt,
		Policy:              pol, ProjectID: req.ProjectID, ExecutorID: req.ExecutorID, RunID: req.RunID,
		Durable: true,
	})
	if err != nil {
		return secretbroker.GitGuardResult{}, err
	}
	g.tokens = append(g.tokens, m.Token)
	sum := sha256.Sum256([]byte(m.Token))
	g.hashes[m.Session.ID] = hex.EncodeToString(sum[:])
	return secretbroker.GitGuardResult{BaseURL: g.git.BaseURL, Username: m.Session.ID, Password: m.Token,
		SessionID: m.Session.ID, ExpiresAt: m.Session.ExpiresAt}, nil
}

func (g *recordGuards) GuardKubeconfig(_ context.Context, req secretbroker.KubeGuardRequest) (secretbroker.KubeGuardResult, error) {
	m, err := g.kube.Mint(kubeguard.MintRequest{
		Kubeconfig: req.Kubeconfig, Policy: kubeguard.Policy{Verbs: req.Verbs, Namespaces: req.Namespaces},
		GrantID: req.GrantID, LeaseID: req.LeaseID, RunID: req.RunID, ProjectID: req.ProjectID, Durable: true,
	})
	if err != nil {
		return secretbroker.KubeGuardResult{}, err
	}
	g.tokens = append(g.tokens, m.Token, string(m.Kubeconfig))
	if _, secret, ok := strings.Cut(m.Token, "."); ok {
		g.tokens = append(g.tokens, secret)
	}
	sum := sha256.Sum256([]byte(m.Token))
	g.hashes[m.Session.ID] = hex.EncodeToString(sum[:])
	return secretbroker.KubeGuardResult{Kubeconfig: m.Kubeconfig, SessionID: m.Session.ID, ExpiresAt: m.Session.ExpiresAt}, nil
}

func TestSessionRecordsHoldNoCredential(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "session-records-conformance-passphrase")
	path := statedbtest.Path(t)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	holder := func() string { return "hub_conformance" }
	clock := secretbrokertest.NewClock(time.Now())
	gh := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	gh.Clock = clock.Now
	ctx := context.Background()

	db.AsControlPlane()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	newBroker := func() *secretbroker.Broker {
		b, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)),
			secretbroker.WithGitHubApp(gh), secretbroker.WithClock(clock.Now),
			secretbroker.WithLeaseRecords("hub_conformance"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	gitReg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatal(err)
	}
	gitReg.Store = sessionrecord.NewGitStore(db, holder, nil)
	kubeReg, err := kubeguard.NewRegistry("https://hub.internal:8444")
	if err != nil {
		t.Fatal(err)
	}
	kubeReg.Store = sessionrecord.NewKubeStore(db, holder, nil)
	guards := &recordGuards{git: gitReg, kube: kubeReg, hashes: map[string]string{}}

	guarded := newBroker()
	guarded.GitGuard, guarded.KubeGuard = guards, guards
	payload := secretbrokertest.AppPayload(401, 402)
	var app struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(payload, &app); err != nil || app.PrivateKey == "" {
		t.Fatalf("app payload: %v", err)
	}
	kubeconfig := `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://prod.example.test
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: app
users:
- name: prod-user
  user:
    token: ` + recordClusterToken + `
`
	for _, s := range []struct {
		name    string
		kind    secretbroker.Kind
		payload []byte
		c       secretbroker.Constraints
	}{
		{"app", secretbroker.KindGitHubApp, payload, secretbroker.Constraints{Repos: []string{"acme/tool"}, Permissions: []string{"contents:write"}}},
		{"pat", secretbroker.KindGitHubPAT, []byte(recordPAT), secretbroker.Constraints{Repos: []string{"acme/*"}}},
		{"kube", secretbroker.KindKubeconfig, []byte(kubeconfig), secretbroker.Constraints{Namespaces: []string{"app"}}},
	} {
		sec, err := guarded.Mint(ctx, secretbroker.MintRequest{Name: s.name, Kind: s.kind, Payload: s.payload, Actor: "t"})
		if err != nil {
			t.Fatalf("mint %s: %v", s.name, err)
		}
		subject := "project:/srv/guarded"
		if s.name == "app" {
			subject = "label:site=any"
		}
		if _, err := guarded.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID, Subject: recordSubject(t, subject),
			Constraints: s.c, TTL: 24 * time.Hour, Actor: "t"}); err != nil {
			t.Fatalf("grant %s: %v", s.name, err)
		}
	}
	// The guarded run: the App, the PAT and the kubeconfig, all through
	// proxy sessions.
	labels := map[string]string{"site": "any"}
	lease, err := guarded.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/guarded",
		RunID: "run_guarded", Labels: labels}, "ui")
	if err != nil || len(lease.Materials) != 3 {
		t.Fatalf("guarded lease = %+v, %v", lease, err)
	}
	// A run with no proxy: the App token delivered into a file, its slot
	// recorded for the keepalive of whoever holds the lease next.
	plain := newBroker()
	fileLease, err := plain.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "edge-2", ProjectID: "/srv/plain",
		RunID: "run_plain", Labels: labels}, "ui")
	if err != nil || len(fileLease.Materials) != 1 {
		t.Fatalf("file lease = %+v, %v", fileLease, err)
	}

	// An egress session, redeemed durably.
	estore, err := secretstore.NewEgressStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ebroker, err := egressbroker.New(estore, egressbroker.WithEndpoint("127.0.0.1:8899"),
		egressbroker.WithSessionStore(sessionrecord.NewEgressStore(db, holder, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ebroker.Grant(ctx, egressbroker.GrantRequest{Subject: recordSubject(t, "project:/srv/guarded"),
		Hosts: []string{"api.example.com"}, TTL: time.Hour, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	red, err := ebroker.Redeem(ctx, egressbroker.RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/guarded"}, RunID: "run_guarded", Durable: true})
	if err != nil {
		t.Fatal(err)
	}
	ebroker.CheckpointSession(red.Session.ID)
	egressSum := sha256.Sum256([]byte(red.Token))
	guards.hashes[red.Session.ID] = hex.EncodeToString(egressSum[:])

	// Every credential the run involved.
	secrets := []string{recordPAT, recordClusterToken, kubeconfig, app.PrivateKey, red.Token, red.ProxyURL}
	secrets = append(secrets, guards.tokens...)
	for _, m := range gh.Minted() {
		secrets = append(secrets, m.Token)
	}
	if len(gh.Scoped()) != 2 {
		t.Fatalf("installation tokens minted = %d, want the guarded run's and the file run's", len(gh.Scoped()))
	}
	// Close one of each, so a closing write is scanned too.
	gitReg.CloseForLease(lease.ID, "lease released")
	ebroker.CloseSession(red.Session.ID, "run ended")
	_ = db.Close()

	raw, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows := map[string]int{}
	for _, table := range []string{"proxy_sessions", "app_token_slots"} {
		for _, row := range dumpTable(t, raw, table) {
			rows[table]++
			for col, val := range row {
				for _, secret := range secrets {
					for _, form := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)),
						base64.RawURLEncoding.EncodeToString([]byte(secret))} {
						if len(form) >= 12 && strings.Contains(val, form) {
							t.Fatalf("%s.%s holds a credential (%d bytes of it): that row outlives the process, "+
								"the run and every revocation", table, col, len(secret))
						}
					}
				}
			}
			if table == "proxy_sessions" {
				id := row["session_id"]
				if want, ok := guards.hashes[id]; !ok || row["token_sha256"] != want {
					t.Fatalf("proxy_sessions row %s: token_sha256 %q is not the SHA-256 of its token (%q)",
						id, row["token_sha256"], want)
				}
			}
		}
	}
	// git ×2 (App and PAT), kube ×1, egress ×1; one guarded and one file slot.
	if rows["proxy_sessions"] != 4 || rows["app_token_slots"] != 2 {
		t.Fatalf("rows scanned = %v; the run did not record what it should have", rows)
	}
}

// dumpTable returns every row of table, each column rendered as text.
func dumpTable(t *testing.T, db *sql.DB, table string) []map[string]string {
	t.Helper()
	rows, err := db.Query("SELECT * FROM " + table)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []map[string]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = vals[i].String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
