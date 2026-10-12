package ui

// Kubernetes shares on the hub (Task 20416): the dashboard's refusal of a
// kubeconfig that runs an exec plugin, the metadata a share is stored with,
// the renew route, the renewal duty and the live monitor sessions that take a
// renewed token up. The cluster is a TLS test server that answers the two calls
// a share makes of it — a TokenRequest and a SelfSubjectReview.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/kubeshare"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// saToken is an unsigned ServiceAccount JWT; the hub reads its claims and the
// fake cluster below decides whether it is valid. Each carries a jti of its
// own, as a real one does: two tokens for one ServiceAccount minted in the same
// second must not be the same token, or a test's "forged" one can coincide
// with one the cluster just issued.
func saToken(ns, name string, iat, exp time.Time) string {
	jti := make([]byte, 8)
	_, _ = rand.Read(jti)
	payload, _ := json.Marshal(map[string]any{
		"sub": "system:serviceaccount:" + ns + ":" + name, "iat": iat.Unix(), "exp": exp.Unix(),
		"jti":           hex.EncodeToString(jti),
		"kubernetes.io": map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": name}},
	})
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

// fakeCluster answers TokenRequest for one ServiceAccount, authenticated by
// whichever token it last issued (or the one it was seeded with), and
// SelfSubjectReview for any token it issued.
type fakeCluster struct {
	srv *httptest.Server
	ns  string
	sa  string

	mu sync.Mutex
	// valid are the tokens it accepts.
	valid map[string]bool
	// refuse, when set, is the status every TokenRequest gets.
	refuse   int
	minted   int
	lifetime time.Duration
	// hits counts every request the cluster answered.
	hits int
}

func newFakeCluster(t *testing.T, ns, sa string) *fakeCluster {
	f := &fakeCluster{ns: ns, sa: sa, valid: map[string]bool{}, lifetime: time.Hour}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCluster) accept(token string) {
	f.mu.Lock()
	f.valid[token] = true
	f.mu.Unlock()
}

func (f *fakeCluster) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *fakeCluster) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	w.Header().Set("Content-Type", "application/json")
	if !f.valid[bearer] {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`))
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/"+f.ns+"/serviceaccounts/"+f.sa+"/token":
		if f.refuse != 0 {
			w.WriteHeader(f.refuse)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"serviceaccounts \"` + f.sa +
				`\" is forbidden: cannot create resource \"serviceaccounts/token\"","reason":"Forbidden"}`))
			return
		}
		f.minted++
		now := time.Now().Add(time.Duration(f.minted) * time.Second)
		tok := saToken(f.ns, f.sa, now, now.Add(f.lifetime))
		f.valid[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
			"token": tok, "expirationTimestamp": now.Add(f.lifetime).UTC().Format(time.RFC3339)}})
	case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
		c, _ := kubeshare.ParseClaims(bearer)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
			"userInfo": map[string]any{"username": c.Subject()}}})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"not found","code":404}`))
	}
}

// shareDoc is the static kubeconfig a share stores, for this fake cluster.
func (f *fakeCluster) shareDoc(t *testing.T, token string) string {
	t.Helper()
	doc, err := kubeshare.RenderKubeconfig(kubeshare.KubeconfigParams{
		Name: "aks-dev", Server: f.srv.URL, CAData: f.caPEM(), Namespace: "team-a", Token: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(doc)
}

// shareMetadata is what `cloop remote kube share` sends, plus some fields the
// hub must not believe.
func shareMetadata(renewal kubeshare.Renewal) map[string]string {
	return map[string]string{
		kubeshare.MetaShare:          "3f9c2a1b",
		kubeshare.MetaRenewal:        string(renewal),
		kubeshare.MetaServiceAccount: "cloop-shares/cloop-aks-dev-3f9c2a1b",
		kubeshare.MetaNamespaces:     "team-a,team-b",
		kubeshare.MetaAccess:         "write",
		kubeshare.MetaContext:        "aks-dev",
		// Lies, which the hub must replace from the token or drop.
		kubeshare.MetaExpiresAt: "2099-01-01T00:00:00Z",
		kubeshare.MetaRenewals:  "42",
		kubeshare.MetaServer:    "https://somewhere-else.example.com",
		// And the ones revoke and renew act on (Task 20420): who made it,
		// which CA its cluster presents, which objects it created.
		kubeshare.MetaOwner:   "root@corp.example",
		kubeshare.MetaCA:      "0000000000000000000000000000000000000000000000000000000000000000",
		kubeshare.MetaObjects: "ClusterRoleBinding:cluster-admin,ServiceAccount:kube-system/default",
	}
}

func withKubeGuardRequired(t *testing.T, on bool) {
	t.Helper()
	// Spend the process's one start of the monitor first. A server built
	// after this (kubeShareHub) would otherwise run it and store the config's
	// answer over this one, so a test calling this passed or failed by
	// whether another had built a server before it — run alone, it failed.
	kubeGuardOnce.Do(func() {})
	prev := kubeGuardRequired.Load()
	kubeGuardRequired.Store(on)
	t.Cleanup(func() { kubeGuardRequired.Store(prev) })
}

// TestDashboardRefusesAnExecPluginKubeconfigAndSaysWhatToRun: the refusal at
// upload names the plugin and gives the exact command, with this hub's URL,
// the name chosen, and the context and namespace from the document.
func TestDashboardRefusesAnExecPluginKubeconfigAndSaysWhatToRun(t *testing.T) {
	f := newPersonalFixture(t)
	aks := `apiVersion: v1
kind: Config
current-context: aks-dev
clusters:
- name: aks-dev
  cluster: {server: "https://aks-dev-dns.hcp.westeurope.azmk8s.io:443"}
contexts:
- name: aks-dev
  context: {cluster: aks-dev, user: clusterUser_rg_aks-dev, namespace: payments}
users:
- name: clusterUser_rg_aks-dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args: [get-token, --login, devicecode]
`
	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": aks,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("POST /api/secrets = %d, want 400: %s", code, body)
	}
	var resp struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	for _, want := range []string{
		"kubelogin (Microsoft Entra ID",
		"cloop remote kube share aks-dev --hub " + f.base + " --context aks-dev --namespaces payments",
	} {
		if !strings.Contains(resp.Error.Message, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, resp.Error.Message)
		}
	}
	if hasName(f.secretNames(t, "alice"), "aks-dev") {
		t.Error("the refused kubeconfig was stored anyway")
	}
}

// TestShareMetadataComesFromTheToken: what the hub keeps about a share's token
// is read from the token, not from whoever uploaded it, and hub renewal is
// accepted only where the monitor would keep the renewal permission out of the
// sandbox.
func TestShareMetadataComesFromTheToken(t *testing.T) {
	f := newPersonalFixture(t)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	tok := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))

	withKubeGuardRequired(t, false)
	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": cl.shareDoc(t, tok), "metadata": shareMetadata(kubeshare.RenewalHub),
	})
	if code != http.StatusBadRequest || !strings.Contains(body, "does not run the Kubernetes access monitor") {
		t.Fatalf("a hub-renewed share on a hub with no monitor: %d %s", code, body)
	}

	withKubeGuardRequired(t, true)
	code, body = f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": cl.shareDoc(t, tok), "metadata": shareMetadata(kubeshare.RenewalHub),
	})
	if code != http.StatusOK {
		t.Fatalf("POST /api/secrets = %d: %s", code, body)
	}
	var sec struct {
		Metadata map[string]string `json:"metadata"`
		Personal bool              `json:"personal"`
	}
	_ = json.Unmarshal([]byte(body), &sec)
	if !sec.Personal {
		t.Error("a share made over a signed-in session was not personal")
	}
	want := map[string]string{
		kubeshare.MetaExpiresAt:      iat.Add(time.Hour).UTC().Format(time.RFC3339),
		kubeshare.MetaIssuedAt:       iat.UTC().Format(time.RFC3339),
		kubeshare.MetaServer:         cl.srv.URL,
		kubeshare.MetaServiceAccount: "cloop-shares/cloop-aks-dev-3f9c2a1b",
		kubeshare.MetaRenewal:        "hub",
		// The uploader, from the session — not the metadata's root.
		kubeshare.MetaOwner: "alice@corp.example",
		kubeshare.MetaCA:    kubeshare.CAFingerprint(cl.caPEM()),
		// What the share's plan creates, not what the client listed.
		kubeshare.MetaObjects: "ServiceAccount:cloop-shares/cloop-aks-dev-3f9c2a1b," +
			"RoleBinding:team-a/cloop-aks-dev-3f9c2a1b,RoleBinding:team-b/cloop-aks-dev-3f9c2a1b," +
			"Role:cloop-shares/cloop-aks-dev-3f9c2a1b-renew,RoleBinding:cloop-shares/cloop-aks-dev-3f9c2a1b-renew",
	}
	for k, v := range want {
		if sec.Metadata[k] != v {
			t.Errorf("metadata %s = %q, want %q", k, sec.Metadata[k], v)
		}
	}
	if _, kept := sec.Metadata[kubeshare.MetaRenewals]; kept {
		t.Error("the client's kube.renewals survived; the hub writes it")
	}
	if code, list := getFull(t, f.clients["alice"], f.base+"/api/secrets"); code != http.StatusOK ||
		!strings.Contains(list, `"kube_guard":{"enabled":true`) {
		t.Errorf("GET /api/secrets does not report the monitor: %s", list)
	}

	// A share carrying something that is not a bounded ServiceAccount token.
	for name, payload := range map[string]string{
		"opaque": strings.Replace(cl.shareDoc(t, tok), tok, "opaque-token", 1),
		"user":   strings.Replace(cl.shareDoc(t, tok), tok, saToken("x", "y", iat, iat.Add(-time.Second)), 1),
	} {
		code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
			"name": "bad-" + name, "kind": "kubeconfig", "payload": payload, "metadata": shareMetadata(kubeshare.RenewalManual),
		})
		if code != http.StatusBadRequest || !strings.Contains(body, "ServiceAccount token") {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}

	// A share whose token is for somebody else's ServiceAccount — its claims
	// are nobody's to verify here, and renew would mint for it (Task 20420).
	for name, sa := range map[string][2]string{
		"kube-system's":   {"kube-system", "default"},
		"another share's": {"cloop-shares", "cloop-aks-dev-deadbeef"},
	} {
		payload := strings.Replace(cl.shareDoc(t, tok), tok, saToken(sa[0], sa[1], iat, iat.Add(time.Hour)), 1)
		code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
			"name": "bad-sa", "kind": "kubeconfig", "payload": payload, "metadata": shareMetadata(kubeshare.RenewalManual),
		})
		if code != http.StatusBadRequest || !strings.Contains(body, "its own ServiceAccount only") {
			t.Errorf("a token for %s ServiceAccount: %d %s", name, code, body)
		}
	}
	// Namespaces that are not namespaces.
	bad := shareMetadata(kubeshare.RenewalManual)
	bad[kubeshare.MetaNamespaces] = "team-a,../../kube-system"
	if code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "bad-ns", "kind": "kubeconfig", "payload": cl.shareDoc(t, tok), "metadata": bad,
	}); code != http.StatusBadRequest || !strings.Contains(body, "not a namespace") {
		t.Errorf("a namespace list naming a path: %d %s", code, body)
	}
}

// TestRenewRoute: a personal share is renewed by its owner — with a token the
// cluster confirms, or by the hub on request when it renews the share — and by
// nobody else, an administrator included.
func TestRenewRoute(t *testing.T) {
	f := newPersonalFixture(t)
	withKubeGuardRequired(t, true)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(first)

	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": cl.shareDoc(t, first), "metadata": shareMetadata(kubeshare.RenewalHub),
	})
	if code != http.StatusOK {
		t.Fatalf("mint: %d %s", code, body)
	}
	var sec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &sec)

	// The hub renews it now, with the share's own token.
	code, body = f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("renew now: %d %s", code, body)
	}
	var view kubeShareView
	_ = json.Unmarshal([]byte(body), &view)
	if view.Renewals != 1 || view.RenewedAt == nil || !view.ExpiresAt.After(iat.Add(time.Hour)) {
		t.Errorf("after renew-now: %+v", view)
	}

	// A token its owner minted at the share's server, which the cluster
	// confirms.
	origin := func(tok string) map[string]any {
		return map[string]any{"token": tok, "server": cl.srv.URL, "ca_sha256": kubeshare.CAFingerprint(cl.caPEM())}
	}
	pushed := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", time.Now(), time.Now().Add(2*time.Hour))
	cl.accept(pushed)
	code, body = f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", origin(pushed))
	if code != http.StatusOK {
		t.Fatalf("push: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &view)
	if !view.Verified || view.Renewals != 2 || view.RenewedBy == "" {
		t.Errorf("after a push: %+v", view)
	}
	if strings.Contains(body, pushed) {
		t.Fatal("the renew route echoed the token")
	}

	// Refusals: another ServiceAccount's token, one the cluster does not
	// accept, somebody else's share.
	other := saToken("cloop-shares", "someone-else", time.Now(), time.Now().Add(time.Hour))
	cl.accept(other)
	if code, body := f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", origin(other)); code != http.StatusBadRequest {
		t.Errorf("another ServiceAccount's token: %d %s", code, body)
	}
	forged := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", time.Now(), time.Now().Add(time.Hour))
	if code, body := f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", origin(forged)); code == http.StatusOK ||
		!strings.Contains(body, "does not accept") {
		t.Errorf("a token the cluster refuses: %d %s", code, body)
	}
	// A token minted at another server, through another CA, or nowhere said
	// is never sent to the share's server to be checked (Task 20420).
	fresh := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", time.Now(), time.Now().Add(time.Hour))
	cl.accept(fresh)
	for name, body := range map[string]map[string]any{
		"another server": {"token": fresh, "server": "https://prod.example.com:6443", "ca_sha256": kubeshare.CAFingerprint(cl.caPEM())},
		"another CA":     {"token": fresh, "server": cl.srv.URL, "ca_sha256": kubeshare.CAFingerprint([]byte("x"))},
		"unsaid":         {"token": fresh},
	} {
		cl.mu.Lock()
		before := cl.hits
		cl.mu.Unlock()
		code, resp := f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", body)
		if code != http.StatusBadRequest || !strings.Contains(resp, "minted") {
			t.Errorf("%s: %d %s", name, code, resp)
		}
		cl.mu.Lock()
		after := cl.hits
		cl.mu.Unlock()
		if after != before {
			t.Errorf("%s: the token was sent to the share's server", name)
		}
	}
	if code, body := f.postJSON(t, "bob", "/api/secrets/"+sec.ID+"/renew", map[string]any{}); code != http.StatusNotFound {
		t.Errorf("bob renewing alice's share: %d %s", code, body)
	}
	if code, body := f.postJSON(t, "root", "/api/secrets/"+sec.ID+"/renew", map[string]any{"token": pushed}); code != http.StatusForbidden {
		t.Errorf("an admin putting a token into alice's share: %d %s", code, body)
	}

	// An ordinary kubeconfig secret is not a share.
	plain := strings.Replace(cl.shareDoc(t, first), first, "static-token", 1)
	code, body = f.postJSON(t, "alice", "/api/secrets", map[string]any{"name": "plain", "kind": "kubeconfig", "payload": plain})
	if code != http.StatusOK {
		t.Fatalf("mint plain: %d %s", code, body)
	}
	var plainSec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &plainSec)
	if code, body := f.postJSON(t, "alice", "/api/secrets/"+plainSec.ID+"/renew", map[string]any{}); code != http.StatusBadRequest ||
		!strings.Contains(body, "not a Kubernetes share") {
		t.Errorf("renewing a plain kubeconfig: %d %s", code, body)
	}
}

// kubeShareHub is a hub with a broker and no browser: what the renewal duty and
// the session sync run against.
func kubeShareHub(t *testing.T) (*Server, *secretbroker.Broker, *statedb.DB) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "kube-share-conformance-passphrase")
	dir := statedbtest.Dir(t)
	if _, err := state.Init(dir, "kube shares", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	srv := New(dir, 0, "")
	bs, err := openBrokersAt(dir)
	if err != nil || bs.secret == nil {
		t.Fatalf("open brokers: %v %+v", err, bs)
	}
	t.Cleanup(bs.close)
	return srv, bs.secret, bs.db
}

func mintShareSecret(t *testing.T, b *secretbroker.Broker, cl *fakeCluster, token string, renewal kubeshare.Renewal) secretbroker.Secret {
	t.Helper()
	meta, err := prepareKubeShare(shareMetadata(renewal), []byte(cl.shareDoc(t, token)), "alice@corp.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "aks-dev", Kind: secretbroker.KindKubeconfig, Payload: []byte(cl.shareDoc(t, token)),
		Metadata: meta, Actor: "alice@corp.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

func shareOf(t *testing.T, b *secretbroker.Broker, id string) kubeshare.Share {
	t.Helper()
	s, err := b.DescribeSecret(id)
	if err != nil {
		t.Fatal(err)
	}
	sh, ok := kubeshare.FromMetadata(s.Metadata)
	if !ok {
		t.Fatal("not a share")
	}
	return sh
}

func countRenewRows(t *testing.T, db *statedb.DB, decision string) int {
	t.Helper()
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(secretbroker.ActionRenew), Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.EventType == string(secretbroker.ActionRenew) && strings.Contains(e.Payload, `"decision":"`+decision+`"`) {
			n++
		}
	}
	return n
}

// TestRenewalDutyRenewsAtHalfLifeAndRecordsFailuresOnce.
func TestRenewalDutyRenewsAtHalfLifeAndRecordsFailuresOnce(t *testing.T) {
	withKubeGuardRequired(t, true)
	srv, b, db := kubeShareHub(t)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(first)
	sec := mintShareSecret(t, b, cl, first, kubeshare.RenewalHub)
	ctx := context.Background()

	// Not yet due.
	if n := srv.renewDueKubeShares(ctx, iat.Add(20*time.Minute)); n != 0 {
		t.Fatalf("renewed %d shares with two thirds of the token left", n)
	}
	// Due at half-life.
	if n := srv.renewDueKubeShares(ctx, iat.Add(31*time.Minute)); n != 1 {
		t.Fatalf("renewed %d shares at half-life, want 1", n)
	}
	sh := shareOf(t, b, sec.ID)
	if sh.Renewals != 1 || sh.RenewedBy != kubeShareActor || !sh.IssuedAt.After(iat) || sh.RenewError != "" {
		t.Errorf("after the renewal: %+v", sh)
	}
	if n := countRenewRows(t, db, "allow"); n != 1 {
		t.Errorf("%d secret.renew allow rows, want 1", n)
	}

	// The self-renewal Role is gone: every attempt fails, the reason is
	// recorded on the share, and audited once rather than once a tick.
	cl.mu.Lock()
	cl.refuse = http.StatusForbidden
	cl.mu.Unlock()
	due := sh.IssuedAt.Add(sh.Lifetime()/2 + time.Minute)
	for i := 0; i < 3; i++ {
		if n := srv.renewDueKubeShares(ctx, due.Add(time.Duration(i)*time.Minute)); n != 0 {
			t.Fatalf("a refused renewal counted as renewed")
		}
	}
	sh = shareOf(t, b, sec.ID)
	if !strings.Contains(sh.RenewError, "self-renewal Role") || sh.Lapsed {
		t.Errorf("a refused renewal: %+v", sh)
	}
	if n := countRenewRows(t, db, "deny"); n != 1 {
		t.Errorf("%d secret.renew deny rows for three identical failures, want 1", n)
	}

	// Past expiry nothing the hub holds can renew it: lapsed, and left alone.
	cl.mu.Lock()
	cl.refuse = 0
	cl.mu.Unlock()
	srv.renewDueKubeShares(ctx, sh.ExpiresAt.Add(time.Minute))
	sh = shareOf(t, b, sec.ID)
	if !sh.Lapsed {
		t.Fatalf("an expired share is not marked lapsed: %+v", sh)
	}
	if n := srv.renewDueKubeShares(ctx, sh.ExpiresAt.Add(2*time.Minute)); n != 0 || cl.minted != 1 {
		t.Errorf("a lapsed share was renewed again (minted %d)", cl.minted)
	}

	// A manually renewed share is never touched by the duty.
	mt := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(mt)
	if err := b.DeleteSecret(ctx, sec.ID, "test"); err != nil {
		t.Fatal(err)
	}
	mintShareSecret(t, b, cl, mt, kubeshare.RenewalManual)
	if n := srv.renewDueKubeShares(ctx, iat.Add(50*time.Minute)); n != 0 {
		t.Errorf("the duty renewed a manually renewed share")
	}
}

// TestLiveMonitorSessionTakesUpTheRenewedToken: a run dispatched before a
// renewal holds a monitor session minted from the old token. After the
// renewal, the sync hands the session the new one — what keeps a long run
// working past the token it started with.
func TestLiveMonitorSessionTakesUpTheRenewedToken(t *testing.T) {
	withKubeGuardRequired(t, true)
	srv, b, _ := kubeShareHub(t)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(first)
	sec := mintShareSecret(t, b, cl, first, kubeshare.RenewalHub)
	ctx := context.Background()

	svc := newTestKubeGuardService(t, kubeguard.Policy{})
	prev := kubeGuardSingleton.Load()
	kubeGuardSingleton.Store(svc)
	t.Cleanup(func() { kubeGuardSingleton.Store(prev) })

	// The dispatch: a lease through a broker with the monitor attached.
	b.KubeGuard = kubeGuard{svc: svc}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Namespaces: []string{"team-a"}}, TTL: time.Hour, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	lease, err := b.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test")
	if err != nil || len(lease.Materials) != 1 {
		t.Fatalf("lease = %+v, %v", lease, err)
	}
	sl := &secretLease{broker: b, lease: lease}
	liveLeases.add(sl)
	t.Cleanup(func() { liveLeases.removeIf(sl) })
	sessions := svc.reg.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("%d monitor sessions", len(sessions))
	}
	sess := sessions[0]
	if got := sess.Upstream().BearerToken; got != first {
		t.Fatal("the session does not hold the share's token")
	}

	if n := srv.syncKubeGuardUpstreams(); n != 0 {
		t.Errorf("a sync with nothing renewed updated %d sessions", n)
	}
	if n := srv.renewDueKubeShares(ctx, iat.Add(31*time.Minute)); n != 1 {
		t.Fatalf("renewed %d", n)
	}
	got := sess.Upstream().BearerToken
	if got == first {
		t.Fatal("the live session still presents the replaced token after the renewal")
	}
	stored, err := b.KubeconfigUpstream(lease.ID, sess.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := kubernetes.ParseKubeconfig(stored, sess.ContextName)
	if err != nil {
		t.Fatal(err)
	}
	if rc.BearerToken != got {
		t.Error("the session presents a token other than the one the share now holds")
	}
	// And again changes nothing.
	if n := srv.syncKubeGuardUpstreams(); n != 0 {
		t.Errorf("an idle sync updated %d sessions", n)
	}
}

// TestSecretAuthorizeRoute: what a terminal asks before it touches the
// cluster with its own credentials (Task 20420) — the same answer the DELETE
// and the renewal give.
func TestSecretAuthorizeRoute(t *testing.T) {
	f := newPersonalFixture(t)
	withKubeGuardRequired(t, false)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	tok := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": cl.shareDoc(t, tok),
		"metadata": shareMetadata(kubeshare.RenewalManual), "personal": true,
	})
	if code != http.StatusOK {
		t.Fatalf("mint: %d %s", code, body)
	}
	var sec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &sec)
	plainCode, plainBody := f.postJSON(t, "lead", "/api/secrets", map[string]any{
		"name": "plain-kube", "kind": "kubeconfig", "payload": testKubeconfigPayload, "personal": false,
	})
	if plainCode != http.StatusOK {
		t.Fatalf("mint plain: %d %s", plainCode, plainBody)
	}
	var plain struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(plainBody), &plain)

	ask := func(who, id, action string) int {
		code, _ := getFull(t, f.clients[who], f.base+"/api/secrets/"+id+"/authorize?action="+action)
		return code
	}
	for _, tc := range []struct {
		who, id, action string
		want            int
	}{
		{"alice", sec.ID, "delete", http.StatusOK},
		{"alice", sec.ID, "renew", http.StatusOK},
		{"bob", sec.ID, "delete", http.StatusNotFound},
		{"bob", sec.ID, "renew", http.StatusNotFound},
		// An administrator may delete a colleague's personal share, and may
		// not put a credential into it.
		{"root", sec.ID, "delete", http.StatusOK},
		{"root", sec.ID, "renew", http.StatusForbidden},
		// A shared secret: secret.revoke deletes it, an operator may not.
		{"lead", plain.ID, "delete", http.StatusOK},
		{"alice", plain.ID, "delete", http.StatusForbidden},
		{"lead", plain.ID, "renew", http.StatusBadRequest},
		{"alice", sec.ID, "explode", http.StatusBadRequest},
	} {
		if got := ask(tc.who, tc.id, tc.action); got != tc.want {
			t.Errorf("%s may %s %s: %d, want %d", tc.who, tc.action, tc.id, got, tc.want)
		}
	}
	// Asking deleted nothing.
	if !hasName(f.secretNames(t, "alice"), "aks-dev") {
		t.Fatal("authorizing a delete deleted the secret")
	}
}

// TestRenewalStopsForADeniedOwner: a personal share is its owner's credential,
// and the hub renewing it keeps it alive. Suspended at the identity provider,
// or offboarded with the secret kept under a legal hold, the owner's share is
// not renewed — and the share and the trail say why (Task 20420). Reactivated,
// renewal resumes.
func TestRenewalStopsForADeniedOwner(t *testing.T) {
	withKubeGuardRequired(t, true)
	srv, b, db := kubeShareHub(t)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(first)
	meta, err := prepareKubeShare(shareMetadata(kubeshare.RenewalHub), []byte(cl.shareDoc(t, first)),
		"alice@corp.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{
		Name: "aks-dev", Kind: secretbroker.KindKubeconfig, Payload: []byte(cl.shareDoc(t, first)),
		Metadata: meta, Actor: "alice@corp.example", Owner: "alice@corp.example", Personal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	due := iat.Add(31 * time.Minute)

	deny, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectDeny, Claim: "email",
		Value: "alice@corp.example", Reason: "incident 4711", CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if n := srv.renewDueKubeShares(ctx, due.Add(time.Duration(i)*time.Minute)); n != 0 {
			t.Fatalf("the share of a denied owner was renewed")
		}
	}
	if cl.minted != 0 {
		t.Fatalf("the cluster minted %d tokens for a denied owner's share", cl.minted)
	}
	sh := shareOf(t, b, sec.ID)
	if !sh.Stopped || !strings.Contains(sh.RenewError, "denied on this hub") ||
		!strings.Contains(sh.RenewError, "incident 4711") {
		t.Fatalf("the share does not say why it is not renewed: %+v", sh)
	}
	if n := countRenewRows(t, db, "deny"); n != 1 {
		t.Errorf("%d secret.renew deny rows for three identical refusals, want 1", n)
	}

	// Under a legal hold, the reason says so.
	if err := db.PutLegalHold(statedb.LegalHoldRow{Identity: "alice@corp.example", Reason: "matter 12",
		PlacedAt: time.Now(), PlacedBy: "legal@corp.example"}, nil); err != nil {
		t.Fatal(err)
	}
	srv.renewDueKubeShares(ctx, due.Add(5*time.Minute))
	if sh := shareOf(t, b, sec.ID); !strings.Contains(sh.RenewError, "legal hold") || !strings.Contains(sh.RenewError, "matter 12") {
		t.Errorf("under a legal hold: %q", sh.RenewError)
	}
	if _, err := db.DeleteLegalHold("alice@corp.example", nil); err != nil {
		t.Fatal(err)
	}

	// Reactivated: the deny goes, and the next pass renews.
	if _, err := db.DeleteRoleBinding(deny.ID); err != nil {
		t.Fatal(err)
	}
	if n := srv.renewDueKubeShares(ctx, due.Add(6*time.Minute)); n != 1 {
		t.Fatalf("renewed %d after the owner was reactivated, want 1", n)
	}
	if sh := shareOf(t, b, sec.ID); sh.Stopped || sh.RenewError != "" || sh.Renewals != 1 {
		t.Errorf("after reactivation: %+v", sh)
	}
}

// suspendAtProvider writes what pkg/provision writes for a user it matched on
// preferred_username when no session carried that name: the user inactive,
// and a deny on the username alone — a claim no owner key can match.
func suspendAtProvider(t *testing.T, db *statedb.DB, local, email string, at time.Time) {
	t.Helper()
	const reason = "deactivated at the identity provider (scim:okta)"
	if _, err := db.WriteSCIMUser(statedb.SCIMUserWrite{Create: true, At: at,
		Row: statedb.SCIMUserRow{ID: "u-" + local, UserName: local + "-okta", Email: email, UpdatedBy: "scim:okta"},
		Suspend: &statedb.SCIMSuspendWrite{
			Denies: []statedb.RoleBindingRow{{Effect: statedb.RoleEffectDeny, Claim: "username",
				Value: local + "-okta", Reason: reason, CreatedBy: "scim:okta"}},
			Record: statedb.SCIMSuspensionRecord{By: "scim:okta", Reason: reason},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRenewalStopsForAnOwnerTheIdentityProviderDeactivated: a suspension that
// resolved neither an email nor a subject denies only a username, which no
// owner key matches. The directory still says who was deactivated: the hub
// stops renewing their share, refuses a token pushed for it — telling the
// terminal before it mints one — and resumes once they are reactivated.
func TestRenewalStopsForAnOwnerTheIdentityProviderDeactivated(t *testing.T) {
	f := newPersonalFixture(t)
	withKubeGuardRequired(t, true)
	cl := newFakeCluster(t, "cloop-shares", "cloop-aks-dev-3f9c2a1b")
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", iat, iat.Add(time.Hour))
	cl.accept(first)
	code, body := f.postJSON(t, "alice", "/api/secrets", map[string]any{
		"name": "aks-dev", "kind": "kubeconfig", "payload": cl.shareDoc(t, first), "metadata": shareMetadata(kubeshare.RenewalHub),
	})
	if code != http.StatusOK {
		t.Fatalf("mint: %d %s", code, body)
	}
	var sec struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &sec)
	bs, err := f.srv.openBrokers()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bs.close)
	ctx := context.Background()
	due := iat.Add(31 * time.Minute)

	suspendAtProvider(t, bs.db, "alice", "alice@corp.example", time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	if n := f.srv.renewDueKubeShares(ctx, due); n != 0 {
		t.Fatal("the share of an owner the identity provider deactivated was renewed")
	}
	if cl.minted != 0 {
		t.Fatalf("the cluster minted %d tokens for a deactivated owner's share", cl.minted)
	}
	if sh := shareOf(t, bs.secret, sec.ID); !sh.Stopped || !strings.Contains(sh.RenewError, "suspended") ||
		!strings.Contains(sh.RenewError, "2026-10-01") {
		t.Fatalf("the share does not say why it is not renewed: %+v", sh)
	}

	// Nor does a token from the owner's terminal keep it alive.
	code, body = getFull(t, f.clients["alice"], f.base+"/api/secrets/"+sec.ID+"/authorize?action=renew")
	if code != http.StatusConflict || !strings.Contains(body, "suspended") {
		t.Errorf("the terminal was not told before minting: %d %s", code, body)
	}
	pushed := saToken("cloop-shares", "cloop-aks-dev-3f9c2a1b", time.Now(), time.Now().Add(2*time.Hour))
	cl.accept(pushed)
	cl.mu.Lock()
	before := cl.hits
	cl.mu.Unlock()
	code, body = f.postJSON(t, "alice", "/api/secrets/"+sec.ID+"/renew", map[string]any{
		"token": pushed, "server": cl.srv.URL, "ca_sha256": kubeshare.CAFingerprint(cl.caPEM())})
	if code != http.StatusConflict || !strings.Contains(body, "suspended") {
		t.Errorf("a pushed token renewed a deactivated owner's share: %d %s", code, body)
	}
	cl.mu.Lock()
	after := cl.hits
	cl.mu.Unlock()
	if after != before {
		t.Error("the refused token was sent to the cluster")
	}

	// Reactivated, as the provider's PATCH active:true does: renewed again.
	if _, err := bs.db.WriteSCIMUser(statedb.SCIMUserWrite{ExpectVersion: 1, Lift: true,
		Row: statedb.SCIMUserRow{ID: "u-alice", UserName: "alice-okta", Email: "alice@corp.example", Active: true,
			UpdatedBy: "scim:okta"}}); err != nil {
		t.Fatal(err)
	}
	if n := f.srv.renewDueKubeShares(ctx, due.Add(time.Minute)); n != 1 {
		t.Fatalf("renewed %d after the owner was reactivated, want 1", n)
	}
	if sh := shareOf(t, bs.secret, sec.ID); sh.Stopped || sh.RenewError != "" {
		t.Errorf("after reactivation: %+v", sh)
	}
}
