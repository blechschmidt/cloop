package hubdoctor

// The doctor's half of tls: auto (Task 20409): a monitor whose certificate the
// hub issues is judged by the CA and the leaf in the control-plane database,
// and a strict hub without a git proxy is told which GitHub grants it hands
// into sandboxes. And `--smoke` on a hub `cloop hub bootstrap` just wrote, with
// both monitors on, passes.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

const monitorTLSPassphrase = "hubdoctor-monitor-tls-passphrase"

// bootstrapGoldenPath is the config `cloop hub bootstrap` writes, resolved
// while the working directory is still this package's.
var bootstrapGoldenPath = func() string {
	p := filepath.Join("..", "..", "cmd", "testdata", "hub_bootstrap.golden.yaml")
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}()

func autoTLSConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Executors.GitProxy = config.GitProxyConfig{Enabled: true, TLS: config.MonitorTLSAuto,
		ListenAddr: "0.0.0.0:8443", AdvertiseURL: "https://hub.example.com:8443"}
	return cfg
}

// issueLeaf mints the hub CA in dir's database and issues the git proxy's leaf
// for names, as of at.
func issueLeaf(t *testing.T, dir string, at time.Time, names ...string) {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase(monitorTLSPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	opts := hubca.Options{Now: func() time.Time { return at }, Actor: "test"}
	ca, err := hubca.OpenAuthority(store, kr, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.NewServer(hubca.ServerConfig{Monitor: hubca.GitProxy, Store: store, Sealer: kr,
		Authority: ca, Want: names, Options: opts}); err != nil {
		t.Fatal(err)
	}
}

func onlyFinding(t *testing.T, got map[string][]Finding, check string) Finding {
	t.Helper()
	fs := got[check]
	if len(fs) != 1 {
		t.Fatalf("%s: %d findings, want 1: %+v", check, len(fs), fs)
	}
	return fs[0]
}

func TestAutoTLSBeforeTheHubFirstStartsPasses(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	got := findingsFor(t, t.TempDir(), autoTLSConfig(), Options{Offline: true})
	f := onlyFinding(t, got, "gitproxy.tls")
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "first time it starts") {
		t.Fatalf("gitproxy.tls = %+v", f)
	}
	if e := onlyFinding(t, got, "gitproxy.enabled"); e.Severity != SeverityPass {
		t.Errorf("gitproxy.enabled = %+v", e)
	}
}

func TestAutoTLSWithoutASealingKeyFails(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	got := findingsFor(t, t.TempDir(), autoTLSConfig(), Options{Offline: true})
	f := onlyFinding(t, got, "gitproxy.tls")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, secretbroker.EnvPassphraseKey) {
		t.Fatalf("gitproxy.tls = %+v", f)
	}
	if len(got["gitproxy.enabled"]) != 0 {
		t.Errorf("a proxy that will not start was also reported enabled: %+v", got["gitproxy.enabled"])
	}
}

func TestAutoTLSHealthyLeafPasses(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	issueLeaf(t, dir, time.Now(), "hub.example.com")
	f := onlyFinding(t, findingsFor(t, dir, autoTLSConfig(), Options{Offline: true}), "gitproxy.tls")
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "valid until") {
		t.Fatalf("gitproxy.tls = %+v", f)
	}
}

// TestAutoTLSLeafNearExpiryFails: the leader renews with two days left, so a
// leaf with less than one has outlived its renewal.
func TestAutoTLSLeafNearExpiryFails(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	issueLeaf(t, dir, time.Now().Add(-(hubca.LeafLifetime - 20*time.Hour)), "hub.example.com")
	f := onlyFinding(t, findingsFor(t, dir, autoTLSConfig(), Options{Offline: true}), "gitproxy.tls")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "renewal has stopped") {
		t.Fatalf("gitproxy.tls = %+v", f)
	}
}

// TestAutoTLSLeafMissingTheAdvertisedNameFails: a leaf for another name is one
// every sandbox's TLS check refuses.
func TestAutoTLSLeafMissingTheAdvertisedNameFails(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	issueLeaf(t, dir, time.Now(), "old-name.example.com")
	f := onlyFinding(t, findingsFor(t, dir, autoTLSConfig(), Options{Offline: true}), "gitproxy.tls")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "hub.example.com") ||
		!strings.Contains(f.Message, "old-name.example.com") {
		t.Fatalf("gitproxy.tls = %+v", f)
	}
}

// TestForgeCredentialsAreNamedOnAStrictHub: with host execution off and no
// proxy, every active GitHub grant is delivered into a sandbox as the token
// itself, and the doctor says which.
func TestForgeCredentialsAreNamedOnAStrictHub(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := secretbroker.New(store)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "deploy-pat",
		Kind: secretbroker.KindGitHubPAT, Payload: []byte("ghp_" + strings.Repeat("a", 36)), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/app"}}, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	strict := &config.Config{}
	off := false
	strict.Executors.AllowHostProcess = &off
	f := onlyFinding(t, findingsFor(t, dir, strict, Options{Offline: true}), "gitproxy.forge_credentials")
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "deploy-pat (github_pat) to project:/srv/app") {
		t.Fatalf("gitproxy.forge_credentials = %+v", f)
	}

	withProxy := autoTLSConfig()
	withProxy.Executors.AllowHostProcess = &off
	if got := findingsFor(t, dir, withProxy, Options{Offline: true}); len(got["gitproxy.forge_credentials"]) != 0 {
		t.Errorf("a hub running the proxy was told its grants reach sandboxes: %+v", got["gitproxy.forge_credentials"])
	}
	if got := findingsFor(t, dir, &config.Config{}, Options{Offline: true}); len(got["gitproxy.forge_credentials"]) != 0 {
		t.Errorf("a permissive hub got the strict-hub finding: %+v", got["gitproxy.forge_credentials"])
	}
}

// TestSmokePassesOnAFreshlyBootstrappedHub runs the whole doctor, --smoke
// included, against the config `cloop hub bootstrap` writes — read from the
// golden copy cmd's TestHubBootstrap_Golden keeps identical to the template —
// with its TLS pair generated the way `cloop hub tls-init` would. Both
// credential monitors are on, nothing has started yet, and the verdict must
// still be clean: no failure, and a smoke that carried a workload.
func TestSmokePassesOnAFreshlyBootstrappedHub(t *testing.T) {
	golden, err := os.ReadFile(bootstrapGoldenPath)
	if err != nil {
		t.Fatalf("read the bootstrap golden config: %v", err)
	}
	w := newSmokeWorld(t)
	cert, key := filepath.Join(w.dir, ".cloop", "tls", "cert.pem"), filepath.Join(w.dir, ".cloop", "tls", "key.pem")
	if err := os.MkdirAll(filepath.Dir(cert), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{
		Hosts: []string{"hub.example.com"}, ValidFor: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReplacer("/etc/cloop/tls/cert.pem", cert, "/etc/cloop/tls/key.pem", key).Replace(string(golden))
	if err := os.WriteFile(config.ConfigPath(w.dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(w.dir)
	if err != nil {
		t.Fatalf("load the bootstrapped config: %v", err)
	}
	if !cfg.Executors.GitProxy.AutoTLS() || !cfg.Executors.KubeGuard.AutoTLS() {
		t.Fatal("premise: bootstrap turns both monitors on with tls: auto")
	}
	// What hub.env holds: a dashboard token beside the sealing key the smoke
	// world set.
	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOOP_UI_TOKEN", base64.RawURLEncoding.EncodeToString(tok[:]))

	rep := Run(context.Background(), w.dir, cfg, Options{
		Smoke: true, SmokeLeaseDir: w.leaseDir, SmokeTimeout: 20 * time.Second, Timeout: 2 * time.Second,
		GlobalBudget: func() (globalbudget.GlobalBudgetConfig, error) { return globalbudget.GlobalBudgetConfig{}, nil },
	})
	for _, f := range rep.Findings {
		if f.Severity == SeverityFail {
			t.Errorf("FAIL %s: %s", f.Check, f.Message)
		}
	}
	if code := rep.SmokeExitCode(); code != SmokeExitOK {
		t.Fatalf("doctor --smoke exit code %d on a freshly bootstrapped hub", code)
	}
	if len(rep.Smoke) != 1 || !rep.Smoke[0].OK() {
		t.Fatalf("smoke result: %+v", rep.Smoke)
	}
}

// TestSmokeKeepsARealKubeconfigOutOfItsSandbox: the smoke leases its own
// throwaway credential and withholds every other grant aimed at its executor
// (Task 20413). A real kubeconfig among them never reaches the smoke sandbox —
// not on a hub whose kube_guard keeps cluster credentials in a monitor this
// process does not run, and not on one without — and the run still proves the
// circuit with the throwaway.
//
// Before Task 20413 the smoke refused the operator's kubeconfig through a
// stand-in guard on a kube_guard hub only, and on any other delivered it beside
// the throwaway at the same path, which refused the dispatch.
func TestSmokeKeepsARealKubeconfigOutOfItsSandbox(t *testing.T) {
	for _, guarded := range []bool{true, false} {
		t.Run(map[bool]string{true: "kube_guard on", false: "kube_guard off"}[guarded], func(t *testing.T) {
			w := newSmokeWorld(t)
			if guarded {
				if err := os.WriteFile(config.ConfigPath(w.dir), []byte("executors:\n  kube_guard:\n    enabled: true\n"+
					"    tls: auto\n    listen_addr: 0.0.0.0:8444\n    advertise_url: https://hub.example.com:8444\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The throwaway alone: the stage passes.
			if res := w.only(t, w.run(t, Options{})); !res.OK() {
				t.Fatalf("smoke with only its own kubeconfig: %+v", res)
			}

			db, err := statedb.Open(state.DBPath(w.dir))
			if err != nil {
				t.Fatal(err)
			}
			store, err := secretstore.New(db)
			if err != nil {
				t.Fatal(err)
			}
			b, err := secretbroker.New(store)
			if err != nil {
				t.Fatal(err)
			}
			const realToken = "real-cluster-token-that-must-stay-in-the-monitor"
			sec, err := b.Mint(context.Background(), secretbroker.MintRequest{Name: "prod-cluster",
				Kind: secretbroker.KindKubeconfig, Actor: "test", Payload: []byte(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://10.0.0.1:6443
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
users:
- name: prod
  user:
    token: ` + realToken + `
`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
				Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: w.ex.ID()},
				Constraints: secretbroker.Constraints{Contexts: []string{"prod"}}, Actor: "test"}); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()

			before := len(w.ex.specs)
			res := w.only(t, w.run(t, Options{}))
			if !res.OK() {
				t.Fatalf("smoke beside a withheld kubeconfig: %+v", res)
			}
			w.ex.mu.Lock()
			specs := append([]executor.Spec(nil), w.ex.specs...)
			w.ex.mu.Unlock()
			if len(specs) <= before {
				t.Fatal("the smoke dispatched nothing, so the assertion below would be vacuous")
			}
			for _, spec := range specs {
				for _, f := range spec.SecretFiles {
					if strings.Contains(string(f.Content), realToken) {
						t.Fatal("the real cluster token reached the smoke sandbox")
					}
				}
				for _, kv := range spec.Env {
					if strings.Contains(kv, realToken) || strings.HasPrefix(kv, secretbroker.KubeContextsEnvKey+"=") {
						t.Fatalf("the operator's kubeconfig reached the smoke workload's environment: %s", kv)
					}
				}
			}
		})
	}
}
