package remote_test

// The hub's own CA on a device (Task 20409), through a real hub, a real agent
// and a real git: a git proxy serving a certificate the hub issued itself
// (tls: auto) fronts a forge; the hub dispatches a workload whose workspace is
// fetched through it. The agent's provisioning fetch trusts the CA the start
// frame carried, the payload's own git pushes through the proxy with it — and
// refuses a second https server whose certificate the same CA signed, because
// the trust is the proxy's URL's and nothing else's.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/secretstore"
)

// proxySource mints a pinned proxy session for every workspace, the way
// gitproxycreds does on a hub with the proxy on.
type proxySource struct {
	reg      *gitproxy.Registry
	upstream string
	pat      string
	minted   chan *gitproxy.Minted
}

func (s *proxySource) ForWorkspace(_ context.Context, _ string, _ executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	m, err := s.reg.Mint(gitproxy.MintRequest{
		Upstream:   s.upstream,
		Credential: gitproxy.Credential{Username: "x-access-token", Password: s.pat},
		Policy: gitproxy.Policy{AllowedRefs: []string{gitproxy.DefaultAllowedRef},
			AllowCreate: true, AllowUpdate: true, AllowFetch: true},
		TTL: 10 * time.Minute, Actor: "e2e",
	})
	if err != nil {
		return executor.WorkspaceAccess{}, func() {}, err
	}
	s.minted <- m
	return executor.WorkspaceAccess{
		Credential: executor.GitCredential{Username: m.Session.ID, Password: m.Token, SessionID: m.Session.ID},
		Repo:       m.RepoURL,
	}, func() {}, nil
}

const deviceCAScript = `set -u
echo "CAINFO=${GIT_SSL_CAINFO:-unset}"
git log --oneline -1 >/dev/null && echo PROVISIONED
git remote get-url origin | grep -q '@' && echo ORIGIN_HOLDS_A_CREDENTIAL
echo "from the device" > device-ca.txt && git add device-ca.txt
git -c user.email=d@cloop.invalid -c user.name=device commit -qm "through the hub CA"
git push -q "https://$CRED@${PROXY#https://}/acme/tool" HEAD:refs/heads/cloop/device-ca && echo PUSHED
if git ls-remote "https://${OTHER#https://}/acme/tool" >/tmp/other-$$.out 2>&1; then
  echo OTHER_TRUSTED
else
  grep -qi certificate /tmp/other-$$.out && echo OTHER_REFUSED
fi
rm -f /tmp/other-$$.out
`

func TestLoopbackDeviceTrustsTheHubCAForTheProxyOnly(t *testing.T) {
	secretbrokertest.GitTools(t)
	const pat = "ghp_device_e2e_forge_token_00000000000000000000"
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(pat, "acme/tool")
	forge := secretbrokertest.NewForge(t, gh, "acme/tool")

	// The hub CA and two leaves from it for 127.0.0.1: the proxy's, and a
	// second server's.
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	db := statedbtest.Open(t)
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase("device-ca-e2e"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := hubca.OpenAuthority(store, kr, hubca.Options{Actor: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	leafFor := func(m hubca.Monitor) *tls.Config {
		srv, err := hubca.NewServer(hubca.ServerConfig{Monitor: m, Store: store, Sealer: kr, Authority: ca,
			Want: []string{"127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := srv.TLSConfig("1.2")
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "https://" + ln.Addr().String()
	reg, err := gitproxy.NewRegistry(base)
	if err != nil {
		t.Fatal(err)
	}
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: forge.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = px.Serve(tls.NewListener(ln, leafFor(hubca.GitProxy))) }()
	t.Cleanup(func() { _ = px.Close() })

	otherLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	otherSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not a forge")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = otherSrv.Serve(tls.NewListener(otherLn, leafFor(hubca.KubeGuard))) }()
	t.Cleanup(func() { _ = otherSrv.Close() })
	other := "https://" + otherLn.Addr().String()

	// A hub whose devices' workspaces are routed through the proxy.
	src := &proxySource{reg: reg, upstream: forge.RepoURL("acme/tool"), pat: pat, minted: make(chan *gitproxy.Minted, 1)}
	memStore := newMemStore()
	registry := executor.NewRegistry()
	logf := detachableLogf(t)
	hub, err := remote.NewHub(remote.HubOptions{
		Store: memStore, Registry: registry,
		WorkspaceSource: func(string) executor.WorkspaceCredentialSource { return src },
		Logf:            func(format string, args ...any) { logf("hub: "+format, args...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	t.Cleanup(hs.Close)
	root := filepath.Join(t.TempDir(), "work")
	token, _, err := remote.Mint(memStore, remote.MintOptions{Name: "edge-ca", TTL: 5 * time.Minute, WorkDirRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{
		Server: "ws" + strings.TrimPrefix(hs.URL, "http"), Token: token,
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"), WorkDirRoot: root,
		Logf: func(format string, args ...any) { logf("agent: "+format, args...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() { defer close(done); _ = a.Run(ctx) }()
	var ex *remote.Executor
	waitFor(t, 15*time.Second, func() bool {
		for _, e := range hub.Executors() {
			if e.Connected() {
				ex = e
				return true
			}
		}
		return false
	}, "the agent should dial in")

	caURL, err := executor.NormalizeGitCAURL(base)
	if err != nil {
		t.Fatal(err)
	}
	spec := executor.Spec{
		WorkDir: "device-ca",
		Argv:    []string{"/bin/sh", "-c", deviceCAScript},
		Workspace: executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/acme/tool.git",
			Ref: "main", CredentialGrant: "grant-1"},
		GitCA: &executor.GitCA{URLs: []string{caURL}, PEM: ca.CertPEM()},
	}
	// The push's credential: the session the workspace was fetched with, as the
	// lease's helper would supply one. Set once minted, through the env the
	// payload inherits — appended before dispatch so the agent sees it.
	runCtx, runCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer runCancel()
	type result struct {
		res executor.RunResult
		err error
	}
	results := make(chan result, 1)
	go func() {
		// Host mode with an explicit environment: PATH, HOME and the payload's
		// own variables. The session credential cannot be known before the
		// mint, so the payload reads it from a file the test writes below.
		spec.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "PROXY=" + base, "OTHER=" + other,
			"GIT_TERMINAL_PROMPT=0", "CRED_FILE=" + filepath.Join(root, "cred")}
		spec.Argv = []string{"/bin/sh", "-c", `i=0; while [ ! -s "$CRED_FILE" ]; do i=$((i+1)); [ $i -gt 300 ] && exit 9; sleep 0.1; done
CRED=$(cat "$CRED_FILE"); export CRED
` + deviceCAScript}
		r, err := executor.Run(runCtx, ex, spec)
		results <- result{r, err}
	}()
	var m *gitproxy.Minted
	select {
	case m = <-src.minted:
	case <-time.After(30 * time.Second):
		t.Fatal("the hub never asked for a workspace credential")
	}
	writeCred(t, filepath.Join(root, "cred"), m.Session.ID+":"+m.Token)
	r := <-results
	out := string(r.res.Output)
	if r.err != nil {
		t.Fatalf("run: %v\n%s", r.err, out)
	}
	for _, want := range []string{"CAINFO=unset", "PROVISIONED", "PUSHED", "OTHER_REFUSED"} {
		if !strings.Contains(out, want) {
			t.Errorf("device did not report %s:\n%s", want, out)
		}
	}
	for _, bad := range []string{"OTHER_TRUSTED", "ORIGIN_HOLDS_A_CREDENTIAL", pat} {
		if strings.Contains(out, bad) {
			t.Errorf("device output carries %q:\n%s", bad, out)
		}
	}
	if forge.Ref(t, "acme/tool", "refs/heads/cloop/device-ca") == "" {
		t.Fatal("the device's push through the proxy did not reach the forge")
	}
}

func writeCred(t *testing.T, path, value string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}
