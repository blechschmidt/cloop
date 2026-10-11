package container

// The hub's own CA in a real container (Task 20409): a git proxy serving a
// certificate the hub issued itself (tls: auto) in front of a forge, and a
// sandbox image that carries no CA of any kind. The driver binds the CA in and
// names it with http.<proxy URL>.sslCAInfo, so the workload's git clones and
// pushes through the proxy — and the same git refuses a second https server
// whose certificate the very same CA signed, because the trust is scoped to the
// proxy's URL and nothing else.
//
// Opt-in, because it builds an image: CLOOP_GITCA_CONTAINER_E2E=1. The image is
// the refresh e2e's: the pinned Alpine base plus git, and nothing of the hub's.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/secretstore"
)

// gitCAScript runs in the sandbox. $PROXY is the proxy's base, $OTHER the
// second server's, $CRED the session's user:token.
const gitCAScript = `set -u
cd /tmp
echo "CAINFO=${GIT_SSL_CAINFO:-unset}"
# The image alone does not trust the hub's CA: with the per-URL setting
# stripped, the proxy's certificate is refused.
if env -u GIT_CONFIG_COUNT git ls-remote "https://$CRED@${PROXY#https://}/acme/tool" >/tmp/bare.out 2>&1; then
  echo IMAGE_TRUSTS_PROXY
else
  grep -qi certificate /tmp/bare.out && echo IMAGE_REFUSES_PROXY
fi
git clone -q "https://$CRED@${PROXY#https://}/acme/tool" repo && echo CLONED
cd repo
echo "from the sandbox" > ca-e2e.txt && git add ca-e2e.txt
git -c user.email=s@cloop.invalid -c user.name=sandbox commit -qm "through the hub CA"
git push -q origin HEAD:refs/heads/cloop/ca-e2e && echo PUSHED
cd /tmp
# Another https server, its certificate from the same CA: not the proxy's URL,
# so not trusted.
if git ls-remote "https://${OTHER#https://}/acme/tool" >/tmp/other.out 2>&1; then
  echo OTHER_TRUSTED
else
  grep -qi certificate /tmp/other.out && echo OTHER_REFUSED
  cat /tmp/other.out
fi
# The control: the same request with the CA trusted globally gets past TLS,
# so the refusal above was the scoping and nothing else.
git -c http.sslCAInfo=/etc/cloop/hub-ca/ca.crt ls-remote "https://${OTHER#https://}/acme/tool" >/tmp/ctl.out 2>&1
grep -qi certificate /tmp/ctl.out || echo CONTROL_PAST_TLS
`

func TestContainerGitTrustsTheHubCAForTheProxyOnly(t *testing.T) {
	if os.Getenv("CLOOP_GITCA_CONTAINER_E2E") != "1" {
		t.Skip("set CLOOP_GITCA_CONTAINER_E2E=1 to run the hub-CA container e2e (it builds an image)")
	}
	docker, err := DetectRuntime("docker")
	if err != nil {
		t.Skipf("docker is unavailable: %v", err)
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, ierr := runCLI(ctx, docker, nil, "info")
		cancel()
		if ierr != nil || res.ExitCode != 0 {
			t.Skip("docker is installed but not responding")
		}
	}
	gateway := dockerBridgeGateway(t)
	image := buildRefreshImage(t)

	// The forge, honouring one broad PAT the proxy holds.
	const pat = "ghp_the_forge_token_that_stays_on_the_hub_000000"
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(pat, "acme/tool")
	forge := secretbrokertest.NewForge(t, gh, "acme/tool")

	// The hub CA, and two leaves from it for the bridge gateway: the proxy's
	// and the second server's (the Kubernetes monitor's, as it would be).
	t.Setenv(secretbroker.EnvPassphraseKey, "")
	db := statedbtest.Open(t)
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase("gitca-e2e-passphrase"))
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
	proxyCert, err := hubca.NewServer(hubca.ServerConfig{Monitor: hubca.GitProxy, Store: store, Sealer: kr,
		Authority: ca, Want: []string{gateway}})
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := hubca.NewServer(hubca.ServerConfig{Monitor: hubca.KubeGuard, Store: store, Sealer: kr,
		Authority: ca, Want: []string{gateway}})
	if err != nil {
		t.Fatal(err)
	}

	// The proxy, on the gateway where the container reaches the host.
	ln, err := net.Listen("tcp", gateway+":0")
	if err != nil {
		t.Fatalf("listen on the bridge gateway: %v", err)
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
	tlsCfg, err := proxyCert.TLSConfig("1.2")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = px.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = px.Close() })

	// The second server: the same CA, another port, any handler at all.
	otherLn, err := net.Listen("tcp", gateway+":0")
	if err != nil {
		t.Fatal(err)
	}
	otherTLS, err := otherCert.TLSConfig("1.2")
	if err != nil {
		t.Fatal(err)
	}
	other := serveTLSOn(t, otherLn, otherTLS)

	minted, err := reg.Mint(gitproxy.MintRequest{
		Upstream:   forge.RepoURL("acme/tool"),
		Credential: gitproxy.Credential{Username: "x-access-token", Password: pat},
		// The hub's own policy: fetch, and push into cloop/** only.
		Policy: gitproxy.Policy{AllowedRefs: []string{gitproxy.DefaultAllowedRef},
			AllowCreate: true, AllowUpdate: true, AllowFetch: true},
		TTL:   10 * time.Minute,
		Actor: "e2e",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	ex, err := New(Options{ID: "test-container", Image: image, Runtime: "docker", Network: NetworkBridge, AllowRootUser: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, id := range ex.Handles() {
			_ = ex.Signal(cctx, id, executor.SignalKill)
		}
		_, _ = ex.ReapOrphans(cctx)
	})
	caURL, err := executor.NormalizeGitCAURL(base)
	if err != nil {
		t.Fatal(err)
	}
	spec := executor.Spec{
		WorkDir: t.TempDir(),
		Argv:    []string{"/bin/sh", "-c", gitCAScript},
		Env: []string{"HOME=/tmp", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0", "PROXY=" + base, "OTHER=" + other,
			"CRED=" + minted.Session.ID + ":" + minted.Token},
		GitCA: &executor.GitCA{URLs: []string{caURL}, PEM: ca.CertPEM()},
	}
	res, err := executor.Run(context.Background(), ex, spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := string(res.Output)
	for _, want := range []string{"CAINFO=unset", "IMAGE_REFUSES_PROXY", "CLONED", "PUSHED", "OTHER_REFUSED", "CONTROL_PAST_TLS"} {
		if !strings.Contains(out, want) {
			t.Errorf("sandbox did not report %s:\n%s", want, out)
		}
	}
	for _, bad := range []string{"IMAGE_TRUSTS_PROXY", "OTHER_TRUSTED", pat} {
		if strings.Contains(out, bad) {
			t.Errorf("sandbox output carries %q:\n%s", bad, out)
		}
	}
	if forge.Ref(t, "acme/tool", "refs/heads/cloop/ca-e2e") == "" {
		t.Fatal("the push through the proxy did not reach the forge")
	}
}

// serveTLSOn answers anything on ln over TLS and returns its https base.
func serveTLSOn(t *testing.T, ln net.Listener, cfg *tls.Config) string {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not a forge")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}
