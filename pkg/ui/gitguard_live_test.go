package ui

// Live proof that a project's branch restriction holds against GitHub
// (Task 20340).
//
// Everything else about the feature is tested against fakes: the proxy against
// git-http-backend, the broker against a fake GitHub, the panel against a real
// browser. This drives the whole path a sandbox takes, with nothing standing in:
// a GitHub App grant assigned through the panel's endpoint, a lease issued the
// way a dispatch issues one, the lease materialised into a directory, and the
// real git binary — configured only by what that directory holds — pushing to a
// real repository through the hub's git proxy. The branch outside the grant is
// refused by the proxy, the one inside lands on GitHub, and the installation
// token never appears in anything the sandbox could read.
//
// It pushes a scratch branch and deletes it again, so it runs only when pointed
// at a repository that may receive one:
//
//	CLOOP_GITHUB_APP_ID=…  CLOOP_GITHUB_APP_KEY=/path/to/app.pem \
//	CLOOP_GITHUB_TEST_REPO=owner/name  go test -run TestLiveBranch ./pkg/ui/

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestLiveBranchRestrictionThroughTheGitProxy(t *testing.T) {
	appID := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_ID"))
	keyPath := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_APP_KEY"))
	repo := strings.TrimSpace(os.Getenv("CLOOP_GITHUB_TEST_REPO"))
	if appID == "" || keyPath == "" || repo == "" {
		t.Skip("set CLOOP_GITHUB_APP_ID, CLOOP_GITHUB_APP_KEY and CLOOP_GITHUB_TEST_REPO " +
			"(a repository the App may push a scratch branch to) to run the live flow")
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	t.Setenv("CLOOP_SECRET_KEY", "live-branch-restriction-passphrase")

	dir := t.TempDir()
	if _, err := state.Init(dir, "live branch restriction", 10); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	// The server first: its boot runs the hub's once-per-process proxy setup,
	// which on a config with no git_proxy section installs "no proxy" — and
	// would overwrite one installed before it.
	ts := newTestServer(t, dir, nil)

	// The hub's git proxy, started by the same function `cloop ui` starts it
	// with, on loopback with a certificate the test's git is told to trust.
	certFile, keyFile := writeLoopbackCert(t, t.TempDir())
	cfg := &config.Config{}
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, ListenAddr: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile,
	}
	svc, err := startGitProxy(cfg, dir)
	if err != nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	prevSvc, prevReq := gitProxySingleton.Load(), gitProxyRequired.Load()
	gitProxySingleton.Store(svc)
	gitProxyRequired.Store(true)
	t.Cleanup(func() {
		svc.Close()
		gitProxySingleton.Store(prevSvc)
		gitProxyRequired.Store(prevReq)
	})

	// Connect the App to the installation that covers the test repository.
	var discovered struct {
		Installations []installationView `json:"installations"`
	}
	postJSON(t, ts, "/api/github-app/installations",
		map[string]any{"app_id": appID, "private_key": string(keyPEM)}, &discovered)
	owner, _, _ := strings.Cut(repo, "/")
	var inst *installationView
	for i := range discovered.Installations {
		if strings.EqualFold(discovered.Installations[i].Account, owner) {
			inst = &discovered.Installations[i]
		}
	}
	if inst == nil {
		t.Fatalf("the App is not installed on %s (installations: %+v)", owner, discovered.Installations)
	}
	payload, _ := json.Marshal(map[string]any{
		"app_id": json.RawMessage(appID), "installation_id": inst.ID, "private_key": string(keyPEM),
	})
	var created struct {
		ID string `json:"id"`
	}
	postJSON(t, ts, "/api/secrets", map[string]any{
		"name": "live-app", "kind": "github_app", "payload": string(payload), "personal": false,
	}, &created)

	// Assign the repository through the panel's endpoint, write access limited
	// to one branch namespace — narrower than the hub's own refs/heads/cloop/**.
	var assigned projectRepoAssignment
	postJSON(t, ts, "/api/projects/0/repositories", map[string]any{
		"secret": created.ID, "repos": []string{repo}, "access": "write",
		"branches": []string{"cloop/live-*"},
	}, &assigned)
	if assigned.BranchEnforcement != branchesByProxy {
		t.Fatalf("branch_enforcement = %q with the proxy running, want %q",
			assigned.BranchEnforcement, branchesByProxy)
	}

	// Lease the way a dispatch does and materialise it into the "sandbox".
	broker, closeDB, err := openUIBroker(dir)
	if err != nil {
		t.Fatalf("openUIBroker: %v", err)
	}
	defer closeDB()
	lease, err := broker.LeaseFor(context.Background(),
		secretbroker.Requester{ExecutorID: "local", ProjectID: dir}, "live-test")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	defer broker.Release(lease.ID)
	defer closeGuardedSessions(lease)

	var mat *secretbroker.Material
	for i := range lease.Materials {
		if lease.Materials[i].Kind == secretbroker.KindGitHubApp {
			mat = &lease.Materials[i]
		}
	}
	if mat == nil {
		t.Fatalf("the lease carries no github_app material (%d materials)", len(lease.Materials))
	}
	installationToken, ok := mat.GitHubToken()
	if !ok || installationToken == "" {
		t.Fatal("the hub holds no installation token for the proxy to push with")
	}
	if got := mat.Env[secretbroker.GitHubPushBranchesEnvKey]; got != "cloop/live-*" {
		t.Errorf("%s = %q; the workload is not told where it may push",
			secretbroker.GitHubPushBranchesEnvKey, got)
	}
	t.Logf("lease material: %s", mat.Summary)

	sandbox := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sandbox, "lease"), 0o700); err != nil {
		t.Fatal(err)
	}
	mount, err := lease.Materialize(filepath.Join(sandbox, "lease"))
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mount.Close()
	assertNoTokenUnder(t, filepath.Join(sandbox, "lease"), installationToken)

	home := filepath.Join(sandbox, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append([]string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_SSL_CAINFO=" + certFile,
		"LC_ALL=C",
	}, mount.Env()...)
	git := func(dir string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, gitBin, args...)
		cmd.Dir = dir
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}

	// The workload clones by the plain GitHub URL; the lease's gitconfig is what
	// sends it to the proxy.
	clone := filepath.Join(sandbox, "work")
	if out, err := git(sandbox, "clone", "https://github.com/"+repo, clone); err != nil {
		t.Fatalf("clone through the proxy: %v\n%s", err, out)
	}
	mainBefore := remoteRef(t, git, clone, "refs/heads/main")
	if mainBefore == "" {
		t.Fatalf("%s has no main branch to protect", repo)
	}

	stamp := time.Now().UTC().Format("20060102-150405") + "-" + randHex(t, 3)
	if err := os.WriteFile(filepath.Join(clone, "t20340-"+stamp+".txt"),
		[]byte("pushed by TestLiveBranchRestrictionThroughTheGitProxy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "."},
		{"-c", "user.email=cloop@example.invalid", "-c", "user.name=cloop live test",
			"commit", "--no-gpg-sign", "-m", "Task 20340 live check " + stamp},
	} {
		if out, err := git(clone, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// main: the push that started the task. Outside the hub's own namespace as
	// well as the grant's, so the hub's list is the one that refuses it.
	out, err := git(clone, "push", "origin", "HEAD:refs/heads/main")
	if err == nil {
		t.Fatalf("push to main succeeded through a grant limited to cloop/live-*\n%s", out)
	}
	if !strings.Contains(out, "refs/heads/main") || !strings.Contains(out, "rejected") {
		t.Errorf("the refusal of main is not reported as a policy refusal:\n%s", out)
	}
	if after := remoteRef(t, git, clone, "refs/heads/main"); after != mainBefore {
		t.Fatalf("main moved from %s to %s despite the refusal", mainBefore, after)
	}

	// Inside the hub's namespace but outside the grant's: refused by the
	// grant's list, and the refusal says so, since that is the list to change.
	other := "cloop/other-" + stamp
	out, err = git(clone, "push", "origin", "HEAD:refs/heads/"+other)
	if err == nil {
		t.Fatalf("push to %s succeeded; the grant allows cloop/live-* only\n%s", other, out)
	}
	if !strings.Contains(out, "grant may push to") || !strings.Contains(out, "refs/heads/cloop/live-*") {
		t.Errorf("the refusal does not name the grant's branch list:\n%s", out)
	}
	if got := remoteRef(t, git, clone, "refs/heads/"+other); got != "" {
		t.Errorf("%s exists on GitHub at %s despite the refusal", other, got)
	}

	// Inside both: lands on GitHub.
	branch := "cloop/live-" + stamp
	if out, err := git(clone, "push", "origin", "HEAD:refs/heads/"+branch); err != nil {
		t.Fatalf("push to %s was refused: %v\n%s", branch, err, out)
	}
	// Deferred rather than t.Cleanup, and registered after the lease's own
	// defers: those run first otherwise, and releasing the lease destroys the
	// installation token this deletion needs.
	defer deleteRemoteBranch(t, repo, branch, installationToken)
	local, _ := git(clone, "rev-parse", "HEAD")
	if got := remoteRef(t, git, clone, "refs/heads/"+branch); got != strings.TrimSpace(local) {
		t.Fatalf("GitHub has %s at %q, want the pushed commit %s", branch, got, strings.TrimSpace(local))
	}

	cfgBytes, _ := os.ReadFile(filepath.Join(clone, ".git", "config"))
	if strings.Contains(string(cfgBytes), installationToken) {
		t.Error("the clone's config holds the installation token")
	}
}

// remoteRef asks GitHub, through the proxy, where a ref points.
func remoteRef(t *testing.T, git func(string, ...string) (string, error), dir, ref string) string {
	t.Helper()
	out, err := git(dir, "ls-remote", "origin", ref)
	if err != nil {
		t.Fatalf("ls-remote %s: %v\n%s", ref, err, out)
	}
	sha, _, _ := strings.Cut(strings.TrimSpace(out), "\t")
	return sha
}

// deleteRemoteBranch removes the scratch branch with the installation token the
// hub holds. Not through the proxy: it refuses deletes, which is the point.
func deleteRemoteBranch(t *testing.T, repo, branch, token string) {
	req, err := http.NewRequest(http.MethodDelete,
		"https://api.github.com/repos/"+repo+"/git/refs/heads/"+branch, nil)
	if err != nil {
		t.Errorf("cleanup: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("cleanup: delete %s: %v", branch, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("cleanup: delete %s = HTTP %d: %s", branch, resp.StatusCode, body)
	}
}

// assertNoTokenUnder fails if any file in dir contains the token.
func assertNoTokenUnder(t *testing.T, dir, token string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), token) {
			t.Errorf("%s holds the installation token", p)
		}
		return nil
	})
}

// writeLoopbackCert creates a self-signed certificate for 127.0.0.1 that is its
// own CA, so git can be told to trust exactly it.
func writeLoopbackCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cloop git proxy (test)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "proxy.crt"), filepath.Join(dir, "proxy.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
