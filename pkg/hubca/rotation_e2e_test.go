package hubca_test

// The trap Task 20409 names for rotation: replacing a monitor's leaf must not
// break a run that is pushing, and a durable git session (Task 20383) must
// survive the rotation and the hub process that served it going away. Real
// git, a real forge behind the real proxy, and git trusting the hub's CA the
// way every driver configures it: http.<proxy>.sslCAInfo, never process-wide.

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// sessionRecords is a gitproxy.SessionStore: what a hub process taking over a
// run reads its sessions back from.
type sessionRecords struct {
	mu   sync.Mutex
	recs map[string]gitproxy.SessionRecord
}

func (s *sessionRecords) SaveSession(rec gitproxy.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[rec.ID] = rec
	return nil
}

func (s *sessionRecords) CloseSession(string, string, time.Time) error { return nil }

func (s *sessionRecords) RenewSession(string, time.Time, time.Time) error { return nil }

func (s *sessionRecords) get(id string) (gitproxy.SessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[id]
	return rec, ok
}

// front is the one address sandboxes know the proxy by. What answers behind
// it, a proxy and the certificate server its listener asks per handshake, is
// replaced the way a hub restart replaces it.
type front struct {
	proxy atomic.Pointer[gitproxy.Proxy]
	certs atomic.Pointer[hubca.Server]
}

func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) { f.proxy.Load().ServeHTTP(w, r) }

func (f *front) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f.certs.Load().GetCertificate(hello)
}

func TestAGitSessionOutlivesARotationAndItsHubProcess(t *testing.T) {
	gitBin, _ := secretbrokertest.GitTools(t)
	const pat = "ghp_rotation_e2e_forge_token_000000000000000000"
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(pat, "acme/tool")
	forge := secretbrokertest.NewForge(t, gh, "acme/tool")

	f := newFixture(t)
	// The TLS stack verifies against the wall clock: the first leaf is issued
	// 25 hours ago, so it is due now and both it and its successor are valid.
	f.clock = &clock{t: time.Now().UTC().Add(-25 * time.Hour)}
	ca := f.authority(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "https://" + ln.Addr().String()
	fr := &front{}
	hs := &http.Server{Handler: fr, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = hs.Serve(tls.NewListener(ln, &tls.Config{GetCertificate: fr.getCertificate, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() { _ = hs.Close() })

	records := &sessionRecords{recs: map[string]gitproxy.SessionRecord{}}
	process := func(member string) (*gitproxy.Registry, *hubca.Server) {
		t.Helper()
		reg, err := gitproxy.NewRegistry(base)
		if err != nil {
			t.Fatal(err)
		}
		reg.Store = records
		px, err := gitproxy.New(reg, gitproxy.Options{Transport: forge.Transport()})
		if err != nil {
			t.Fatal(err)
		}
		srv, err := hubca.NewServer(hubca.ServerConfig{
			Monitor: hubca.GitProxy, Store: f.store, Sealer: f.keyring, Authority: ca,
			Want: []string{"127.0.0.1"}, Options: f.opts(member),
		})
		if err != nil {
			t.Fatal(err)
		}
		fr.proxy.Store(px)
		fr.certs.Store(srv)
		return reg, srv
	}

	// Hub process A serves the proxy and mints the run's durable session.
	regA, srvA := process("member-a")
	m, err := regA.Mint(gitproxy.MintRequest{
		Upstream: forge.RepoURL("acme/tool"),
		Credential: gitproxy.Credential{Username: "x-access-token", Password: pat,
			LeaseID: "lease_1", GrantID: "grant_1"},
		Policy: gitproxy.Policy{AllowedRefs: []string{gitproxy.DefaultAllowedRef},
			AllowCreate: true, AllowUpdate: true, AllowFetch: true},
		TTL: time.Hour, Actor: "e2e", RunID: "run_1", Durable: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The workload's git: a closed environment, the session's credential
	// scoped to the proxy, and the hub CA trusted there and nowhere else.
	work := t.TempDir()
	caFile := filepath.Join(work, "ca.crt")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	closed := []string{"HOME=" + work, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	cred, err := executor.GitCredentialConfig(executor.Workspace{Kind: executor.WorkspaceGit, Repo: m.RepoURL},
		executor.GitCredential{Username: m.Session.ID, Password: m.Token})
	if err != nil {
		t.Fatal(err)
	}
	trust := &executor.GitCA{URLs: []string{base + "/"}, PEM: ca.CertPEM()}
	env, err := executor.WithGitConfig(closed, append(trust.ConfigPairs(caFile), cred...))
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := executor.WithGitConfig(closed, cred)
	if err != nil {
		t.Fatal(err)
	}
	git := func(env []string, dir string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, gitBin, args...)
		cmd.Dir, cmd.Env = dir, env
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	push := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, "repo", name+".txt"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"add", "."}, {"-c", "user.email=e2e@cloop.invalid", "-c", "user.name=e2e",
			"commit", "-qm", name}} {
			if out, err := git(env, filepath.Join(work, "repo"), args...); err != nil {
				t.Fatalf("git %s: %v\n%s", args[0], err, out)
			}
		}
		ref := "refs/heads/cloop/" + name
		if out, err := git(env, filepath.Join(work, "repo"), "push", "-q", "origin", "HEAD:"+ref); err != nil {
			t.Fatalf("push %s: %v\n%s", name, err, out)
		}
		if forge.Ref(t, "acme/tool", ref) == "" {
			t.Fatalf("push %s did not reach the forge", name)
		}
	}

	if out, err := git(env, work, "clone", "-q", m.RepoURL, "repo"); err != nil {
		t.Fatalf("clone through the auto-TLS proxy: %v\n%s", err, out)
	}
	// The trust is what verifies the proxy, not something ambient.
	if out, err := git(untrusted, work, "ls-remote", m.RepoURL); err == nil || !strings.Contains(strings.ToLower(out), "certificate") {
		t.Fatalf("git without the hub CA reached the proxy (err=%v):\n%s", err, out)
	}

	// The leader renews mid-run. The next push gets the new leaf on a new
	// connection, and the same CA and the same session carry it.
	first := srvA.Current()
	f.clock.advance(25 * time.Hour)
	if issued, err := srvA.Renew(); err != nil || !issued {
		t.Fatalf("renew: issued=%v err=%v", issued, err)
	}
	second := srvA.Current()
	if second.Serial == first.Serial {
		t.Fatal("renewal kept the same leaf")
	}
	push("after-rotation")

	// Hub process A goes away; B takes over at the same address with an empty
	// registry. It adopts the leaf A's leader stored rather than issuing one of
	// its own, and restores the session from its record.
	regB, srvB := process("member-b")
	if got := srvB.Current().Serial; got != second.Serial {
		t.Fatalf("the adopting process serves leaf %s, want the renewed %s", got, second.Serial)
	}
	rec, ok := records.get(m.Session.ID)
	if !ok {
		t.Fatal("the durable session left no record to restore")
	}
	if _, err := regB.Restore(gitproxy.RestoreRequest{
		Record:     rec,
		Credential: gitproxy.Credential{Username: "x-access-token", Password: pat},
		From:       "member-a",
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	push("after-handover")
}
