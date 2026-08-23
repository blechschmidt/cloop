package ui

// gitproxy_test.go covers the hub's half of the git interception proxy: that a
// config section starts a real TLS listener, that the credential a driver is
// handed is routed through it, and that the workspace which comes out is still
// a workspace every downstream consumer accepts.
//
// The proxy's own enforcement — which refs a push may touch — is proven against
// a real git binary in pkg/gitproxy/e2e_test.go. What is verifiable only here is
// the wiring: a boundary nothing switches on is not a boundary, and every bug
// this file would catch is one where the hub quietly hands out the forge
// credential while the config says it does not.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

const (
	testForgePAT  = "ghp_the_forge_credential_that_must_stay_on_the_hub"
	testUpstream  = "https://github.com/acme/tool.git"
	testProxyRepo = "acme/tool"
)

// gitProxyTestConfig writes TLS material into a temp dir and returns a config
// with the section enabled.
func gitProxyTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "proxy.crt")
	key := filepath.Join(dir, "proxy.key")
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{
		Hosts: []string{"localhost", "127.0.0.1"},
	}); err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	cfg := &config.Config{}
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled:    true,
		ListenAddr: "127.0.0.1:0",
		CertFile:   cert,
		KeyFile:    key,
	}
	return cfg
}

func TestStartGitProxyDisabledIsNil(t *testing.T) {
	svc, err := startGitProxy(&config.Config{}, t.TempDir())
	if err != nil {
		t.Fatalf("startGitProxy on a disabled section: %v", err)
	}
	if svc != nil {
		t.Fatal("a disabled section started a proxy")
	}
	// Every accessor must tolerate the nil service, because that is what the
	// wiring sites hold on an ordinary un-proxied hub and none of them checks.
	if svc.BaseURL() != "" || svc.Addr() != "" {
		t.Fatal("nil service returned a non-empty address")
	}
	svc.Close()
	if got := svc.Wrap("exec-1", nil); got != nil {
		t.Fatal("nil service wrapped a nil source into something non-nil")
	}
}

func TestStartGitProxyServesTLS(t *testing.T) {
	cfg := gitProxyTestConfig(t)
	svc, err := startGitProxy(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	if svc == nil {
		t.Fatal("an enabled section started no proxy")
	}
	defer svc.Close()

	if !strings.HasPrefix(svc.BaseURL(), "https://127.0.0.1:") {
		t.Fatalf("BaseURL = %q, want an https loopback URL", svc.BaseURL())
	}
	// The listener must actually speak TLS. A proxy that came up as cleartext
	// would publish every session token it was handed rather than deliver it,
	// and nothing else in the stack would notice.
	conn, err := tls.Dial("tcp", svc.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("the proxy does not speak TLS on %s: %v", svc.Addr(), err)
	}
	_ = conn.Close()

	// An unauthenticated request is refused rather than proxied.
	cl := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := cl.Get(svc.BaseURL() + "/acme/tool/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET through the proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", resp.StatusCode)
	}
}

// TestGitProxyRoutesTheWorkspace is the assertion the whole task turns on: the
// credential a driver receives is a session token, not the forge PAT, and the
// URL it is good against is the proxy's.
func TestGitProxyRoutesTheWorkspace(t *testing.T) {
	cfg := gitProxyTestConfig(t)
	svc, err := startGitProxy(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	defer svc.Close()

	inner := &recordingSource{cred: executor.GitCredential{
		Username:   "x-access-token",
		Password:   testForgePAT,
		LeaseID:    "lease-1",
		GrantID:    "grant-1",
		SecretName: "github-pat",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}}
	routed := svc.Wrap("exec-1", inner)
	if routed == nil {
		t.Fatal("Wrap returned nil for a live service")
	}

	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: testUpstream,
		Ref: "main", CredentialGrant: "github-pat",
	}
	access, release, err := routed.ForWorkspace(t.Context(), "/srv/acme", w)
	if err != nil {
		t.Fatalf("ForWorkspace: %v", err)
	}
	defer release()

	if access.Credential.Password == testForgePAT {
		t.Fatal("the forge PAT was handed to the sandbox: the proxy is not interposed")
	}
	if access.Credential.Password == "" {
		t.Fatal("no credential at all was returned")
	}
	if !strings.HasPrefix(access.Repo, svc.BaseURL()+"/") {
		t.Fatalf("routed repo = %q, want a URL under the proxy base %q", access.Repo, svc.BaseURL())
	}

	// The routed workspace has to remain a workspace: the drivers validate it,
	// render a git plan from it, and match a grant's repository allowlist
	// against its owner/name. A proxy URL that broke any of those would fail
	// far from here, in an init container or on an edge device.
	got := access.Apply(w)
	if err := got.Validate(); err != nil {
		t.Fatalf("the routed workspace no longer validates: %v", err)
	}
	if path, ok := got.RepoPath(); !ok || path != testProxyRepo {
		t.Fatalf("routed RepoPath = %q,%v want %q,true — grant matching would break",
			path, ok, testProxyRepo)
	}
	if _, err := got.GitPlan("/workspace"); err != nil {
		t.Fatalf("the routed workspace produces no git plan: %v", err)
	}
	// The credential is delivered as a header scoped to Workspace.BaseURL, so
	// this must be the proxy's origin. Were it still the forge's, git would
	// send no Authorization to the proxy and every fetch would 401.
	if base := got.BaseURL(); !strings.HasPrefix(svc.BaseURL()+"/", base) {
		t.Fatalf("routed BaseURL = %q, want the proxy origin %q", base, svc.BaseURL())
	}

	// The session, not the lease, is what now bounds the sandbox.
	if !access.Credential.ExpiresAt.After(inner.cred.ExpiresAt) {
		t.Fatalf("credential expiry %s is not the session's — the sandbox's access "+
			"is still bounded by the lease it no longer holds", access.Credential.ExpiresAt)
	}
	// Audit joinability: the grant that authorised the fetch is still named.
	if access.Credential.GrantID != "grant-1" || access.Credential.LeaseID != "lease-1" {
		t.Fatalf("grant/lease identifiers were dropped: %+v", access.Credential)
	}
}

// TestGitProxyWrapIsNilSafe pins the property every wiring site relies on: an
// un-proxied hub passes its source through untouched rather than losing it.
func TestGitProxyWrapIsNilSafe(t *testing.T) {
	inner := &recordingSource{}
	if got := activeGitProxyNil().Wrap("exec-1", inner); got != executor.WorkspaceCredentialSource(inner) {
		t.Fatal("a nil proxy service did not return the source unchanged")
	}
}

func activeGitProxyNil() *gitProxyService { return nil }

func TestGitProxyBaseURL(t *testing.T) {
	tests := []struct {
		name      string
		advertise string
		addr      net.Addr
		want      string
		wantErr   bool
	}{
		{
			name: "advertised url wins",
			// The bound address is right only when the sandbox shares the
			// hub's network namespace; everything else must be told.
			advertise: "https://hub.internal:8443",
			addr:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want:      "https://hub.internal:8443",
		},
		{
			name:      "trailing slash is trimmed",
			advertise: "https://hub.internal:8443/",
			addr:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want:      "https://hub.internal:8443",
		},
		{
			name: "bound loopback",
			addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want: "https://127.0.0.1:9000",
		},
		{
			// 0.0.0.0 is a bind address and never a destination, so it must
			// not be advertised as one.
			name: "unspecified bind becomes loopback",
			addr: &net.TCPAddr{IP: net.IPv4zero, Port: 9000},
			want: "https://127.0.0.1:9000",
		},
		{
			name:    "a non-TCP listener cannot be advertised",
			addr:    &net.UnixAddr{Name: "/tmp/x", Net: "unix"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gitProxyBaseURL(tc.advertise, tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("gitProxyBaseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("gitProxyBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGitProxyCloseEndsSessions checks that shutdown leaves no session behind
// and that the audit trail records why each ended.
func TestGitProxyCloseEndsSessions(t *testing.T) {
	cfg := gitProxyTestConfig(t)
	svc, err := startGitProxy(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("startGitProxy: %v", err)
	}
	inner := &recordingSource{cred: executor.GitCredential{
		Username: "x-access-token", Password: testForgePAT,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}}
	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: testUpstream,
		Ref: "main", CredentialGrant: "github-pat",
	}
	_, release, err := svc.Wrap("exec-1", inner).ForWorkspace(t.Context(), "/srv/acme", w)
	if err != nil {
		t.Fatalf("ForWorkspace: %v", err)
	}
	release()
	if n := len(svc.reg.Sessions()); n != 1 {
		t.Fatalf("live sessions = %d, want 1", n)
	}

	svc.Close()
	for _, s := range svc.reg.Sessions() {
		if !s.Closed() {
			t.Fatalf("session %s survived shutdown", s.ID)
		}
	}
}

// recordingSource is a WorkspaceCredentialSource that hands out a canned
// credential and counts its releases.
type recordingSource struct {
	cred     executor.GitCredential
	err      error
	released int
}

func (r *recordingSource) ForWorkspace(_ context.Context, _ string, _ executor.Workspace) (executor.WorkspaceAccess, func(), error) {
	if r.err != nil {
		return executor.WorkspaceAccess{}, func() {}, r.err
	}
	return executor.WorkspaceAccess{Credential: r.cred}, func() { r.released++ }, nil
}

// TestGitProxyRequiredButAbsentFailsClosed pins the resolution of a genuine
// conflict: `cloop ui` should not refuse to boot over a bad proxy certificate,
// but a hub whose config asks for interception must not quietly go back to
// handing sandboxes the forge PAT either.
//
// The answer is that the dashboard comes up and *git workspaces* stop. Nothing
// else on the hub is affected, and the refusal names the fix.
func TestGitProxyRequiredButAbsentFailsClosed(t *testing.T) {
	prev := gitProxyRequired.Load()
	t.Cleanup(func() { gitProxyRequired.Store(prev) })
	gitProxyRequired.Store(true)

	inner := &recordingSource{cred: executor.GitCredential{
		Username: "x-access-token", Password: testForgePAT,
	}}
	var absent *gitProxyService
	src := absent.Wrap("exec-1", inner)
	if src == executor.WorkspaceCredentialSource(inner) {
		t.Fatal("a hub configured for interception fell back to the undecorated source, " +
			"which delivers the forge PAT into the sandbox")
	}

	w := executor.Workspace{
		Kind: executor.WorkspaceGit, Repo: testUpstream,
		Ref: "main", CredentialGrant: "github-pat",
	}
	access, release, err := src.ForWorkspace(t.Context(), "/srv/acme", w)
	if release != nil {
		release()
	}
	if err == nil {
		t.Fatal("the workspace was provisioned with no proxy running")
	}
	if !errors.Is(err, executor.ErrWorkspaceUnavailable) {
		t.Fatalf("refusal does not carry ErrWorkspaceUnavailable, so callers cannot "+
			"distinguish it from a missing grant: %v", err)
	}
	if !access.Credential.Empty() || access.Repo != "" {
		t.Fatalf("a refused workspace still produced access material: %+v", access)
	}
	if strings.Contains(err.Error(), testForgePAT) {
		t.Fatal("the refusal echoes the forge PAT")
	}

	// And with no proxy configured at all, the source passes through: an
	// ordinary un-proxied hub must be completely unaffected.
	gitProxyRequired.Store(false)
	if got := absent.Wrap("exec-1", inner); got != executor.WorkspaceCredentialSource(inner) {
		t.Fatal("an un-proxied hub did not pass its credential source through unchanged")
	}
}
