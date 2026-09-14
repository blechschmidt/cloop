package security

// Guarantee: a github_app grant delivers a token, never the signing key it was
// minted from.
//
// This is the one credential kind where cloop holds a *key generator* rather
// than a credential. The payload is a GitHub App private key: it does not
// expire, and anyone holding it can mint a token for every repository in the
// installation, at any permission the App has, forever. Delivering it to a
// sandbox would make github_app strictly worse than the github_pat it exists to
// improve on — and that is exactly what the broker did until Task 20254, by
// folding KindGitHubApp into the PAT branch and handing the payload over as if
// it were a token.
//
// So this file asserts the negative on every surface an executor actually
// reads. The hub signs a short-lived JWT with the key, asks GitHub for an
// installation token narrowed to the grant, and delivers that. The key stays in
// the hub's memory.
//
// Both delivery paths are covered, because they are separate implementations:
// Materialize writes files for a backend that shares the hub's filesystem, and
// Deliver hands bytes to a driver that stages them somewhere the hub cannot see.
// A leak in one would be invisible to a test that only exercised the other.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// ---------------------------------------------------------------------------
// A GitHub that never leaves the process
// ---------------------------------------------------------------------------

// conformanceGitHub is a GitHubAppAPI standing in for api.github.com.
//
// It also acts as an oracle for the property under test: every request carries
// an app JWT, and a JWT is *derived* from the private key rather than
// containing it, so any request body that contained the PEM would be a leak the
// fake can see. assertKeyAbsent below checks the recorded traffic for exactly
// that.
type conformanceGitHub struct {
	mu sync.Mutex

	repos []secretbroker.InstallationRepo
	seq   int

	// jwts records every assertion cloop signed, so the test can confirm the
	// hub authenticated with a signature rather than by forwarding the key.
	jwts []string
	// scopes records the repository IDs each minted token was narrowed to.
	scopes [][]int64
	// revoked records DELETE /installation/token calls.
	revoked []string
}

func (g *conformanceGitHub) CreateInstallationToken(_ context.Context, req secretbroker.InstallationTokenRequest) (secretbroker.InstallationToken, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.jwts = append(g.jwts, req.AppJWT)
	g.scopes = append(g.scopes, append([]int64(nil), req.RepositoryIDs...))
	g.seq++
	return secretbroker.InstallationToken{
		Token:     fmt.Sprintf("ghs_conformance%03d", g.seq),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, nil
}

func (g *conformanceGitHub) ListInstallationRepos(_ context.Context, _, _ string) ([]secretbroker.InstallationRepo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]secretbroker.InstallationRepo(nil), g.repos...), nil
}

func (g *conformanceGitHub) RevokeInstallationToken(_ context.Context, _, token string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.revoked = append(g.revoked, token)
	return nil
}

func (g *conformanceGitHub) recorded() (jwts []string, scopes [][]int64, revoked []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.jwts...),
		append([][]int64(nil), g.scopes...),
		append([]string(nil), g.revoked...)
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

// appKeyFixture is the App private key under test, in PEM form, plus the
// distinctive fragment of its base64 body.
//
// The fragment matters: "-----BEGIN RSA PRIVATE KEY-----" appears in any PEM
// and would make a substring search match armour rather than key material. A
// line of the encoded modulus appears nowhere by chance.
type appKeyFixture struct {
	pem      string
	fragment string
	payload  []byte
}

func newAppKeyFixture(t *testing.T) appKeyFixture {
	t.Helper()
	// 2048 is the floor ParseGitHubApp enforces and what GitHub issues. The
	// keygen is the slowest thing in this file at roughly 100ms, which is the
	// price of testing the real parser rather than a stub.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	var fragment string
	for _, line := range strings.Split(encoded, "\n") {
		if len(line) >= 40 && !strings.HasPrefix(line, "-----") {
			fragment = line
			break
		}
	}
	if fragment == "" {
		t.Fatal("generated PEM has no usable body line — the leak check would be vacuous")
	}

	payload, err := json.Marshal(map[string]any{
		"app_id":          424242,
		"installation_id": 313131,
		"private_key":     encoded,
	})
	if err != nil {
		t.Fatalf("marshal github_app payload: %v", err)
	}
	return appKeyFixture{pem: encoded, fragment: fragment, payload: payload}
}

// appLease runs the full mint → grant → lease lifecycle for a github_app
// secret against the fake GitHub.
func appLease(t *testing.T, gh *conformanceGitHub, fx appKeyFixture, repos []string) (*secretbroker.Broker, *secretbroker.Lease, *recordingAuditor) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "conformance-suite-passphrase")
	ctx := context.Background()

	auditor := &recordingAuditor{}
	b, err := secretbroker.New(newMemStore(),
		secretbroker.WithAuditor(auditor),
		secretbroker.WithGitHubApp(gh))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}

	// Mint zeroes the slice it is handed, so the fixture's payload is copied
	// rather than consumed — a second use would otherwise seal a run of NULs.
	sec, err := b.Mint(ctx, secretbroker.MintRequest{
		Name:    "conformance-app",
		Kind:    secretbroker.KindGitHubApp,
		Payload: append([]byte(nil), fx.payload...),
		Actor:   "conformance-suite",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
		Constraints: secretbroker.Constraints{Repos: repos},
		TTL:         time.Hour,
		Actor:       "conformance-suite",
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	lease, err := b.Lease(ctx, "edge-01", "/srv/app-project")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if lease.Empty() {
		t.Fatal("the github_app lease carries no materials — every check below would be vacuous")
	}
	return b, lease, auditor
}

// ---------------------------------------------------------------------------
// The guarantee
// ---------------------------------------------------------------------------

// TestGitHubAppPrivateKeyNeverReachesAnExecutor is the assertion the kind
// exists for.
//
// It sweeps every surface an executor reads — the materialised mount's files
// and environment, the delivery a remote driver stages, the marshalled lease,
// and the audit trail — for the key in any encoding. It then asserts the
// positive so the sweep cannot pass by delivering nothing: the token GitHub
// minted *is* in the credential file, narrowed to the repository the grant
// named.
func TestGitHubAppPrivateKeyNeverReachesAnExecutor(t *testing.T) {
	gh := &conformanceGitHub{repos: []secretbroker.InstallationRepo{
		{ID: 11, FullName: "acme/service"},
		{ID: 22, FullName: "acme/tool"},
		{ID: 33, FullName: "other/secret-crown-jewels"},
	}}
	fx := newAppKeyFixture(t)
	b, lease, auditor := appLease(t, gh, fx, []string{"acme/tool"})
	defer b.Release(lease.ID)

	// --- the host-path delivery ------------------------------------------
	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer mount.Close()

	for _, kv := range mount.Env() {
		assertKeyAbsent(t, kv, fx, "the materialised mount's environment")
	}
	entries, err := os.ReadDir(mount.Dir)
	if err != nil {
		t.Fatalf("read lease dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the lease directory is empty — the file sweep would be vacuous")
	}
	var tokenFile string
	for _, entry := range entries {
		body, rerr := os.ReadFile(filepath.Join(mount.Dir, entry.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", entry.Name(), rerr)
		}
		assertKeyAbsent(t, string(body), fx, "lease file "+entry.Name())
		if entry.Name() == "github-token" {
			tokenFile = strings.TrimSpace(string(body))
		}
	}

	// --- the isolated-executor delivery ----------------------------------
	delivery, err := lease.Deliver(secretbroker.SandboxLeaseDir(lease.ID))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	defer delivery.Close()

	for _, kv := range delivery.Env() {
		assertKeyAbsent(t, kv, fx, "the sandbox delivery's environment")
	}
	delivered := delivery.Files()
	if len(delivered) == 0 {
		t.Fatal("the delivery carries no files — the sweep would be vacuous")
	}
	for _, f := range delivered {
		assertKeyAbsent(t, string(f.Content), fx, "delivered file "+f.Name)
	}

	// --- the describing surfaces ------------------------------------------
	if encoded, merr := json.Marshal(lease); merr == nil {
		assertKeyAbsent(t, string(encoded), fx, "the marshalled lease")
	}
	assertKeyAbsent(t, auditor.dump(t), fx, "the audit trail")

	// The hub authenticated to GitHub with a signature over the key, not by
	// forwarding it: the request carries a three-part JWS and no PEM.
	jwts, scopes, _ := gh.recorded()
	if len(jwts) == 0 {
		t.Fatal("no app JWT was signed — nothing minted, so the test proves nothing")
	}
	for _, j := range jwts {
		assertKeyAbsent(t, j, fx, "the app JWT sent to GitHub")
		if strings.Count(j, ".") != 2 {
			t.Errorf("the assertion sent to GitHub is not a JWS: %q", preview(j))
		}
	}

	// --- and the positive, so none of the above passes vacuously ----------
	if !strings.HasPrefix(tokenFile, "ghs_conformance") {
		t.Fatalf("github-token holds %q, not the installation token GitHub minted", preview(tokenFile))
	}
	last := scopes[len(scopes)-1]
	if len(last) != 1 || last[0] != 22 {
		t.Errorf("the delivered token was scoped to %v, want only acme/tool's id (22) — "+
			"GitHub, not a shell script, is what bounds an App credential", last)
	}
}

// TestGitHubAppTokenDiesAtGitHubOnRelease is the other half of "the sandbox
// never holds the key": what it does hold must be destroyable.
//
// Wiping the lease directory removes the copy on disk, which is all any other
// credential kind can offer. An App token is a credential the hub brought into
// existence at GitHub, so releasing the lease must end it there too — otherwise
// a sandbox that exfiltrated the token before exiting keeps a working
// credential for the rest of GitHub's hour.
func TestGitHubAppTokenDiesAtGitHubOnRelease(t *testing.T) {
	gh := &conformanceGitHub{repos: []secretbroker.InstallationRepo{
		{ID: 11, FullName: "acme/tool"},
	}}
	fx := newAppKeyFixture(t)
	b, lease, _ := appLease(t, gh, fx, []string{"acme/tool"})

	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(mount.Dir, "github-token"))
	if err != nil {
		t.Fatalf("read github-token: %v", err)
	}
	token := strings.TrimSpace(string(body))
	if err := mount.Close(); err != nil {
		t.Fatalf("mount.Close: %v", err)
	}

	b.Release(lease.ID)

	_, _, revoked := gh.recorded()
	var found bool
	for _, r := range revoked {
		if r == token {
			found = true
		}
	}
	if !found {
		t.Fatalf("releasing the lease did not destroy %s at GitHub; revoked = %v",
			preview(token), revoked)
	}
}

// assertKeyAbsent fails if haystack contains the App private key in any form.
//
// Two needles, because they fail differently. The whole PEM catches a delivery
// that hands the payload over verbatim — the pre-Task-20254 bug. The body
// fragment catches every partial or re-encoded copy: a key reassembled without
// its armour, embedded in JSON, or split across a struct. Both go through
// assertNoSecretLeak, which checks base64, hex and URL encodings as well as the
// raw bytes, because a leak that survives one round-trip is still a leak.
func assertKeyAbsent(t *testing.T, haystack string, fx appKeyFixture, sink string) {
	t.Helper()
	if haystack == "" {
		return
	}
	assertNoSecretLeak(t, haystack, fx.pem, sink)
	assertNoSecretLeak(t, haystack, fx.fragment, sink)
}
