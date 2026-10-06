// Package secretbrokertest provides fakes for testing code that leases GitHub
// App credentials through pkg/secretbroker: an in-memory store, a GitHub App
// API whose clock a test drives, a git forge that honours only the tokens that
// API minted and has not expired or revoked, and an HTTPS CONNECT proxy that
// lets a workload reach that forge under the name github.com.
//
// It exists for Task 20375 (keeping an App token working past GitHub's hour),
// whose claims span packages — the git proxy, the container driver, a device's
// agent — and each needs the same stand-in for GitHub: one that mints a token
// with an expiry, and a forge that then refuses it when that expiry passes. A
// fake that never refused an expired token would let every one of those tests
// pass without a refresh ever happening.
//
// Nothing outside _test.go files may import this package, except a harness
// under tests/: tests/kube serves the forge from a container in a cluster.
package secretbrokertest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

// Clock is a settable time source. One is shared by the broker, the fake
// GitHub, the forge and whatever else a test needs to agree on "now".
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock reading start.
func NewClock(start time.Time) *Clock { return &Clock{now: start.UTC()} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// App payload
// ---------------------------------------------------------------------------

var (
	keyOnce sync.Once
	keyPEM  string
)

// AppPayload returns a well-formed github_app secret payload: the App and
// installation IDs given, and a 2048-bit key generated once per process.
func AppPayload(appID, installationID int64) []byte {
	keyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("secretbrokertest: generate app key: " + err.Error())
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
	})
	body, err := json.Marshal(map[string]any{
		"app_id": appID, "installation_id": installationID, "private_key": keyPEM,
	})
	if err != nil {
		panic("secretbrokertest: marshal app payload: " + err.Error())
	}
	return body
}

// ---------------------------------------------------------------------------
// Fake GitHub App API
// ---------------------------------------------------------------------------

// MintedToken is what the fake remembers about a token it minted.
type MintedToken struct {
	Token         string
	ExpiresAt     time.Time
	RepositoryIDs []int64
	Permissions   map[string]string
	Revoked       bool
}

// GitHub is a secretbroker.GitHubAppAPI standing in for api.github.com.
//
// Tokens it mints expire Lifetime after its clock's now, and Valid answers
// whether GitHub would still honour one — the question a forge asks.
type GitHub struct {
	// Lifetime of a minted token. Zero means an hour, as GitHub's.
	Lifetime time.Duration
	// Clock is the time source. Nil means the wall clock.
	Clock func() time.Time

	mu      sync.Mutex
	repos   []secretbroker.InstallationRepo
	tokens  map[string]*MintedToken
	order   []string
	refuse  error
	failing error
	creates []secretbroker.InstallationTokenRequest
	// pats are personal access tokens the fake honours (Task 20385): each
	// covers the repositories listed, or every repository when none are. They
	// never expire, as a PAT does not on any clock the hub knows.
	pats map[string][]string
}

// AcceptPAT makes the fake — and so a forge built on it — honour token as a
// personal access token covering repos ("owner/name"), or every repository
// when repos is empty.
//
// A broad PAT is the interesting case for a git proxy: the forge would let it
// reach a repository the grant does not name, so a refusal can only have come
// from the proxy.
func (g *GitHub) AcceptPAT(token string, repos ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pats == nil {
		g.pats = map[string][]string{}
	}
	g.pats[token] = append([]string(nil), repos...)
}

// NewGitHub returns a fake whose installation covers repos.
func NewGitHub(repos ...secretbroker.InstallationRepo) *GitHub {
	return &GitHub{repos: repos, tokens: map[string]*MintedToken{}}
}

func (g *GitHub) now() time.Time {
	if g.Clock != nil {
		return g.Clock().UTC()
	}
	return time.Now().UTC()
}

// SetRepos replaces the installation's inventory: a repository added to or
// removed from the App installation.
func (g *GitHub) SetRepos(repos ...secretbroker.InstallationRepo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.repos = repos
}

// RefuseMints makes every later mint fail with GitHub saying no (a suspended
// installation, a repository gone from it) until it is called with nil.
func (g *GitHub) RefuseMints(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if reason == "" {
		g.refuse = nil
		return
	}
	g.refuse = fmt.Errorf("%w: %w: create installation token: github returned 422 Unprocessable Entity: %s",
		secretbroker.ErrGitHubAppMint, secretbroker.ErrGitHubAppRefused, reason)
}

// FailMints makes every later mint fail the way an unreachable GitHub does,
// until it is called with false.
func (g *GitHub) FailMints(fail bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !fail {
		g.failing = nil
		return
	}
	g.failing = fmt.Errorf("%w: create installation token: dial tcp: connection refused",
		secretbroker.ErrGitHubAppMint)
}

// CreateInstallationToken implements secretbroker.GitHubAppAPI.
func (g *GitHub) CreateInstallationToken(_ context.Context, req secretbroker.InstallationTokenRequest) (secretbroker.InstallationToken, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if strings.Count(req.AppJWT, ".") != 2 {
		return secretbroker.InstallationToken{}, errors.New("fake github: the app jwt is not a three-part JWS")
	}
	if g.refuse != nil {
		return secretbroker.InstallationToken{}, g.refuse
	}
	if g.failing != nil {
		return secretbroker.InstallationToken{}, g.failing
	}
	for _, id := range req.RepositoryIDs {
		if !g.coversLocked(id) {
			return secretbroker.InstallationToken{}, fmt.Errorf("%w: %w: github returned 422: repository %d is "+
				"not accessible to the installation", secretbroker.ErrGitHubAppMint, secretbroker.ErrGitHubAppRefused, id)
		}
	}
	g.creates = append(g.creates, req)
	life := g.Lifetime
	if life == 0 {
		life = time.Hour
	}
	raw := make([]byte, 10)
	_, _ = rand.Read(raw)
	tok := fmt.Sprintf("ghs_fake%03d%s", len(g.order)+1, hex.EncodeToString(raw))
	perms := map[string]string{}
	for k, v := range req.Permissions {
		perms[k] = v
	}
	if req.Permissions == nil {
		perms = map[string]string{"contents": "write", "metadata": "read"}
	}
	m := &MintedToken{
		Token:         tok,
		ExpiresAt:     g.now().Add(life),
		RepositoryIDs: append([]int64(nil), req.RepositoryIDs...),
		Permissions:   perms,
	}
	g.tokens[tok] = m
	g.order = append(g.order, tok)
	return secretbroker.InstallationToken{
		Token: tok, ExpiresAt: m.ExpiresAt, Permissions: copyMap(perms),
		RepositorySelection: selection(req.RepositoryIDs),
	}, nil
}

func (g *GitHub) coversLocked(id int64) bool {
	for _, r := range g.repos {
		if r.ID == id {
			return true
		}
	}
	return false
}

// ListInstallationRepos implements secretbroker.GitHubAppAPI.
func (g *GitHub) ListInstallationRepos(_ context.Context, _, token string) ([]secretbroker.InstallationRepo, error) {
	if !g.Valid(token) {
		return nil, fmt.Errorf("%w: github returned 401: bad credentials", secretbroker.ErrGitHubAppMint)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]secretbroker.InstallationRepo(nil), g.repos...), nil
}

// RevokeInstallationToken implements secretbroker.GitHubAppAPI.
func (g *GitHub) RevokeInstallationToken(_ context.Context, _, token string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.tokens[token]; ok {
		m.Revoked = true
	}
	return nil
}

// ListAppInstallations implements secretbroker.GitHubAppAPI.
func (g *GitHub) ListAppInstallations(context.Context, string, string) ([]secretbroker.AppInstallation, error) {
	return nil, nil
}

// Valid reports whether GitHub would honour token now: minted here, not
// revoked, not expired.
func (g *GitHub) Valid(token string) bool {
	_, ok := g.Authorize(token)
	return ok
}

// Authorize returns the record of a token GitHub would honour now.
func (g *GitHub) Authorize(token string) (MintedToken, bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.tokens[token]
	if !ok || m.Revoked || !now.Before(m.ExpiresAt) {
		return MintedToken{}, false
	}
	return *m, true
}

// Token returns the record of a minted token, revoked and expired ones
// included.
func (g *GitHub) Token(token string) (MintedToken, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.tokens[token]
	if !ok {
		return MintedToken{}, false
	}
	return *m, true
}

// Minted returns every token minted, oldest first, discovery tokens included.
func (g *GitHub) Minted() []MintedToken {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]MintedToken, 0, len(g.order))
	for _, tok := range g.order {
		out = append(out, *g.tokens[tok])
	}
	return out
}

// Scoped returns the minted tokens that were narrowed to repositories — the
// ones a lease delivers, as opposed to the metadata:read discovery tokens the
// inventory lookup mints and destroys.
func (g *GitHub) Scoped() []MintedToken {
	var out []MintedToken
	for _, m := range g.Minted() {
		if _, discovery := m.Permissions["metadata"]; discovery && len(m.Permissions) == 1 {
			continue
		}
		out = append(out, m)
	}
	return out
}

// Creates returns every mint request, oldest first.
func (g *GitHub) Creates() []secretbroker.InstallationTokenRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]secretbroker.InstallationTokenRequest(nil), g.creates...)
}

// LiveTokens returns the tokens GitHub would honour now, sorted.
func (g *GitHub) LiveTokens() []string {
	var out []string
	for _, m := range g.Minted() {
		if g.Valid(m.Token) {
			out = append(out, m.Token)
		}
	}
	sort.Strings(out)
	return out
}

// CoversRepo reports whether token is scoped to repo — "owner/name" — under
// the installation's current inventory, or is a PAT (AcceptPAT) covering it.
func (g *GitHub) CoversRepo(token, repo string) bool {
	g.mu.Lock()
	scope, isPAT := g.pats[token]
	g.mu.Unlock()
	if isPAT {
		if len(scope) == 0 {
			return true
		}
		for _, r := range scope {
			if strings.EqualFold(r, repo) {
				return true
			}
		}
		return false
	}
	m, ok := g.Authorize(token)
	if !ok {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(m.RepositoryIDs) == 0 {
		return true
	}
	for _, r := range g.repos {
		if !strings.EqualFold(r.FullName, repo) {
			continue
		}
		for _, id := range m.RepositoryIDs {
			if id == r.ID {
				return true
			}
		}
	}
	return false
}

func selection(ids []int64) string {
	if len(ids) == 0 {
		return "all"
	}
	return "selected"
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

var _ secretbroker.GitHubAppAPI = (*GitHub)(nil)
