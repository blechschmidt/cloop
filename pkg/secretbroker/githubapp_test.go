package secretbroker

// Tests for GitHub App installation-token minting.
//
// The guarantee under test is narrow and load-bearing: a github_app grant
// delivers a token GitHub scoped, never the signing key it was minted from.
// Before Task 20254 the kind was folded into the PAT branch, so a sandbox
// received an App private key — a credential with no expiry that can mint
// tokens for every repository in the installation. TestAppPrivateKeyNeverLeaves
// is the regression guard for exactly that.
//
// Everything is hermetic. fakeGitHub stands in for api.github.com and records
// what was asked of it, so "narrowed to the grant's repositories" is asserted
// against the request cloop actually sent rather than against a comment.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// testAppKey is generated once for the whole package: a 2048-bit RSA keygen
// costs ~100ms and every test here needs one, so paying it per test would make
// the suite slower than everything else in this package put together.
var (
	testAppKeyOnce sync.Once
	testAppKeyPEM  string
	testAppKey     *rsa.PrivateKey
)

func appKeyPEM(t testing.TB) string {
	t.Helper()
	testAppKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("generate test app key: " + err.Error())
		}
		testAppKey = key
		testAppKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
	})
	return testAppKeyPEM
}

// appPayloadJSON builds a well-formed github_app payload.
func appPayloadJSON(t testing.TB) []byte {
	t.Helper()
	body, err := json.Marshal(appPayload{
		AppID:          12345,
		InstallationID: 67890,
		PrivateKey:     appKeyPEM(t),
	})
	if err != nil {
		t.Fatalf("marshal app payload: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// Fake GitHub
// ---------------------------------------------------------------------------

// fakeGitHub is a GitHubAppAPI that mints predictable tokens and remembers
// every request, so a test can assert on the scope cloop asked for.
type fakeGitHub struct {
	mu sync.Mutex

	// repos is the installation's inventory.
	repos []InstallationRepo
	// now supplies expires_at; tokens are minted an hour out by default,
	// matching GitHub.
	lifetime time.Duration
	clock    func() time.Time

	// installs is where the app is installed, for discovery.
	installs []AppInstallation

	// createErr, listErr, revokeErr and installErr force failures.
	createErr  error
	listErr    error
	revokeErr  error
	installErr error

	// Recorded traffic.
	creates      []InstallationTokenRequest
	revoked      []string
	lists        int
	installCalls int

	// live tracks tokens minted and not yet revoked, which is what makes
	// "the credential died at the source" checkable.
	live map[string]bool
	seq  int
}

func newFakeGitHub(repos ...InstallationRepo) *fakeGitHub {
	return &fakeGitHub{repos: repos, live: map[string]bool{}, lifetime: time.Hour}
}

func (f *fakeGitHub) now() time.Time {
	if f.clock != nil {
		return f.clock().UTC()
	}
	return time.Now().UTC()
}

func (f *fakeGitHub) CreateInstallationToken(_ context.Context, req InstallationTokenRequest) (InstallationToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return InstallationToken{}, f.createErr
	}
	if strings.Count(req.AppJWT, ".") != 2 {
		return InstallationToken{}, fmt.Errorf("fake github: app jwt is not a three-part JWS")
	}
	f.creates = append(f.creates, req)
	f.seq++
	tok := fmt.Sprintf("ghs_faketoken%02d", f.seq)
	f.live[tok] = true
	return InstallationToken{
		Token:       tok,
		ExpiresAt:   f.now().Add(f.lifetime),
		Permissions: req.Permissions,
	}, nil
}

func (f *fakeGitHub) ListAppInstallations(_ context.Context, _, appJWT string) ([]AppInstallation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installErr != nil {
		return nil, f.installErr
	}
	// Discovery runs before any installation is known, so it must be the app
	// JWT that authenticates it. Asserted here because a implementation that
	// reached for an installation token instead would still pass every
	// behavioural test while being impossible to use for its one purpose.
	if strings.Count(appJWT, ".") != 2 {
		return nil, fmt.Errorf("fake github: app jwt is not a three-part JWS")
	}
	f.installCalls++
	return append([]AppInstallation(nil), f.installs...), nil
}

func (f *fakeGitHub) ListInstallationRepos(_ context.Context, _, token string) ([]InstallationRepo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	if !f.live[token] {
		return nil, fmt.Errorf("fake github: listing with a token that is not live")
	}
	f.lists++
	return append([]InstallationRepo(nil), f.repos...), nil
}

func (f *fakeGitHub) RevokeInstallationToken(_ context.Context, _, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, token)
	delete(f.live, token)
	return nil
}

// liveTokens returns the tokens the fake still honours, sorted for stable
// failure messages.
func (f *fakeGitHub) liveTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.live))
	for tok := range f.live {
		out = append(out, tok)
	}
	return out
}

func (f *fakeGitHub) wasRevoked(token string) bool { return f.revokeCount(token) > 0 }

// revokeCount is how many times a *specific* token was destroyed. Counting the
// whole revoked slice would fold in the discovery token the inventory lookup
// mints and immediately destroys, which is not what any caller means.
func (f *fakeGitHub) revokeCount(token string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range f.revoked {
		if t == token {
			n++
		}
	}
	return n
}

// deliveredCreate returns the mint request that produced the *delivered*
// token — the last one, since the inventory lookup's discovery token is minted
// first and destroyed immediately.
func (f *fakeGitHub) deliveredCreate(t testing.TB) InstallationTokenRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		t.Fatal("no installation token was minted")
	}
	return f.creates[len(f.creates)-1]
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// appBroker builds a broker over a fake GitHub with one github_app secret and
// one grant, and returns everything a test needs to drive it.
func appBroker(t *testing.T, repos []string, perms []string, gh *fakeGitHub) (*Broker, *fakeGitHub, Grant) {
	t.Helper()
	b, _, _, clk := newTestBroker(t)
	gh.clock = clk.Now
	b.appMinter = newGitHubAppMinter(gh, clk.Now)

	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "prod-app", Kind: KindGitHubApp, Payload: appPayloadJSON(t),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	g, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: repos, Permissions: perms},
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return b, gh, g
}

func leaseOnce(t *testing.T, b *Broker) *Lease {
	t.Helper()
	lease, err := b.Lease(context.Background(), "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	return lease
}

// tokenFrom returns the credential a lease delivered for the github_app
// material, read out of the file the executor would read.
func tokenFrom(t *testing.T, lease *Lease) string {
	t.Helper()
	for _, m := range lease.Materials {
		if m.Kind != KindGitHubApp {
			continue
		}
		tok, ok := m.GitHubToken()
		if !ok {
			t.Fatal("github_app material carries no token file")
		}
		return tok
	}
	t.Fatal("lease carries no github_app material")
	return ""
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

func TestParseGitHubAppAcceptsWellFormedPayload(t *testing.T) {
	cred, err := ParseGitHubApp(appPayloadJSON(t))
	if err != nil {
		t.Fatalf("ParseGitHubApp: %v", err)
	}
	if cred.AppID != 12345 || cred.InstallationID != 67890 {
		t.Errorf("ids = %d/%d, want 12345/67890", cred.AppID, cred.InstallationID)
	}
	if cred.BaseURL != defaultGitHubBaseURL {
		t.Errorf("BaseURL = %q, want the public API", cred.BaseURL)
	}
	if cred.key == nil || cred.key.N.Cmp(testAppKey.N) != 0 {
		t.Error("parsed key is not the key that was written")
	}
}

// TestParseGitHubAppRejectsFreeFormBlob is the reason the parser exists. The
// kind used to accept anything, which meant the single most likely operator
// error — pasting a PAT under --kind github_app — was stored as a working
// secret and failed in somebody's run.
func TestParseGitHubAppRejectsFreeFormBlob(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wants   string
	}{
		{"a PAT", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "github_pat"},
		{"empty", "", "empty"},
		{"a bare PEM", appKeyPEM(t), "JSON object"},
		{"app_id missing", `{"installation_id":1,"private_key":"x"}`, "app_id"},
		{"app_id not an integer", `{"app_id":"not-a-number","installation_id":1,"private_key":"x"}`, "not an integer"},
		{"app_id a float", `{"app_id":1.5,"installation_id":1,"private_key":"x"}`, "not an integer"},
		{"app_id negative", `{"app_id":-3,"installation_id":1,"private_key":"x"}`, "positive integer"},
		{"installation_id missing", `{"app_id":1,"private_key":"x"}`, "installation_id"},
		{"private_key missing", `{"app_id":1,"installation_id":2}`, "private_key is missing"},
		{"private_key not PEM", `{"app_id":1,"installation_id":2,"private_key":"hunter2"}`, "not PEM"},
		{"unknown field", `{"app_id":1,"installation_id":2,"private_key":"x","appId":3}`, "unknown field"},
		{"base_url not https", `{"app_id":1,"installation_id":2,"private_key":"x","base_url":"http://ghe"}`, "https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseGitHubApp([]byte(tc.payload))
			if err == nil {
				t.Fatalf("ParseGitHubApp accepted %q", tc.payload)
			}
			if !errors.Is(err, ErrMalformedPayload) {
				t.Errorf("err = %v; want ErrMalformedPayload", err)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("err = %v; want it to mention %q", err, tc.wants)
			}
		})
	}
}

// TestParseGitHubAppRejectsWeakKey guards the other direction: a key that parses
// but is too small to be a real GitHub App key is an artefact, not a credential.
func TestParseGitHubAppRejectsWeakKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	weak := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small),
	}))
	body, _ := json.Marshal(appPayload{AppID: 1, InstallationID: 2, PrivateKey: weak})
	if _, err := ParseGitHubApp(body); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("ParseGitHubApp(1024-bit key) = %v; want a refusal naming 2048", err)
	}
}

func TestAppJWTIsRS256AndShortLived(t *testing.T) {
	cred, err := ParseGitHubApp(appPayloadJSON(t))
	if err != nil {
		t.Fatalf("ParseGitHubApp: %v", err)
	}
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	signed, err := cred.signJWT(now)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	decodeSegment(t, parts[0], &header)
	if header.Alg != "RS256" || header.Typ != "JWT" {
		t.Errorf("header = %+v, want RS256/JWT", header)
	}

	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	decodeSegment(t, parts[1], &claims)
	if claims.Iss != "12345" {
		t.Errorf("iss = %q, want the app id", claims.Iss)
	}
	// GitHub refuses a JWT whose lifetime exceeds ten minutes, measured from
	// its own iat — which is backdated here to absorb clock skew, so the span
	// that matters is exp-iat and not exp-now.
	if span := claims.Exp - claims.Iat; span > 600 {
		t.Errorf("exp-iat = %ds, more than GitHub's 600s maximum", span)
	}
	if claims.Iat >= now.Unix() {
		t.Errorf("iat = %d is not backdated relative to %d", claims.Iat, now.Unix())
	}
}

func decodeSegment(t *testing.T, seg string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode jwt segment: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("unmarshal jwt segment: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

func TestGitHubAppPermissions(t *testing.T) {
	tests := []struct {
		name  string
		perms []string
		want  map[string]string
		err   string
	}{
		{"default is read-only", nil, map[string]string{"contents": "read"}, ""},
		{"explicit read", []string{"contents:read"}, map[string]string{"contents": "read"}, ""},
		{"push widens contents", []string{"contents:write"}, map[string]string{"contents": "write"}, ""},
		{"bare scope means write", []string{"contents"}, map[string]string{"contents": "write"}, ""},
		{
			"read cannot narrow a write listed beside it",
			[]string{"contents:write", "contents:read"},
			map[string]string{"contents": "write"}, "",
		},
		{
			"other scopes ride along, contents stays readable",
			[]string{"pull_requests:write"},
			map[string]string{"contents": "read", "pull_requests": "write"}, "",
		},
		{"wildcard asks for the installation's own set", []string{"*"}, nil, ""},
		{"bad level", []string{"contents:maybe"}, nil, "want read, write or admin"},
		{"bad scope", []string{"Contents-Read:read"}, nil, "unusable scope name"},
		{"no scope", []string{":read"}, nil, "has no scope"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GitHubAppPermissions(Constraints{Permissions: tc.perms})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v; want one mentioning %q", err, tc.err)
				}
				if !errors.Is(err, ErrInvalidConstraint) {
					t.Errorf("err = %v; want ErrInvalidConstraint", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("GitHubAppPermissions: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("permissions = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("permissions[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestGrantValidationRejectsBadAppPermission checks that the typo is refused in
// front of the operator rather than eight hours later inside a lease — and that
// a github_pat grant, whose permissions nothing transmits, still accepts the
// free-form strings it always did.
func TestGrantValidationRejectsBadAppPermission(t *testing.T) {
	c := Constraints{Repos: []string{"org/*"}, Permissions: []string{"contents:maybe"}}
	if err := c.ValidateFor(KindGitHubApp); err == nil {
		t.Error("ValidateFor(github_app) accepted an unusable permission level")
	}
	if err := c.ValidateFor(KindGitHubPAT); err != nil {
		t.Errorf("ValidateFor(github_pat) rejected a free-form permission: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

// TestLeaseMintsScopedInstallationToken is the core of the task: GitHub, not a
// shell script, is what bounds an App credential.
func TestLeaseMintsScopedInstallationToken(t *testing.T) {
	gh := newFakeGitHub(
		InstallationRepo{ID: 1, FullName: "org/tool"},
		InstallationRepo{ID: 2, FullName: "org/service"},
		InstallationRepo{ID: 3, FullName: "other/private"},
	)
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	lease := leaseOnce(t, b)
	req := gh.deliveredCreate(t)

	if len(req.RepositoryIDs) != 1 || req.RepositoryIDs[0] != 1 {
		t.Errorf("repository_ids = %v, want just org/tool's id", req.RepositoryIDs)
	}
	if req.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v, want contents:read", req.Permissions)
	}
	if got := tokenFrom(t, lease); !strings.HasPrefix(got, "ghs_faketoken") {
		t.Errorf("delivered %q, want the minted installation token", got)
	}
}

// TestLeaseResolvesGlobAgainstInstallation: "org/*" is not something GitHub can
// be told, so it is resolved against the installation's own inventory — which
// is also what makes "other/private" unreachable rather than merely undesired.
func TestLeaseResolvesGlobAgainstInstallation(t *testing.T) {
	gh := newFakeGitHub(
		InstallationRepo{ID: 1, FullName: "org/tool"},
		InstallationRepo{ID: 2, FullName: "org/service"},
		InstallationRepo{ID: 3, FullName: "other/private"},
	)
	b, gh, _ := appBroker(t, []string{"org/*"}, nil, gh)

	leaseOnce(t, b)
	req := gh.deliveredCreate(t)
	if len(req.RepositoryIDs) != 2 {
		t.Fatalf("repository_ids = %v, want org/tool and org/service", req.RepositoryIDs)
	}
	for _, id := range req.RepositoryIDs {
		if id == 3 {
			t.Error("the token was scoped to other/private, which org/* does not cover")
		}
	}
}

// TestLeaseWritePermissionFollowsTheGrant: a grant that allows pushes gets
// contents:write, and one that does not gets read — so GitHub refuses the push
// rather than cloop asking the workload not to try.
func TestLeaseWritePermissionFollowsTheGrant(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/tool"}, []string{"contents:write"}, gh)

	leaseOnce(t, b)
	if got := gh.deliveredCreate(t).Permissions["contents"]; got != "write" {
		t.Errorf("contents = %q, want write", got)
	}
}

// TestLeaseAllowAllSkipsRepositoryScoping: "*" is the one allowlist that means
// the installation, so nothing is sent and no inventory lookup happens.
func TestLeaseAllowAllSkipsRepositoryScoping(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"*"}, nil, gh)

	leaseOnce(t, b)
	if req := gh.deliveredCreate(t); len(req.RepositoryIDs) != 0 {
		t.Errorf("repository_ids = %v, want none for an explicit '*' allowlist", req.RepositoryIDs)
	}
	if gh.lists != 0 {
		t.Errorf("enumerated the installation %d times for an allow-all grant", gh.lists)
	}
}

// TestLeaseFailsLoudlyOnScopeMismatch is the "do not mint a token that 404s at
// the first clone" case, in both of its shapes.
func TestLeaseFailsLoudlyOnScopeMismatch(t *testing.T) {
	t.Run("a named repository outside the installation", func(t *testing.T) {
		gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
		b, gh, _ := appBroker(t, []string{"org/absent"}, nil, gh)

		lease := leaseOnce(t, b)
		if !lease.Empty() {
			t.Fatal("a grant naming a repository outside the installation still delivered material")
		}
		// And the discovery token minted to find that out was destroyed, so a
		// refusal does not leave a live credential behind.
		if live := gh.liveTokens(); len(live) != 0 {
			t.Errorf("tokens still live after a denied grant: %v", live)
		}
	})

	t.Run("a pattern matching nothing", func(t *testing.T) {
		gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
		b, gh, _ := appBroker(t, []string{"nobody/*"}, nil, gh)

		if lease := leaseOnce(t, b); !lease.Empty() {
			t.Fatal("a grant whose allowlist matches nothing still delivered material")
		}
		if live := gh.liveTokens(); len(live) != 0 {
			t.Errorf("tokens still live after a denied grant: %v", live)
		}
	})
}

// TestSelectInstallationReposDistinguishesTheTwoFailures pins the error text,
// because the two cases call for opposite fixes and a generic "no repositories
// matched" is how an operator spends an hour editing the wrong side.
func TestSelectInstallationReposDistinguishesTheTwoFailures(t *testing.T) {
	inv := []InstallationRepo{{ID: 1, FullName: "org/tool"}}

	_, err := selectInstallationRepos(inv, Constraints{Repos: []string{"org/absent"}})
	if err == nil || !strings.Contains(err.Error(), "does not cover org/absent") {
		t.Errorf("named-repo error = %v; want it to name the missing repository", err)
	}
	if !errors.Is(err, ErrRepoDenied) {
		t.Errorf("err = %v; want ErrRepoDenied", err)
	}

	_, err = selectInstallationRepos(inv, Constraints{Repos: []string{"nobody/*"}})
	if err == nil || !strings.Contains(err.Error(), "matches the grant's allowlist") {
		t.Errorf("glob error = %v; want it to blame the pattern", err)
	}
}

// TestMintFailureDeniesRatherThanFallingBack is the guard against the fix
// regressing into its own bug: if GitHub cannot be reached, the grant is denied.
// Delivering the private key as a fallback would restore exactly the behaviour
// Task 20254 removed.
func TestMintFailureDeniesRatherThanFallingBack(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	gh.createErr = errors.New("github is unreachable")
	b, _, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	lease := leaseOnce(t, b)
	if !lease.Empty() {
		t.Fatalf("a failed mint still delivered %d material(s)", len(lease.Materials))
	}
}

// TestBrokerWithoutGitHubClientDeniesAppGrants covers the deployment shape a
// fallback would be most tempting in: a hub with no outbound access.
func TestBrokerWithoutGitHubClientDeniesAppGrants(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	b.appMinter = newGitHubAppMinter(nil, nil)

	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "prod-app", Kind: KindGitHubApp, Payload: appPayloadJSON(t),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: []string{"org/tool"}},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if lease := leaseOnce(t, b); !lease.Empty() {
		t.Fatal("a hub with no GitHub client delivered github_app material anyway")
	}
}

// ---------------------------------------------------------------------------
// The regression this task exists for
// ---------------------------------------------------------------------------

// TestAppPrivateKeyNeverLeaves is the guarantee in one assertion: no byte of the
// signing key reaches a lease's files or environment.
//
// The pre-Task-20254 code handed the whole payload over as the "token", so this
// fails loudly against it — the key would be sitting in github-token.
func TestAppPrivateKeyNeverLeaves(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, _, _ := appBroker(t, []string{"org/tool"}, nil, gh)
	lease := leaseOnce(t, b)

	// A distinctive middle slice of the PEM body: the BEGIN/END armour is
	// generic, but base64 of a real modulus appears nowhere by chance.
	key := appKeyPEM(t)
	needles := []string{key, keyBodyFragment(t, key)}

	for _, m := range lease.Materials {
		for _, f := range m.Files {
			for _, needle := range needles {
				if strings.Contains(string(f.Content), needle) {
					t.Fatalf("lease file %s contains the App private key", f.Name)
				}
			}
		}
		for k, v := range m.Env {
			for _, needle := range needles {
				if strings.Contains(v, needle) {
					t.Fatalf("lease env %s contains the App private key", k)
				}
			}
		}
		if strings.Contains(m.Summary, "PRIVATE KEY") {
			t.Fatalf("material summary leaks key material: %q", m.Summary)
		}
	}
}

// keyBodyFragment returns a chunk of a PEM's base64 body, which is unique to
// this key in a way the armour lines are not.
func keyBodyFragment(t *testing.T, pemText string) string {
	t.Helper()
	for _, line := range strings.Split(pemText, "\n") {
		if len(line) >= 40 && !strings.HasPrefix(line, "-----") {
			return line
		}
	}
	t.Fatal("no usable PEM body line")
	return ""
}

// ---------------------------------------------------------------------------
// Refresh and revoke
// ---------------------------------------------------------------------------

// TestRenewMintsFreshTokenAndKillsTheOld is what "refresh on renew before
// expiry" buys: the workload never holds an ageing token, and a long run does
// not accumulate one live credential per lease period.
func TestRenewMintsFreshTokenAndKillsTheOld(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	first := leaseOnce(t, b)
	firstToken := tokenFrom(t, first)

	renewed, err := b.Renew(context.Background(), first.ID)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	secondToken := tokenFrom(t, renewed)

	if firstToken == secondToken {
		t.Error("renewal re-delivered the same token instead of minting a fresh one")
	}
	if !gh.wasRevoked(firstToken) {
		t.Error("the pre-renewal token was not destroyed at GitHub")
	}
	if live := gh.liveTokens(); len(live) != 1 || live[0] != secondToken {
		t.Errorf("live tokens = %v, want only the renewed one", live)
	}
}

// TestReleaseDestroysTokenAtGitHub is the difference between revocation and
// forgetting: wiping the lease directory removes the copy on disk, and this
// removes the one GitHub would still honour.
func TestReleaseDestroysTokenAtGitHub(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	lease := leaseOnce(t, b)
	token := tokenFrom(t, lease)

	b.Release(lease.ID)
	if !gh.wasRevoked(token) {
		t.Fatal("Release left the installation token live at GitHub")
	}
	// Idempotent: a second Release must not re-revoke or panic.
	b.Release(lease.ID)
	if got := gh.revokeCount(token); got != 1 {
		t.Errorf("token revoked %d times, want exactly 1", got)
	}
}

// TestRevokeGrantDestroysLiveTokens: for every other kind, revocation lands at
// the next renewal and the short lease TTL is what bounds the gap. An App token
// is a credential the hub created, so it can end it now.
func TestRevokeGrantDestroysLiveTokens(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, g := appBroker(t, []string{"org/tool"}, nil, gh)

	lease := leaseOnce(t, b)
	token := tokenFrom(t, lease)

	if err := b.Revoke(context.Background(), g.ID, "operator"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !gh.wasRevoked(token) {
		t.Fatal("revoking the grant left its installation token live at GitHub")
	}
}

// TestDeleteSecretDestroysLiveTokens covers the incident-response path: deleting
// the App credential must not be the one withdrawal that leaves live tokens
// behind.
func TestDeleteSecretDestroysLiveTokens(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	token := tokenFrom(t, leaseOnce(t, b))
	if err := b.DeleteSecret(context.Background(), "prod-app", "operator"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if !gh.wasRevoked(token) {
		t.Fatal("deleting the secret left its installation token live at GitHub")
	}
}

// TestSweepExpiredDestroysTokens covers the executor that goes away without
// releasing — the case where a token would otherwise survive with nothing
// pointing at it.
func TestSweepExpiredDestroysTokens(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, _, _, clk := newTestBroker(t)
	gh.clock = clk.Now
	b.appMinter = newGitHubAppMinter(gh, clk.Now)

	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "prod-app", Kind: KindGitHubApp, Payload: appPayloadJSON(t),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: []string{"org/tool"}},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	token := tokenFrom(t, leaseOnce(t, b))
	clk.advance(DefaultMaxLeaseTTL + time.Minute)
	b.SweepExpired()

	if !gh.wasRevoked(token) {
		t.Fatal("an expired lease left its installation token live at GitHub")
	}
}

// TestRevokeFailureIsAudited: a token that outlives its lease is exactly what an
// operator responding to an incident needs told, so the failure lands in the
// audit trail rather than being swallowed by a cleanup path.
func TestRevokeFailureIsAudited(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, aud, clk := appBrokerWithAuditor(t, []string{"org/tool"}, gh)
	_ = clk

	lease := leaseOnce(t, b)
	gh.revokeErr = errors.New("github says no")
	b.Release(lease.ID)

	var found bool
	for _, ev := range aud.byAction(ActionAppTokenDestroy) {
		if ev.Decision == DecisionDeny && strings.Contains(ev.Reason, "stays live until") {
			found = true
		}
	}
	if !found {
		t.Fatal("a failed token revocation produced no denial in the audit trail")
	}
}

// appBrokerWithAuditor is appBroker with the recording auditor handed back.
func appBrokerWithAuditor(t *testing.T, repos []string, gh *fakeGitHub) (*Broker, *recordingAuditor, *fakeClock) {
	t.Helper()
	b, _, aud, clk := newTestBroker(t)
	gh.clock = clk.Now
	b.appMinter = newGitHubAppMinter(gh, clk.Now)

	sec, err := b.Mint(context.Background(), MintRequest{
		Name: "prod-app", Kind: KindGitHubApp, Payload: appPayloadJSON(t),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   sec.ID,
		Subject:     Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Repos: repos},
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return b, aud, clk
}

// ---------------------------------------------------------------------------
// Inventory caching
// ---------------------------------------------------------------------------

// TestInventoryIsCachedAcrossLeases: a 15-minute lease renewed through a long
// run must not re-enumerate the installation every time. The discovery token is
// still destroyed on the call that does fetch.
func TestInventoryIsCachedAcrossLeases(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/*"}, nil, gh)

	leaseOnce(t, b)
	leaseOnce(t, b)
	if gh.lists != 1 {
		t.Errorf("enumerated the installation %d times across two leases, want 1", gh.lists)
	}

	// Every discovery token is revoked; only the two delivered ones remain.
	if live := gh.liveTokens(); len(live) != 2 {
		t.Errorf("live tokens = %v, want the two delivered ones and no discovery token", live)
	}
}

// TestDiscoveryTokenIsMetadataOnly: the inventory lookup needs an installation
// token because GitHub offers no app-JWT route to the list. That token is
// installation-wide for an instant, so it must not be able to read a line of
// code.
func TestDiscoveryTokenIsMetadataOnly(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	b, gh, _ := appBroker(t, []string{"org/*"}, []string{"contents:write"}, gh)

	leaseOnce(t, b)
	gh.mu.Lock()
	defer gh.mu.Unlock()
	if len(gh.creates) != 2 {
		t.Fatalf("mint requests = %d, want a discovery token and a delivered one", len(gh.creates))
	}
	discovery := gh.creates[0]
	if len(discovery.Permissions) != 1 || discovery.Permissions["metadata"] != "read" {
		t.Errorf("discovery permissions = %v, want only metadata:read", discovery.Permissions)
	}
	if len(discovery.RepositoryIDs) != 0 {
		t.Errorf("discovery token was repo-scoped (%v); it cannot be, that is what it is for",
			discovery.RepositoryIDs)
	}
}

// TestTokenTooCloseToExpiryIsRefused guards the freshness check: a credential
// due to die before the lease carrying it would fail a run halfway through,
// with an authentication error nobody can trace back to here.
func TestTokenTooCloseToExpiryIsRefused(t *testing.T) {
	gh := newFakeGitHub(InstallationRepo{ID: 1, FullName: "org/tool"})
	gh.lifetime = time.Minute
	b, gh, _ := appBroker(t, []string{"org/tool"}, nil, gh)

	if lease := leaseOnce(t, b); !lease.Empty() {
		t.Fatal("a token expiring in a minute was delivered anyway")
	}
	if live := gh.liveTokens(); len(live) != 0 {
		t.Errorf("refused token left live at GitHub: %v", live)
	}
}
