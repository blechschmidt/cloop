package ciworkflow_test

// github_test.go plays the two GitHub services a workflow step touches when it
// federates: the OIDC issuer the hub verifies against, and the runner's
// ID-token endpoint the step asks for a token.
//
// On GitHub those are different hosts — token.actions.githubusercontent.com
// issues and publishes keys, while $ACTIONS_ID_TOKEN_REQUEST_URL points at the
// pipelines service that mints on the job's behalf. Here one server does both,
// which nothing downstream can observe: the hub only ever talks to the issuer,
// and the step only ever talks to the request URL.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint (RFC 7517 §4.8)
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// idTokenPath is the request URL's path, shaped like the pipelines service's.
// The query string it is handed out with already carries api-version, which is
// why the workflow appends `&audience=…` rather than `?audience=…`; a request
// URL without one would let a step that got that wrong pass here and fail on
// GitHub.
const idTokenPath = "/_apis/distributedtask/hubs/Actions/plans/7d1b0f9c-plan/jobs/5c3e8a21-job/idtoken"

// jobIdentity is who the job is, as GitHub's claims describe it. The runner
// derives its GITHUB_* variables from the same values, so the token and the
// environment cannot disagree about which job is running.
type jobIdentity struct {
	Repository  string // owner/name
	RepoID      string
	OwnerID     string
	Ref         string
	SHA         string
	Workflow    string // display name
	WorkflowRef string // owner/name/.github/workflows/file.yml@ref
	Actor       string
	ActorID     string
	EventName   string
	RunID       string
	RunNumber   string
	RunAttempt  string
	Environment string // empty: the job declares none
}

func (j jobIdentity) owner() string {
	owner, _, _ := strings.Cut(j.Repository, "/")
	return owner
}

// subject is GitHub's `sub`, whose shape depends on the job's context.
func (j jobIdentity) subject() string {
	switch {
	case j.Environment != "":
		return "repo:" + j.Repository + ":environment:" + j.Environment
	case j.EventName == "pull_request":
		return "repo:" + j.Repository + ":pull_request"
	default:
		return "repo:" + j.Repository + ":ref:" + j.Ref
	}
}

// defaultJob is the pipeline the guide's examples are about.
func defaultJob() jobIdentity {
	return jobIdentity{
		Repository:  "acme/tool",
		RepoID:      "123456",
		OwnerID:     "654321",
		Ref:         "refs/heads/main",
		SHA:         "", // filled in from the checkout the runner makes
		Workflow:    "Review",
		WorkflowRef: "acme/tool/.github/workflows/review.yml@refs/heads/main",
		Actor:       "dana",
		ActorID:     "4242",
		EventName:   "push",
		RunID:       "9876543210",
		RunNumber:   "17",
		RunAttempt:  "1",
	}
}

// idTokenRequest is one call the job made to the request URL.
type idTokenRequest struct {
	Audience    string
	HasAudience bool
	APIVersion  string
	Authorized  bool
	Token       string // what was issued, "" when refused
}

// fakeGitHub is the issuer and the ID-token endpoint.
type fakeGitHub struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
	x5t string

	// requestToken is $ACTIONS_ID_TOKEN_REQUEST_TOKEN: the bearer the runner
	// hands a job that declared `id-token: write`, and nothing else.
	requestToken string

	mu       sync.Mutex
	job      jobIdentity
	requests []idTokenRequest
	fetches  map[string]int // discovery and key-set fetches, by path
}

func newFakeGitHub(t *testing.T, pki *testPKI) *fakeGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	g := &fakeGitHub{
		t:            t,
		key:          key,
		requestToken: "ghrt_" + randHex(t, 24),
		job:          defaultJob(),
		fetches:      map[string]int{},
	}
	// GitHub publishes its keys with a kid and an x5t, both derived from the
	// certificate behind the key. Only the kid is load-bearing for the hub.
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal issuer key: %v", err)
	}
	sum := sha1.Sum(pub) //nolint:gosec // thumbprint, not a security boundary
	g.kid = strings.ToUpper(hex.EncodeToString(sum[:]))
	g.x5t = b64(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", g.serveDiscovery)
	mux.HandleFunc("GET /.well-known/jwks", g.serveJWKS)
	mux.HandleFunc("GET "+idTokenPath, g.serveIDToken)
	g.srv = httptest.NewUnstartedServer(mux)
	g.srv.TLS = pki.serverTLS()
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("randomness: %v", err)
	}
	return hex.EncodeToString(b)
}

// issuer is the `iss` this fake stamps, and what the hub is configured with.
func (g *fakeGitHub) issuer() string { return g.srv.URL }

// requestURL is $ACTIONS_ID_TOKEN_REQUEST_URL.
func (g *fakeGitHub) requestURL() string { return g.srv.URL + idTokenPath + "?api-version=2.0" }

func (g *fakeGitHub) setJob(j jobIdentity) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.job = j
}

func (g *fakeGitHub) currentJob() jobIdentity {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.job
}

// idTokenRequests returns the calls made to the request URL, in order.
func (g *fakeGitHub) idTokenRequests() []idTokenRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]idTokenRequest(nil), g.requests...)
}

// keyFetches reports how often the hub fetched discovery and the key set.
func (g *fakeGitHub) keyFetches() (discovery, jwks int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fetches["discovery"], g.fetches["jwks"]
}

func (g *fakeGitHub) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	g.fetches["discovery"]++
	g.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                g.issuer(),
		"jwks_uri":                              g.issuer() + "/.well-known/jwks",
		"subject_types_supported":               []string{"public", "pairwise"},
		"response_types_supported":              []string{"id_token"},
		"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "ref", "repository", "repository_id", "repository_owner", "repository_owner_id", "run_id", "run_number", "run_attempt", "actor", "actor_id", "workflow", "workflow_ref", "workflow_sha", "head_ref", "base_ref", "event_name", "ref_type", "ref_protected", "environment", "job_workflow_ref", "job_workflow_sha", "repository_visibility", "runner_environment"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid"},
	})
}

func (g *fakeGitHub) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	g.fetches["jwks"]++
	g.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "alg": "RS256", "use": "sig",
		"kid": g.kid, "x5t": g.x5t,
		"n": b64(g.key.N.Bytes()),
		"e": b64(big.NewInt(int64(g.key.E)).Bytes()),
	}}})
}

// serveIDToken mints a token the way the pipelines service does for a job
// that declared `permissions: id-token: write`.
func (g *fakeGitHub) serveIDToken(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := idTokenRequest{
		APIVersion:  q.Get("api-version"),
		Audience:    q.Get("audience"),
		HasAudience: q.Has("audience"),
	}
	// The runtime accepts the scheme in either case; the documented
	// workflow happens to send "Bearer".
	scheme, cred, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	req.Authorized = strings.EqualFold(scheme, "bearer") && cred == g.requestToken
	defer func() {
		g.mu.Lock()
		g.requests = append(g.requests, req)
		g.mu.Unlock()
	}()
	if !req.Authorized {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "Bad credentials"})
		return
	}
	if req.APIVersion != "2.0" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "api-version is required"})
		return
	}
	job := g.currentJob()
	aud := req.Audience
	if !req.HasAudience {
		// GitHub's default audience is the owner's URL, which is exactly why
		// a hub cannot rely on it: every job of that owner gets the same one.
		aud = "https://github.com/" + job.owner()
	}
	req.Token = g.sign(job, aud)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(req.Token), "value": req.Token})
}

// sign mints an RS256 token for job. Every claim GitHub sends as a string is
// a string here, the numeric ids included; only the JWT time claims are
// numbers. A fake that sent `"run_id": 42` would pass rules GitHub's tokens
// cannot.
func (g *fakeGitHub) sign(job jobIdentity, aud string) string {
	now := time.Now()
	claims := map[string]any{
		"jti":                   newUUID(g.t),
		"sub":                   job.subject(),
		"aud":                   aud,
		"iss":                   g.issuer(),
		"ref":                   job.Ref,
		"ref_protected":         "false",
		"ref_type":              "branch",
		"sha":                   job.SHA,
		"repository":            job.Repository,
		"repository_id":         job.RepoID,
		"repository_owner":      job.owner(),
		"repository_owner_id":   job.OwnerID,
		"repository_visibility": "private",
		"run_id":                job.RunID,
		"run_number":            job.RunNumber,
		"run_attempt":           job.RunAttempt,
		"runner_environment":    "github-hosted",
		"actor":                 job.Actor,
		"actor_id":              job.ActorID,
		"workflow":              job.Workflow,
		"workflow_ref":          job.WorkflowRef,
		"workflow_sha":          job.SHA,
		"job_workflow_ref":      job.WorkflowRef,
		"job_workflow_sha":      job.SHA,
		"head_ref":              "",
		"base_ref":              "",
		"event_name":            job.EventName,
		// GitHub backdates nbf and gives the token five minutes.
		"nbf": now.Add(-10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	if !strings.Contains(job.WorkflowRef, "@") {
		g.t.Errorf("job workflow_ref %q has no @ref, which GitHub's always does", job.WorkflowRef)
	}
	if job.Environment != "" {
		claims["environment"] = job.Environment
	}
	hdr, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "RS256", "kid": g.kid, "x5t": g.x5t})
	body, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(body)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	if err != nil {
		g.t.Errorf("sign: %v", err)
		return ""
	}
	return signing + "." + b64(sig)
}

func newUUID(t *testing.T) string {
	h := randHex(t, 16)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// decodeClaims reads a token's payload without verifying it — for assertions
// about what the fake issued, never for trust.
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	return claims
}

// String renders a request for failure messages. It never includes a token.
func (r idTokenRequest) String() string {
	return fmt.Sprintf("audience=%q (present %v) api-version=%q authorized=%v issued=%v",
		r.Audience, r.HasAudience, r.APIVersion, r.Authorized, r.Token != "")
}
