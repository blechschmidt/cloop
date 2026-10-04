package secretbroker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHub App installation tokens.
//
// The point of this file is that github_app is the one GitHub credential kind
// GitHub itself can narrow. A PAT cannot be reshaped after it is issued, which
// is why github_pat delivery falls back to a credential helper that withholds
// the token for repositories outside the allowlist (see githubpat.go) — real
// enforcement, but enforcement that binds `git` rather than the workload.
//
// An App is different: the stored payload is a *signing key*, and the thing the
// sandbox needs is a token minted from it. So the hub signs a short app JWT,
// asks GitHub for an installation token narrowed to exactly the grant's
// repositories and permissions, and delivers only that. The workload receives a
// credential that expires in an hour and that GitHub will refuse to use outside
// the grant, whatever the workload does with it.
//
// Which makes the pre-Task-20254 behaviour strictly worse than a PAT rather
// than better: folding KindGitHubApp into the PAT branch handed the sandbox the
// App's private key, which never expires and can mint tokens for every
// repository in the installation. The key now never leaves this process.
//
// Everything that talks to GitHub goes through GitHubAppAPI so tests are
// hermetic. Nothing in this file reaches the network directly.

// appJWTLifetime is how long the app JWT the hub signs is valid for.
//
// GitHub rejects a JWT whose exp is more than ten minutes after its iat, and
// the iat is backdated by appJWTBackdate to absorb clock skew between this host
// and GitHub's. 8 minutes + 1 minute of backdating is 9, which leaves a minute
// of headroom against that limit rather than sitting exactly on it.
const appJWTLifetime = 8 * time.Minute

// appJWTBackdate shifts iat into the past. A hub whose clock runs a few seconds
// fast would otherwise present a token GitHub considers issued in the future.
const appJWTBackdate = time.Minute

// appTokenMinLifetime is the shortest remaining lifetime a minted installation
// token may have and still be handed to a workload.
//
// It is a sanity floor, not the refresh mechanism. Refreshing is Renew's job and
// it does it by minting a *new* token rather than extending the old one, so a
// delivered token always has GitHub's full hour ahead of it. This catches the
// cases where that is not true — a badly skewed hub clock, or GitHub returning
// something unexpected — before a run inherits a credential due to die halfway
// through it.
const appTokenMinLifetime = 5 * time.Minute

// appInventoryTTL is how long an installation's repository list is cached.
//
// Staleness can only narrow: a repository added to the installation is
// unreachable until the entry lapses, and a repository removed from it is one
// GitHub will refuse to scope a token to regardless of what this cache still
// remembers. Both directions fail closed, which is what makes caching a
// security-relevant list acceptable at all.
const appInventoryTTL = 10 * time.Minute

// appRevokeTimeout bounds the DELETE that destroys a token at the source.
//
// Release carries no context — it is called from executor cleanup paths that
// have already finished their work — so the revocation gets its own deadline.
// Short, because a hub blocking on api.github.com while a task teardown waits
// is a worse failure than a token that lapses on GitHub's own hour.
const appRevokeTimeout = 10 * time.Second

// defaultGitHubBaseURL is the public API. A GitHub Enterprise Server
// installation overrides it with base_url in the payload.
const defaultGitHubBaseURL = "https://api.github.com"

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

// AppCredential is a parsed, validated github_app payload.
//
// The private key is unexported and there is no accessor: the only thing any
// caller may do with an AppCredential is ask it to sign a JWT, which is what
// keeps "the key never leaves the hub" a property of the type rather than a
// convention.
type AppCredential struct {
	AppID          int64
	InstallationID int64
	// BaseURL is the API root, defaulted to github.com.
	BaseURL string

	key *rsa.PrivateKey
}

// appPayload is the wire shape of a github_app secret.
type appPayload struct {
	AppID          appNumber `json:"app_id"`
	InstallationID appNumber `json:"installation_id"`
	PrivateKey     string    `json:"private_key"`
	BaseURL        string    `json:"base_url,omitempty"`
}

// appNumber accepts a JSON number or a decimal string, because GitHub's own UI
// shows the App ID as text and half the people pasting one will quote it. It
// still refuses anything that is not an integer — a float, an empty string, a
// name — which is what the task asks for.
type appNumber int64

func (n *appNumber) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		return errors.New("is null")
	}
	s = strings.Trim(s, `"`)
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("is empty")
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("%q is not an integer", s)
	}
	*n = appNumber(v)
	return nil
}

// ParseGitHubApp parses and validates a github_app payload.
//
// It is deliberately strict. Before Task 20254 the payload was free-form — the
// broker never looked at it, so a typo, a PEM with a mangled line ending, or a
// PAT pasted into the wrong kind was stored happily and failed at lease time,
// during someone else's run. Now the only accepted shape is
//
//	{"app_id": 123, "installation_id": 456, "private_key": "-----BEGIN ..."}
//
// with an optional "base_url" for GitHub Enterprise Server. Both IDs must be
// integers and the key must parse as RSA, because RS256 is the only algorithm
// GitHub accepts for an app JWT.
func ParseGitHubApp(payload []byte) (*AppCredential, error) {
	return parseGitHubApp(payload, true)
}

// ParseGitHubAppConnection parses the half of a github_app payload that exists
// before the App's installation is known: the App ID and the signing key.
//
// It is what discovery runs on. An operator configuring cloop has just come
// from GitHub's App settings page, which shows an App ID and offers a key
// download, and has no installation ID because that is a property of the
// *install*, not of the App. The credential this returns can sign an app JWT —
// enough to ask GitHub where the App is installed — and nothing else: its
// InstallationID is zero, so mint refuses it (see mint's guard) and it can
// never be stored as a working secret by mistake.
//
// Everything else is validated exactly as ParseGitHubApp validates it, so a
// malformed key is reported in the connect dialog rather than at the next step.
func ParseGitHubAppConnection(payload []byte) (*AppCredential, error) {
	return parseGitHubApp(payload, false)
}

func parseGitHubApp(payload []byte, requireInstallation bool) (*AppCredential, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, wrapf(ErrMalformedPayload, "github_app payload is empty")
	}
	if trimmed[0] != '{' {
		return nil, wrapf(ErrMalformedPayload,
			"github_app payload must be a JSON object with app_id, installation_id and private_key "+
				"(a bare token belongs to kind github_pat)")
	}

	var p appPayload
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	// Unknown fields are refused rather than ignored: "app-id" and "appId" are
	// the two spellings anyone writing this by hand reaches for, and silently
	// dropping either would leave the error as "app_id is missing" on a payload
	// that visibly contains one.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, wrapf(ErrMalformedPayload, "github_app payload: %v", err)
	}
	if p.AppID <= 0 {
		return nil, wrapf(ErrMalformedPayload, "github_app payload: app_id must be a positive integer")
	}
	switch {
	case requireInstallation && p.InstallationID <= 0:
		return nil, wrapf(ErrMalformedPayload,
			"github_app payload: installation_id must be a positive integer "+
				"(the hub can discover it from the App ID and key — see the Connect GitHub App dialog)")
	case !requireInstallation && p.InstallationID < 0:
		// Absent is the point of this path; negative is still a typo.
		return nil, wrapf(ErrMalformedPayload,
			"github_app payload: installation_id must be a positive integer")
	}

	// Structural fields before the crypto: a bad base_url is cheaper to detect
	// and is the field that decides *which host* receives an assertion of this
	// hub's identity, so it is worth refusing before anything is parsed with a
	// key in hand.
	base, err := normalizeAPIBaseURL(p.BaseURL)
	if err != nil {
		return nil, err
	}

	key, err := parseRSAPrivateKey(p.PrivateKey)
	if err != nil {
		return nil, wrapf(ErrMalformedPayload, "github_app payload: private_key %v", err)
	}

	return &AppCredential{
		AppID:          int64(p.AppID),
		InstallationID: int64(p.InstallationID),
		BaseURL:        base,
		key:            key,
	}, nil
}

// parseRSAPrivateKey accepts the two PEM shapes GitHub hands out: PKCS#1
// ("BEGIN RSA PRIVATE KEY", what the download button produces) and PKCS#8
// ("BEGIN PRIVATE KEY", what openssl produces from it).
//
// The error messages name the shape rather than echoing the input, because the
// input is a private key and this error will end up in a terminal, a log, or an
// issue.
func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	text := strings.TrimSpace(pemText)
	if text == "" {
		return nil, errors.New("is missing")
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("is not PEM (expected a -----BEGIN ... PRIVATE KEY----- block)")
	}
	switch {
	case strings.Contains(block.Type, "RSA PRIVATE KEY"):
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("is not a valid PKCS#1 RSA key: %v", err)
		}
		return key, validateRSAKey(key)
	case strings.Contains(block.Type, "PRIVATE KEY"):
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("is not a valid PKCS#8 key: %v", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("is a %T, but GitHub app JWTs are RS256 and need an RSA key", parsed)
		}
		return key, validateRSAKey(key)
	default:
		return nil, fmt.Errorf("has PEM type %q, want an RSA private key", block.Type)
	}
}

// validateRSAKey rejects a key too small to sign anything GitHub will accept.
// GitHub issues 2048-bit keys; anything under 2048 is either a test artefact or
// a key that should have been rotated years ago.
func validateRSAKey(key *rsa.PrivateKey) error {
	if key == nil {
		return errors.New("is empty")
	}
	if bits := key.N.BitLen(); bits < 2048 {
		return fmt.Errorf("is a %d-bit RSA key; GitHub app keys are at least 2048-bit", bits)
	}
	return key.Validate()
}

// normalizeAPIBaseURL canonicalises the optional base_url. https only, no path
// beyond a prefix, no credentials: this value selects which host receives a
// signed assertion of the hub's identity, so it is a trust decision and not a
// convenience field.
func normalizeAPIBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultGitHubBaseURL, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", wrapf(ErrMalformedPayload, "github_app payload: base_url is not a URL: %v", err)
	}
	if u.Scheme != "https" {
		return "", wrapf(ErrMalformedPayload,
			"github_app payload: base_url must be https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return "", wrapf(ErrMalformedPayload, "github_app payload: base_url has no host")
	}
	if u.User != nil {
		return "", wrapf(ErrMalformedPayload, "github_app payload: base_url must not carry credentials")
	}
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

// cacheKey identifies one installation for the inventory cache. It contains no
// key material — an app ID and an installation ID are both public identifiers.
func (c *AppCredential) cacheKey() string {
	return c.BaseURL + "|" + strconv.FormatInt(c.AppID, 10) + "|" + strconv.FormatInt(c.InstallationID, 10)
}

// signJWT mints the short-lived assertion that authenticates the *app* (not an
// installation) to GitHub. RS256, because that is the only algorithm GitHub
// accepts here.
func (c *AppCredential) signJWT(now time.Time) (string, error) {
	if c == nil || c.key == nil {
		return "", wrapf(ErrMalformedPayload, "github app credential has no signing key")
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-appJWTBackdate).Unix(),
		"exp": now.Add(appJWTLifetime).Unix(),
		"iss": strconv.FormatInt(c.AppID, 10),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("secretbroker: encode app jwt header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("secretbroker: encode app jwt claims: %w", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("secretbroker: sign app jwt: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ---------------------------------------------------------------------------
// The GitHub surface, behind an interface
// ---------------------------------------------------------------------------

// InstallationRepo is one repository an installation covers.
type InstallationRepo struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// AppInstallation is one place an App has been installed: an organisation or a
// user account.
//
// It exists because an installation ID is the one field of a github_app payload
// that the person configuring it does not have. GitHub hands out an App ID and
// a private key on the App's own settings page; the installation is created
// afterwards, by whoever installs the App on their org, and its ID appears only
// in the URL of a settings page that person may never visit. Asking an operator
// to go and find it — as this package did before Task 20306 — is asking them to
// read a number out of a browser address bar, which is exactly the kind of step
// that gets guessed wrong and surfaces as a 404 at lease time.
//
// So the hub asks GitHub instead. Nothing here is a secret: an App ID, an
// installation ID and an account name are all public identifiers, which is what
// makes it safe to show the whole list in a dialog.
type AppInstallation struct {
	// ID is the installation_id a github_app payload needs.
	ID int64 `json:"id"`
	// AppID is the app the installation belongs to. Echoed back so a caller
	// holding several keys can tell which one produced this list.
	AppID int64 `json:"app_id"`
	// Account is the org or user the App is installed on ("bb-selforg").
	Account string `json:"account"`
	// AccountType is "Organization" or "User".
	AccountType string `json:"account_type"`
	// RepositorySelection is "all" or "selected" — whether the installation
	// covers every repository the account owns or an explicitly chosen subset.
	// An operator who granted "all" and still cannot reach a repository has a
	// different problem from one who granted "selected" and forgot to tick it.
	RepositorySelection string `json:"repository_selection"`
}

// InstallationTokenRequest is a mint request. Zero-valued scoping fields mean
// "the whole installation", which is why every caller here sets one unless the
// grant's allowlist is explicitly "*".
type InstallationTokenRequest struct {
	// BaseURL and AppJWT authenticate the request as the app.
	BaseURL string
	AppJWT  string
	// InstallationID names the installation to mint for.
	InstallationID int64
	// RepositoryIDs narrows the token to these repositories. IDs rather than
	// names: a name is ambiguous across the owners an installation may span,
	// and an ID cannot be made to mean a different repository by a rename.
	RepositoryIDs []int64
	// Permissions narrows what the token may do. Nil asks for the
	// installation's full permission set.
	Permissions map[string]string
}

// InstallationToken is what GitHub minted.
type InstallationToken struct {
	Token               string            `json:"token"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Permissions         map[string]string `json:"permissions,omitempty"`
	RepositorySelection string            `json:"repository_selection,omitempty"`
}

// String redacts the token so a %v on a mint result cannot log a credential.
func (t InstallationToken) String() string {
	return fmt.Sprintf("installation token (%d bytes, expires %s) [redacted]",
		len(t.Token), t.ExpiresAt.UTC().Format(time.RFC3339))
}

// GoString mirrors String so %#v is redacted too.
func (t InstallationToken) GoString() string { return t.String() }

// GitHubAppAPI is every call this package makes to GitHub.
//
// It exists so the mint/refresh/revoke logic can be tested without a network,
// and so that a hub operator reading this file can see the complete list of
// what cloop asks GitHub for on their behalf: mint a scoped token, enumerate
// the installation, destroy a token.
type GitHubAppAPI interface {
	// CreateInstallationToken mints an installation access token.
	CreateInstallationToken(ctx context.Context, req InstallationTokenRequest) (InstallationToken, error)
	// ListInstallationRepos enumerates the repositories the *token* reaches.
	// It is authenticated with an installation token, not the app JWT —
	// GitHub offers no app-JWT route to this list.
	ListInstallationRepos(ctx context.Context, baseURL, installationToken string) ([]InstallationRepo, error)
	// RevokeInstallationToken destroys the token used to authenticate the
	// call. After it returns nil the credential is dead at GitHub, not merely
	// deleted from a sandbox's disk.
	RevokeInstallationToken(ctx context.Context, baseURL, installationToken string) error
	// ListAppInstallations enumerates where the App is installed. It is
	// authenticated with the app JWT rather than an installation token —
	// it is the one call that runs before any installation is known, which is
	// the whole reason it exists.
	ListAppInstallations(ctx context.Context, baseURL, appJWT string) ([]AppInstallation, error)
}

// ---------------------------------------------------------------------------
// HTTP implementation
// ---------------------------------------------------------------------------

// httpGitHubApp is the production GitHubAppAPI.
type httpGitHubApp struct{ client *http.Client }

// defaultGitHubAppAPI is the API a Broker uses unless WithGitHubApp overrides
// it. The timeout is per-request and generous enough for a paged listing on a
// large installation without letting a hung connection hold a lease open.
var defaultGitHubAppAPI GitHubAppAPI = &httpGitHubApp{
	client: &http.Client{Timeout: 30 * time.Second},
}

// maxRepoPages bounds the installation listing. 100 per page × 50 pages is
// 5,000 repositories, past which an allowlist of concrete names is the right
// answer anyway — and an unbounded loop against a paginating API is how a hub
// spends an afternoon on one lease.
const maxRepoPages = 50

func (h *httpGitHubApp) do(ctx context.Context, method, url, auth string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, fmt.Errorf("secretbroker: build github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return h.client.Do(req)
}

func (h *httpGitHubApp) CreateInstallationToken(ctx context.Context, req InstallationTokenRequest) (InstallationToken, error) {
	payload := struct {
		RepositoryIDs []int64           `json:"repository_ids,omitempty"`
		Permissions   map[string]string `json:"permissions,omitempty"`
	}{RepositoryIDs: req.RepositoryIDs, Permissions: req.Permissions}
	body, err := json.Marshal(payload)
	if err != nil {
		return InstallationToken{}, fmt.Errorf("secretbroker: encode token request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", req.BaseURL, req.InstallationID)
	resp, err := h.do(ctx, http.MethodPost, endpoint, req.AppJWT, body)
	if err != nil {
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "create installation token: %v", err)
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		message, described := readGitHubError(resp)
		if githubRefusal(resp.StatusCode, resp.Header, message) {
			return InstallationToken{}, fmt.Errorf("%w: %w: create installation token: %s",
				ErrGitHubAppMint, ErrGitHubAppRefused, described)
		}
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "create installation token: %s", described)
	}
	var tok InstallationToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "decode installation token: %v", err)
	}
	if strings.TrimSpace(tok.Token) == "" {
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "github returned an empty installation token")
	}
	return tok, nil
}

func (h *httpGitHubApp) ListInstallationRepos(ctx context.Context, baseURL, token string) ([]InstallationRepo, error) {
	var out []InstallationRepo
	for page := 1; page <= maxRepoPages; page++ {
		endpoint := fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", baseURL, page)
		resp, err := h.do(ctx, http.MethodGet, endpoint, token, nil)
		if err != nil {
			return nil, wrapf(ErrGitHubAppMint, "list installation repositories: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			err := wrapf(ErrGitHubAppMint, "list installation repositories: %s", describeGitHubError(resp))
			drainClose(resp)
			return nil, err
		}
		var body struct {
			TotalCount   int                `json:"total_count"`
			Repositories []InstallationRepo `json:"repositories"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body)
		drainClose(resp)
		if derr != nil {
			return nil, wrapf(ErrGitHubAppMint, "decode installation repositories: %v", derr)
		}
		out = append(out, body.Repositories...)
		if len(body.Repositories) == 0 || len(out) >= body.TotalCount {
			break
		}
	}
	return out, nil
}

// maxInstallationPages bounds the installation listing for the same reason
// maxRepoPages bounds the repository one. An App installed on more than 5,000
// accounts is not a configuration this dialog can help with anyway.
const maxInstallationPages = 50

func (h *httpGitHubApp) ListAppInstallations(ctx context.Context, baseURL, appJWT string) ([]AppInstallation, error) {
	// GitHub's wire shape nests the account, and names the same field
	// differently for an org and a user, so it is decoded into a local type
	// rather than onto AppInstallation directly.
	type wireInstallation struct {
		ID      int64 `json:"id"`
		AppID   int64 `json:"app_id"`
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
		RepositorySelection string `json:"repository_selection"`
	}

	var out []AppInstallation
	for page := 1; page <= maxInstallationPages; page++ {
		endpoint := fmt.Sprintf("%s/app/installations?per_page=100&page=%d", baseURL, page)
		resp, err := h.do(ctx, http.MethodGet, endpoint, appJWT, nil)
		if err != nil {
			return nil, wrapf(ErrGitHubAppMint, "list app installations: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			err := wrapf(ErrGitHubAppMint, "list app installations: %s", describeGitHubError(resp))
			drainClose(resp)
			return nil, err
		}
		var page0 []wireInstallation
		derr := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&page0)
		drainClose(resp)
		if derr != nil {
			return nil, wrapf(ErrGitHubAppMint, "decode app installations: %v", derr)
		}
		for _, w := range page0 {
			out = append(out, AppInstallation{
				ID:                  w.ID,
				AppID:               w.AppID,
				Account:             w.Account.Login,
				AccountType:         w.Account.Type,
				RepositorySelection: w.RepositorySelection,
			})
		}
		// This endpoint carries no total_count, so a short page is the only
		// end-of-list signal there is.
		if len(page0) < 100 {
			break
		}
	}
	return out, nil
}

func (h *httpGitHubApp) RevokeInstallationToken(ctx context.Context, baseURL, token string) error {
	resp, err := h.do(ctx, http.MethodDelete, baseURL+"/installation/token", token, nil)
	if err != nil {
		return wrapf(ErrGitHubAppRevoke, "revoke installation token: %v", err)
	}
	defer drainClose(resp)
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusNotFound:
		// The token is already dead — expired, or revoked by a concurrent
		// path. That is the end state this call exists to reach, so reporting
		// it as a failure would make an operator chase a credential that is
		// gone.
		return nil
	default:
		return wrapf(ErrGitHubAppRevoke, "revoke installation token: %s", describeGitHubError(resp))
	}
}

// drainClose consumes and closes a response body so the connection can be
// reused rather than torn down after every call.
func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}

// githubRefusal reports whether a failed mint is GitHub saying no for good, as
// opposed to GitHub being unreachable, busy or briefly unwilling (Task 20375).
//
// The difference decides what a refresh does next. A refusal ends the grant's
// access the way a revocation does — its tokens destroyed, a proxy session
// closed — while anything else is retried and the token already held keeps
// working. Getting it wrong in the refusal direction cuts a long run off over
// something that would have cleared in a minute, so the answer is "refused"
// only where GitHub's own words say the authority is gone:
//
//   - 404: the installation is gone (uninstalled).
//   - 422: the request names repositories or permissions the installation no
//     longer covers — a repository removed from it, a permission withdrawn.
//   - 403 naming a suspension ("This installation has been suspended"). Every
//     other 403 — a secondary rate limit, which GitHub does not always mark
//     with Retry-After or an exhausted X-RateLimit-Remaining, an abuse
//     detection — may pass.
//   - 401, unless GitHub objects to the JWT's timing ("'iat' claim", "'exp'
//     claim"), which is this hub's clock and not the App: otherwise the App's
//     key or the App itself is gone.
//
// 429 and every 5xx are retried.
func githubRefusal(status int, header http.Header, message string) bool {
	msg := strings.ToLower(message)
	switch status {
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return true
	case http.StatusForbidden:
		if strings.TrimSpace(header.Get("Retry-After")) != "" ||
			strings.TrimSpace(header.Get("X-RateLimit-Remaining")) == "0" {
			return false
		}
		return strings.Contains(msg, "suspended")
	case http.StatusUnauthorized:
		for _, timing := range []string{"claim", "'iat'", "'exp'", "issued at", "expiration time"} {
			if strings.Contains(msg, timing) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// readGitHubError reads a failed response once and returns GitHub's own
// "message" field, if there was one, and the rendering describeGitHubError
// gives it.
func readGitHubError(resp *http.Response) (message, described string) {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &parsed) == nil && strings.TrimSpace(parsed.Message) != "" {
		message = strings.TrimSpace(parsed.Message)
		return message, fmt.Sprintf("github returned %s: %s", resp.Status, message)
	}
	excerpt := strings.TrimSpace(string(raw))
	if len(excerpt) > 200 {
		excerpt = excerpt[:200] + "…"
	}
	if excerpt == "" {
		return "", "github returned " + resp.Status
	}
	return excerpt, fmt.Sprintf("github returned %s: %s", resp.Status, excerpt)
}

// describeGitHubError renders a failed response for an error message: the
// status plus GitHub's own "message" field when there is one.
//
// The excerpt is bounded and taken from the *response*, never the request: a
// request body carries the JWT, and an error string is the single most likely
// place for a credential to escape into a ticket.
func describeGitHubError(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &parsed) == nil && strings.TrimSpace(parsed.Message) != "" {
		return fmt.Sprintf("github returned %s: %s", resp.Status, strings.TrimSpace(parsed.Message))
	}
	excerpt := strings.TrimSpace(string(raw))
	if len(excerpt) > 200 {
		excerpt = excerpt[:200] + "…"
	}
	if excerpt == "" {
		return "github returned " + resp.Status
	}
	return fmt.Sprintf("github returned %s: %s", resp.Status, excerpt)
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

// appPermissionLevels are the values GitHub accepts for a permission.
var appPermissionLevels = map[string]bool{"read": true, "write": true, "admin": true}

// GitHubAppPermissions maps a grant's permission set onto the permissions
// object of an installation token request.
//
// The default is contents:read, because a github credential in cloop exists to
// clone, and a grant that says nothing about permissions has authorised nothing
// more than reading. A grant that allows a write to contents gets
// contents:write, so a push works and nothing else widens.
//
// A "*" entry returns nil, which asks GitHub for the installation's full
// permission set. That is the same reading allowsAllRepos gives the repository
// allowlist: the wildcard has to be written out, and when it is, it means it.
//
// The error is the reason this is exported to Constraints.ValidateFor as well
// as used at mint time: "pull_requests:maybe" is a typo that should be refused
// in front of the operator who wrote it, not eight hours later inside a lease.
func GitHubAppPermissions(c Constraints) (map[string]string, error) {
	perms := map[string]string{"contents": "read"}
	for _, raw := range c.Permissions {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return nil, nil
		}
		scope, level, found := strings.Cut(entry, ":")
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, wrapf(ErrInvalidConstraint,
				"github_app permission %q has no scope (want scope:level, e.g. contents:write)", raw)
		}
		if !found {
			// A bare scope covers both levels for AllowsPermission (see
			// constraints.go), so it has to mean the wider one here or the two
			// matchers would disagree about what the grant authorised.
			level = "write"
		}
		level = strings.TrimSpace(level)
		if !appPermissionLevels[level] {
			return nil, wrapf(ErrInvalidConstraint,
				"github_app permission %q has level %q (want read, write or admin)", raw, level)
		}
		if !validGitHubPermissionScope(scope) {
			return nil, wrapf(ErrInvalidConstraint,
				"github_app permission %q has an unusable scope name", raw)
		}
		// Widen rather than overwrite: "contents:read" and "contents:write"
		// listed together must mean write, whichever order they were written in.
		if prev, ok := perms[scope]; ok && permissionRank(prev) > permissionRank(level) {
			continue
		}
		perms[scope] = level
	}
	return perms, nil
}

func permissionRank(level string) int {
	switch level {
	case "admin":
		return 3
	case "write":
		return 2
	case "read":
		return 1
	default:
		return 0
	}
}

// validGitHubPermissionScope restricts scope names to GitHub's own charset
// (lower-case letters and underscores). It is a charset check rather than an
// allowlist of known scopes because GitHub adds permissions regularly, and a
// stale allowlist here would refuse a grant that GitHub would have honoured.
func validGitHubPermissionScope(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

// githubAppMinter turns a stored App credential plus a grant's constraints into
// one narrowly-scoped installation token, and caches the installation's
// repository inventory so a renewal does not re-enumerate it.
type githubAppMinter struct {
	api   GitHubAppAPI
	clock func() time.Time

	mu  sync.Mutex
	inv map[string]inventoryEntry
}

type inventoryEntry struct {
	repos     []InstallationRepo
	fetchedAt time.Time
}

func newGitHubAppMinter(api GitHubAppAPI, clock func() time.Time) *githubAppMinter {
	return &githubAppMinter{api: api, clock: clock, inv: map[string]inventoryEntry{}}
}

// mintResult is one minted token plus the audit-safe description of what it
// reaches. The token is a credential; the summary deliberately is not.
type mintResult struct {
	token   InstallationToken
	summary string
	// scope is exactly what GitHub was asked for, kept so a refresh can ask
	// for the same and nothing more (Task 20375).
	scope appTokenScope
}

// appTokenScope is the request an installation token was minted under: which
// installation, which repositories by ID, which permissions. A refresh replays
// it verbatim rather than re-deriving it from the grant, because re-deriving
// would resolve the allowlist against the installation's *current* inventory —
// and a repository added to the installation since dispatch, matching "org/*",
// would then widen a credential the run already holds.
type appTokenScope struct {
	baseURL        string
	installationID int64
	// repositoryIDs is nil for an installation-wide token (a "*" allowlist).
	repositoryIDs []int64
	// permissions is what was asked for; nil asked for the installation's
	// whole permission set (a "*" permission list).
	permissions map[string]string
	// granted is what GitHub answered the first mint with. A refresh whose
	// answer exceeds it is refused, so even a "*" grant cannot come back wider
	// than the token it replaces.
	granted map[string]string
	// summary names what the token reaches: "org/a|org/b" or
	// "installation-wide". Audit-safe.
	summary string
}

// clone returns a copy whose slices and maps are not shared.
func (s appTokenScope) clone() appTokenScope {
	out := s
	out.repositoryIDs = append([]int64(nil), s.repositoryIDs...)
	out.permissions = copyPermissions(s.permissions)
	out.granted = copyPermissions(s.granted)
	return out
}

func copyPermissions(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// widerThan reports how got exceeds the scope's granted permissions, or "" when
// it does not: a scope GitHub granted that the first token did not have, or a
// higher level of one it did. Nothing is compared when either side is unknown
// — GitHub always reports permissions, so that is a fake or a future API.
func (s appTokenScope) widerThan(got map[string]string) string {
	if s.granted == nil || got == nil {
		return ""
	}
	var wider []string
	for scope, level := range got {
		had, ok := s.granted[scope]
		switch {
		case !ok:
			wider = append(wider, scope+":"+level)
		case permissionRank(level) > permissionRank(had):
			wider = append(wider, scope+":"+level+" (was "+had+")")
		}
	}
	sort.Strings(wider)
	return strings.Join(wider, ", ")
}

// mint issues an installation token narrowed to the grant.
//
// The whole flow runs in the hub. The sandbox is handed the last line's token
// and nothing else — not the private key, not the app JWT, not the discovery
// token the inventory lookup uses.
func (m *githubAppMinter) mint(ctx context.Context, cred *AppCredential, c Constraints) (mintResult, error) {
	if m == nil || m.api == nil {
		return mintResult{}, wrapf(ErrGitHubAppMint,
			"this hub has no GitHub API client, so a github_app grant cannot be minted "+
				"(the stored private key is deliberately never delivered as-is)")
	}
	if cred == nil || cred.InstallationID <= 0 {
		// A connection credential (ParseGitHubAppConnection) can sign a JWT but
		// names no installation, so it must never reach a mint. Without this the
		// request below would POST to /app/installations/0/access_tokens and the
		// failure would arrive as a GitHub 404 that names nothing useful.
		return mintResult{}, wrapf(ErrGitHubAppMint,
			"github app credential names no installation; discover the installation first")
	}
	perms, err := GitHubAppPermissions(c)
	if err != nil {
		return mintResult{}, err
	}
	now := m.now()
	appJWT, err := cred.signJWT(now)
	if err != nil {
		return mintResult{}, err
	}

	req := InstallationTokenRequest{
		BaseURL:        cred.BaseURL,
		AppJWT:         appJWT,
		InstallationID: cred.InstallationID,
		Permissions:    perms,
	}
	summary := "installation-wide"

	if !allowsAllRepos(c.Repos) {
		// The allowlist is narrower than the installation, so GitHub has to be
		// told which repositories in IDs it understands. Resolving the patterns
		// against the installation's own inventory is what turns "org/*" into
		// something GitHub can enforce — and what makes a repository the
		// installation does not cover a loud refusal here rather than a 404 at
		// the sandbox's first clone.
		repos, err := m.inventory(ctx, cred, appJWT)
		if err != nil {
			return mintResult{}, err
		}
		matched, err := selectInstallationRepos(repos, c)
		if err != nil {
			return mintResult{}, err
		}
		req.RepositoryIDs = make([]int64, 0, len(matched))
		names := make([]string, 0, len(matched))
		for _, r := range matched {
			req.RepositoryIDs = append(req.RepositoryIDs, r.ID)
			names = append(names, r.FullName)
		}
		summary = strings.Join(names, "|")
	}

	tok, err := m.api.CreateInstallationToken(ctx, req)
	if err != nil {
		return mintResult{}, err
	}
	if err := m.checkFreshness(tok, now); err != nil {
		// A token that is already inside the refresh window would hand the
		// workload a credential due to die before its lease does. Destroy it
		// rather than deliver it: the alternative is a run that fails halfway
		// with an authentication error nobody can trace back to here.
		m.revoke(ctx, cred.BaseURL, tok.Token)
		return mintResult{}, err
	}
	scope := appTokenScope{
		baseURL:        cred.BaseURL,
		installationID: cred.InstallationID,
		repositoryIDs:  append([]int64(nil), req.RepositoryIDs...),
		permissions:    copyPermissions(req.Permissions),
		granted:        copyPermissions(tok.Permissions),
		summary:        summary,
	}
	return mintResult{token: tok, summary: summary, scope: scope}, nil
}

// remint mints a replacement for a token minted under scope, asking GitHub for
// exactly what the first mint asked for (Task 20375).
//
// Nothing about the grant is consulted here, by design: the caller has already
// re-checked that the grant still authorises the lease, and the scope is the
// ceiling. The repository list is replayed by ID rather than re-resolved, and
// the answer is held to the first token's permissions — a refresh can come back
// narrower (GitHub is told the same, and an installation that lost a permission
// grants less) but never wider. A token that came back wider is destroyed.
func (m *githubAppMinter) remint(ctx context.Context, cred *AppCredential, scope appTokenScope) (InstallationToken, error) {
	if m == nil || m.api == nil {
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "this hub has no GitHub API client")
	}
	if cred == nil || cred.InstallationID <= 0 {
		return InstallationToken{}, wrapf(ErrGitHubAppMint, "github app credential names no installation")
	}
	if cred.InstallationID != scope.installationID || cred.BaseURL != scope.baseURL {
		// Secrets are immutable, so this cannot happen through the broker. A
		// store edited underneath it could do it, and a refresh must not follow
		// the edit to another installation or another GitHub.
		return InstallationToken{}, fmt.Errorf("%w: %w: the secret now names installation %d at %s, not "+
			"installation %d at %s the token was minted for", ErrGitHubAppMint, ErrGitHubAppRefused,
			cred.InstallationID, cred.BaseURL, scope.installationID, scope.baseURL)
	}
	now := m.now()
	appJWT, err := cred.signJWT(now)
	if err != nil {
		return InstallationToken{}, err
	}
	perms := copyPermissions(scope.permissions)
	if perms == nil {
		// A "*" grant asked the first time for the installation's whole
		// permission set. Asking for that again would take whatever the
		// installation holds *now*: a permission an org admin accepted since
		// would come back, be refused as wider than the first token, and cut
		// the run off. Asking for exactly what the first token was granted
		// keeps the refresh at the first token's reach.
		perms = copyPermissions(scope.granted)
	}
	tok, err := m.api.CreateInstallationToken(ctx, InstallationTokenRequest{
		BaseURL:        scope.baseURL,
		AppJWT:         appJWT,
		InstallationID: scope.installationID,
		RepositoryIDs:  append([]int64(nil), scope.repositoryIDs...),
		Permissions:    perms,
	})
	if err != nil {
		return InstallationToken{}, err
	}
	if err := m.checkFreshness(tok, now); err != nil {
		m.revoke(ctx, scope.baseURL, tok.Token)
		return InstallationToken{}, err
	}
	if wider := scope.widerThan(tok.Permissions); wider != "" {
		m.revoke(ctx, scope.baseURL, tok.Token)
		return InstallationToken{}, fmt.Errorf("%w: %w: github answered the refresh with permissions the "+
			"first token did not have (%s); it was destroyed rather than delivered",
			ErrGitHubAppMint, ErrGitHubAppRefused, wider)
	}
	return tok, nil
}

func (m *githubAppMinter) now() time.Time {
	if m == nil || m.clock == nil {
		return time.Now().UTC()
	}
	return m.clock().UTC()
}

// checkFreshness refuses a token that expires too soon to be useful.
//
// GitHub issues one-hour tokens, so in practice this only fires when the hub's
// clock is badly wrong or GitHub returns something unexpected — both of which
// are better surfaced here than as an opaque 401 inside a sandbox.
func (m *githubAppMinter) checkFreshness(tok InstallationToken, now time.Time) error {
	if tok.ExpiresAt.IsZero() {
		// GitHub always sets expires_at. A response without one is not a
		// credential this hub is willing to describe as short-lived.
		return wrapf(ErrGitHubAppMint, "github returned an installation token with no expiry")
	}
	if remaining := tok.ExpiresAt.Sub(now); remaining < appTokenMinLifetime {
		return wrapf(ErrGitHubAppMint,
			"github returned an installation token expiring in %s, less than the %s minimum",
			remaining.Round(time.Second), appTokenMinLifetime)
	}
	return nil
}

// inventory returns the installation's repositories, from cache when fresh.
//
// The listing needs an installation token — GitHub has no app-JWT route to it —
// so one is minted with metadata:read and destroyed before this function
// returns. metadata is the minimum that can enumerate names, and it cannot read
// a line of code, which is what makes the momentary installation-wide token
// acceptable where an installation-wide *contents* token would not be.
func (m *githubAppMinter) inventory(ctx context.Context, cred *AppCredential, appJWT string) ([]InstallationRepo, error) {
	key := cred.cacheKey()
	now := m.now()

	m.mu.Lock()
	entry, ok := m.inv[key]
	m.mu.Unlock()
	if ok && now.Sub(entry.fetchedAt) < appInventoryTTL {
		return entry.repos, nil
	}

	discovery, err := m.api.CreateInstallationToken(ctx, InstallationTokenRequest{
		BaseURL:        cred.BaseURL,
		AppJWT:         appJWT,
		InstallationID: cred.InstallationID,
		Permissions:    map[string]string{"metadata": "read"},
	})
	if err != nil {
		return nil, err
	}
	defer m.revoke(ctx, cred.BaseURL, discovery.Token)

	repos, err := m.api.ListInstallationRepos(ctx, cred.BaseURL, discovery.Token)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.inv[key] = inventoryEntry{repos: repos, fetchedAt: now}
	m.mu.Unlock()
	return repos, nil
}

// revoke destroys a token, ignoring the outcome. Used for the tokens this
// package mints for its own purposes and then discards; the caller-visible
// revocation path reports failures (see Broker.destroyAppTokens).
func (m *githubAppMinter) revoke(ctx context.Context, baseURL, token string) {
	if strings.TrimSpace(token) == "" {
		return
	}
	// A fresh deadline: the caller's context may already be cancelled — a
	// cancelled lease is exactly when a discovery token most needs destroying.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appRevokeTimeout)
	defer cancel()
	_ = m.api.RevokeInstallationToken(rctx, baseURL, token)
}

// selectInstallationRepos resolves the grant's allowlist against the
// installation's inventory.
//
// Two distinct failures, reported distinctly, because they call for opposite
// fixes: a *named* repository that the installation does not cover is an
// installation problem ("add it to the App"), while an allowlist that matches
// nothing at all is a grant problem ("your pattern is wrong"). Collapsing them
// into "no repositories matched" is how an operator spends an hour editing the
// wrong side.
func selectInstallationRepos(repos []InstallationRepo, c Constraints) ([]InstallationRepo, error) {
	// A concrete pattern names exactly one repository, so its absence is
	// checkable. A glob does not, so it is only held to "matched something".
	var missing []string
	for _, pat := range c.Repos {
		norm, err := NormalizeRepo(pat)
		if err != nil {
			// Not a concrete owner/repo — a glob, or something ValidateFor
			// accepted as a pattern. Covered by the empty-match check below.
			continue
		}
		found := false
		for _, r := range repos {
			if strings.EqualFold(r.FullName, norm) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, norm)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, wrapf(ErrRepoDenied,
			"the GitHub App installation does not cover %s; add the repositor%s to the App installation "+
				"or narrow the grant (installation currently covers %d repositor%s)",
			strings.Join(missing, ", "), plural(len(missing), "y", "ies"),
			len(repos), plural(len(repos), "y", "ies"))
	}

	var matched []InstallationRepo
	seen := make(map[int64]bool, len(repos))
	for _, r := range repos {
		if seen[r.ID] || !c.AllowsRepo(r.FullName) {
			continue
		}
		seen[r.ID] = true
		matched = append(matched, r)
	}
	if len(matched) == 0 {
		return nil, wrapf(ErrRepoDenied,
			"no repository in the GitHub App installation matches the grant's allowlist (%s); "+
				"the installation covers %d repositor%s",
			strings.Join(c.Repos, ", "), len(repos), plural(len(repos), "y", "ies"))
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].FullName < matched[j].FullName })
	return matched, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
