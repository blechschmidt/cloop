package imagepolicy

// registry.go resolves a tag to the digest its registry serves for it, for an
// enforcer that has no image store of its own to ask (Task 20424).
//
// The container driver resolves against its engine's local store: the image it
// is about to run is the image it holds. The hub deciding what an edge device
// may run holds nothing. A device runs project images from its own store, which
// the hub cannot read, and a signature can only be checked against a digest —
// so the hub asks the registry what the tag names now, verifies that digest,
// and dispatches the digest. The device's driver never pulls and inspects
// exactly the reference it is given, so it runs the verified bytes or refuses
// naming the pull. Nothing about the device's own copy of the tag is taken on
// trust.
//
// The signature does not rest on the registry's honesty. A registry that names
// some other digest gets that digest verified instead: signed by an accepted
// key it is an image the policy admits, unsigned it is refused. TLS is still
// required, because a resolution an attacker on the path could steer is one
// they could steer to an older signed image.
//
// Scope: the distribution API's manifest endpoint — HEAD, then GET when a
// registry leaves out the digest header — with the two authentication schemes
// registries use, a Bearer token service and Basic. Credentials come from the
// Docker-format files cosign's own keychain reads (registryauth.go), or — for a
// Kubernetes executor, which resolves every tag a Pod would carry (Task 20457)
// — from the registry secret the hub holds for it and nowhere else. A
// credential helper is not run: a repository whose login lives only in one is
// resolved anonymously and refused if that is not enough. A reference pinned by
// digest is never resolved at all.
//
// The registry is named by whoever wrote the reference, which on a hub with no
// image policy is any project. So what it can make this host do is bounded: a
// redirect is followed over https only (checkRegistryRedirect), a token service
// over plain HTTP or on this host's loopback is refused unless the registry is
// itself on this host (realmAllowed), and a login is offered only to the
// registry it is stored for.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrRegistry is the class of every failure to resolve a reference at its
// registry: unreachable, refusing, not knowing the tag, or answering something
// that is not a digest. It is distinct from a policy denial because it is not a
// verdict on the image; the caller decides whether not knowing is a refusal.
var ErrRegistry = errors.New("imagepolicy: the registry did not resolve the reference")

// registryRequestTimeout bounds one request to a registry or its token
// service, body included.
const registryRequestTimeout = 30 * time.Second

// maxManifestBytes bounds the manifest read when a registry's HEAD carries no
// digest. An index over a dozen platforms is a few kilobytes; this is a ceiling
// against a registry streaming without end, not a size a manifest approaches.
const maxManifestBytes = 4 << 20

// maxTokenBytes bounds a token service's answer.
const maxTokenBytes = 64 << 10

// manifestAccept is the manifest media types a resolution accepts, indexes
// first, so a multi-platform tag resolves to its index digest: the one `docker
// pull` records for the tag and the one a signing pipeline signs.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// RegistryCredential is a login at a registry: a username with its password
// or access token.
type RegistryCredential struct {
	Username string
	Password string
}

// RegistryResolver implements Resolver by asking the registry a reference
// names. The zero value is usable.
type RegistryResolver struct {
	// Client performs the requests. Nil uses one bounded by
	// registryRequestTimeout that honours the proxy environment.
	Client *http.Client
	// Credentials returns the login for a registry host, false when there is
	// none. Nil reads DockerConfigCredential.
	Credentials func(registry string) (RegistryCredential, bool)
	// Endpoint returns the base URL a registry's API is served at. Nil serves
	// every registry over https at its own host and Docker Hub at
	// registry-1.docker.io. Tests point it at a local server.
	Endpoint func(registry string) string
}

// NewRegistryResolver returns a resolver with the defaults.
func NewRegistryResolver() *RegistryResolver { return &RegistryResolver{} }

// defaultRegistryClient is the client a resolver without one uses.
var defaultRegistryClient = &http.Client{Timeout: registryRequestTimeout}

// maxRegistryRedirects bounds the redirects one registry request follows. A
// manifest or a token is served where it is asked for; a registry that bounces
// a request around is not one worth following far.
const maxRegistryRedirects = 3

// checkRegistryRedirect is the redirect policy of every registry request,
// whichever client makes it (Task 20457).
//
// The reference a resolution follows is named by a project, so the registry at
// the other end may be anybody's, and a redirect is that registry choosing a
// URL for this host to fetch. Followed to anything, it is a request from the
// hub's own network position to an address of a stranger's choosing — a
// plain-HTTP service on the hub's loopback, a cloud metadata endpoint — whose
// answer the resolution then acts on: a token service's "token" is presented
// back to the registry that asked for it. So a redirect is followed over https
// only, a few hops at most; plain HTTP only where the request began on this
// host's loopback over plain HTTP, which is a registry on this host.
func checkRegistryRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRegistryRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRegistryRedirects)
	}
	if req.URL.Scheme == "https" {
		return nil
	}
	if len(via) > 0 {
		first := via[0].URL
		if first.Scheme == "http" && isLoopbackHost(first.Hostname()) && isLoopbackHost(req.URL.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("refused a redirect to %s: a registry is followed over https only", req.URL.Redacted())
}

// ResolveDigest implements Resolver: the digest ref's registry serves for its
// tag now. A reference already pinned resolves to its own digest without a
// request.
func (r *RegistryResolver) ResolveDigest(ctx context.Context, ref string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := ParseReference(ref)
	if err != nil {
		return "", err
	}
	if parsed.Pinned() {
		return parsed.Digest, nil
	}
	if parsed.Registry == "" {
		return "", fmt.Errorf("%w: %q names no registry to ask", ErrRegistry, ref)
	}
	tag := parsed.Tag
	if tag == "" {
		tag = "latest"
	}
	// The repository and the tag were validated by ParseReference against
	// their grammars, neither of which admits a character a URL path would
	// need escaped.
	manifestURL := r.endpoint(parsed.Registry) + "/v2/" + parsed.Repository + "/manifests/" + tag
	return r.manifestDigest(ctx, parsed, manifestURL)
}

// manifestDigest asks for the manifest at manifestURL and returns its digest,
// authenticating once if the registry asks.
func (r *RegistryResolver) manifestDigest(ctx context.Context, ref Reference, manifestURL string) (string, error) {
	auth := ""
	authorized := false
	method := http.MethodHead
	// Four exchanges at most: HEAD, HEAD again with a token, then the GET a
	// registry that answers HEAD without a digest needs.
	for attempt := 0; attempt < 4; attempt++ {
		resp, err := r.do(ctx, method, manifestURL, auth)
		if err != nil {
			return "", fmt.Errorf("%w: %s is unreachable from this host: %v", ErrRegistry, ref.Registry, err)
		}
		switch code := resp.StatusCode; {
		case code == http.StatusUnauthorized && !authorized:
			challenges := resp.Header.Values("Www-Authenticate")
			drain(resp)
			auth, err = r.authorize(ctx, ref, manifestURL, challenges)
			if err != nil {
				return "", err
			}
			authorized = true
		case code == http.StatusOK && method == http.MethodHead:
			digest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
			drain(resp)
			if digest == "" {
				method = http.MethodGet
				continue
			}
			if err := validateDigest(digest); err != nil {
				return "", fmt.Errorf("%w: %s answered %q for %s, which is not a digest: %v",
					ErrRegistry, ref.Registry, digest, ref.String(), err)
			}
			return digest, nil
		case code == http.StatusOK:
			// The digest of what was served, whatever a header claims: that is
			// what content addressing means, and it is what a pull by this
			// digest will be checked against.
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
			_ = resp.Body.Close()
			if err != nil {
				return "", fmt.Errorf("%w: reading the manifest of %s from %s: %v", ErrRegistry, ref.String(), ref.Registry, err)
			}
			if len(body) > maxManifestBytes {
				return "", fmt.Errorf("%w: %s served a manifest for %s larger than %d bytes",
					ErrRegistry, ref.Registry, ref.String(), maxManifestBytes)
			}
			sum := sha256.Sum256(body)
			return "sha256:" + hex.EncodeToString(sum[:]), nil
		case code == http.StatusMethodNotAllowed && method == http.MethodHead:
			drain(resp)
			method = http.MethodGet
		case code == http.StatusNotFound:
			drain(resp)
			return "", fmt.Errorf("%w: %s has no manifest for %s", ErrRegistry, ref.Registry, ref.String())
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			drain(resp)
			return "", fmt.Errorf("%w: %s refused this host access to %s (HTTP %d)%s",
				ErrRegistry, ref.Registry, ref.Name(), code, r.loginHint(ref.Registry))
		default:
			drain(resp)
			return "", fmt.Errorf("%w: %s answered HTTP %d for %s", ErrRegistry, ref.Registry, code, ref.String())
		}
	}
	return "", fmt.Errorf("%w: %s did not settle on an answer for %s", ErrRegistry, ref.Registry, ref.String())
}

// do sends one manifest request.
func (r *RegistryResolver) do(ctx context.Context, method, target, auth string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return r.client().Do(req)
}

// isLoopbackHost reports whether host names this machine's loopback interface:
// "localhost", or a loopback address literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// realmAllowed refuses a token service a registry has no business naming.
//
// The realm is the registry's choice, and the hub fetches it and presents what
// it answers back to the registry as a bearer token. A registry elsewhere that
// names a service on the hub's own loopback is asking the hub to read one of its
// own local services and hand the answer to a stranger, so the realm may be on
// this host's loopback only when the registry is too — a registry this host
// serves itself, as a test's is.
func realmAllowed(manifestURL string, realm *url.URL) bool {
	if !isLoopbackHost(realm.Hostname()) {
		return true
	}
	u, err := url.Parse(manifestURL)
	return err == nil && isLoopbackHost(u.Hostname())
}

// authorize answers a registry's 401 with the Authorization header to retry
// with: a token from its token service when it offers one, else Basic.
func (r *RegistryResolver) authorize(ctx context.Context, ref Reference, manifestURL string, challenges []string) (string, error) {
	cred, haveCred := r.credential(ref.Registry)
	for _, c := range challenges {
		scheme, params := parseChallenge(c)
		if strings.EqualFold(scheme, "bearer") {
			token, err := r.fetchToken(ctx, ref, manifestURL, params["realm"], params["service"], cred, haveCred)
			if err != nil {
				return "", err
			}
			return "Bearer " + token, nil
		}
	}
	for _, c := range challenges {
		scheme, _ := parseChallenge(c)
		if !strings.EqualFold(scheme, "basic") {
			continue
		}
		if !haveCred {
			return "", fmt.Errorf("%w: %s requires a login to read %s%s",
				ErrRegistry, ref.Registry, ref.Name(), r.loginHint(ref.Registry))
		}
		if u, err := url.Parse(manifestURL); err != nil || !protectsCredentials(u) {
			return "", fmt.Errorf("%w: %s asked for a password over plain HTTP, which this host does not send",
				ErrRegistry, ref.Registry)
		}
		return "Basic " + basicAuth(cred), nil
	}
	return "", fmt.Errorf("%w: %s asked for an authentication scheme this host does not speak (%s)",
		ErrRegistry, ref.Registry, strings.Join(challenges, "; "))
}

// fetchToken asks a registry's token service for a pull token on ref's
// repository.
//
// The scope is always this repository's pull, whatever the challenge asked
// for: a resolution reads one manifest, and a token able to do more is a token
// that could be spent on more.
func (r *RegistryResolver) fetchToken(ctx context.Context, ref Reference, manifestURL, realm, service string,
	cred RegistryCredential, haveCred bool) (string, error) {
	u, err := url.Parse(realm)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%w: %s named an unusable token service %q", ErrRegistry, ref.Registry, realm)
	}
	if !protectsCredentials(u) {
		return "", fmt.Errorf("%w: %s named a token service over plain HTTP (%s), which this host does not use",
			ErrRegistry, ref.Registry, u.Redacted())
	}
	if !realmAllowed(manifestURL, u) {
		return "", fmt.Errorf("%w: %s named a token service on this host's own loopback interface (%s), which "+
			"only a registry on this host may", ErrRegistry, ref.Registry, u.Redacted())
	}
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	q.Set("scope", "repository:"+ref.Repository+":pull")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: token request to %s: %v", ErrRegistry, u.Host, err)
	}
	if haveCred {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: the token service of %s is unreachable from this host: %v", ErrRegistry, ref.Registry, err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		hint := ""
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint = r.loginHint(ref.Registry)
		}
		return "", fmt.Errorf("%w: the token service of %s refused a pull token for %s (HTTP %d)%s",
			ErrRegistry, ref.Registry, ref.Name(), resp.StatusCode, hint)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBytes)).Decode(&body); err != nil {
		return "", fmt.Errorf("%w: the token service of %s answered something that is not a token: %v",
			ErrRegistry, ref.Registry, err)
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("%w: the token service of %s answered without a token", ErrRegistry, ref.Registry)
	}
	return token, nil
}

// loginHint says where a login would come from, for a refusal that a login
// would answer.
func (r *RegistryResolver) loginHint(registry string) string {
	if _, ok := r.credential(registry); ok {
		return " — the login this host holds for it was not accepted"
	}
	return " — this host holds no login for it (`docker login " + registry + "` as the hub's user writes one " +
		"where it is read), or pin the image by digest so nothing has to be resolved"
}

// credential returns the login for registry, if any.
func (r *RegistryResolver) credential(registry string) (RegistryCredential, bool) {
	if r.Credentials != nil {
		return r.Credentials(registry)
	}
	return DockerConfigCredential(registry)
}

// endpoint returns the base URL registry's API is served at.
func (r *RegistryResolver) endpoint(registry string) string {
	if r.Endpoint != nil {
		return strings.TrimRight(r.Endpoint(registry), "/")
	}
	if registry == DockerHub {
		return "https://registry-1.docker.io"
	}
	return "https://" + registry
}

// client returns the client requests go through: the configured one, or the
// default, with the registry redirect policy in force either way — a caller's
// client is trusted for its transport and its roots, not for where it follows a
// stranger's registry to.
func (r *RegistryResolver) client() *http.Client {
	c := *defaultRegistryClient
	if r.Client != nil {
		c = *r.Client
	}
	c.CheckRedirect = checkRegistryRedirect
	return &c
}

// protectsCredentials reports whether u is a place a password may be sent:
// https, or plain HTTP to this host's own loopback interface.
func protectsCredentials(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

// basicAuth renders a credential as the Basic scheme's token.
func basicAuth(c RegistryCredential) string {
	return base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))
}

// drain discards what is left of a response body, bounded, and closes it, so
// the connection can be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// parseChallenge splits one WWW-Authenticate value into its scheme and its
// auth-params: `Bearer realm="https://auth.example/token",service="x"`.
// Quoted values may contain commas and backslash escapes.
func parseChallenge(h string) (scheme string, params map[string]string) {
	h = strings.TrimSpace(h)
	i := strings.IndexByte(h, ' ')
	if i < 0 {
		return h, map[string]string{}
	}
	scheme, rest := h[:i], h[i+1:]
	params = map[string]string{}
	for {
		rest = strings.TrimLeft(rest, " \t,")
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return scheme, params
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimLeft(rest[eq+1:], " \t")
		var val strings.Builder
		if strings.HasPrefix(rest, `"`) {
			j := 1
			for ; j < len(rest); j++ {
				c := rest[j]
				if c == '\\' && j+1 < len(rest) {
					j++
					val.WriteByte(rest[j])
					continue
				}
				if c == '"' {
					break
				}
				val.WriteByte(c)
			}
			if j < len(rest) {
				rest = rest[j+1:]
			} else {
				rest = ""
			}
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			val.WriteString(strings.TrimSpace(rest[:end]))
			rest = rest[end:]
		}
		params[key] = val.String()
	}
}
