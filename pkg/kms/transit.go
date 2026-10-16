package kms

// HashiCorp Vault / OpenBao Transit (Task 20433).
//
// Transit is encryption as a service: the key never leaves Vault, and a client
// with the right policy posts plaintext to /encrypt/<key> and ciphertext to
// /decrypt/<key>. The hub needs three capabilities on its key and nothing
// else:
//
//	path "transit/encrypt/cloop" { capabilities = ["update"] }
//	path "transit/decrypt/cloop" { capabilities = ["update"] }
//	path "transit/keys/cloop"    { capabilities = ["read"] }
//
// The last is what Status reads: the key's latest version, which is what a
// rotation of the Transit key changes, and what the hub compares the versions
// its key-encryption keys were wrapped under with.
//
// # Authentication
//
// A Vault token comes from a file (token_file) re-read on every call, which is
// how a Vault Agent sink renews one in place, or from Vault's Kubernetes auth
// method, logging in with the Pod's service account token. Never from the
// configuration file, and never from the environment: a VAULT_TOKEN in the
// hub's environment would be in every child process that is not scrubbed of
// it.
//
// # Transport
//
// HTTPS with the system roots and an optional CA bundle; plain http only to a
// loopback address (config.validateTransit refuses anything else). A redirect
// is followed only to the server the configuration names: Go forwards custom
// headers on a redirect, and X-Vault-Token is one.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// transitMaxResponse bounds a Vault response the client reads.
const transitMaxResponse = 1 << 20

type transitClient struct {
	name      string
	base      *url.URL
	mount     string
	key       string
	namespace string
	timeout   time.Duration
	http      *http.Client

	tokenFile string
	k8sRole   string
	k8sMount  string
	k8sJWT    string

	mu       sync.Mutex
	token    string    // from a Kubernetes login
	tokenExp time.Time // when to log in again
}

func newTransit(cfg config.KMSConfig) (*transitClient, error) {
	t := cfg.Transit
	ep, err := tlsconf.ParseEndpoint(t.Address)
	if err != nil {
		return nil, fmt.Errorf("kms: secrets.kms.transit.address: %w", err)
	}
	if !ep.Secure && !ep.Loopback {
		return nil, fmt.Errorf("kms: %w: %s is plain http to a host that is not loopback", tlsconf.ErrInsecureTransport,
			ep.URL.Redacted())
	}
	tlsCfg, err := tlsconf.ClientConfig(tlsconf.ClientOptions{RootCAFile: t.CAFile})
	if err != nil {
		return nil, fmt.Errorf("kms: secrets.kms.transit.ca_file: %w", err)
	}
	base := *ep.URL
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawQuery, base.Fragment = "", ""
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	c := &transitClient{
		name:      cfg.EffectiveName(),
		base:      &base,
		mount:     t.EffectiveMount(),
		key:       strings.Trim(strings.TrimSpace(t.Key), "/"),
		namespace: strings.Trim(strings.TrimSpace(t.Namespace), "/"),
		timeout:   cfg.EffectiveTimeout(),
		tokenFile: strings.TrimSpace(t.TokenFile),
		k8sRole:   strings.TrimSpace(t.Kubernetes.Role),
		k8sMount:  t.Kubernetes.EffectiveMount(),
		k8sJWT:    t.Kubernetes.EffectiveTokenFile(),
	}
	c.http = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != c.base.Scheme || req.URL.Host != c.base.Host {
				return fmt.Errorf("Vault redirected to %s, another server than %s; the hub does not send its "+
					"token there — point secrets.kms.transit.address at the active node or a load balancer",
					req.URL.Host, c.base.Host)
			}
			if len(via) >= 3 {
				return errors.New("Vault redirected three times")
			}
			return nil
		},
	}
	return c, nil
}

func (c *transitClient) Name() string { return c.name }
func (c *transitClient) Kind() string { return config.KMSProviderTransit }
func (c *transitClient) Describe() string {
	return fmt.Sprintf("the Transit key %s/%s at %s", c.mount, c.key, c.base.Redacted())
}
func (c *transitClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Encrypt wraps plaintext under the Transit key's latest version.
func (c *transitClient) Encrypt(ctx context.Context, plaintext []byte) (out secretbroker.KMSCiphertext, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderTransit, OpEncrypt, start, err) }()
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if err := c.call(ctx, OpEncrypt, http.MethodPost, c.mount+"/encrypt/"+c.key, body, &resp); err != nil {
		return out, err
	}
	ct := resp.Data.Ciphertext
	version := resp.Data.KeyVersion
	if version == 0 {
		version = ciphertextVersion(ct) // Vault before 1.10 does not report it
	}
	if !strings.HasPrefix(ct, "vault:v") || version <= 0 {
		return out, &Error{KMS: c.name, Op: OpEncrypt, Result: ResultError,
			Err: errors.New("Vault returned something that is not a Transit ciphertext")}
	}
	return secretbroker.KMSCiphertext{KeyID: c.keyID(version), Ciphertext: []byte(ct)}, nil
}

// Decrypt unwraps a Transit ciphertext.
func (c *transitClient) Decrypt(ctx context.Context, in secretbroker.KMSCiphertext) (out []byte, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderTransit, OpDecrypt, start, err) }()
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	body := map[string]string{"ciphertext": string(in.Ciphertext)}
	if err := c.call(ctx, OpDecrypt, http.MethodPost, c.mount+"/decrypt/"+c.key, body, &resp); err != nil {
		return nil, err
	}
	out, derr := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	resp.Data.Plaintext = ""
	if derr != nil || len(out) == 0 {
		return nil, &Error{KMS: c.name, Op: OpDecrypt, Result: ResultError,
			Err: errors.New("Vault returned a plaintext that is not base64, or none")}
	}
	return out, nil
}

// Status reads the Transit key: the version it encrypts under now.
func (c *transitClient) Status(ctx context.Context) (st Status, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderTransit, OpStatus, start, err) }()
	var resp struct {
		Data struct {
			LatestVersion int    `json:"latest_version"`
			Type          string `json:"type"`
		} `json:"data"`
	}
	if err := c.call(ctx, OpStatus, http.MethodGet, c.mount+"/keys/"+c.key, nil, &resp); err != nil {
		return Status{}, err
	}
	if resp.Data.LatestVersion <= 0 {
		return Status{}, &Error{KMS: c.name, Op: OpStatus, Result: ResultError,
			Err: errors.New("Vault reports no version of the Transit key")}
	}
	return Status{Healthy: true, Healthz: "ok", KeyID: c.keyID(resp.Data.LatestVersion)}, nil
}

// CurrentKeyID is the Transit key's latest version.
func (c *transitClient) CurrentKeyID(ctx context.Context) (string, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return "", err
	}
	return st.KeyID, nil
}

func (c *transitClient) keyID(version int) string {
	return c.mount + "/" + c.key + ":v" + strconv.Itoa(version)
}

// ciphertextVersion reads N out of "vault:vN:…".
func ciphertextVersion(ct string) int {
	rest, ok := strings.CutPrefix(ct, "vault:v")
	if !ok {
		return 0
	}
	n, _, ok := strings.Cut(rest, ":")
	if !ok {
		return 0
	}
	v, err := strconv.Atoi(n)
	if err != nil {
		return 0
	}
	return v
}

// call makes one authenticated request, logging in again once if Vault says
// the token it was given is no good.
func (c *transitClient) call(ctx context.Context, op, method, path string, in, out any) error {
	ctx, cancel := withTimeout(ctx, c.timeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		token, err := c.currentToken(ctx, attempt > 0)
		if err != nil {
			return err
		}
		status, err := c.do(ctx, op, method, path, token, in, out)
		if status == http.StatusForbidden && attempt == 0 && c.k8sRole != "" {
			continue // the login lapsed early: log in again, once
		}
		return err
	}
}

// do sends one request and decodes the answer into out.
func (c *transitClient) do(ctx context.Context, op, method, path, token string, in, out any) (int, error) {
	u := *c.base
	u.Path = c.base.Path + "/v1/" + path
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, &Error{KMS: c.name, Op: op, Result: ResultError, Err: err}
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, &Error{KMS: c.name, Op: op, Result: ResultError, Err: err}
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("X-Vault-Request", "true")
	resp, err := c.http.Do(req)
	if err != nil {
		// A url.Error repeats the URL, which holds no token but says nothing
		// the KMS's name does not; keep its cause.
		cause := err
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			cause = ue.Err
		}
		return 0, &Error{KMS: c.name, Op: op, Result: unreachable(err), Err: cause}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, transitMaxResponse+1))
	if err != nil {
		return resp.StatusCode, &Error{KMS: c.name, Op: op, Result: unreachable(err), Err: err}
	}
	if len(data) > transitMaxResponse {
		return resp.StatusCode, &Error{KMS: c.name, Op: op, Result: ResultError,
			Err: fmt.Errorf("Vault answered with more than %d bytes", transitMaxResponse)}
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, &Error{KMS: c.name, Op: op, Result: transitResult(resp.StatusCode),
			Err: fmt.Errorf("HTTP %d: %s", resp.StatusCode, vaultErrors(data))}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp.StatusCode, &Error{KMS: c.name, Op: op, Result: ResultError,
			Err: fmt.Errorf("Vault answered with something that is not JSON: %v", err)}
	}
	return resp.StatusCode, nil
}

// transitResult classifies an HTTP status from Vault.
func transitResult(code int) string {
	switch {
	case code == http.StatusForbidden || code == http.StatusUnauthorized:
		return ResultDenied
	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable ||
		code == http.StatusBadGateway || code == http.StatusGatewayTimeout:
		// 503 is also what a sealed Vault answers: unreachable for every
		// purpose of the hub's until it is unsealed.
		return ResultUnavailable
	case code == http.StatusBadRequest || code == http.StatusNotFound:
		return ResultInvalid
	}
	return ResultError
}

// vaultErrors is Vault's {"errors": [...]} as one line.
func vaultErrors(data []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
		return truncate(strings.Join(e.Errors, "; "), 300)
	}
	return truncate(strings.TrimSpace(string(data)), 200)
}

// currentToken is the token to send: the token file's, read now, or the
// Kubernetes login's, logging in when there is none or relogin is set.
func (c *transitClient) currentToken(ctx context.Context, relogin bool) (string, error) {
	if c.tokenFile != "" {
		tok, err := readSmallFile(c.tokenFile, "Vault token file")
		if err != nil {
			return "", &Error{KMS: c.name, Op: OpLogin, Result: ResultDenied, Err: err}
		}
		return tok, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !relogin && c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	tok, ttl, err := c.login(ctx)
	if err != nil {
		return "", err
	}
	c.token = tok
	// Log in again at four fifths of the lease: a token that lapses between
	// the check and the call costs a retry, not a failure.
	c.tokenExp = time.Now().Add(ttl * 4 / 5)
	return tok, nil
}

// login is Vault's Kubernetes auth method.
func (c *transitClient) login(ctx context.Context) (tok string, ttl time.Duration, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderTransit, OpLogin, start, err) }()
	jwt, err := readSmallFile(c.k8sJWT, "service account token")
	if err != nil {
		return "", 0, &Error{KMS: c.name, Op: OpLogin, Result: ResultDenied, Err: err}
	}
	var resp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	body := map[string]string{"role": c.k8sRole, "jwt": jwt}
	if _, err := c.do(ctx, OpLogin, http.MethodPost, "auth/"+c.k8sMount+"/login", "", body, &resp); err != nil {
		return "", 0, err
	}
	if resp.Auth.ClientToken == "" {
		return "", 0, &Error{KMS: c.name, Op: OpLogin, Result: ResultError,
			Err: errors.New("Vault's Kubernetes login returned no token")}
	}
	ttl = time.Duration(resp.Auth.LeaseDuration) * time.Second
	if ttl < time.Minute {
		ttl = time.Minute
	}
	return resp.Auth.ClientToken, ttl, nil
}
