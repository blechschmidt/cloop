package config

// secrets: where the secret store's key-encryption keys come from (Task 20433).
//
// Every secret, session refresh token and hub CA key is sealed under a data key
// of its own, and only that data key is sealed under a key-encryption key (KEK).
// Until this section a KEK was always derived from CLOOP_SECRET_KEY and a salt
// stored beside it, so a copy of the database and of the key file opened every
// stored credential, offline, for as long as anybody kept the copy.
//
// secrets.kms makes a KEK random instead, held only wrapped by a key in an
// external key-management service: the record keeps the KMS's ciphertext and
// key id, and the hub asks the KMS to unwrap it into memory. Whoever copies the
// database and the key file then still needs the KMS to open anything — a call
// the KMS logs and its owner can refuse.
//
// # The roots
//
// The keyring holds a current root, which mints new KEKs and opens, and during
// a change of root a previous one, which only opens (Task 20425). This section
// decides which roots those are:
//
//	secrets.kms set                    the KMS is the current root
//	secrets.kms unset                  CLOOP_SECRET_KEY is, as before
//	previous_root: passphrase          CLOOP_SECRET_KEY is the previous root:
//	                                   moving onto a KMS
//	secrets.kms_previous set           that KMS is the previous root: moving off
//	                                   a KMS, onto CLOOP_SECRET_KEY or another KMS
//	CLOOP_SECRET_KEY_PREVIOUS set      changing CLOOP_SECRET_KEY itself
//
// At most one previous root: a change of root moves from one root to one other.
// `cloop hub key rotate --retire-previous` finishes every one of these changes.
//
// # Nothing falls back
//
// A KMS section that is configured and wrong is an error wherever the store is
// opened, never a reason to seal under something else: `cloop ui` refuses to
// start on one, and on a KMS it cannot reach. That is why a bad block is not
// dropped at load the way a bad audit sink is (auditforward.go) — dropping it
// would make the passphrase the current root, which is the fallback this
// section exists to rule out. Load leaves it as written, and ValidateSecrets
// says what is wrong with it.
//
// Hub-scope: `cloop ui` reads it with its per-instance overlay merged, and the
// `cloop hub key` commands with the overlay their --port names. Every member of
// a hub cluster opens one store, so every member needs the same roots — which
// is why config.yaml, not an overlay, is the usual place for it.

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// KMS providers.
const (
	// KMSProviderKMSv2 is a Kubernetes KMS v2 plugin, spoken to over gRPC on a
	// unix socket. One integration reaches Azure Key Vault, AWS KMS, Google
	// Cloud KMS and Vault through their existing plugins.
	KMSProviderKMSv2 = "kmsv2"
	// KMSProviderTransit is HashiCorp Vault's (or OpenBao's) Transit secrets
	// engine, spoken to over HTTPS.
	KMSProviderTransit = "transit"
)

// Values of secrets.previous_root.
const (
	// PreviousRootPassphrase: CLOOP_SECRET_KEY is the root being replaced by
	// secrets.kms. It only opens.
	PreviousRootPassphrase = "passphrase"
)

// Bounds and defaults for a KMS block.
const (
	// KMSTimeoutDefault bounds one call to the KMS. A KMS v2 plugin answers
	// from the same Pod, and a Transit call is one HTTPS round trip; seconds
	// are generous for either.
	KMSTimeoutDefault = 5 * time.Second
	KMSTimeoutLower   = 100 * time.Millisecond
	KMSTimeoutUpper   = time.Minute

	// KMSStartupTimeoutDefault is how long `cloop ui` waits for the KMS to
	// answer at startup before refusing to start. A plugin sidecar that
	// starts beside the hub needs a few seconds to open its socket.
	KMSStartupTimeoutDefault = 30 * time.Second
	KMSStartupTimeoutLower   = 0
	KMSStartupTimeoutUpper   = 10 * time.Minute

	// KMSTransitMountDefault is where Vault mounts Transit unless told
	// otherwise.
	KMSTransitMountDefault = "transit"
	// KMSKubernetesAuthMountDefault is where Vault mounts the Kubernetes auth
	// method unless told otherwise.
	KMSKubernetesAuthMountDefault = "kubernetes"
	// KMSServiceAccountTokenDefault is where a Pod's service account token is
	// projected.
	KMSServiceAccountTokenDefault = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// kmsNameMax bounds a KMS block's name: it is recorded on every sealing
	// key and advertised in every hub member's row.
	kmsNameMax = 200
)

// SecretsConfig is the secrets section.
type SecretsConfig struct {
	// KMS, when its provider is set, is the current root: every new
	// key-encryption key is random and held wrapped by it.
	KMS KMSConfig `yaml:"kms,omitempty"`
	// KMSPrevious, when its provider is set, is the root a change of root is
	// moving off: it opens the keys it wraps until `cloop hub key rotate
	// --retire-previous` has moved everything onto the current root.
	KMSPrevious KMSConfig `yaml:"kms_previous,omitempty"`
	// PreviousRoot is PreviousRootPassphrase while moving from
	// CLOOP_SECRET_KEY onto secrets.kms, and empty otherwise.
	PreviousRoot string `yaml:"previous_root,omitempty"`
}

// KMSConfig is one external key-management service key.
type KMSConfig struct {
	// Provider is KMSProviderKMSv2 or KMSProviderTransit; empty means the
	// block is not configured.
	Provider string `yaml:"provider,omitempty"`
	// Name is what the key registry records as the root of each key this KMS
	// wraps, and what a hub cluster member advertises as its root. Defaults
	// to one derived from the provider and the key it is pointed at; set it
	// to keep a key's name when its endpoint moves.
	Name string `yaml:"name,omitempty"`
	// Timeout bounds one call ("5s" by default).
	Timeout string `yaml:"timeout,omitempty"`
	// StartupTimeout is how long `cloop ui` waits for the KMS to answer
	// before refusing to start ("30s" by default; "0s" refuses at once).
	StartupTimeout string `yaml:"startup_timeout,omitempty"`

	KMSv2   KMSv2Config      `yaml:"kmsv2,omitempty"`
	Transit KMSTransitConfig `yaml:"transit,omitempty"`
}

// KMSv2Config locates a Kubernetes KMS v2 plugin.
type KMSv2Config struct {
	// Endpoint is the plugin's unix socket, as the API server's
	// EncryptionConfiguration names it — unix:///var/run/kmsplugin/socket.sock
	// — or as an absolute path.
	Endpoint string `yaml:"endpoint,omitempty"`
}

// KMSTransitConfig locates a Vault or OpenBao Transit key, and says how the hub
// authenticates to it.
type KMSTransitConfig struct {
	// Address is the server's URL: https://vault.example.com:8200. Plain http
	// is accepted only to a loopback host.
	Address string `yaml:"address,omitempty"`
	// Mount is where Transit is mounted ("transit" by default).
	Mount string `yaml:"mount,omitempty"`
	// Key is the Transit key's name.
	Key string `yaml:"key,omitempty"`
	// Namespace is the Vault Enterprise or OpenBao namespace, if any.
	Namespace string `yaml:"namespace,omitempty"`
	// CAFile is a PEM bundle trusted beside the system roots.
	CAFile string `yaml:"ca_file,omitempty"`
	// TokenFile holds a Vault token, re-read on every call — a Vault Agent
	// sink renews it in place. One of TokenFile and Kubernetes is required.
	TokenFile string `yaml:"token_file,omitempty"`
	// Kubernetes logs in with the Pod's service account token instead.
	Kubernetes KMSTransitKubernetesAuth `yaml:"kubernetes,omitempty"`
}

// KMSTransitKubernetesAuth is Vault's Kubernetes auth method.
type KMSTransitKubernetesAuth struct {
	// Role is the Vault role to log in as; setting it selects this method.
	Role string `yaml:"role,omitempty"`
	// Mount is where the auth method is mounted ("kubernetes" by default).
	Mount string `yaml:"mount,omitempty"`
	// TokenFile is the service account token presented to Vault.
	TokenFile string `yaml:"token_file,omitempty"`
}

// Configured reports whether the block names a provider.
func (k KMSConfig) Configured() bool { return strings.TrimSpace(k.Provider) != "" }

// UsesKMS reports whether any KMS takes part in the keyring.
func (s SecretsConfig) UsesKMS() bool { return s.KMS.Configured() || s.KMSPrevious.Configured() }

// EffectiveTimeout is the per-call bound, default applied. Call it on a block
// ValidateSecrets accepted.
func (k KMSConfig) EffectiveTimeout() time.Duration {
	d, err := parseKMSDuration(k.Timeout)
	if err != nil || d == 0 {
		return KMSTimeoutDefault
	}
	return d
}

// EffectiveStartupTimeout is how long startup waits, default applied.
func (k KMSConfig) EffectiveStartupTimeout() time.Duration {
	if strings.TrimSpace(k.StartupTimeout) == "" {
		return KMSStartupTimeoutDefault
	}
	d, err := parseKMSDuration(k.StartupTimeout)
	if err != nil {
		return KMSStartupTimeoutDefault
	}
	return d
}

// EffectiveName is the block's name, or the one derived from what it points
// at: "kmsv2:<socket path>" or "transit:<host>/<mount>/<key>". Derived names
// depend on the key, not on the slot (kms or kms_previous), so moving a block
// from one slot to the other keeps the name its keys were recorded under.
func (k KMSConfig) EffectiveName() string {
	if n := strings.TrimSpace(k.Name); n != "" {
		return n
	}
	switch strings.TrimSpace(k.Provider) {
	case KMSProviderKMSv2:
		path, err := KMSv2SocketPath(k.KMSv2.Endpoint)
		if err != nil {
			path = strings.TrimSpace(k.KMSv2.Endpoint)
		}
		return KMSProviderKMSv2 + ":" + path
	case KMSProviderTransit:
		host := strings.TrimSpace(k.Transit.Address)
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Host
		}
		name := KMSProviderTransit + ":" + host + "/" + k.Transit.EffectiveMount() + "/" + strings.TrimSpace(k.Transit.Key)
		if ns := strings.Trim(strings.TrimSpace(k.Transit.Namespace), "/"); ns != "" {
			name += "@" + ns
		}
		return name
	}
	return strings.TrimSpace(k.Provider)
}

// EffectiveMount is the Transit mount, default applied.
func (t KMSTransitConfig) EffectiveMount() string {
	if m := strings.Trim(strings.TrimSpace(t.Mount), "/"); m != "" {
		return m
	}
	return KMSTransitMountDefault
}

// EffectiveMount is the auth mount, default applied.
func (a KMSTransitKubernetesAuth) EffectiveMount() string {
	if m := strings.Trim(strings.TrimSpace(a.Mount), "/"); m != "" {
		return m
	}
	return KMSKubernetesAuthMountDefault
}

// EffectiveTokenFile is the service account token's path, default applied.
func (a KMSTransitKubernetesAuth) EffectiveTokenFile() string {
	if p := strings.TrimSpace(a.TokenFile); p != "" {
		return p
	}
	return KMSServiceAccountTokenDefault
}

// KMSv2SocketPath returns the socket path a KMS v2 endpoint names:
// "unix:///abs/path", "unix:/abs/path" or "/abs/path". The API server accepts
// only unix sockets for a KMS plugin, and so does the hub: a KMS reached over a
// network would put the key it unwraps on that network.
func KMSv2SocketPath(endpoint string) (string, error) {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return "", fmt.Errorf("secrets.kms.kmsv2.endpoint is empty")
	}
	path := e
	if strings.Contains(e, "://") || strings.HasPrefix(e, "unix:") {
		u, err := url.Parse(e)
		if err != nil {
			return "", fmt.Errorf("secrets.kms.kmsv2.endpoint %q: %v", e, err)
		}
		if u.Scheme != "unix" {
			return "", fmt.Errorf("secrets.kms.kmsv2.endpoint %q: a KMS v2 plugin is reached over a unix socket "+
				"(unix:///path/to/socket), not %s", e, u.Scheme)
		}
		if u.Host != "" {
			return "", fmt.Errorf("secrets.kms.kmsv2.endpoint %q names a host; write it unix:///abs/path", e)
		}
		path = u.Path
		if path == "" {
			path = u.Opaque
		}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("secrets.kms.kmsv2.endpoint %q is not an absolute socket path", e)
	}
	return filepath.Clean(path), nil
}

// ValidateSecrets checks the secrets section. It is called wherever the store
// is opened with it — `cloop ui` refuses to start on an error — and by `cloop
// hub doctor`; Load itself leaves the section as written (see the file
// comment).
func ValidateSecrets(s SecretsConfig) error {
	if s.KMS.Configured() {
		if err := validateKMS("secrets.kms", s.KMS); err != nil {
			return err
		}
	} else if blockStated(s.KMS) {
		return fmt.Errorf("secrets.kms has settings but no provider; set provider to %q or %q",
			KMSProviderKMSv2, KMSProviderTransit)
	}
	if s.KMSPrevious.Configured() {
		if err := validateKMS("secrets.kms_previous", s.KMSPrevious); err != nil {
			return err
		}
	} else if blockStated(s.KMSPrevious) {
		return fmt.Errorf("secrets.kms_previous has settings but no provider; set provider to %q or %q",
			KMSProviderKMSv2, KMSProviderTransit)
	}

	switch strings.TrimSpace(s.PreviousRoot) {
	case "":
	case PreviousRootPassphrase:
		if !s.KMS.Configured() {
			return fmt.Errorf("secrets.previous_root: %s names CLOOP_SECRET_KEY as the root secrets.kms is "+
				"replacing, and no secrets.kms is configured", PreviousRootPassphrase)
		}
		if s.KMSPrevious.Configured() {
			return fmt.Errorf("secrets.previous_root: %s and secrets.kms_previous both name a previous root; "+
				"a change of root moves from one root to one other — finish one change first", PreviousRootPassphrase)
		}
	default:
		return fmt.Errorf("secrets.previous_root must be %q or empty (got %q); a KMS being replaced is "+
			"configured as secrets.kms_previous", PreviousRootPassphrase, s.PreviousRoot)
	}

	if s.KMS.Configured() && s.KMSPrevious.Configured() &&
		s.KMS.EffectiveName() == s.KMSPrevious.EffectiveName() {
		return fmt.Errorf("secrets.kms and secrets.kms_previous are both named %q; the registry records each "+
			"key's root by name, so the two roots of a change need two names (set name on one of them)",
			s.KMS.EffectiveName())
	}
	return nil
}

// blockStated reports whether a KMS block holds anything at all.
func blockStated(k KMSConfig) bool {
	return k != (KMSConfig{})
}

func validateKMS(field string, k KMSConfig) error {
	name := k.EffectiveName()
	if len(name) > kmsNameMax {
		return fmt.Errorf("%s.name is %d characters; at most %d", field, len(name), kmsNameMax)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s.name holds a control character", field)
		}
	}
	if strings.TrimSpace(k.Timeout) != "" {
		d, err := parseKMSDuration(k.Timeout)
		if err != nil {
			return fmt.Errorf("%s.timeout: %v", field, err)
		}
		if d < KMSTimeoutLower || d > KMSTimeoutUpper {
			return fmt.Errorf("%s.timeout must be between %s and %s (got %s)", field, KMSTimeoutLower, KMSTimeoutUpper, d)
		}
	}
	if strings.TrimSpace(k.StartupTimeout) != "" {
		d, err := parseKMSDuration(k.StartupTimeout)
		if err != nil {
			return fmt.Errorf("%s.startup_timeout: %v", field, err)
		}
		if d < KMSStartupTimeoutLower || d > KMSStartupTimeoutUpper {
			return fmt.Errorf("%s.startup_timeout must be between %s and %s (got %s)", field,
				time.Duration(KMSStartupTimeoutLower), KMSStartupTimeoutUpper, d)
		}
	}

	switch strings.TrimSpace(k.Provider) {
	case KMSProviderKMSv2:
		if _, err := KMSv2SocketPath(k.KMSv2.Endpoint); err != nil {
			return fmt.Errorf("%s: %v", field, strings.TrimPrefix(err.Error(), "secrets.kms."))
		}
		if k.Transit != (KMSTransitConfig{}) {
			return fmt.Errorf("%s.provider is %s, and the block also has transit settings — remove them, or set "+
				"provider: %s", field, KMSProviderKMSv2, KMSProviderTransit)
		}
	case KMSProviderTransit:
		if err := validateTransit(field+".transit", k.Transit); err != nil {
			return err
		}
		if k.KMSv2 != (KMSv2Config{}) {
			return fmt.Errorf("%s.provider is %s, and the block also has kmsv2 settings — remove them, or set "+
				"provider: %s", field, KMSProviderTransit, KMSProviderKMSv2)
		}
	default:
		return fmt.Errorf("%s.provider must be %q or %q (got %q)", field, KMSProviderKMSv2, KMSProviderTransit, k.Provider)
	}
	return nil
}

func validateTransit(field string, t KMSTransitConfig) error {
	if strings.TrimSpace(t.Address) == "" {
		return fmt.Errorf("%s.address is required", field)
	}
	ep, err := tlsconf.ParseEndpoint(t.Address)
	if err != nil || ep.URL.Scheme == "ws" || ep.URL.Scheme == "wss" {
		return fmt.Errorf("%s.address %q is not an http(s) URL", field, t.Address)
	}
	if ep.URL.User != nil {
		return fmt.Errorf("%s.address carries credentials; the token comes from token_file or kubernetes", field)
	}
	if !ep.Secure && !ep.Loopback {
		return fmt.Errorf("%s.address %s is plain http to a host that is not loopback: the Vault token and every "+
			"key-encryption key it unwraps would cross the network in the clear — use https", field, ep.URL.Redacted())
	}
	if strings.TrimSpace(t.Key) == "" {
		return fmt.Errorf("%s.key is required: the name of the Transit key", field)
	}
	for _, part := range []struct{ name, v string }{{"key", t.Key}, {"mount", t.Mount}, {"namespace", t.Namespace},
		{"kubernetes.mount", t.Kubernetes.Mount}, {"kubernetes.role", t.Kubernetes.Role}} {
		if strings.ContainsAny(part.v, "?#%\\ \t\n") || strings.Contains(part.v, "..") {
			return fmt.Errorf("%s.%s %q is not a Vault path segment", field, part.name, part.v)
		}
	}
	if strings.Contains(strings.Trim(t.Key, "/"), "/") {
		return fmt.Errorf("%s.key %q holds a slash; it is one Transit key name", field, t.Key)
	}
	hasToken := strings.TrimSpace(t.TokenFile) != ""
	hasK8s := strings.TrimSpace(t.Kubernetes.Role) != ""
	switch {
	case hasToken && hasK8s:
		return fmt.Errorf("%s: token_file and kubernetes.role both say how to authenticate; keep one", field)
	case !hasToken && !hasK8s:
		return fmt.Errorf("%s: set token_file (a Vault Agent sink, say) or kubernetes.role — there is no token "+
			"in the configuration file and none is read from the environment", field)
	}
	for _, p := range []struct{ name, v string }{{"token_file", t.TokenFile}, {"ca_file", t.CAFile},
		{"kubernetes.token_file", t.Kubernetes.TokenFile}} {
		if v := strings.TrimSpace(p.v); v != "" && !filepath.IsAbs(v) {
			return fmt.Errorf("%s.%s %q is not an absolute path", field, p.name, v)
		}
	}
	if (strings.TrimSpace(t.Kubernetes.Mount) != "" || strings.TrimSpace(t.Kubernetes.TokenFile) != "") && !hasK8s {
		return fmt.Errorf("%s.kubernetes has settings but no role", field)
	}
	return nil
}

func parseKMSDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (write it like 5s or 1m)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative", s)
	}
	return d, nil
}
