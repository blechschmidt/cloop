package imagepolicy

// registryauth.go reads the registry logins this host's user holds, in the
// Docker-format files cosign's own keychain reads (Task 20424). The hub then
// resolves a tag as the same identity that verifies its signature, rather than
// as one with a different view of a private repository.
//
// Only the "auths" entries are read. A credential helper ("credsStore",
// "credHelpers") is not run: executing a program named by a config file to
// answer a resolution is more than a resolution should do, and a hub whose
// logins live in a helper pins its project images by digest instead, which
// needs no resolution at all.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxAuthFileBytes bounds one credentials file read.
const maxAuthFileBytes = 1 << 20

// authFilePaths lists the credential files consulted, in order:
// $DOCKER_CONFIG/config.json or ~/.docker/config.json, $REGISTRY_AUTH_FILE, and
// $XDG_RUNTIME_DIR/containers/auth.json, where podman keeps its logins.
func authFilePaths() []string {
	var out []string
	if dir := strings.TrimSpace(os.Getenv("DOCKER_CONFIG")); dir != "" {
		out = append(out, filepath.Join(dir, "config.json"))
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, ".docker", "config.json"))
	}
	if f := strings.TrimSpace(os.Getenv("REGISTRY_AUTH_FILE")); f != "" {
		out = append(out, f)
	}
	if dir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); dir != "" {
		out = append(out, filepath.Join(dir, "containers", "auth.json"))
	}
	return out
}

// authEntry is one "auths" entry.
type authEntry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DockerConfigCredential returns the login the first credentials file that
// holds one has for registry. A file that is missing, unreadable or malformed
// is skipped: it holds no login, which a resolution without one already
// handles by trying anonymously.
func DockerConfigCredential(registry string) (RegistryCredential, bool) {
	registry = authKeyRegistry(registry)
	if registry == "" {
		return RegistryCredential{}, false
	}
	for _, path := range authFilePaths() {
		if cred, ok := credentialIn(path, registry); ok {
			return cred, true
		}
	}
	return RegistryCredential{}, false
}

// credentialIn reads registry's login from one credentials file.
func credentialIn(path, registry string) (RegistryCredential, bool) {
	f, err := os.Open(path)
	if err != nil {
		return RegistryCredential{}, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAuthFileBytes))
	if err != nil {
		return RegistryCredential{}, false
	}
	var cfg struct {
		Auths map[string]authEntry `json:"auths"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return RegistryCredential{}, false
	}
	for key, entry := range cfg.Auths {
		if authKeyRegistry(key) != registry {
			continue
		}
		if cred, ok := entry.credential(); ok {
			return cred, true
		}
	}
	return RegistryCredential{}, false
}

// credential decodes an entry: "auth" is base64 of "user:password", and the
// separate fields are the other spelling of the same thing.
func (e authEntry) credential() (RegistryCredential, bool) {
	if e.Auth != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.Auth))
		if err != nil {
			return RegistryCredential{}, false
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok || user == "" {
			return RegistryCredential{}, false
		}
		return RegistryCredential{Username: user, Password: pass}, true
	}
	if e.Username != "" && e.Password != "" {
		return RegistryCredential{Username: e.Username, Password: e.Password}, true
	}
	return RegistryCredential{}, false
}

// DockerLogins is a set of registry logins read from a Docker-format
// configuration — the registry secret a Kubernetes executor resolves tags with
// (executors.kubernetes.registry_secret, Task 20457). Each login is offered to
// the registry its key names and to no other: a project that names an image on
// some other host gets an anonymous request there, never this one's password.
//
// The zero value holds no login.
type DockerLogins struct {
	logins map[string]RegistryCredential
}

// ParseDockerConfig reads the "auths" of a Docker-format configuration —
// what `docker login` writes to config.json — into the logins it holds.
//
// It refuses what is not one rather than reading it as "no login": a registry
// secret an operator stored is meant to be used, and resolving anonymously
// beside a mistyped one would hide the mistake until a private image failed.
// The errors name keys, never values: the input is a credential.
func ParseDockerConfig(data []byte) (DockerLogins, error) {
	var cfg struct {
		Auths map[string]authEntry `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DockerLogins{}, errors.New("not a Docker configuration: expected JSON with an \"auths\" " +
			"object, as `docker login` writes to config.json")
	}
	if len(cfg.Auths) == 0 {
		return DockerLogins{}, errors.New("the Docker configuration holds no login: its \"auths\" object is " +
			"missing or empty (a login kept by a credential helper is not in the file)")
	}
	out := DockerLogins{logins: make(map[string]RegistryCredential, len(cfg.Auths))}
	keys := make([]string, 0, len(cfg.Auths))
	for key := range cfg.Auths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		registry := authKeyRegistry(key)
		if registry == "" {
			return DockerLogins{}, fmt.Errorf("the Docker configuration's login %q names no registry", key)
		}
		cred, ok := cfg.Auths[key].credential()
		if !ok {
			return DockerLogins{}, fmt.Errorf("the Docker configuration's login for %s is not usable: it needs "+
				"\"auth\" (base64 of user:password) or \"username\" and \"password\"", registry)
		}
		if prev, dup := out.logins[registry]; dup && prev != cred {
			return DockerLogins{}, fmt.Errorf("the Docker configuration holds two different logins for %s", registry)
		}
		out.logins[registry] = cred
	}
	return out, nil
}

// Login returns the login for registry, if the configuration holds one. The
// registry is matched in the spelling ParseReference gives it, so Docker Hub's
// aliases find its one login.
func (l DockerLogins) Login(registry string) (RegistryCredential, bool) {
	if len(l.logins) == 0 {
		return RegistryCredential{}, false
	}
	cred, ok := l.logins[authKeyRegistry(registry)]
	return cred, ok
}

// Registries lists the registries the configuration holds a login for, sorted.
func (l DockerLogins) Registries() []string {
	out := make([]string, 0, len(l.logins))
	for r := range l.logins {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Empty reports whether no login is held.
func (l DockerLogins) Empty() bool { return len(l.logins) == 0 }

// dockerConfigFor renders the one login for registry as a Docker
// configuration, for a cosign run that has to fetch a signature from it.
func (l DockerLogins) dockerConfigFor(registry string) ([]byte, bool) {
	cred, ok := l.Login(registry)
	if !ok {
		return nil, false
	}
	// The key is the registry in the spelling go-containerregistry's keychain
	// looks up, which for Docker Hub is its v1 index URL.
	key := authKeyRegistry(registry)
	if key == DockerHub {
		key = "https://index.docker.io/v1/"
	}
	data, err := json.Marshal(map[string]any{"auths": map[string]any{
		key: map[string]string{"auth": basicAuth(cred)},
	}})
	if err != nil {
		return nil, false
	}
	return data, true
}

// loginsKey carries DockerLogins on a context.
type loginsKey struct{}

// WithRegistryLogins returns ctx carrying logins for the registry requests made
// under it — the signature check cosign runs for a Kubernetes Pod's image, which
// has to fetch the signature from the registry the tag was resolved at, as the
// same identity (Task 20457). A cosign run under a context with no login for the
// image's registry keeps cosign's own environment.
func WithRegistryLogins(ctx context.Context, logins DockerLogins) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, loginsKey{}, logins)
}

// registryLoginsFrom returns the logins ctx carries.
func registryLoginsFrom(ctx context.Context) (DockerLogins, bool) {
	if ctx == nil {
		return DockerLogins{}, false
	}
	l, ok := ctx.Value(loginsKey{}).(DockerLogins)
	return l, ok
}

// authKeyRegistry reduces an "auths" key — "ghcr.io", "https://ghcr.io/",
// "https://index.docker.io/v1/" — to the registry host it names, in the
// spelling ParseReference gives a reference's registry.
func authKeyRegistry(key string) string {
	key = strings.TrimSpace(key)
	if i := strings.Index(key, "://"); i >= 0 {
		key = key[i+3:]
	}
	if i := strings.IndexByte(key, '/'); i >= 0 {
		key = key[:i]
	}
	key = strings.ToLower(key)
	if canonical, ok := dockerHubAliases[key]; ok {
		return canonical
	}
	return key
}
