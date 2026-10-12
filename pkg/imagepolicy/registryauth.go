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
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
