// Package hubclient is the terminal's side of a cloop hub with single sign-on
// (Task 20412): where `cloop login` keeps the session it was approved for, the
// device-authorization client that gets one, and the handful of API calls the
// `cloop remote` commands and `cloop task attach` make with it.
//
// # The credential file
//
// $XDG_CONFIG_HOME/cloop/hubs.json (~/.config/cloop/hubs.json when the
// variable is unset), one entry per hub URL plus an optional default. The
// session credential in it is the bearer the hub authenticates the terminal
// by, so the file is written 0600 in a 0700 directory, and a file anybody
// but its owner can read is refused outright rather than used: a credential
// another account could have copied is one to replace, not to keep presenting.
// Nothing in this package prints a credential, and every error that mentions
// the file names its path and its mode, never its contents.
package hubclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FileName is the credential file's name inside the cloop config directory.
const FileName = "hubs.json"

// ErrInsecurePermissions means the credential file is readable by somebody
// other than its owner, or is not a plain file, and was refused.
var ErrInsecurePermissions = errors.New("hubclient: the credential file is readable by other users")

// Hub is one signed-in hub.
type Hub struct {
	// URL is the hub's base URL as NormalizeURL renders it.
	URL string `json:"url"`
	// Credential is the terminal's session credential: the bearer the hub
	// authenticates this terminal by. Never printed.
	Credential string `json:"credential"`
	// SessionID is the session's public id — the credential's digest — as
	// the hub's Active Sessions table and audit trail name it.
	SessionID string `json:"session_id"`
	// CAFile is a PEM bundle to trust for this hub, for a hub whose
	// certificate is not signed by a public CA.
	CAFile string `json:"ca_file,omitempty"`

	Subject string `json:"subject,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`

	// SignedInAt is when the hub approved the session and ExpiresAt when it
	// ends at the latest; it may end sooner, idle or revoked.
	SignedInAt time.Time `json:"signed_in_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	// Client is the host name the terminal reported when it signed in.
	Client string `json:"client,omitempty"`

	// revalidated and idle are what the hub said about the session when it
	// approved it (see LoginNotes); reported once, never stored.
	revalidated bool
	idle        time.Duration
}

// Label is how a hub's identity is shown: the email, else the name, else the
// subject.
func (h *Hub) Label() string {
	switch {
	case h == nil:
		return ""
	case h.Email != "":
		return h.Email
	case h.Name != "":
		return h.Name
	}
	return h.Subject
}

// File is the credential file's contents.
type File struct {
	// Default is the URL of the hub commands talk to when none is named.
	Default string `json:"default,omitempty"`
	// Hubs is keyed by NormalizeURL of each hub's URL.
	Hubs map[string]*Hub `json:"hubs"`
}

// DefaultPath returns where the credential file lives: under
// $XDG_CONFIG_HOME, or ~/.config when that is unset or not absolute — the
// XDG Base Directory rule.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" || !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("hubclient: locate the config directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "cloop", FileName), nil
}

// Load reads the credential file. A missing file is an empty one. A file
// other users can read, or one that is not a plain file, is refused with an
// error wrapping ErrInsecurePermissions.
func Load(path string) (*File, error) {
	return load(path, true)
}

// LoadForRevocation reads the credential file even when other users can read
// it — for `cloop logout`, whose job with such a file is exactly to revoke the
// sessions in it at their hubs, since somebody may have copied them, and then
// to delete it. Anything that would present a credential uses Load.
func LoadForRevocation(path string) (*File, error) {
	return load(path, false)
}

func load(path string, strict bool) (*File, error) {
	f := &File{Hubs: map[string]*Hub{}}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hubclient: %s: %w", path, err)
	}
	if err := checkPrivate(path, info); err != nil && (strict || !info.Mode().IsRegular()) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hubclient: read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return f, nil
	}
	if err := json.Unmarshal(data, f); err != nil {
		// Not the contents: they hold credentials.
		return nil, fmt.Errorf("hubclient: %s is not a valid credential file — delete it and run `cloop login` again", path)
	}
	if f.Hubs == nil {
		f.Hubs = map[string]*Hub{}
	}
	return f, nil
}

// checkPrivate refuses a credential file that is not a plain file, or that
// its group or anybody else may read or write.
func checkPrivate(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a plain file (%s) — remove it and run `cloop login` again",
			ErrInsecurePermissions, path, info.Mode().Type())
	}
	if runtime.GOOS == "windows" {
		// Mode bits mean nothing there; the profile directory's ACL is what
		// protects it.
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %#o, so other users may have copied the session credentials in it. "+
			"Run `cloop logout --all` to revoke them at their hubs and delete the file, then `cloop login` again",
			ErrInsecurePermissions, path, perm)
	}
	return nil
}

// Save writes the file at path, mode 0600 in a 0700 directory, by writing a
// temporary file beside it and renaming it into place — so a crash leaves the
// old file or the new one, never half of either, and the credential is never
// on disk under a looser mode for even a moment.
func (f *File) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("hubclient: create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("hubclient: encode credentials: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".hubs-*.json")
	if err != nil {
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("hubclient: write %s: %w", path, err)
	}
	return nil
}

// Lookup returns the entry for a hub URL, in any spelling NormalizeURL
// accepts.
func (f *File) Lookup(rawURL string) (*Hub, bool) {
	if f == nil {
		return nil, false
	}
	key, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, false
	}
	h, ok := f.Hubs[key]
	return h, ok && h != nil
}

// Put records a hub's entry under its normalised URL, making it the default
// when there is none yet.
func (f *File) Put(h *Hub) {
	if f.Hubs == nil {
		f.Hubs = map[string]*Hub{}
	}
	f.Hubs[h.URL] = h
	if f.Default == "" {
		f.Default = h.URL
	}
}

// Remove drops a hub's entry, and the default if it named that hub — the next
// remaining hub, if exactly one remains, becomes the default.
func (f *File) Remove(url string) {
	delete(f.Hubs, url)
	if f.Default == url {
		f.Default = ""
		if len(f.Hubs) == 1 {
			for k := range f.Hubs {
				f.Default = k
			}
		}
	}
}

// URLs lists the signed-in hubs, sorted.
func (f *File) URLs() []string {
	out := make([]string, 0, len(f.Hubs))
	for k := range f.Hubs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NormalizeURL renders a hub URL the one way the credential file keys it:
// scheme and host, lower-cased, a default port dropped, no path. A bare host
// is taken as https. Anything with a path, a query, a fragment or user
// information is refused — `cloop login https://hub/device` is a mistake worth
// naming rather than a URL to guess at.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("hubclient: a hub URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("hubclient: hub URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("hubclient: hub URL %q must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("hubclient: hub URL %q names no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("hubclient: hub URL %q must not carry a user name or password", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("hubclient: hub URL %q has a path; give the hub's base URL, like %s://%s", raw, scheme, u.Host)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}
