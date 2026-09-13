// Package claudecodeauth - identity.go allocates one private Claude CLI
// configuration directory per hub user, which is what makes per-user logins
// possible at all.
//
// Motivation (Task 20241): `claude auth login` writes its OAuth credential to
// a single well-known location derived from the process's HOME. On a
// single-user desktop that is exactly right. On an OIDC hub it means every
// signed-in user shares one Claude account: whoever logged in last owns the
// credential, their subscription is billed for everybody's tasks, and the
// next person to log in silently evicts them. `claude auth logout` logs the
// whole deployment out.
//
// The CLI reads CLAUDE_CONFIG_DIR in preference to HOME and keeps *all* of
// its per-account state there — credentials, session transcripts, project
// history — so pointing each identity at its own directory isolates not just
// the token but the conversation history that would otherwise leak across
// tenants.
//
// These directories live under the hub's global config directory and
// deliberately NOT under any project tree: a task runs an agent inside the
// project working directory, so a credential stored there would be readable
// by the very code it is meant to be isolated from.
package claudecodeauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// homesDirName is the subdirectory of the cloop global config directory that
// holds one Claude CLI config directory per identity.
const homesDirName = "claude-identities"

// ErrNoIdentity is returned when a per-user home is requested for an empty
// owner key. Callers treat it as "use the host default", which is the
// pre-OIDC behaviour and the correct answer for a single-user deployment.
var ErrNoIdentity = errors.New("claudecodeauth: no identity")

// configRoot returns the cloop global config directory, matching the
// convention used by pkg/workspace and pkg/globalbudget (XDG_CONFIG_HOME,
// falling back to ~/.config/cloop).
func configRoot() (string, error) {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "cloop"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".config", "cloop"), nil
}

// IdentitySlug maps an identity's owner key onto a stable, filesystem-safe
// directory name.
//
// The owner key is an email address or "sub:<subject>" — both attacker-
// influenced (an IdP subject is whatever the issuer says it is) and neither
// safe as a path component: they can contain "/" and ".." , differ only by
// case on a case-insensitive filesystem, or exceed NAME_MAX. Hashing sidesteps
// every one of those without needing to enumerate them. 128 bits of the digest
// is far beyond collision range for a user directory.
//
// The mapping is deliberately deterministic and unsalted so an operator can
// recompute it: sha256(owner_key) truncated to 32 hex characters.
func IdentitySlug(ownerKey string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(ownerKey))))
	return hex.EncodeToString(sum[:])[:32]
}

// HomeRoot returns the directory holding every identity's Claude config
// directory, creating it 0700 if absent.
func HomeRoot() (string, error) {
	root, err := configRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, homesDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create claude identity root %s: %w", dir, err)
	}
	// MkdirAll is a no-op on an existing directory, so a root created by an
	// older build (or a careless operator) keeps whatever mode it had. Tighten
	// it: this tree holds OAuth refresh tokens for every user of the hub.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("restrict claude identity root %s: %w", dir, err)
	}
	return dir, nil
}

// HomeFor returns the private Claude CLI configuration directory for one
// identity, creating it 0700 if absent. The returned path is what callers
// place in CLAUDE_CONFIG_DIR.
//
// An empty owner key yields ErrNoIdentity rather than a shared fallback
// directory: "no identity" must mean "use the host default", never "use the
// directory that every anonymous caller shares", which would recreate the
// pooled-credential problem this package exists to remove.
func HomeFor(ownerKey string) (string, error) {
	if strings.TrimSpace(ownerKey) == "" {
		return "", ErrNoIdentity
	}
	root, err := HomeRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, IdentitySlug(ownerKey))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create claude identity home %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("restrict claude identity home %s: %w", dir, err)
	}
	return dir, nil
}

// ForgetHome removes an identity's Claude configuration directory entirely,
// destroying the stored credential along with the CLI's cached session
// transcripts.
//
// This is the deprovisioning path: `claude auth logout` revokes the session
// but leaves the directory populated, and a hub that keeps an ex-employee's
// refresh token on disk has not really removed them.
func ForgetHome(ownerKey string) error {
	if strings.TrimSpace(ownerKey) == "" {
		return ErrNoIdentity
	}
	root, err := HomeRoot()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, IdentitySlug(ownerKey))
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove claude identity home %s: %w", dir, err)
	}
	return nil
}

// CredentialsPath returns where the CLI stores its OAuth credential inside a
// config directory. Exported so the usage/refresh path in pkg/ratelimit and
// the tests agree on one definition.
func CredentialsPath(configDir string) string {
	return filepath.Join(configDir, ".credentials.json")
}

// HasCredential reports whether a config directory holds a non-empty
// credentials file. Used to answer "is this user logged in?" without paying
// for a CLI subprocess.
func HasCredential(configDir string) bool {
	if strings.TrimSpace(configDir) == "" {
		return false
	}
	st, err := os.Stat(CredentialsPath(configDir))
	return err == nil && st.Size() > 0
}
