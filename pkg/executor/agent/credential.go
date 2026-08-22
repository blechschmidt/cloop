// Package agent is the device side of cloop's remote executor: the process
// that runs on an edge device, dials out to a control plane, and executes the
// workloads it is sent.
//
// It exists because the interesting devices are unreachable. A build box in an
// office, a Jetson on a factory floor, a laptop on hotel wifi — all can make
// outbound HTTPS and none can accept an inbound connection. So the agent
// inverts the usual direction: it dials the control plane, holds one
// multiplexed WebSocket open, and receives work over it.
//
// Three properties shape the implementation:
//
//   - Reconnection is normal. Networks on edge devices drop constantly, so the
//     agent reconnects with capped exponential backoff plus jitter and resumes
//     log streaming from the offset the control plane actually received.
//   - Memory is finite. A device with 512 MiB of RAM cannot buffer a chatty
//     harness's output while the link is down, so retention is bounded and
//     overflow is reported rather than silently absorbed.
//   - The control plane is not trusted with the filesystem. Every workdir is
//     confined beneath a configured root, enforced on the device, because the
//     device is the only party that knows its own filesystem.
package agent

// credential.go persists the long-lived agent identity.
//
// The enrollment token is single-use and short-lived by design, so it cannot
// be what the agent authenticates with on every reconnect. Redemption yields a
// durable credential, and this file is where it lives: ~/.cloop/agent.json,
// mode 0600, written atomically.
//
// The file is the whole identity. Losing it means re-enrolling; leaking it
// means an attacker can impersonate the device until the credential is
// revoked. Hence 0600 and hence the permission check on load, which warns
// rather than fails — refusing to start a fleet of devices because a
// provisioning script used the wrong umask would be worse than the exposure it
// prevents, but silently accepting it would be worse still.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CredentialFileMode is the required permission for the credential file.
const CredentialFileMode os.FileMode = 0o600

// Credential is the durable identity the agent authenticates with.
type Credential struct {
	// Server is the control-plane WebSocket URL this credential is valid for.
	// Stored alongside the secret so `cloop executor agent` can be re-run with
	// no flags at all once enrolled.
	Server string `json:"server"`
	// AgentID is the control plane's identifier for this device. It is also
	// the executor ID projects bind to.
	AgentID string `json:"agent_id"`
	// Name is the operator-facing label chosen at enrollment.
	Name string `json:"name,omitempty"`
	// Credential is the long-lived secret. The control plane stores only its
	// hash, so this file is the only copy in existence.
	Credential string `json:"credential"`
	// WorkDirRoot is the filesystem root every workload is confined beneath.
	WorkDirRoot string `json:"workdir_root,omitempty"`
	// Pin is the control plane's SPKI fingerprint ("sha256:<base64>"), or
	// "" when the device was enrolled without one.
	//
	// It is persisted alongside the secret because pinning that only applied
	// to the enrollment connection would protect the least valuable moment
	// and leave every subsequent one — thousands of reconnects carrying a
	// long-lived credential, over years, from a device nobody visits —
	// trusting whatever answers DNS. Storing it makes the pin a property of
	// the device's identity rather than of one command line.
	Pin string `json:"pin,omitempty"`
	// EnrolledAt records when the credential was issued.
	EnrolledAt time.Time `json:"enrolled_at"`
}

// Valid reports whether the credential has the fields needed to connect.
func (c Credential) Valid() bool {
	return strings.TrimSpace(c.Credential) != "" && strings.TrimSpace(c.Server) != ""
}

// DefaultCredentialPath returns ~/.cloop/agent.json.
//
// It is under the user's home rather than the project's .cloop directory
// because the agent's identity belongs to the *device*, not to any project: a
// device runs workloads for many projects, and several of them may not exist
// on it yet.
func DefaultCredentialPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("agent: locate home directory: %w", err)
	}
	return filepath.Join(home, ".cloop", "agent.json"), nil
}

// LoadCredential reads the credential file.
//
// A missing file is reported as os.ErrNotExist so callers can distinguish
// "not enrolled yet" (prompt for a token) from "enrolled but broken" (a real
// error the operator must fix).
func LoadCredential(path string) (Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return Credential{}, fmt.Errorf("agent: parse %s: %w", path, err)
	}
	if strings.TrimSpace(c.Credential) == "" {
		return Credential{}, fmt.Errorf("agent: %s contains no credential; re-enroll this device", path)
	}
	return c, nil
}

// CheckCredentialPermissions reports a warning when the credential file is
// readable by anyone but its owner. Returns "" when the permissions are fine.
func CheckCredentialPermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf(
			"%s is mode %04o; the agent credential is readable by other users. Run: chmod 600 %s",
			path, perm, path)
	}
	return ""
}

// SaveCredential writes the credential atomically with 0600 permissions.
//
// Atomic because a device that loses power mid-write must not come back with a
// half-written identity it can neither use nor diagnose — the rename either
// happened or it did not.
//
// The temp file is created with 0600 from the outset rather than chmod'ed
// afterwards: a create-then-chmod sequence leaves a window in which the secret
// exists on disk world-readable, and on a shared device that window is enough.
func SaveCredential(path string, c Credential) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("agent: credential path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("agent: create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode credential: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, CredentialFileMode)
	if err != nil {
		return fmt.Errorf("agent: create %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("agent: write %s: %w", tmp, err)
	}
	// fsync before rename: on a device that may lose power without warning, a
	// rename can otherwise land in the directory entry while the file's own
	// contents are still in the page cache, yielding an empty agent.json.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("agent: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("agent: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("agent: install %s: %w", path, err)
	}
	// Re-assert the mode: if the file already existed, O_CREATE left the
	// original permissions in place rather than applying ours.
	if err := os.Chmod(path, CredentialFileMode); err != nil {
		return fmt.Errorf("agent: chmod %s: %w", path, err)
	}
	return nil
}
