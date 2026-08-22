package remote

// bundle.go is the operator-carried output of enrollment: everything a device
// needs to reach the right control plane, in one blob.
//
// Before this existed, `cloop executor enroll` printed a URL and a token, and
// the device took the URL on faith. That is the gap this closes. A token is
// proof the *device* is authorised; it says nothing about whether the server
// that answered is the control plane. An attacker who can answer DNS — a
// hostile coffee-shop network, a compromised upstream resolver, a
// mis-transcribed hostname — collects the enrollment token from the first
// connection and enrolls itself instead. Carrying the hub's SPKI pin alongside
// the token makes the trust mutual: the device proves who it is, and the pin
// proves who the server is, both before any credential leaves the device.
//
// The pin is over the public key, not the certificate, so a routine
// certificate renewal that reuses the key does not invalidate every bundle and
// every enrolled device. See pkg/tlsconf for the reasoning in full.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Bundle is the enrollment payload handed to a device.
//
// It is deliberately JSON with an unpadded-base64 envelope rather than a
// bespoke format: an operator pastes it into a terminal, a provisioning script
// pipes it through a file, and both need it to survive being a single opaque
// word with no shell-special characters in it.
type Bundle struct {
	// Server is the control-plane WebSocket URL the device dials.
	Server string `json:"server"`
	// Token is the single-use enrollment token.
	Token string `json:"token"`
	// Pin is the hub's SPKI fingerprint ("sha256:<base64>"), or "" when the
	// control plane has no TLS certificate configured. An empty pin is not a
	// silent downgrade: the device still refuses plaintext to a non-loopback
	// host, so an unpinned bundle can only be used against a server with a
	// publicly-trusted certificate, or over loopback.
	Pin string `json:"pin,omitempty"`
	// EnrollmentID identifies the minted token for revocation.
	EnrollmentID string `json:"enrollment_id"`
	// Name is the operator-facing label the device will carry.
	Name string `json:"name"`
	// WorkDirRoot is the filesystem root the device confines workloads to.
	WorkDirRoot string `json:"workdir_root,omitempty"`
	// ExpiresAt is when the token stops being redeemable.
	ExpiresAt time.Time `json:"expires_at"`
}

// bundlePrefix tags the encoded form so a mis-pasted string fails with a
// useful message instead of a base64 error.
const bundlePrefix = "cloopenroll1."

// Validate reports whether the bundle has the fields a device needs.
func (b Bundle) Validate() error {
	if strings.TrimSpace(b.Server) == "" {
		return fmt.Errorf("remote: enrollment bundle has no server URL")
	}
	if strings.TrimSpace(b.Token) == "" {
		return fmt.Errorf("remote: enrollment bundle has no token")
	}
	return nil
}

// Encode renders the bundle as a single copy-pasteable token.
func (b Bundle) Encode() (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("remote: encode enrollment bundle: %w", err)
	}
	return bundlePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeBundle parses the output of Encode.
func DecodeBundle(s string) (Bundle, error) {
	v := strings.TrimSpace(s)
	if !strings.HasPrefix(v, bundlePrefix) {
		return Bundle{}, fmt.Errorf("remote: not an enrollment bundle (expected a %s… string)", bundlePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, bundlePrefix))
	if err != nil {
		return Bundle{}, fmt.Errorf("remote: decode enrollment bundle: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("remote: parse enrollment bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Command renders the copy-pasteable device command for this bundle.
//
// The pin is included as a flag rather than left to the bundle blob because
// the flag form is what an operator reads, checks against what the control
// plane printed, and notices when it is missing.
func (b Bundle) Command() string {
	var sb strings.Builder
	sb.WriteString("cloop executor agent")
	sb.WriteString(" --server " + shellQuote(b.Server))
	sb.WriteString(" --token " + shellQuote(b.Token))
	if p := strings.TrimSpace(b.Pin); p != "" {
		sb.WriteString(" --pin " + shellQuote(p))
	}
	return sb.String()
}

// shellQuote wraps a value in single quotes when it contains anything a shell
// would interpret, so a copied command does the same thing it displays.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_.:/@+=", r):
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// MintBundle mints an enrollment token and wraps it, with the hub's pin, into
// the blob the operator carries to the device.
//
// It is a thin layer over Mint rather than a replacement so the storage-facing
// contract (single-use, hash-only persistence, MAC-bound tokens) stays in one
// place and is exercised by both paths.
func MintBundle(store Store, opts MintOptions) (Bundle, EnrollmentRecord, error) {
	token, rec, err := Mint(store, opts)
	if err != nil {
		return Bundle{}, EnrollmentRecord{}, err
	}
	return Bundle{
		Server:       strings.TrimSpace(opts.Server),
		Token:        token,
		Pin:          strings.TrimSpace(opts.Pin),
		EnrollmentID: rec.ID,
		Name:         rec.Name,
		WorkDirRoot:  rec.WorkDirRoot,
		ExpiresAt:    rec.ExpiresAt,
	}, rec, nil
}
