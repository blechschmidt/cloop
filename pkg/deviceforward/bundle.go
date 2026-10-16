package deviceforward

// bundle.go is the operator-carried output of forwarder enrollment: the server
// URL, the single-use token and the hub's SPKI pin, in one copy-pasteable
// blob. Same design and the same reasoning as pkg/executor/remote/bundle.go —
// a token proves the device is authorised, and only the pin proves the server
// that answered is the control plane rather than whoever can answer DNS.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Bundle is the enrollment payload handed to a forwarder.
type Bundle struct {
	Server       string          `json:"server"`
	Token        string          `json:"token"`
	Pin          string          `json:"pin,omitempty"`
	EnrollmentID string          `json:"enrollment_id"`
	Name         string          `json:"name"`
	Device       ForwardedDevice `json:"device"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

// bundlePrefix tags the encoded form so a mis-pasted string fails with a
// useful message instead of a base64 error, and so a forwarder bundle is never
// confused with an executor-agent one.
const bundlePrefix = "cloopfwd1."

// Validate reports whether the bundle has the fields a forwarder needs.
func (b Bundle) Validate() error {
	if strings.TrimSpace(b.Server) == "" {
		return fmt.Errorf("deviceforward: enrollment bundle has no server URL")
	}
	if strings.TrimSpace(b.Token) == "" {
		return fmt.Errorf("deviceforward: enrollment bundle has no token")
	}
	return nil
}

// Encode renders the bundle as a single copy-pasteable token.
func (b Bundle) Encode() (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("deviceforward: encode enrollment bundle: %w", err)
	}
	return bundlePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeBundle parses the output of Encode.
func DecodeBundle(s string) (Bundle, error) {
	v := strings.TrimSpace(s)
	if !strings.HasPrefix(v, bundlePrefix) {
		return Bundle{}, fmt.Errorf("deviceforward: not a forwarder enrollment bundle (expected a %s… string)", bundlePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, bundlePrefix))
	if err != nil {
		return Bundle{}, fmt.Errorf("deviceforward: decode enrollment bundle: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("deviceforward: parse enrollment bundle: %w", err)
	}
	return b, nil
}

// MintBundle mints a token and wraps it, the server URL and the pin into a
// bundle in one step, for the enroll command and the dashboard.
func MintBundle(store Store, opts MintOptions) (encoded string, rec EnrollmentRecord, err error) {
	token, rec, err := Mint(store, opts)
	if err != nil {
		return "", EnrollmentRecord{}, err
	}
	b := Bundle{
		Server:       strings.TrimSpace(opts.Server),
		Token:        token,
		Pin:          strings.TrimSpace(opts.Pin),
		EnrollmentID: rec.ID,
		Name:         rec.Name,
		Device:       rec.Device,
		ExpiresAt:    rec.ExpiresAt,
	}
	encoded, err = b.Encode()
	if err != nil {
		return "", EnrollmentRecord{}, err
	}
	return encoded, rec, nil
}

// TokenFileMode is the permission an enrollment file must carry.
const TokenFileMode os.FileMode = 0o600

// ReadTokenFile loads enrollment material from a file, accepting either a
// bundle or a bare token, exactly as the agent's loader does.
func ReadTokenFile(path string) (b Bundle, warning string, err error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return Bundle{}, "", fmt.Errorf("deviceforward: no enrollment file path given")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return Bundle{}, "", fmt.Errorf("deviceforward: read enrollment file %s: %w", clean, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		warning = fmt.Sprintf(
			"enrollment file %s is mode %04o; it should be %04o — treat the token as exposed and revoke it after enrolling",
			clean, perm, TokenFileMode)
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return Bundle{}, warning, fmt.Errorf("deviceforward: read enrollment file %s: %w", clean, err)
	}
	body := strings.TrimSpace(string(raw))
	if body == "" {
		return Bundle{}, warning, fmt.Errorf("deviceforward: enrollment file %s is empty", clean)
	}
	if strings.HasPrefix(body, bundlePrefix) {
		bundle, decErr := DecodeBundle(body)
		if decErr != nil {
			return Bundle{}, warning, decErr
		}
		return bundle, warning, nil
	}
	if strings.ContainsAny(body, " \t\n") {
		return Bundle{}, warning, fmt.Errorf(
			"deviceforward: enrollment file %s does not look like a token or a %s… bundle", clean, bundlePrefix)
	}
	return Bundle{Token: body}, warning, nil
}
