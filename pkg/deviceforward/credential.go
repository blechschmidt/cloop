package deviceforward

// credential.go persists a forwarder's long-lived credential on the device,
// the same way the executor agent persists its own: a 0600 JSON file holding
// the server URL, the forwarder ID and the credential secret, so that after
// first enrollment the device reconnects with no token on its command line.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// Credential is what a forwarder saves after enrolling.
type Credential struct {
	Server      string          `json:"server"`
	ForwarderID string          `json:"forwarder_id"`
	Credential  string          `json:"credential"`
	Name        string          `json:"name,omitempty"`
	Device      ForwardedDevice `json:"device"`
	Pin         string          `json:"pin,omitempty"`
}

// credentialMode is the permission the credential file must carry: it is a
// bearer secret for the life of the device.
const credentialMode os.FileMode = 0o600

// SaveCredential writes the credential atomically at 0600.
func SaveCredential(path string, c Credential) error {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return fmt.Errorf("deviceforward: no credential path")
	}
	if dir := filepath.Dir(clean); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("deviceforward: create credential directory: %w", err)
		}
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("deviceforward: encode credential: %w", err)
	}
	if err := atomicfile.Write(clean, raw, credentialMode); err != nil {
		return fmt.Errorf("deviceforward: write credential: %w", err)
	}
	return nil
}

// LoadCredential reads a saved credential. A missing file is reported as
// (zero, false, nil): the caller then needs an enrollment token.
func LoadCredential(path string) (Credential, bool, error) {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return Credential{}, false, nil
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, false, nil
		}
		return Credential{}, false, fmt.Errorf("deviceforward: read credential %s: %w", clean, err)
	}
	var c Credential
	if err := json.Unmarshal(raw, &c); err != nil {
		return Credential{}, false, fmt.Errorf("deviceforward: parse credential %s: %w", clean, err)
	}
	if strings.TrimSpace(c.Credential) == "" {
		return Credential{}, false, fmt.Errorf("deviceforward: credential %s has no secret", clean)
	}
	return c, true, nil
}
