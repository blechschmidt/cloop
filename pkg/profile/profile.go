// Package profile manages named provider/model configuration profiles stored globally in ~/.cloop/profiles.yaml.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/config"
	"gopkg.in/yaml.v3"
)

// profilesMu serialises in-process writes to ~/.cloop/profiles.yaml and
// ~/.cloop/active_profile. Upsert/Delete do a load → modify → save cycle, so
// concurrent goroutines without this mutex would clobber each other's edits.
// It also pairs with the atomic-rename writes below: the rename is what
// protects against torn writes across processes; the mutex prevents the same
// process from racing itself.
var profilesMu sync.Mutex

// Profile is a named set of provider/model configuration overrides.
type Profile struct {
	Name        string `yaml:"name"`
	Provider    string `yaml:"provider,omitempty"`
	Model       string `yaml:"model,omitempty"`
	BaseURL     string `yaml:"base_url,omitempty"`
	APIKey      string `yaml:"api_key,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// profilesFile holds the list of profiles for YAML serialisation.
type profilesFile struct {
	Profiles []Profile `yaml:"profiles"`
}

// globalDir returns the ~/.cloop directory path.
func globalDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cloop"), nil
}

// profilesPath returns the path to ~/.cloop/profiles.yaml.
func profilesPath() (string, error) {
	dir, err := globalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.yaml"), nil
}

// activeProfilePath returns the path to ~/.cloop/active_profile.
func activeProfilePath() (string, error) {
	dir, err := globalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "active_profile"), nil
}

// LoadProfiles reads all profiles from ~/.cloop/profiles.yaml.
// Returns an empty slice (not an error) if the file does not exist.
//
// Reads don't take profilesMu — the atomic-rename writers always present a
// complete file, so a concurrent reader sees either the previous version or
// the new one, never a torn one.
func LoadProfiles() ([]Profile, error) {
	return loadProfilesLocked()
}

// SaveProfiles writes the profiles slice to ~/.cloop/profiles.yaml.
//
// The write is atomic — data is staged in a sibling .tmp file, fsynced, then
// renamed into place. profiles.yaml may contain API keys, so a torn write
// (crash, ENOSPC, or two cloop instances saving simultaneously) would silently
// drop credentials and break every profile-driven run until the user
// re-pasted them.
func SaveProfiles(profiles []Profile) error {
	profilesMu.Lock()
	defer profilesMu.Unlock()
	return saveProfilesLocked(profiles)
}

// saveProfilesLocked is the unsynchronised body of SaveProfiles. Callers that
// already hold profilesMu (e.g. Upsert/Delete) use this to avoid re-entrant
// locking.
func saveProfilesLocked(profiles []Profile) error {
	dir, err := globalDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "profiles.yaml")
	pf := profilesFile{Profiles: profiles}
	data, err := yaml.Marshal(pf)
	if err != nil {
		return err
	}
	// 0o600: owner read/write only — file may contain API keys.
	return writeAtomic(dir, path, ".profiles.yaml.*.tmp", data, 0o600)
}

// writeAtomic stages data in a sibling .tmp file in dir, fsyncs it, chmods to
// mode, then renames into path. Rename on POSIX is atomic with respect to
// readers, so they always see either the old or the new file — never a
// truncated one.
func writeAtomic(dir, path, tmpPattern string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("profile: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("profile: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("profile: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("profile: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("profile: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("profile: rename tmp: %w", err)
	}
	return nil
}

// GetActive returns the name of the active profile, or "" if none is set.
func GetActive() string {
	path, err := activeProfilePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SetActive writes the active profile name to ~/.cloop/active_profile.
// Pass "" to clear the active profile.
//
// The write is atomic and serialised — a partial write here would resolve to
// the wrong profile (or none) on the next run, silently swapping which API
// key/model gets used.
func SetActive(name string) error {
	profilesMu.Lock()
	defer profilesMu.Unlock()
	dir, err := globalDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "active_profile")
	if name == "" {
		// Remove file to clear the active profile.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomic(dir, path, ".active_profile.*.tmp", []byte(name+"\n"), 0o600)
}

// Get returns the named profile, or an error if it does not exist.
func Get(name string) (*Profile, error) {
	profiles, err := LoadProfiles()
	if err != nil {
		return nil, err
	}
	for i := range profiles {
		if profiles[i].Name == name {
			return &profiles[i], nil
		}
	}
	return nil, fmt.Errorf("profile %q not found", name)
}

// Apply overlays the non-empty fields from p onto cfg.
// Provider and Model override the top-level config fields.
// BaseURL and APIKey are applied to the matching provider sub-config.
func Apply(p Profile, cfg *config.Config) {
	if p.Provider != "" {
		cfg.Provider = p.Provider
	}
	switch cfg.Provider {
	case "anthropic":
		if p.Model != "" {
			cfg.Anthropic.Model = p.Model
		}
		if p.BaseURL != "" {
			cfg.Anthropic.BaseURL = p.BaseURL
		}
		if p.APIKey != "" {
			cfg.Anthropic.APIKey = p.APIKey
		}
	case "openai":
		if p.Model != "" {
			cfg.OpenAI.Model = p.Model
		}
		if p.BaseURL != "" {
			cfg.OpenAI.BaseURL = p.BaseURL
		}
		if p.APIKey != "" {
			cfg.OpenAI.APIKey = p.APIKey
		}
	case "ollama":
		if p.Model != "" {
			cfg.Ollama.Model = p.Model
		}
		if p.BaseURL != "" {
			cfg.Ollama.BaseURL = p.BaseURL
		}
	case "claudecode":
		if p.Model != "" {
			cfg.ClaudeCode.Model = p.Model
		}
	}
}

// Upsert adds a new profile or replaces an existing one with the same name.
//
// The load → modify → save cycle runs under profilesMu so two concurrent
// Upsert calls in the same process can't read the same baseline and drop one
// of the writes. Cross-process safety still relies on the atomic rename in
// saveProfilesLocked.
func Upsert(p Profile) error {
	profilesMu.Lock()
	defer profilesMu.Unlock()
	profiles, err := loadProfilesLocked()
	if err != nil {
		return err
	}
	for i, existing := range profiles {
		if existing.Name == p.Name {
			profiles[i] = p
			return saveProfilesLocked(profiles)
		}
	}
	profiles = append(profiles, p)
	return saveProfilesLocked(profiles)
}

// Delete removes the named profile. Returns nil if it does not exist.
func Delete(name string) error {
	profilesMu.Lock()
	defer profilesMu.Unlock()
	profiles, err := loadProfilesLocked()
	if err != nil {
		return err
	}
	filtered := profiles[:0]
	for _, p := range profiles {
		if p.Name != name {
			filtered = append(filtered, p)
		}
	}
	return saveProfilesLocked(filtered)
}

// loadProfilesLocked is the unsynchronised body of LoadProfiles for callers
// that already hold profilesMu.
func loadProfilesLocked() ([]Profile, error) {
	path, err := profilesPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var pf profilesFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	return pf.Profiles, nil
}
