// Package profile manages named provider/model configuration profiles stored globally in ~/.cloop/profiles.yaml.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"gopkg.in/yaml.v3"
)

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
func LoadProfiles() ([]Profile, error) {
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

// SaveProfiles writes the profiles slice to ~/.cloop/profiles.yaml.
func SaveProfiles(profiles []Profile) error {
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
	return os.WriteFile(path, data, 0o644)
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
func SetActive(name string) error {
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
	return os.WriteFile(path, []byte(name+"\n"), 0o644)
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
func Upsert(p Profile) error {
	profiles, err := LoadProfiles()
	if err != nil {
		return err
	}
	for i, existing := range profiles {
		if existing.Name == p.Name {
			profiles[i] = p
			return SaveProfiles(profiles)
		}
	}
	profiles = append(profiles, p)
	return SaveProfiles(profiles)
}

// Delete removes the named profile. Returns nil if it does not exist.
func Delete(name string) error {
	profiles, err := LoadProfiles()
	if err != nil {
		return err
	}
	filtered := profiles[:0]
	for _, p := range profiles {
		if p.Name != name {
			filtered = append(filtered, p)
		}
	}
	return SaveProfiles(filtered)
}
