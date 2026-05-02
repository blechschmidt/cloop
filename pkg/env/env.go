// Package env manages per-project environment variables for cloop.
// Variables are stored in .cloop/env.yaml. Secret values are stored
// base64-encoded with an "enc:" prefix so they are not in plain text.
package env

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	envFile   = "env.yaml"
	secretPfx = "enc:"
)

// Var is a single environment variable entry.
type Var struct {
	Key         string `yaml:"key"`
	Value       string `yaml:"value"`
	Description string `yaml:"description,omitempty"`
	Secret      bool   `yaml:"secret,omitempty"`
}

// envFile path within .cloop/.
func envPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", envFile)
}

// Load reads .cloop/env.yaml and returns all vars.
// Returns an empty slice (not an error) if the file does not exist.
func Load(workDir string) ([]Var, error) {
	data, err := os.ReadFile(envPath(workDir))
	if os.IsNotExist(err) {
		return []Var{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("env: read %s: %w", envFile, err)
	}
	var vars []Var
	if err := yaml.Unmarshal(data, &vars); err != nil {
		return nil, fmt.Errorf("env: parse %s: %w", envFile, err)
	}
	if vars == nil {
		vars = []Var{}
	}
	return vars, nil
}

// Save writes vars to .cloop/env.yaml, encoding Secret values.
// Secret values that are not already encoded are base64-encoded and
// stored with the "enc:" prefix.
func Save(workDir string, vars []Var) error {
	out := make([]Var, len(vars))
	for i, v := range vars {
		out[i] = v
		if v.Secret && v.Value != "" && !strings.HasPrefix(v.Value, secretPfx) {
			out[i].Value = secretPfx + base64.StdEncoding.EncodeToString([]byte(v.Value))
		}
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("env: marshal: %w", err)
	}
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("env: mkdir .cloop: %w", err)
	}
	if err := os.WriteFile(envPath(workDir), data, 0o600); err != nil {
		return fmt.Errorf("env: write %s: %w", envFile, err)
	}
	return nil
}

// Expand returns a key→plain-text-value map, decoding any "enc:" secrets.
func Expand(vars []Var) map[string]string {
	m := make(map[string]string, len(vars))
	for _, v := range vars {
		val := v.Value
		if strings.HasPrefix(val, secretPfx) {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, secretPfx))
			if err == nil {
				val = string(decoded)
			}
		}
		m[v.Key] = val
	}
	return m
}

// InjectIntoPrompt replaces {{KEY}} placeholders in prompt with the
// corresponding values from vars. Unknown placeholders are left intact.
func InjectIntoPrompt(prompt string, vars []Var) string {
	if len(vars) == 0 {
		return prompt
	}
	m := Expand(vars)
	for k, val := range m {
		prompt = strings.ReplaceAll(prompt, "{{"+k+"}}", val)
	}
	return prompt
}

// EnvLines returns the vars as KEY=value pairs suitable for os/exec Env.
// Secret values are decoded before being returned.
func EnvLines(vars []Var) []string {
	m := Expand(vars)
	lines := make([]string, 0, len(m))
	for k, v := range m {
		lines = append(lines, k+"="+v)
	}
	return lines
}

// Upsert adds or replaces the var with v.Key in vars and returns the new slice.
func Upsert(vars []Var, v Var) []Var {
	for i, existing := range vars {
		if existing.Key == v.Key {
			vars[i] = v
			return vars
		}
	}
	return append(vars, v)
}

// Delete removes the var with the given key from vars and returns the new slice.
// Returns the slice unchanged and false if the key was not found.
func Delete(vars []Var, key string) ([]Var, bool) {
	for i, v := range vars {
		if v.Key == key {
			return append(vars[:i], vars[i+1:]...), true
		}
	}
	return vars, false
}

// Get returns the Var for the given key and true if found.
func Get(vars []Var, key string) (Var, bool) {
	for _, v := range vars {
		if v.Key == key {
			return v, true
		}
	}
	return Var{}, false
}

// DecodeValue returns the plain-text value for a Var, decoding "enc:" secrets.
func DecodeValue(v Var) string {
	if strings.HasPrefix(v.Value, secretPfx) {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v.Value, secretPfx))
		if err == nil {
			return string(decoded)
		}
	}
	return v.Value
}
