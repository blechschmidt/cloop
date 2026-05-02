// Package mock provides a deterministic offline provider for CI and testing.
// It returns scripted responses based on prompt substring or hash matching,
// without making any network calls.
package mock

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
	"gopkg.in/yaml.v3"
)

const (
	ProviderName = "mock"
	DefaultModel = "mock-model"
	// DefaultResponse is returned when no rule matches and no default is configured.
	DefaultResponse = "TASK_DONE"
)

// ResponseRule maps a prompt pattern to a canned response.
type ResponseRule struct {
	// Substring, if non-empty, matches when the prompt contains this string (case-sensitive).
	Substring string `yaml:"substring"`
	// Hash, if non-empty, matches when the SHA-256 hex digest of the prompt equals this value.
	// Use this for exact, deterministic matching independent of substring.
	Hash string `yaml:"hash"`
	// Response is the canned output returned when this rule matches.
	Response string `yaml:"response"`
}

// ResponsesConfig is the structure of the mock_responses.yaml file.
type ResponsesConfig struct {
	// Rules are evaluated in order; the first match wins.
	Rules []ResponseRule `yaml:"rules"`
	// Default is returned when no rule matches. Defaults to "TASK_DONE".
	Default string `yaml:"default"`
}

// Provider is a deterministic mock provider that never makes network calls.
type Provider struct {
	// responsesFile is the path to the YAML responses config file.
	// If empty, the provider auto-detects .cloop/mock_responses.yaml from workDir.
	responsesFile string
	// workDir is the fallback working directory used when opts.WorkDir is empty.
	// Set via NewWithWorkDir for test scenarios where callers don't pass WorkDir in opts.
	workDir string
}

// New creates a mock provider that reads scripted responses from responsesFile.
// When a call to Complete() provides opts.WorkDir, that directory is used to
// locate the responses file; otherwise it falls back to auto-detecting
// .cloop/mock_responses.yaml in the current directory.
// If responsesFile is empty, the default path .cloop/mock_responses.yaml is used.
func New(responsesFile string) *Provider {
	return &Provider{responsesFile: responsesFile}
}

// NewWithWorkDir creates a mock provider with an explicit fallback workDir.
// Use this when callers (e.g. pm.Decompose) do not pass opts.WorkDir.
func NewWithWorkDir(responsesFile, workDir string) *Provider {
	return &Provider{responsesFile: responsesFile, workDir: workDir}
}

func (p *Provider) Name() string         { return ProviderName }
func (p *Provider) DefaultModel() string { return DefaultModel }

// Complete returns a scripted response without any network calls.
// Rules in the responses file are checked in order; the first match wins.
// If no rule matches, the configured default (or DefaultResponse) is returned.
func (p *Provider) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = p.workDir
	}
	cfg := p.loadConfig(workDir)

	response := p.match(cfg, prompt)

	if opts.OnToken != nil {
		opts.OnToken(response)
	}

	return &provider.Result{
		Output:   response,
		Provider: ProviderName,
		Model:    opts.Model,
		Duration: time.Millisecond,
	}, nil
}

// loadConfig loads the responses config from the configured file path.
// Falls back gracefully if the file is missing or unparseable.
func (p *Provider) loadConfig(workDir string) ResponsesConfig {
	path := p.resolvedPath(workDir)
	if path == "" {
		return ResponsesConfig{}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// File not found or unreadable — use empty config (default response).
		return ResponsesConfig{}
	}

	var cfg ResponsesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// Malformed YAML — use empty config.
		return ResponsesConfig{}
	}
	return cfg
}

// resolvedPath returns the absolute path to the responses file.
// If the configured path is relative, it is resolved against workDir.
// When no responsesFile is configured, falls back to .cloop/mock_responses.yaml
// relative to workDir.
func (p *Provider) resolvedPath(workDir string) string {
	if p.responsesFile == "" {
		if workDir != "" {
			return filepath.Join(workDir, ".cloop", "mock_responses.yaml")
		}
		return ""
	}
	if filepath.IsAbs(p.responsesFile) {
		return p.responsesFile
	}
	if workDir != "" {
		return filepath.Join(workDir, p.responsesFile)
	}
	return p.responsesFile
}

// match finds the first matching rule for prompt, returning its response.
// If no rule matches, the config default (or DefaultResponse) is used.
func (p *Provider) match(cfg ResponsesConfig, prompt string) string {
	promptHash := hashPrompt(prompt)

	for _, rule := range cfg.Rules {
		if rule.Hash != "" && strings.EqualFold(rule.Hash, promptHash) {
			return rule.Response
		}
		if rule.Substring != "" && strings.Contains(prompt, rule.Substring) {
			return rule.Response
		}
	}

	if cfg.Default != "" {
		return cfg.Default
	}
	return DefaultResponse
}

// hashPrompt returns the lowercase hex SHA-256 digest of prompt.
func hashPrompt(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return fmt.Sprintf("%x", sum)
}

// HashPrompt is exported for use in tests and tooling that generate response files.
func HashPrompt(prompt string) string {
	return hashPrompt(prompt)
}
