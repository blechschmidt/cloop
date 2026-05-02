package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RegistryPlugin describes a plugin entry in the remote registry.
type RegistryPlugin struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	URL         string   `json:"url"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
}

// Registry is the top-level structure of the remote plugin registry JSON.
type Registry struct {
	Plugins []RegistryPlugin `json:"plugins"`
}

// FetchRegistry downloads and parses the plugin registry from the given URL.
func FetchRegistry(url string) (*Registry, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetching registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading registry response: %w", err)
	}

	var reg Registry
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, fmt.Errorf("parsing registry JSON: %w", err)
	}
	return &reg, nil
}

// Search filters registry plugins whose name, description, or tags contain
// all words in query (case-insensitive). If query is empty all plugins are
// returned.
func Search(reg *Registry, query string) []RegistryPlugin {
	if query == "" {
		out := make([]RegistryPlugin, len(reg.Plugins))
		copy(out, reg.Plugins)
		return out
	}

	words := strings.Fields(strings.ToLower(query))
	var results []RegistryPlugin
	for _, p := range reg.Plugins {
		if matchesAll(p, words) {
			results = append(results, p)
		}
	}
	return results
}

// matchesAll returns true if every word appears in at least one of the plugin's
// searchable fields (name, description, tags).
func matchesAll(p RegistryPlugin, words []string) bool {
	haystack := strings.ToLower(p.Name + " " + p.Description + " " + strings.Join(p.Tags, " "))
	for _, w := range words {
		if !strings.Contains(haystack, w) {
			return false
		}
	}
	return true
}
