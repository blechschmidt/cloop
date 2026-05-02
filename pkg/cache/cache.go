// Package cache provides a disk-based LRU response cache for AI provider calls.
// Cache key = SHA256(provider+model+prompt). Entries stored as gzip-compressed
// JSON files under .cloop/cache/. Supports TTL expiry and LRU eviction.
package cache

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	DefaultTTL      = 24 * time.Hour
	DefaultMaxSize  = 100
	cacheDir        = ".cloop/cache"
	statsFile       = ".cloop/cache/stats.json"
)

// Entry is a single cached response stored on disk.
type Entry struct {
	Key       string    `json:"key"`
	Response  string    `json:"response"`
	Provider  string    `json:"provider"`
	Model     string    `json:"model"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	HitCount  int       `json:"hit_count"`
}

// Stats holds aggregate cache statistics.
type Stats struct {
	Hits     int64   `json:"hits"`
	Misses   int64   `json:"misses"`
	Entries  int     `json:"entries"`
	HitRate  float64 `json:"hit_rate"`
}

// Cache is a disk-based LRU response cache.
type Cache struct {
	mu      sync.Mutex
	workDir string
	ttl     time.Duration
	maxSize int
	hits    int64
	misses  int64
}

// New creates a new Cache rooted at workDir with the given TTL and max entry count.
func New(workDir string, ttl time.Duration, maxSize int) (*Cache, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	dir := filepath.Join(workDir, cacheDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: create dir: %w", err)
	}
	c := &Cache{workDir: workDir, ttl: ttl, maxSize: maxSize}
	c.loadStats()
	return c, nil
}

// Key computes a deterministic cache key for a given provider, model, and prompt.
func Key(providerName, model, prompt string) string {
	h := sha256.New()
	h.Write([]byte(providerName))
	h.Write([]byte{0})
	h.Write([]byte(model))
	h.Write([]byte{0})
	h.Write([]byte(prompt))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Get returns the cached response for key, or ("", false) on miss/expiry.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, err := c.readEntry(key)
	if err != nil {
		c.misses++
		c.saveStats()
		return "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		// Expired — delete and return miss.
		_ = os.Remove(c.entryPath(key))
		c.misses++
		c.saveStats()
		return "", false
	}

	// Update hit count and atime (write back).
	entry.HitCount++
	_ = c.writeEntry(entry)

	c.hits++
	c.saveStats()
	return entry.Response, true
}

// Put stores a response in the cache, evicting LRU entries if needed.
func (c *Cache) Put(key, response, providerName, model string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &Entry{
		Key:       key,
		Response:  response,
		Provider:  providerName,
		Model:     model,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(c.ttl),
		HitCount:  0,
	}

	if err := c.writeEntry(entry); err != nil {
		return err
	}

	return c.evict()
}

// Stats returns current cache statistics.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := c.listEntries()
	total := c.hits + c.misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}
	return Stats{
		Hits:    c.hits,
		Misses:  c.misses,
		Entries: len(entries),
		HitRate: hitRate,
	}
}

// Clear removes all cached entries and resets statistics.
func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Join(c.workDir, cacheDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("cache: clear: %w", err)
	}
	for _, e := range entries {
		if e.Name() == "stats.json" {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	c.hits = 0
	c.misses = 0
	c.saveStats()
	return nil
}

// entryPath returns the file path for a cache entry key.
func (c *Cache) entryPath(key string) string {
	return filepath.Join(c.workDir, cacheDir, key+".json.gz")
}

// readEntry reads and decompresses a cache entry from disk.
func (c *Cache) readEntry(key string) (*Entry, error) {
	f, err := os.Open(c.entryPath(key))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("cache: gzip reader: %w", err)
	}
	defer gz.Close()

	var entry Entry
	if err := json.NewDecoder(gz).Decode(&entry); err != nil {
		return nil, fmt.Errorf("cache: decode: %w", err)
	}
	return &entry, nil
}

// writeEntry compresses and writes a cache entry to disk.
func (c *Cache) writeEntry(entry *Entry) error {
	path := c.entryPath(entry.Key)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cache: create file: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(entry); err != nil {
		return fmt.Errorf("cache: encode: %w", err)
	}
	return gz.Close()
}

type entryMeta struct {
	key     string
	path    string
	modTime time.Time
	hits    int
}

// listEntries returns metadata for all valid cache files sorted by LRU order
// (oldest modification time first — least recently used).
func (c *Cache) listEntries() []entryMeta {
	dir := filepath.Join(c.workDir, cacheDir)
	infos, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var metas []entryMeta
	for _, info := range infos {
		name := info.Name()
		if len(name) <= 8 || name[len(name)-8:] != ".json.gz" {
			continue
		}
		fi, err := info.Info()
		if err != nil {
			continue
		}
		key := name[:len(name)-8]
		metas = append(metas, entryMeta{
			key:     key,
			path:    filepath.Join(dir, name),
			modTime: fi.ModTime(),
		})
	}
	// Sort by mod time ascending (oldest = LRU first).
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].modTime.Before(metas[j].modTime)
	})
	return metas
}

// evict removes the least-recently-used entries until the cache is within maxSize.
func (c *Cache) evict() error {
	entries := c.listEntries()
	for len(entries) > c.maxSize {
		if err := os.Remove(entries[0].path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cache: evict: %w", err)
		}
		entries = entries[1:]
	}
	return nil
}

// persistedStats mirrors just the counters we save between runs.
type persistedStats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
}

func (c *Cache) saveStats() {
	data, err := json.Marshal(persistedStats{Hits: c.hits, Misses: c.misses})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(c.workDir, statsFile), data, 0o644)
}

func (c *Cache) loadStats() {
	data, err := os.ReadFile(filepath.Join(c.workDir, statsFile))
	if err != nil {
		return
	}
	var ps persistedStats
	if err := json.Unmarshal(data, &ps); err != nil {
		return
	}
	c.hits = ps.Hits
	c.misses = ps.Misses
}
