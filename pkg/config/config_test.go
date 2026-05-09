package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-config-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// --- Default ---

func TestDefault_HasClaudeCodeProvider(t *testing.T) {
	cfg := Default()
	if cfg.Provider != "claudecode" {
		t.Errorf("expected default provider 'claudecode', got %q", cfg.Provider)
	}
}

func TestDefault_HasModels(t *testing.T) {
	cfg := Default()
	if cfg.Anthropic.Model == "" {
		t.Error("expected a default Anthropic model")
	}
	if cfg.OpenAI.Model == "" {
		t.Error("expected a default OpenAI model")
	}
	if cfg.Ollama.Model == "" {
		t.Error("expected a default Ollama model")
	}
	if cfg.Ollama.BaseURL == "" {
		t.Error("expected a default Ollama base URL")
	}
}

// --- ConfigPath ---

func TestConfigPath(t *testing.T) {
	got := ConfigPath("/some/project")
	expected := "/some/project/.cloop/config.yaml"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// --- Load ---

func TestLoad_ReturnDefaultsWhenMissing(t *testing.T) {
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Provider != "claudecode" {
		t.Errorf("expected default provider, got %q", cfg.Provider)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	dir := tempDir(t)

	cfg := Default()
	cfg.Provider = "anthropic"
	cfg.Anthropic.APIKey = "test-key"
	cfg.Anthropic.Model = "claude-opus-4-6"

	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.Provider != "anthropic" {
		t.Errorf("provider mismatch: got %q", loaded.Provider)
	}
	if loaded.Anthropic.APIKey != "test-key" {
		t.Errorf("api_key mismatch: got %q", loaded.Anthropic.APIKey)
	}
	if loaded.Anthropic.Model != "claude-opus-4-6" {
		t.Errorf("model mismatch: got %q", loaded.Anthropic.Model)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := tempDir(t)
	cfgDir := filepath.Join(dir, ".cloop")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte("provider: [invalid yaml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// --- Save ---

func TestSave_CreatesDirectory(t *testing.T) {
	dir := tempDir(t)
	cfg := Default()
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(ConfigPath(dir)); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestSave_WritesAllProviders(t *testing.T) {
	dir := tempDir(t)
	cfg := Default()
	cfg.OpenAI.APIKey = "oai-key"
	cfg.OpenAI.BaseURL = "https://custom.openai.com"
	cfg.Ollama.BaseURL = "http://localhost:9999"
	cfg.ClaudeCode.Model = "claude-sonnet-4-6"

	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.OpenAI.APIKey != "oai-key" {
		t.Errorf("openai api_key mismatch: %q", loaded.OpenAI.APIKey)
	}
	if loaded.OpenAI.BaseURL != "https://custom.openai.com" {
		t.Errorf("openai base_url mismatch: %q", loaded.OpenAI.BaseURL)
	}
	if loaded.Ollama.BaseURL != "http://localhost:9999" {
		t.Errorf("ollama base_url mismatch: %q", loaded.Ollama.BaseURL)
	}
	if loaded.ClaudeCode.Model != "claude-sonnet-4-6" {
		t.Errorf("claudecode model mismatch: %q", loaded.ClaudeCode.Model)
	}
}

func TestSave_NoLeftoverTmpFiles(t *testing.T) {
	// Atomic-write regression: every Save() goes through a sibling .tmp file
	// that must be renamed away before the function returns. If we ever
	// accumulate orphan .tmp files (e.g. someone reverts to os.WriteFile or
	// the cleanup defer breaks), this test catches it.
	dir := tempDir(t)
	cfg := Default()
	for i := 0; i < 5; i++ {
		cfg.Anthropic.APIKey = "key-iteration"
		if err := Save(dir, cfg); err != nil {
			t.Fatalf("save iter %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".cloop"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "config.yaml" {
			continue
		}
		t.Errorf("unexpected leftover file in .cloop/: %q (atomic-write tmp not cleaned up)", name)
	}
}

func TestSave_ConcurrentReaderNeverSeesEmptyFile(t *testing.T) {
	// Atomic-write guarantee: a reader that opens config.yaml at any moment
	// during a Save() must see either the previous full content or the new
	// full content — never an empty or half-written file. With os.WriteFile
	// (truncate-then-write) a concurrent reader could observe a 0-byte file.
	// With rename-from-tmp the destination inode is swapped atomically.
	dir := tempDir(t)
	cfg := Default()
	cfg.Anthropic.APIKey = "initial"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	stop := make(chan struct{})
	emptyObserved := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(ConfigPath(dir))
			if err == nil && len(data) == 0 {
				select {
				case emptyObserved <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		cfg.Anthropic.APIKey = "iter"
		if err := Save(dir, cfg); err != nil {
			close(stop)
			t.Fatalf("save iter %d: %v", i, err)
		}
	}
	close(stop)

	select {
	case <-emptyObserved:
		t.Fatal("reader observed empty config.yaml during Save() — write is not atomic")
	default:
	}
}

// --- WriteDefault ---

func TestWriteDefault_CreatesFileIfAbsent(t *testing.T) {
	dir := tempDir(t)
	if err := WriteDefault(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(ConfigPath(dir)); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestWriteDefault_DoesNotOverwriteExisting(t *testing.T) {
	dir := tempDir(t)
	// Write a custom config first
	cfg := Default()
	cfg.Provider = "openai"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}
	// WriteDefault should not clobber it
	if err := WriteDefault(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if loaded.Provider != "openai" {
		t.Errorf("WriteDefault overwrote existing config: got provider %q", loaded.Provider)
	}
}

// --- applyEnvVars / env var override ---

func setenv(t *testing.T, key, value string) {
	t.Helper()
	old, hadOld := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if hadOld {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestLoad_EnvVar_AnthropicAPIKey(t *testing.T) {
	setenv(t, "ANTHROPIC_API_KEY", "env-anthropic-key")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.APIKey != "env-anthropic-key" {
		t.Errorf("expected env key, got %q", cfg.Anthropic.APIKey)
	}
}

func TestLoad_EnvVar_AnthropicBaseURL(t *testing.T) {
	setenv(t, "ANTHROPIC_BASE_URL", "https://custom.anthropic.com")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Anthropic.BaseURL != "https://custom.anthropic.com" {
		t.Errorf("expected env base_url, got %q", cfg.Anthropic.BaseURL)
	}
}

func TestLoad_EnvVar_OpenAIAPIKey(t *testing.T) {
	setenv(t, "OPENAI_API_KEY", "env-openai-key")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.APIKey != "env-openai-key" {
		t.Errorf("expected env openai key, got %q", cfg.OpenAI.APIKey)
	}
}

func TestLoad_EnvVar_OpenAIBaseURL(t *testing.T) {
	setenv(t, "OPENAI_BASE_URL", "https://custom.openai.com")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OpenAI.BaseURL != "https://custom.openai.com" {
		t.Errorf("expected env openai base_url, got %q", cfg.OpenAI.BaseURL)
	}
}

func TestLoad_EnvVar_OllamaBaseURL(t *testing.T) {
	setenv(t, "OLLAMA_BASE_URL", "http://remote:11434")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ollama.BaseURL != "http://remote:11434" {
		t.Errorf("expected env ollama base_url, got %q", cfg.Ollama.BaseURL)
	}
}

func TestLoad_EnvVar_CloopProvider(t *testing.T) {
	setenv(t, "CLOOP_PROVIDER", "anthropic")
	dir := tempDir(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Provider != "anthropic" {
		t.Errorf("expected env provider 'anthropic', got %q", cfg.Provider)
	}
}

func TestLoad_EnvVar_OverridesFileValue(t *testing.T) {
	// Env var should win over config file value
	setenv(t, "ANTHROPIC_API_KEY", "env-wins")
	dir := tempDir(t)

	cfg := Default()
	cfg.Anthropic.APIKey = "file-value"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "env-wins" {
		t.Errorf("expected env var to override file, got %q", loaded.Anthropic.APIKey)
	}
}

func TestLoad_EnvVar_EmptyDoesNotOverride(t *testing.T) {
	// Unset env var should not clear file value
	os.Unsetenv("ANTHROPIC_API_KEY")
	dir := tempDir(t)

	cfg := Default()
	cfg.Anthropic.APIKey = "file-value"
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Anthropic.APIKey != "file-value" {
		t.Errorf("expected file value to persist, got %q", loaded.Anthropic.APIKey)
	}
}

// captureStderr swaps os.Stderr for a pipe, runs fn, restores os.Stderr,
// and returns whatever fn wrote to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.Bytes()
	}()

	fn()
	w.Close()
	return string(<-done)
}

// resetPermWarned clears the global dedup table so tests don't pollute one
// another. Safe to call concurrently.
func resetPermWarned() {
	permWarnedMu.Lock()
	permWarnedPaths = map[string]struct{}{}
	permWarnedMu.Unlock()
}

// TestLoad_PermWarning_DedupedAcrossCalls locks in the fix for the
// log-spam bug where long-running processes (UI, daemon, auto-evolve) flooded
// stderr with the "permissions 644 — it may contain API keys" warning every
// time Load() ran. The warning must fire exactly once per path per process.
func TestLoad_PermWarning_DedupedAcrossCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission warning is Unix-only")
	}
	resetPermWarned()

	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := ConfigPath(dir)
	if err := os.WriteFile(path, []byte("provider: claudecode\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output := captureStderr(t, func() {
		for i := 0; i < 50; i++ {
			if _, err := Load(dir); err != nil {
				t.Fatalf("load %d: %v", i, err)
			}
		}
	})

	count := strings.Count(output, "it may contain API keys")
	if count != 1 {
		t.Errorf("expected exactly 1 perm-warning across 50 Load() calls, got %d\nstderr:\n%s", count, output)
	}
}

// TestLoad_PermWarning_SeparatePathsWarnIndependently makes sure the dedup
// is per-path: two different config files each get their own one-shot warning.
func TestLoad_PermWarning_SeparatePathsWarnIndependently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission warning is Unix-only")
	}
	resetPermWarned()

	dirA := tempDir(t)
	dirB := tempDir(t)
	for _, d := range []string{dirA, dirB} {
		if err := os.MkdirAll(filepath.Join(d, ".cloop"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(ConfigPath(d), []byte("provider: claudecode\n"), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	output := captureStderr(t, func() {
		for i := 0; i < 5; i++ {
			if _, err := Load(dirA); err != nil {
				t.Fatalf("load A: %v", err)
			}
			if _, err := Load(dirB); err != nil {
				t.Fatalf("load B: %v", err)
			}
		}
	})

	// The warning template prints the path twice ("warning: P ... chmod 600 P"),
	// so a per-line count is the right unit. Each path should appear in exactly
	// one stderr line.
	linesA, linesB := 0, 0
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "it may contain API keys") {
			continue
		}
		if strings.Contains(line, ConfigPath(dirA)) {
			linesA++
		}
		if strings.Contains(line, ConfigPath(dirB)) {
			linesB++
		}
	}
	if linesA != 1 {
		t.Errorf("expected 1 warning line for dirA, got %d\nstderr:\n%s", linesA, output)
	}
	if linesB != 1 {
		t.Errorf("expected 1 warning line for dirB, got %d\nstderr:\n%s", linesB, output)
	}
}

// --- Numeric validation (Task 20082) ---
//
// These tests lock in the bounds enforced by validateAndClamp and
// ValidateNumeric. Bad values reaching runtime have caused real damage in
// the past — an absurd max_parallel spawns thousands of goroutines, a
// negative budget cap silently disables enforcement, and a sub-1 rate-limit
// burst makes every HTTP server reject the first request. The tests cover
// each documented bound from both the warn-and-clamp side (Load()) and the
// reject side (ValidateNumeric).

// resetClampWarned clears the once-per-(path,field) dedup table so each
// numeric-validation test can observe its own stderr cleanly.
func resetClampWarned() {
	clampWarnedMu.Lock()
	clampWarnedPairs = map[string]struct{}{}
	clampWarnedMu.Unlock()
}

func writeYAMLConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestLoad_ClampsAbsurdMaxParallel(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nmax_parallel: 5000\n")
	var cfg *Config
	out := captureStderr(t, func() {
		var err error
		cfg, err = Load(dir)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
	})
	if cfg.MaxParallel != 0 {
		t.Errorf("expected max_parallel clamped to 0, got %d", cfg.MaxParallel)
	}
	if !strings.Contains(out, "max_parallel") {
		t.Errorf("expected stderr warning about max_parallel, got: %q", out)
	}
}

func TestLoad_ClampsNegativeMaxParallel(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nmax_parallel: -2\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.MaxParallel != 0 {
		t.Errorf("expected max_parallel clamped to 0, got %d", cfg.MaxParallel)
	}
}

func TestLoad_AcceptsValidMaxParallel(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nmax_parallel: 8\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.MaxParallel != 8 {
		t.Errorf("expected max_parallel=8, got %d", cfg.MaxParallel)
	}
}

func TestLoad_ClampsNegativeBudget(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nbudget:\n  monthly_usd: -10.0\n  daily_usd_limit: -5.0\n  daily_token_limit: -1\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Budget.MonthlyUSD != 0 {
		t.Errorf("expected monthly_usd clamped to 0, got %f", cfg.Budget.MonthlyUSD)
	}
	if cfg.Budget.DailyUSDLimit != 0 {
		t.Errorf("expected daily_usd_limit clamped to 0, got %f", cfg.Budget.DailyUSDLimit)
	}
	if cfg.Budget.DailyTokenLimit != 0 {
		t.Errorf("expected daily_token_limit clamped to 0, got %d", cfg.Budget.DailyTokenLimit)
	}
}

func TestLoad_ClampsBadAlertThreshold(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nbudget:\n  alert_threshold_pct: 150\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Budget.AlertThresholdPct != 0 {
		t.Errorf("expected alert_threshold_pct clamped to 0, got %d", cfg.Budget.AlertThresholdPct)
	}
}

func TestLoad_ClampsRateLimitBurst(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nrate_limit:\n  requests_per_second: -1\n  burst: -3\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RateLimit.RequestsPerSecond != 0 {
		t.Errorf("expected rate_limit.requests_per_second clamped to 0, got %f", cfg.RateLimit.RequestsPerSecond)
	}
	if cfg.RateLimit.Burst != 0 {
		t.Errorf("expected rate_limit.burst clamped to 0, got %d", cfg.RateLimit.Burst)
	}
}

func TestLoad_ClampsBadClaudeCodePct(t *testing.T) {
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nclaudecode:\n  max_weekly_pct: 200\n  max_five_hour_pct: -10\n")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ClaudeCode.MaxWeeklyPct != 0 {
		t.Errorf("expected max_weekly_pct clamped to 0, got %f", cfg.ClaudeCode.MaxWeeklyPct)
	}
	if cfg.ClaudeCode.MaxFiveHourPct != 0 {
		t.Errorf("expected max_five_hour_pct clamped to 0, got %f", cfg.ClaudeCode.MaxFiveHourPct)
	}
}

func TestValidateNumeric_AcceptsZeroValues(t *testing.T) {
	cfg := Default()
	if err := cfg.ValidateNumeric(); err != nil {
		t.Errorf("default config should validate, got %v", err)
	}
}

func TestValidateNumeric_RejectsBadMaxParallel(t *testing.T) {
	cases := []int{-1, 0 - 1, 65, 5000}
	for _, v := range cases {
		cfg := Default()
		cfg.MaxParallel = v
		if err := cfg.ValidateNumeric(); err == nil {
			t.Errorf("expected error for max_parallel=%d", v)
		}
	}
}

func TestValidateNumeric_AcceptsValidMaxParallel(t *testing.T) {
	for _, v := range []int{1, 8, 32, 64} {
		cfg := Default()
		cfg.MaxParallel = v
		if err := cfg.ValidateNumeric(); err != nil {
			t.Errorf("max_parallel=%d should be accepted, got %v", v, err)
		}
	}
}

func TestValidateNumeric_RejectsBadRateLimit(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.RequestsPerSecond = -1
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for negative requests_per_second")
	}
	cfg = Default()
	cfg.RateLimit.RequestsPerSecond = 0.5
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for sub-1 requests_per_second")
	}
	cfg = Default()
	cfg.RateLimit.Burst = -5
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for negative burst")
	}
}

func TestValidateNumeric_RejectsNegativeBudget(t *testing.T) {
	cfg := Default()
	cfg.Budget.MonthlyUSD = -1
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for negative monthly_usd")
	}
	cfg = Default()
	cfg.Budget.DailyUSDLimit = -1
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for negative daily_usd_limit")
	}
	cfg = Default()
	cfg.Budget.DailyTokenLimit = -1
	if err := cfg.ValidateNumeric(); err == nil {
		t.Error("expected error for negative daily_token_limit")
	}
}

func TestValidateNumeric_RejectsBadAlertThreshold(t *testing.T) {
	for _, v := range []int{-1, 101, 200} {
		cfg := Default()
		cfg.Budget.AlertThresholdPct = v
		if err := cfg.ValidateNumeric(); err == nil {
			t.Errorf("expected error for alert_threshold_pct=%d", v)
		}
	}
}

func TestValidateNumeric_RejectsBadGlobalPct(t *testing.T) {
	for _, v := range []float64{-0.1, 100.1, 200} {
		cfg := Default()
		cfg.Budget.GlobalUSDPct = v
		if err := cfg.ValidateNumeric(); err == nil {
			t.Errorf("expected error for global_usd_pct=%v", v)
		}
		cfg = Default()
		cfg.Budget.GlobalTokenPct = v
		if err := cfg.ValidateNumeric(); err == nil {
			t.Errorf("expected error for global_token_pct=%v", v)
		}
	}
}

func TestValidateNumeric_AcceptsZeroBudget(t *testing.T) {
	// Zero is "no limit" for budget caps and must pass validation.
	cfg := Default()
	cfg.Budget.MonthlyUSD = 0
	cfg.Budget.DailyUSDLimit = 0
	cfg.Budget.DailyTokenLimit = 0
	if err := cfg.ValidateNumeric(); err != nil {
		t.Errorf("zero budget should be accepted, got %v", err)
	}
}

func TestValidateNumeric_RejectsBadClaudeCodeCaps(t *testing.T) {
	for _, v := range []float64{-1, 101, 9999} {
		cfg := Default()
		cfg.ClaudeCode.MaxWeeklyPct = v
		if err := cfg.ValidateNumeric(); err == nil {
			t.Errorf("expected error for claudecode.max_weekly_pct=%v", v)
		}
	}
}

func TestLoad_ClampWarning_DedupedAcrossCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("clamp warning is Unix-only")
	}
	resetClampWarned()
	dir := tempDir(t)
	writeYAMLConfig(t, dir, "provider: claudecode\nmax_parallel: 5000\n")
	out := captureStderr(t, func() {
		for i := 0; i < 25; i++ {
			if _, err := Load(dir); err != nil {
				t.Fatalf("load %d: %v", i, err)
			}
		}
	})
	count := strings.Count(out, "max_parallel")
	if count != 1 {
		t.Errorf("expected exactly 1 clamp-warning across 25 Load() calls, got %d\nstderr:\n%s", count, out)
	}
}

// TestLoad_PermWarning_ConcurrentLoadsDoNotRaceOrDuplicate proves the dedup
// table is safe under concurrent Load() (the realistic UI scenario where
// many handlers can race on the same project's config) and that the warning
// still fires only once.
func TestLoad_PermWarning_ConcurrentLoadsDoNotRaceOrDuplicate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission warning is Unix-only")
	}
	resetPermWarned()

	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte("provider: claudecode\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output := captureStderr(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					_, _ = Load(dir)
				}
			}()
		}
		wg.Wait()
	})

	count := strings.Count(output, "it may contain API keys")
	if count != 1 {
		t.Errorf("expected exactly 1 perm-warning across 320 concurrent Load() calls, got %d\nstderr:\n%s", count, output)
	}
}
