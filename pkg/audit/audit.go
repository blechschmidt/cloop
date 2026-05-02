// Package audit implements security and compliance scanning for cloop projects.
package audit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/env"
)

// Level indicates the severity of an audit finding.
type Level int

const (
	Pass Level = iota
	Warn
	Fail
)

func (l Level) String() string {
	switch l {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	default:
		return "UNKN"
	}
}

// Finding is a single audit result.
type Finding struct {
	Name    string
	Level   Level
	Message string
	Fix     string // optional remediation hint
}

// Options configures the audit run.
type Options struct {
	// SnapshotSizeThresholdMB is the threshold in MiB above which the snapshot
	// directory triggers a warning. Defaults to 50.
	SnapshotSizeThresholdMB int64
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() Options {
	return Options{SnapshotSizeThresholdMB: 50}
}

type addFn func(Finding)

// Audit inspects the cloop project for security and compliance issues and
// returns a slice of Findings. cfg may be nil; defaults are used in that case.
func Audit(workDir string, cfg *config.Config, opts Options) ([]Finding, error) {
	if opts.SnapshotSizeThresholdMB <= 0 {
		opts.SnapshotSizeThresholdMB = 50
	}
	if cfg == nil {
		cfg = config.Default()
	}

	var findings []Finding
	add := func(f Finding) { findings = append(findings, f) }

	checkAPIKeysInGit(workDir, cfg, add)
	checkWebhookHTTP(cfg, add)
	checkUIToken(workDir, add)
	checkEnvSecretsInArtifacts(workDir, add)
	checkHookPermissions(cfg, add)
	checkSnapshotSize(workDir, opts.SnapshotSizeThresholdMB, add)

	return findings, nil
}

// ---------------------------------------------------------------------------
// Check 1: API keys accidentally committed to git
// ---------------------------------------------------------------------------

// apiKeyPattern matches common API key prefixes found in plaintext.
var apiKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),    // Anthropic
	regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),   // OpenAI project key
	regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),           // OpenAI legacy
	regexp.MustCompile(`ghp_[A-Za-z0-9]{30,}`),          // GitHub PAT classic
	regexp.MustCompile(`ghs_[A-Za-z0-9]{30,}`),          // GitHub App token
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{50,}`),  // GitHub fine-grained PAT
	regexp.MustCompile(`AIzaSy[A-Za-z0-9_-]{33}`),       // Google API key
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),              // AWS access key
}

func checkAPIKeysInGit(workDir string, cfg *config.Config, add addFn) {
	// Is this even a git repo?
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	cmd := exec.Command("git", "-C", workDir, "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return // not a git repo — nothing to scan
	}

	// Collect non-empty API key values from the loaded config so we can look
	// for the actual secrets verbatim, in addition to pattern-based scanning.
	verbatim := collectConfigSecrets(cfg)

	// Scan git log of .cloop/ for key patterns and verbatim secrets.
	// We use --all to cover every branch/tag.
	gitLog := exec.Command("git", "-C", workDir, "log", "--all", "-p",
		"--diff-filter=ACDM", "--", ".cloop/")
	out, err := gitLog.Output()
	if err != nil {
		// git log failing (e.g. no commits) is not an error worth surfacing.
		add(Finding{
			Name:    "API keys in git history",
			Level:   Pass,
			Message: "No git history for .cloop/ to scan",
		})
		return
	}

	leaks := scanForLeaks(string(out), verbatim)
	if len(leaks) == 0 {
		add(Finding{
			Name:    "API keys in git history",
			Level:   Pass,
			Message: ".cloop/ git history contains no detected API key patterns",
		})
		return
	}

	add(Finding{
		Name:    "API keys in git history",
		Level:   Fail,
		Message: fmt.Sprintf("Possible API key(s) detected in .cloop/ git history: %s", strings.Join(leaks, ", ")),
		Fix:     "Use 'git filter-repo' or BFG Repo-Cleaner to purge secrets, then rotate the affected keys immediately",
	})
}

// collectConfigSecrets returns non-empty, non-trivial secret values from cfg.
func collectConfigSecrets(cfg *config.Config) []string {
	var secrets []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) >= 16 { // ignore very short/placeholder values
			secrets = append(secrets, v)
		}
	}
	add(cfg.Anthropic.APIKey)
	add(cfg.OpenAI.APIKey)
	add(cfg.GitHub.Token)
	add(cfg.Webhook.Secret)
	return secrets
}

// scanForLeaks returns descriptive labels for each leak found in text.
func scanForLeaks(text string, verbatim []string) []string {
	seen := map[string]bool{}
	var labels []string

	record := func(label string) {
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}

	for _, pat := range apiKeyPatterns {
		if pat.MatchString(text) {
			record(describePattern(pat.String()))
		}
	}
	for _, secret := range verbatim {
		if strings.Contains(text, secret) {
			record("configured-secret")
		}
	}
	return labels
}

func describePattern(pat string) string {
	switch {
	case strings.Contains(pat, "sk-ant"):
		return "Anthropic API key"
	case strings.Contains(pat, "sk-proj"):
		return "OpenAI project key"
	case strings.Contains(pat, "sk-"):
		return "OpenAI API key"
	case strings.Contains(pat, "ghp_"):
		return "GitHub classic PAT"
	case strings.Contains(pat, "ghs_"):
		return "GitHub app token"
	case strings.Contains(pat, "github_pat"):
		return "GitHub fine-grained PAT"
	case strings.Contains(pat, "AIzaSy"):
		return "Google API key"
	case strings.Contains(pat, "AKIA"):
		return "AWS access key"
	default:
		return "unknown key pattern"
	}
}

// ---------------------------------------------------------------------------
// Check 2: Webhook URLs using HTTP instead of HTTPS
// ---------------------------------------------------------------------------

func checkWebhookHTTP(cfg *config.Config, add addFn) {
	type urlCheck struct {
		name string
		url  string
	}
	checks := []urlCheck{
		{"webhook.url", cfg.Webhook.URL},
		{"notify.slack_webhook", cfg.Notify.SlackWebhook},
		{"notify.discord_webhook", cfg.Notify.DiscordWebhook},
	}

	any := false
	for _, c := range checks {
		if c.url == "" {
			continue
		}
		any = true
		if strings.HasPrefix(strings.ToLower(c.url), "http://") {
			add(Finding{
				Name:    fmt.Sprintf("Webhook TLS (%s)", c.name),
				Level:   Fail,
				Message: fmt.Sprintf("%s uses plain HTTP — data is transmitted unencrypted: %s", c.name, c.url),
				Fix:     fmt.Sprintf("Change %s to use https:// in .cloop/config.yaml", c.name),
			})
		} else {
			add(Finding{
				Name:    fmt.Sprintf("Webhook TLS (%s)", c.name),
				Level:   Pass,
				Message: fmt.Sprintf("%s uses HTTPS", c.name),
			})
		}
	}

	if !any {
		add(Finding{
			Name:    "Webhook TLS",
			Level:   Pass,
			Message: "No webhook URLs configured",
		})
	}
}

// ---------------------------------------------------------------------------
// Check 3: Web UI running without a token
// ---------------------------------------------------------------------------

func checkUIToken(workDir string, add addFn) {
	// Check env var first.
	if os.Getenv("CLOOP_UI_TOKEN") != "" {
		add(Finding{
			Name:    "Web UI token",
			Level:   Pass,
			Message: "CLOOP_UI_TOKEN is set in environment — UI authentication is configured",
		})
		return
	}

	// Check .cloop/env.yaml for CLOOP_UI_TOKEN.
	vars, err := env.Load(workDir)
	if err == nil {
		for _, v := range vars {
			if v.Key == "CLOOP_UI_TOKEN" {
				add(Finding{
					Name:    "Web UI token",
					Level:   Pass,
					Message: "CLOOP_UI_TOKEN found in .cloop/env.yaml — UI authentication is configured",
				})
				return
			}
		}
	}

	add(Finding{
		Name:    "Web UI token",
		Level:   Warn,
		Message: "CLOOP_UI_TOKEN is not set — 'cloop ui' will start without authentication",
		Fix:     "Set CLOOP_UI_TOKEN env var or run: cloop env set CLOOP_UI_TOKEN <token> --secret",
	})
}

// ---------------------------------------------------------------------------
// Check 4: Env var secrets exposed in task output artifacts
// ---------------------------------------------------------------------------

// secretKeyPattern matches env var names that likely hold secrets.
var secretKeyPattern = regexp.MustCompile(
	`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth|credential|passwd)`,
)

func checkEnvSecretsInArtifacts(workDir string, add addFn) {
	vars, err := env.Load(workDir)
	if err != nil || len(vars) == 0 {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: "No env vars configured in .cloop/env.yaml",
		})
		return
	}

	// Build list of secret values to search for.
	var secretValues []string
	for _, v := range vars {
		if !v.Secret && !secretKeyPattern.MatchString(v.Key) {
			continue
		}
		plain := env.DecodeValue(v)
		if len(plain) < 8 {
			continue // too short to be meaningful
		}
		secretValues = append(secretValues, plain)
	}

	if len(secretValues) == 0 {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: "No secret env vars found in .cloop/env.yaml",
		})
		return
	}

	// Scan task artifact files.
	tasksDir := filepath.Join(workDir, ".cloop", "tasks")
	entries, err := os.ReadDir(tasksDir)
	if err != nil {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: "No task artifact directory (.cloop/tasks/) to scan",
		})
		return
	}

	var exposed []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(tasksDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		for _, secret := range secretValues {
			if strings.Contains(content, secret) {
				exposed = append(exposed, entry.Name())
				break
			}
		}
	}

	if len(exposed) == 0 {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Pass,
			Message: fmt.Sprintf("Scanned %d artifact file(s) — no secret values detected", len(entries)),
		})
	} else {
		add(Finding{
			Name:    "Env secrets in task artifacts",
			Level:   Fail,
			Message: fmt.Sprintf("Secret env var values found in %d artifact file(s): %s", len(exposed), strings.Join(exposed, ", ")),
			Fix:     "Remove or redact secrets from task artifacts in .cloop/tasks/; consider marking sensitive vars with --secret",
		})
	}
}

// ---------------------------------------------------------------------------
// Check 5: Hook scripts running as root or world-writable
// ---------------------------------------------------------------------------

func checkHookPermissions(cfg *config.Config, add addFn) {
	hooks := []struct {
		name string
		cmd  string
	}{
		{"hooks.pre_task", cfg.Hooks.PreTask},
		{"hooks.post_task", cfg.Hooks.PostTask},
		{"hooks.pre_plan", cfg.Hooks.PrePlan},
		{"hooks.post_plan", cfg.Hooks.PostPlan},
	}

	runningAsRoot := os.Getuid() == 0
	if runningAsRoot {
		add(Finding{
			Name:    "Hook execution context (root)",
			Level:   Warn,
			Message: "cloop is running as root — hook scripts will execute with root privileges",
			Fix:     "Run cloop as a non-privileged user",
		})
	}

	anyHook := false
	for _, h := range hooks {
		if h.cmd == "" {
			continue
		}
		anyHook = true
		parts := strings.Fields(h.cmd)
		if len(parts) == 0 {
			continue
		}
		script := parts[0]

		// Only stat file-path-like scripts (contain a slash).
		if !strings.Contains(script, "/") {
			continue
		}

		info, err := os.Stat(script)
		if err != nil {
			// Script not found — this is already caught by doctor; skip here.
			continue
		}

		mode := info.Mode()
		worldWritable := mode&0o002 != 0

		if worldWritable {
			add(Finding{
				Name:    fmt.Sprintf("Hook script permissions (%s)", h.name),
				Level:   Fail,
				Message: fmt.Sprintf("Hook script %q is world-writable (%s) — anyone can modify it", script, mode),
				Fix:     fmt.Sprintf("Run: chmod o-w %s", script),
			})
		} else {
			add(Finding{
				Name:    fmt.Sprintf("Hook script permissions (%s)", h.name),
				Level:   Pass,
				Message: fmt.Sprintf("Hook script %q permissions look safe (%s)", script, mode),
			})
		}
	}

	if !anyHook && !runningAsRoot {
		add(Finding{
			Name:    "Hook script permissions",
			Level:   Pass,
			Message: "No hook scripts configured",
		})
	}
}

// ---------------------------------------------------------------------------
// Check 6: Snapshot directory size
// ---------------------------------------------------------------------------

func checkSnapshotSize(workDir string, thresholdMB int64, add addFn) {
	snapDir := filepath.Join(workDir, ".cloop", "plan-history")
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Pass,
			Message: "No plan-history/ directory found",
		})
		return
	}

	var totalBytes int64
	err := filepath.Walk(snapDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !info.IsDir() {
			totalBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return
	}

	totalMB := totalBytes / (1024 * 1024)
	if totalMB >= thresholdMB {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Warn,
			Message: fmt.Sprintf(".cloop/plan-history/ is %d MiB (threshold: %d MiB)", totalMB, thresholdMB),
			Fix:     "Remove old snapshots: rm -rf .cloop/plan-history/*.json, or raise the threshold with --snapshot-threshold",
		})
	} else {
		add(Finding{
			Name:    "Snapshot directory size",
			Level:   Pass,
			Message: fmt.Sprintf(".cloop/plan-history/ is %d MiB (threshold: %d MiB)", totalMB, thresholdMB),
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// CountsByLevel returns pass, warn, fail counts from a slice of findings.
func CountsByLevel(findings []Finding) (pass, warn, fail int) {
	for _, f := range findings {
		switch f.Level {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return
}

// ScannerLines is a helper that iterates lines of text via a Scanner.
// (Kept for potential future use by callers.)
func ScannerLines(text string, fn func(string)) {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		fn(sc.Text())
	}
}
