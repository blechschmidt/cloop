// Package doctor implements environment and configuration health checks for cloop.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/configvalidate"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Level indicates the severity of a diagnostic result.
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

// Result is a single diagnostic check result.
type Result struct {
	Name    string
	Level   Level
	Message string
	Fix     string // optional hint for fixing the issue
}

// Report contains all diagnostic results.
type Report struct {
	Results []Result
}

// Counts returns pass, warn, fail counts.
func (r *Report) Counts() (pass, warn, fail int) {
	for _, res := range r.Results {
		switch res.Level {
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

type addFn func(Result)

// Run executes all diagnostic checks and returns a report.
func Run(ctx context.Context, workdir string, cfg *config.Config, testProviders bool) *Report {
	rep := &Report{}
	add := func(r Result) { rep.Results = append(rep.Results, r) }

	checkDirStructure(workdir, add)
	checkStateJSON(workdir, add)
	checkGoBinary(add)
	checkEnvVars(cfg, add)
	if testProviders {
		checkProviders(ctx, cfg, add)
	}
	checkGitRepo(workdir, cfg, add)
	checkWebhooks(ctx, cfg, add)
	checkHookScripts(cfg, add)
	checkEnvYamlGitignored(workdir, add)
	checkConfigValidate(ctx, workdir, add)

	return rep
}

// checkDirStructure verifies .cloop/ directory and key files exist.
func checkDirStructure(workdir string, add addFn) {
	clDir := filepath.Join(workdir, ".cloop")
	info, err := os.Stat(clDir)
	if err != nil || !info.IsDir() {
		add(Result{
			Name:    ".cloop/ directory",
			Level:   Warn,
			Message: ".cloop/ directory not found — project may not be initialized",
			Fix:     "Run: cloop init \"<your goal>\"",
		})
		return
	}
	add(Result{
		Name:    ".cloop/ directory",
		Level:   Pass,
		Message: ".cloop/ directory exists",
	})

	// Check config.yaml
	cfgPath := filepath.Join(clDir, "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		add(Result{
			Name:    ".cloop/config.yaml",
			Level:   Warn,
			Message: "config.yaml not found (using defaults)",
			Fix:     "Run: cloop init to create it, or cloop config set <key> <value>",
		})
	} else {
		add(Result{
			Name:    ".cloop/config.yaml",
			Level:   Pass,
			Message: "config.yaml present",
		})
	}

	// Check tasks/ artifact directory
	tasksDir := filepath.Join(clDir, "tasks")
	if _, err := os.Stat(tasksDir); err != nil {
		add(Result{
			Name:    ".cloop/tasks/ directory",
			Level:   Warn,
			Message: "tasks/ artifact directory not found (created on first task run)",
		})
	} else {
		add(Result{
			Name:    ".cloop/tasks/ directory",
			Level:   Pass,
			Message: "tasks/ artifact directory exists",
		})
	}
}

// checkStateJSON validates .cloop/state.json is well-formed JSON.
func checkStateJSON(workdir string, add addFn) {
	statePath := filepath.Join(workdir, ".cloop", "state.json")
	data, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		add(Result{
			Name:    ".cloop/state.json",
			Level:   Warn,
			Message: "state.json not found — no session has been run yet",
			Fix:     "Run: cloop run to start a session",
		})
		return
	}
	if err != nil {
		add(Result{
			Name:    ".cloop/state.json",
			Level:   Fail,
			Message: fmt.Sprintf("cannot read state.json: %v", err),
			Fix:     "Check file permissions on .cloop/state.json",
		})
		return
	}
	if !json.Valid(data) {
		add(Result{
			Name:    ".cloop/state.json",
			Level:   Fail,
			Message: "state.json contains invalid JSON",
			Fix:     "Run: cloop reset to reinitialize state",
		})
		return
	}
	add(Result{
		Name:    ".cloop/state.json",
		Level:   Pass,
		Message: "state.json is valid JSON",
	})
}

// checkGoBinary checks whether `go` is available and reports its version.
func checkGoBinary(add addFn) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		add(Result{
			Name:    "Go binary",
			Level:   Warn,
			Message: "go binary not found in PATH",
			Fix:     "Install Go from https://go.dev/dl/ or ensure it is on your PATH",
		})
		return
	}
	out, err := exec.Command(goPath, "version").Output()
	if err != nil {
		add(Result{
			Name:    "Go binary",
			Level:   Warn,
			Message: fmt.Sprintf("go binary found at %s but version check failed: %v", goPath, err),
		})
		return
	}
	add(Result{
		Name:    "Go binary",
		Level:   Pass,
		Message: strings.TrimSpace(string(out)),
	})
}

// checkEnvVars checks for expected environment variables based on configuration.
func checkEnvVars(cfg *config.Config, add addFn) {
	// Anthropic: needed if provider is anthropic and no key in config
	if cfg.Provider == "anthropic" || cfg.Anthropic.APIKey != "" {
		key := cfg.Anthropic.APIKey
		if key == "" {
			key = os.Getenv("ANTHROPIC_API_KEY")
		}
		if key == "" {
			add(Result{
				Name:    "ANTHROPIC_API_KEY",
				Level:   Fail,
				Message: "Anthropic provider configured but ANTHROPIC_API_KEY is not set",
				Fix:     "Set env var ANTHROPIC_API_KEY or run: cloop config set anthropic.api_key <key>",
			})
		} else {
			add(Result{
				Name:    "ANTHROPIC_API_KEY",
				Level:   Pass,
				Message: "Anthropic API key is set",
			})
		}
	}

	// OpenAI: needed if provider is openai and no key in config
	if cfg.Provider == "openai" || cfg.OpenAI.APIKey != "" {
		key := cfg.OpenAI.APIKey
		if key == "" {
			key = os.Getenv("OPENAI_API_KEY")
		}
		if key == "" {
			add(Result{
				Name:    "OPENAI_API_KEY",
				Level:   Fail,
				Message: "OpenAI provider configured but OPENAI_API_KEY is not set",
				Fix:     "Set env var OPENAI_API_KEY or run: cloop config set openai.api_key <key>",
			})
		} else {
			add(Result{
				Name:    "OPENAI_API_KEY",
				Level:   Pass,
				Message: "OpenAI API key is set",
			})
		}
	}

	// GitHub token: needed if GitHub sync is configured
	if cfg.GitHub.Repo != "" || cfg.GitHub.Token != "" {
		token := cfg.GitHub.Token
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		if token == "" {
			add(Result{
				Name:    "GITHUB_TOKEN",
				Level:   Warn,
				Message: "GitHub repo configured but GITHUB_TOKEN is not set — sync will fail",
				Fix:     "Set env var GITHUB_TOKEN or run: cloop config set github.token <token>",
			})
		} else {
			add(Result{
				Name:    "GITHUB_TOKEN",
				Level:   Pass,
				Message: "GitHub token is set",
			})
		}
	}

	// claudecode: check that the claude binary is available
	if cfg.Provider == "claudecode" || cfg.Provider == "" {
		if _, err := exec.LookPath("claude"); err != nil {
			add(Result{
				Name:    "claude binary (claudecode provider)",
				Level:   Fail,
				Message: "claude CLI binary not found in PATH — claudecode provider will not work",
				Fix:     "Install Claude Code CLI or switch provider: cloop config set provider anthropic",
			})
		} else {
			add(Result{
				Name:    "claude binary (claudecode provider)",
				Level:   Pass,
				Message: "claude CLI binary found in PATH",
			})
		}
	}
}

// checkProviders tests connectivity for each configured provider.
func checkProviders(ctx context.Context, cfg *config.Config, add addFn) {
	type provCheck struct {
		name    string
		enabled bool
		pcfg    provider.ProviderConfig
	}

	checks := []provCheck{
		{
			name:    "claudecode connectivity",
			enabled: cfg.Provider == "claudecode" || cfg.Provider == "",
			pcfg:    provider.ProviderConfig{Name: "claudecode"},
		},
		{
			name:    "anthropic connectivity",
			enabled: cfg.Provider == "anthropic" || cfg.Anthropic.APIKey != "" || os.Getenv("ANTHROPIC_API_KEY") != "",
			pcfg: provider.ProviderConfig{
				Name:             "anthropic",
				AnthropicAPIKey:  cfg.Anthropic.APIKey,
				AnthropicBaseURL: cfg.Anthropic.BaseURL,
			},
		},
		{
			name:    "openai connectivity",
			enabled: cfg.Provider == "openai" || cfg.OpenAI.APIKey != "" || os.Getenv("OPENAI_API_KEY") != "",
			pcfg: provider.ProviderConfig{
				Name:          "openai",
				OpenAIAPIKey:  cfg.OpenAI.APIKey,
				OpenAIBaseURL: cfg.OpenAI.BaseURL,
			},
		},
		{
			name:    "ollama connectivity",
			enabled: cfg.Provider == "ollama",
			pcfg: provider.ProviderConfig{
				Name:          "ollama",
				OllamaBaseURL: cfg.Ollama.BaseURL,
			},
		},
	}

	for _, c := range checks {
		if !c.enabled {
			continue
		}
		prov, err := provider.Build(c.pcfg)
		if err != nil {
			add(Result{
				Name:    c.name,
				Level:   Fail,
				Message: fmt.Sprintf("failed to build provider: %v", err),
			})
			continue
		}

		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err = prov.Complete(tctx, "Say OK", provider.Options{MaxTokens: 5, Timeout: 30 * time.Second})
		cancel()
		if err != nil {
			add(Result{
				Name:    c.name,
				Level:   Fail,
				Message: fmt.Sprintf("connectivity test failed: %v", err),
				Fix:     "Check API key, network, and provider status",
			})
		} else {
			add(Result{
				Name:    c.name,
				Level:   Pass,
				Message: "connectivity test passed",
			})
		}
	}
}

// checkGitRepo verifies a git repository is present when git workflow features are used.
func checkGitRepo(workdir string, cfg *config.Config, add addFn) {
	// We check for git if the GitHub integration is configured.
	if cfg.GitHub.Repo == "" && cfg.GitHub.Token == "" && os.Getenv("GITHUB_TOKEN") == "" {
		return // git check not applicable
	}

	if _, err := exec.LookPath("git"); err != nil {
		add(Result{
			Name:    "git binary",
			Level:   Fail,
			Message: "git not found in PATH — GitHub sync requires git",
			Fix:     "Install git and ensure it is on your PATH",
		})
		return
	}

	// Check if we're inside a git repo.
	cmd := exec.Command("git", "-C", workdir, "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		add(Result{
			Name:    "git repository",
			Level:   Warn,
			Message: "current directory is not a git repository — GitHub sync may not detect remote",
			Fix:     "Run: git init && git remote add origin <url>",
		})
	} else {
		add(Result{
			Name:    "git repository",
			Level:   Pass,
			Message: "git repository detected",
		})
	}
}

// checkWebhooks performs a HEAD request to configured webhook URLs.
func checkWebhooks(ctx context.Context, cfg *config.Config, add addFn) {
	type webhookCheck struct {
		name string
		url  string
	}

	var checks []webhookCheck
	if cfg.Webhook.URL != "" {
		checks = append(checks, webhookCheck{"webhook URL", cfg.Webhook.URL})
	}
	if cfg.Notify.SlackWebhook != "" {
		checks = append(checks, webhookCheck{"Slack webhook URL", cfg.Notify.SlackWebhook})
	}
	if cfg.Notify.DiscordWebhook != "" {
		checks = append(checks, webhookCheck{"Discord webhook URL", cfg.Notify.DiscordWebhook})
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, wh := range checks {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, wh.url, nil)
		if err != nil {
			add(Result{
				Name:    wh.name,
				Level:   Fail,
				Message: fmt.Sprintf("invalid URL %q: %v", wh.url, err),
				Fix:     "Check the URL in .cloop/config.yaml",
			})
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			add(Result{
				Name:    wh.name,
				Level:   Warn,
				Message: fmt.Sprintf("HEAD %s failed: %v", wh.url, err),
				Fix:     "Check network connectivity and the webhook URL",
			})
			continue
		}
		resp.Body.Close()
		// Webhook endpoints often return 405 (Method Not Allowed) for HEAD — that's fine.
		if resp.StatusCode >= 500 {
			add(Result{
				Name:    wh.name,
				Level:   Warn,
				Message: fmt.Sprintf("HEAD %s returned HTTP %d", wh.url, resp.StatusCode),
				Fix:     "The webhook endpoint may be down or misconfigured",
			})
		} else {
			add(Result{
				Name:    wh.name,
				Level:   Pass,
				Message: fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode),
			})
		}
	}
}

// checkEnvYamlGitignored warns if .cloop/env.yaml exists but is not in .gitignore.
// Committing env.yaml could expose secrets stored in it.
func checkEnvYamlGitignored(workdir string, add addFn) {
	envYaml := filepath.Join(workdir, ".cloop", "env.yaml")
	if _, err := os.Stat(envYaml); os.IsNotExist(err) {
		return // no env.yaml → nothing to check
	}

	giPath := filepath.Join(workdir, ".gitignore")
	data, err := os.ReadFile(giPath)
	if err != nil {
		// No .gitignore at all.
		add(Result{
			Name:    ".cloop/env.yaml in .gitignore",
			Level:   Warn,
			Message: ".cloop/env.yaml exists but no .gitignore found — secrets may be committed",
			Fix:     "Add '.cloop/env.yaml' to .gitignore: echo '.cloop/env.yaml' >> .gitignore",
		})
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == ".cloop/env.yaml" {
			add(Result{
				Name:    ".cloop/env.yaml in .gitignore",
				Level:   Pass,
				Message: ".cloop/env.yaml is listed in .gitignore",
			})
			return
		}
	}
	add(Result{
		Name:    ".cloop/env.yaml in .gitignore",
		Level:   Warn,
		Message: ".cloop/env.yaml is NOT in .gitignore — secrets may be accidentally committed",
		Fix:     "Add '.cloop/env.yaml' to .gitignore: echo '.cloop/env.yaml' >> .gitignore",
	})
}

// checkConfigValidate runs the config/state schema validator and surfaces any findings
// as doctor results. ERRORs → Fail, WARNs → Warn, no issues → Pass.
func checkConfigValidate(ctx context.Context, workdir string, add addFn) {
	rep, err := configvalidate.Run(ctx, workdir, configvalidate.ValidateOptions{})
	if err != nil {
		add(Result{
			Name:    "config validate",
			Level:   Warn,
			Message: fmt.Sprintf("config validate could not run: %v", err),
		})
		return
	}

	if len(rep.Findings) == 0 {
		add(Result{
			Name:    "config validate",
			Level:   Pass,
			Message: "config.yaml and state.db pass schema validation",
		})
		return
	}

	// Surface each finding as its own result so the user sees details.
	for _, f := range rep.Findings {
		var lvl Level
		var fixHint string
		switch f.Severity {
		case configvalidate.SeverityError:
			lvl = Fail
		case configvalidate.SeverityWarn:
			lvl = Warn
		default:
			lvl = Pass
		}
		if f.FixNote != "" {
			fixHint = "cloop config validate --fix: " + f.FixNote
		}
		add(Result{
			Name:    fmt.Sprintf("config validate: %s", f.Field),
			Level:   lvl,
			Message: f.Message,
			Fix:     fixHint,
		})
	}
}

// checkHookScripts verifies that configured hook script paths are executable.
func checkHookScripts(cfg *config.Config, add addFn) {
	hooks := []struct {
		name string
		cmd  string
	}{
		{"hooks.pre_task", cfg.Hooks.PreTask},
		{"hooks.post_task", cfg.Hooks.PostTask},
		{"hooks.pre_plan", cfg.Hooks.PrePlan},
		{"hooks.post_plan", cfg.Hooks.PostPlan},
	}

	for _, h := range hooks {
		if h.cmd == "" {
			continue
		}
		// Extract the first word as the potential script path.
		parts := strings.Fields(h.cmd)
		if len(parts) == 0 {
			continue
		}
		script := parts[0]

		// Skip inline shell builtins and short commands (assume they're valid).
		if !strings.Contains(script, "/") {
			// Could be a system command — check with LookPath.
			if _, err := exec.LookPath(script); err != nil {
				add(Result{
					Name:    h.name,
					Level:   Warn,
					Message: fmt.Sprintf("hook command %q not found in PATH", script),
					Fix:     fmt.Sprintf("Ensure %q is installed and on your PATH", script),
				})
			} else {
				add(Result{
					Name:    h.name,
					Level:   Pass,
					Message: fmt.Sprintf("hook command %q found in PATH", script),
				})
			}
			continue
		}

		// It looks like a file path — check it exists and is executable.
		info, err := os.Stat(script)
		if err != nil {
			add(Result{
				Name:    h.name,
				Level:   Fail,
				Message: fmt.Sprintf("hook script %q not found: %v", script, err),
				Fix:     fmt.Sprintf("Create the script or fix the path in .cloop/config.yaml hooks.%s", h.name),
			})
			continue
		}
		if info.Mode()&0o111 == 0 {
			add(Result{
				Name:    h.name,
				Level:   Fail,
				Message: fmt.Sprintf("hook script %q is not executable", script),
				Fix:     fmt.Sprintf("Run: chmod +x %s", script),
			})
		} else {
			add(Result{
				Name:    h.name,
				Level:   Pass,
				Message: fmt.Sprintf("hook script %q exists and is executable", script),
			})
		}
	}
}
