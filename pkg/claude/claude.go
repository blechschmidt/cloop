package claude

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var envOnce sync.Once

type Options struct {
	Model                string
	WorkDir              string
	MaxTokens            int
	Timeout              time.Duration
	SkipPermissions      bool
}

type Result struct {
	Output   string
	ExitCode int
	Duration time.Duration
}

// loadEnvFile reads a .env file and sets any unset environment variables.
func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
	}
}

// Run executes claude with --print mode, feeding the prompt via stdin.
func Run(ctx context.Context, prompt string, opts Options) (*Result, error) {
	// Load API keys from common .env files (once)
	envOnce.Do(func() {
		home, _ := os.UserHomeDir()
		envPaths := []string{
			filepath.Join(home, ".openclaw", "workspace", ".env"),
			filepath.Join(home, ".env"),
			".env",
		}
		for _, p := range envPaths {
			loadEnvFile(p)
		}
	})

	args := []string{
		"--print",
		"--output-format", "text",
	}

	if opts.SkipPermissions {
		args = append(args, "--permission-mode", "auto")
	}

	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}

	if opts.MaxTokens > 0 {
		args = append(args, "--max-tokens", fmt.Sprintf("%d", opts.MaxTokens))
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "claude", args...)
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}

	// Feed prompt via stdin (avoids arg length limits and special char issues)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to run claude: %w", err)
		}
	}

	output := stdout.String()
	if output == "" && stderr.String() != "" {
		output = stderr.String()
	}

	return &Result{
		Output:   strings.TrimSpace(output),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}
