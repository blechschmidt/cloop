// Package cipipe generates CI/CD pipeline configurations tailored to a project's
// tech stack and cloop task plan. Supports GitHub Actions, GitLab CI, and CircleCI.
package cipipe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Platform is the CI platform to generate a pipeline for.
type Platform string

const (
	PlatformGitHub   Platform = "github"
	PlatformGitLab   Platform = "gitlab"
	PlatformCircleCI Platform = "circleci"
)

// DefaultOutputPath returns the default output file path for a given platform.
func DefaultOutputPath(platform Platform) string {
	switch platform {
	case PlatformGitLab:
		return ".gitlab-ci.yml"
	case PlatformCircleCI:
		return ".circleci/config.yml"
	default: // github
		return ".github/workflows/cloop-ci.yml"
	}
}

// TechStack describes the detected technologies in a project directory.
type TechStack struct {
	// Go project signals
	HasGoMod bool
	GoModule string // module name from go.mod (e.g. "github.com/user/repo")

	// Node/JS project signals
	HasPackageJSON bool
	PackageName    string
	HasNodeModules bool
	HasYarnLock    bool

	// Python project signals
	HasRequirementsTxt bool
	HasPyprojectToml   bool
	HasSetupPy         bool

	// Docker signals
	HasDockerfile      bool
	HasDockerCompose   bool

	// Build tool signals
	HasMakefile bool

	// CI signals (existing pipelines detected)
	HasGitHubActions bool
	HasGitLabCI      bool
	HasCircleCI      bool

	// Terraform / IaC
	HasTerraform bool
}

// Languages returns a compact summary of detected languages/frameworks.
func (s TechStack) Languages() []string {
	var langs []string
	if s.HasGoMod {
		langs = append(langs, "Go")
	}
	if s.HasPackageJSON {
		langs = append(langs, "Node.js")
	}
	if s.HasRequirementsTxt || s.HasPyprojectToml || s.HasSetupPy {
		langs = append(langs, "Python")
	}
	return langs
}

// Detect scans dir for well-known project files and returns a TechStack.
func Detect(dir string) TechStack {
	var s TechStack

	check := func(rel string) bool {
		_, err := os.Stat(filepath.Join(dir, rel))
		return err == nil
	}

	// Go
	if check("go.mod") {
		s.HasGoMod = true
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					s.GoModule = strings.TrimSpace(strings.TrimPrefix(line, "module "))
					break
				}
			}
		}
	}

	// Node / JS
	s.HasPackageJSON = check("package.json")
	s.HasNodeModules = check("node_modules")
	s.HasYarnLock = check("yarn.lock")
	if s.HasPackageJSON {
		if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
			// Extract "name" field with a simple scan (avoid json import cycle)
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, `"name"`) {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						name := strings.Trim(strings.TrimSpace(parts[1]), `",`)
						s.PackageName = name
					}
					break
				}
			}
		}
	}

	// Python
	s.HasRequirementsTxt = check("requirements.txt")
	s.HasPyprojectToml = check("pyproject.toml")
	s.HasSetupPy = check("setup.py")

	// Docker
	s.HasDockerfile = check("Dockerfile")
	s.HasDockerCompose = check("docker-compose.yml") || check("docker-compose.yaml")

	// Make
	s.HasMakefile = check("Makefile")

	// Existing CI
	s.HasGitHubActions = check(".github/workflows")
	s.HasGitLabCI = check(".gitlab-ci.yml")
	s.HasCircleCI = check(".circleci/config.yml")

	// Terraform
	entries, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	s.HasTerraform = len(entries) > 0

	return s
}

// GeneratePrompt builds the AI prompt that asks the provider to produce a CI YAML
// for the given platform, tech stack, and (optional) task plan.
func GeneratePrompt(platform Platform, stack TechStack, plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are a DevOps engineer. Generate a production-quality CI/CD pipeline configuration.\n\n")

	b.WriteString("## PLATFORM\n")
	switch platform {
	case PlatformGitLab:
		b.WriteString("GitLab CI (.gitlab-ci.yml)\n\n")
	case PlatformCircleCI:
		b.WriteString("CircleCI (.circleci/config.yml, version 2.1)\n\n")
	default:
		b.WriteString("GitHub Actions (.github/workflows/cloop-ci.yml)\n\n")
	}

	b.WriteString("## DETECTED TECH STACK\n")
	if stack.HasGoMod {
		module := stack.GoModule
		if module == "" {
			module = "(unknown)"
		}
		b.WriteString(fmt.Sprintf("- Go module: %s\n", module))
	}
	if stack.HasPackageJSON {
		pkg := stack.PackageName
		if pkg == "" {
			pkg = "(unknown)"
		}
		b.WriteString(fmt.Sprintf("- Node.js package: %s", pkg))
		if stack.HasYarnLock {
			b.WriteString(" (yarn)")
		} else {
			b.WriteString(" (npm)")
		}
		b.WriteString("\n")
	}
	if stack.HasRequirementsTxt {
		b.WriteString("- Python (requirements.txt)\n")
	}
	if stack.HasPyprojectToml {
		b.WriteString("- Python (pyproject.toml)\n")
	}
	if stack.HasSetupPy {
		b.WriteString("- Python (setup.py)\n")
	}
	if stack.HasDockerfile {
		b.WriteString("- Dockerfile present\n")
	}
	if stack.HasDockerCompose {
		b.WriteString("- docker-compose present\n")
	}
	if stack.HasMakefile {
		b.WriteString("- Makefile present\n")
	}
	if stack.HasTerraform {
		b.WriteString("- Terraform files present\n")
	}
	b.WriteString("\n")

	if plan != nil && len(plan.Tasks) > 0 {
		b.WriteString("## CLOOP TASK PLAN\n")
		b.WriteString(fmt.Sprintf("Goal: %s\n\n", plan.Goal))
		b.WriteString("Tasks:\n")
		for _, t := range plan.Tasks {
			status := string(t.Status)
			b.WriteString(fmt.Sprintf("  [%s] #%d %s", status, t.ID, t.Title))
			if t.Role != "" {
				b.WriteString(fmt.Sprintf(" (role: %s)", t.Role))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## REQUIREMENTS\n")
	b.WriteString("Generate a complete, valid CI pipeline YAML that:\n")
	b.WriteString("1. Runs on pushes and pull requests to the main branch\n")
	b.WriteString("2. Includes stages: build, test, lint (where applicable to the stack)\n")
	b.WriteString("3. Includes a 'cloop' step that:\n")

	if stack.HasGoMod {
		b.WriteString("   - Installs cloop by running: go install github.com/blechschmidt/cloop@latest\n")
	} else {
		b.WriteString("   - Downloads and installs the cloop binary from GitHub releases\n")
	}
	b.WriteString("   - Runs: cloop status\n")
	b.WriteString("4. Caches dependencies (Go module cache, node_modules, pip cache, etc.)\n")
	b.WriteString("5. Uses current, stable versions of language runtimes\n")
	b.WriteString("6. Includes meaningful job/step names\n")

	if stack.HasDockerfile {
		b.WriteString("7. Builds the Docker image (but does not push — no credentials assumed)\n")
	}
	if stack.HasTerraform {
		b.WriteString("8. Includes a Terraform validate step\n")
	}

	b.WriteString("\n## OUTPUT FORMAT\n")
	b.WriteString("Return ONLY the raw YAML content — no markdown code fences, no explanatory prose.\n")
	b.WriteString("The first line must be valid YAML (a comment or a top-level key).\n")

	return b.String()
}

// Generate calls the AI provider with the GeneratePrompt and returns the pipeline YAML.
func Generate(ctx context.Context, p provider.Provider, model string, platform Platform, stack TechStack, plan *pm.Plan) (string, error) {
	prompt := GeneratePrompt(platform, stack, plan)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return "", fmt.Errorf("generating CI pipeline: %w", err)
	}

	// Strip any markdown code fences the AI may have added despite instructions.
	yaml := strings.TrimSpace(result.Output)
	yaml = stripCodeFences(yaml)

	return yaml, nil
}

// Write writes content to path, creating parent directories as needed.
func Write(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// stripCodeFences removes leading/trailing markdown code fences (``` or ```yaml etc).
func stripCodeFences(s string) string {
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		return s
	}
	// Strip leading fence
	if strings.HasPrefix(strings.TrimSpace(lines[0]), "```") {
		lines = lines[1:]
	}
	// Strip trailing fence
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
		lines = lines[:len(lines)-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
