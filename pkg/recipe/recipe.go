// Package recipe implements a named, shareable workflow library for cloop.
// A recipe bundles a flow YAML, a goal template, lifecycle hooks, and default
// environment variables into a single installable YAML file stored in
// .cloop/recipes/<name>.yaml.
package recipe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/blechschmidt/cloop/pkg/env"
	"github.com/blechschmidt/cloop/pkg/flow"
	"github.com/blechschmidt/cloop/pkg/hooks"
	"gopkg.in/yaml.v3"
)

const recipesDir = "recipes"

// Recipe is a named, shareable automation workflow that combines a flow
// pipeline, a goal template, lifecycle hooks, and default environment
// variables into a single installable unit.
type Recipe struct {
	// Name is the unique identifier for the recipe (used as the file stem).
	Name string `yaml:"name"`

	// Description is a short human-readable summary.
	Description string `yaml:"description,omitempty"`

	// Version is an optional semantic version string (e.g. "1.0.0").
	Version string `yaml:"version,omitempty"`

	// Author is the optional creator name or email.
	Author string `yaml:"author,omitempty"`

	// FlowYAML is the embedded flow pipeline definition (YAML text).
	// It is rendered as a Go text/template before execution; use {{.Goal}},
	// {{.Name}}, or any key from ExtraVars.
	FlowYAML string `yaml:"flow_yaml"`

	// GoalTemplate is an optional Go text/template that generates the cloop
	// goal string. The template receives a TemplateData value.
	// When empty, the --goal flag value is used verbatim.
	GoalTemplate string `yaml:"goal_template,omitempty"`

	// Hooks defines shell commands to run at plan/task lifecycle events.
	Hooks hooks.Config `yaml:"hooks,omitempty"`

	// EnvVars lists environment variables to set before running the recipe.
	// These are merged with the project's existing env vars (recipe values win).
	EnvVars []env.Var `yaml:"env_vars,omitempty"`
}

// TemplateData is passed to GoalTemplate and FlowYAML rendering.
type TemplateData struct {
	// Goal is the goal string provided via --goal or the recipe default.
	Goal string
	// Name is the recipe name.
	Name string
	// Timestamp is the current UTC time.
	Timestamp time.Time
	// Extra holds any additional key→value pairs passed by the caller.
	Extra map[string]string
}

// recipesPath returns the absolute path to the recipes directory.
func recipesPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", recipesDir)
}

// recipePath returns the path to a single recipe file.
func recipePath(workDir, name string) string {
	return filepath.Join(recipesPath(workDir), name+".yaml")
}

// Load reads and parses a recipe from .cloop/recipes/<name>.yaml.
func Load(workDir, name string) (*Recipe, error) {
	path := recipePath(workDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("recipe %q not found (expected %s)", name, path)
		}
		return nil, fmt.Errorf("reading recipe %q: %w", name, err)
	}
	return parse(data)
}

// parse unmarshals raw YAML bytes into a Recipe.
func parse(data []byte) (*Recipe, error) {
	var r Recipe
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing recipe YAML: %w", err)
	}
	if r.Name == "" {
		return nil, fmt.Errorf("recipe YAML must have a non-empty 'name' field")
	}
	if r.FlowYAML == "" {
		return nil, fmt.Errorf("recipe %q has no 'flow_yaml' content", r.Name)
	}
	return &r, nil
}

// List returns all Recipe objects found in .cloop/recipes/.
// Returns an empty slice (not an error) when the directory does not exist.
func List(workDir string) ([]*Recipe, error) {
	dir := recipesPath(workDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []*Recipe{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing recipes: %w", err)
	}

	var recipes []*Recipe
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		r, err := Load(workDir, name)
		if err != nil {
			// Include a placeholder so the user sees the broken file.
			recipes = append(recipes, &Recipe{
				Name:        name,
				Description: fmt.Sprintf("(parse error: %v)", err),
			})
			continue
		}
		recipes = append(recipes, r)
	}
	return recipes, nil
}

// Install copies a recipe from a local file path or HTTP(S) URL into
// .cloop/recipes/<name>.yaml.  The source must contain valid recipe YAML.
func Install(workDir, source string) (*Recipe, error) {
	data, err := fetchSource(source)
	if err != nil {
		return nil, fmt.Errorf("fetching recipe from %q: %w", source, err)
	}

	r, err := parse(data)
	if err != nil {
		return nil, err
	}

	dir := recipesPath(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating recipes directory: %w", err)
	}

	dest := recipePath(workDir, r.Name)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return nil, fmt.Errorf("writing recipe %q: %w", r.Name, err)
	}
	return r, nil
}

// fetchSource reads raw bytes from a local path or an HTTP(S) URL.
func fetchSource(source string) ([]byte, error) {
	u, err := url.Parse(source)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source) //nolint:noctx
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, source)
		}
		return io.ReadAll(resp.Body)
	}
	// Treat as a local file path.
	return os.ReadFile(source)
}

// Remove deletes the recipe file for the given name.
func Remove(workDir, name string) error {
	path := recipePath(workDir, name)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("recipe %q not found", name)
		}
		return fmt.Errorf("removing recipe %q: %w", name, err)
	}
	return nil
}

// Export serialises a recipe back to YAML bytes suitable for sharing.
func Export(workDir, name string) ([]byte, error) {
	r, err := Load(workDir, name)
	if err != nil {
		return nil, err
	}
	return marshalYAML(r)
}

// marshalYAML serialises a Recipe to YAML bytes.
func marshalYAML(r *Recipe) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("marshalling recipe: %w", err)
	}
	return buf.Bytes(), nil
}

// RunConfig controls recipe execution behaviour.
type RunConfig struct {
	// Goal overrides the default goal. Required when GoalTemplate is non-empty
	// and no default is embedded in the recipe.
	Goal string

	// ExtraVars are additional key→value pairs available inside templates.
	ExtraVars map[string]string

	// WorkDir is the project working directory.
	WorkDir string

	// CloopBin is the path to the cloop binary (defaults to os.Executable).
	CloopBin string

	// DryRun prints steps without executing them.
	DryRun bool
}

// RunResult captures the outcome of executing a recipe.
type RunResult struct {
	// Recipe is the recipe that was executed.
	Recipe *Recipe

	// FlowResults contains per-step outcomes.
	FlowResults []flow.StepResult

	// Err is the first fatal error, if any.
	Err error
}

// Run instantiates the recipe (renders templates, applies env vars and hooks),
// writes a temporary flow file, then delegates to flow.Run.
func Run(ctx context.Context, r *Recipe, cfg RunConfig) (*RunResult, error) {
	td := TemplateData{
		Goal:      cfg.Goal,
		Name:      r.Name,
		Timestamp: time.Now().UTC(),
		Extra:     cfg.ExtraVars,
	}

	// Render the goal from GoalTemplate if provided.
	goal := cfg.Goal
	if r.GoalTemplate != "" {
		rendered, err := renderTemplate("goal", r.GoalTemplate, td)
		if err != nil {
			return nil, fmt.Errorf("rendering goal template: %w", err)
		}
		if rendered != "" {
			goal = rendered
		}
	}
	td.Goal = goal

	// Render the flow YAML through text/template.
	renderedFlow, err := renderTemplate("flow", r.FlowYAML, td)
	if err != nil {
		return nil, fmt.Errorf("rendering flow YAML: %w", err)
	}

	// Parse the rendered flow YAML.
	var f flow.Flow
	if err := yaml.Unmarshal([]byte(renderedFlow), &f); err != nil {
		return nil, fmt.Errorf("parsing rendered flow YAML: %w", err)
	}
	if f.Name == "" {
		f.Name = r.Name
	}

	// Apply recipe env vars to the process environment (non-destructive:
	// only set vars that are not already present in the environment).
	for _, v := range r.EnvVars {
		key := v.Key
		if key == "" {
			continue
		}
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, v.Value); err != nil {
				return nil, fmt.Errorf("setting env var %s: %w", key, err)
			}
		}
	}

	planCtx := hooks.PlanContext{Goal: goal}

	// Run the pre-plan hook if configured.
	if r.Hooks.PrePlan != "" {
		if err := hooks.RunPrePlan(r.Hooks, planCtx); err != nil {
			return nil, fmt.Errorf("pre_plan hook failed: %w", err)
		}
	}

	flowCfg := flow.RunConfig{
		WorkDir:  cfg.WorkDir,
		CloopBin: cfg.CloopBin,
		DryRun:   cfg.DryRun,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}

	results, runErr := flow.Run(ctx, &f, flowCfg)

	// Run the post-plan hook regardless of success/failure.
	if r.Hooks.PostPlan != "" {
		_ = hooks.RunPostPlan(r.Hooks, planCtx) // best-effort
	}

	return &RunResult{
		Recipe:      r,
		FlowResults: results,
		Err:         runErr,
	}, nil
}

// renderTemplate executes a named Go text/template with the given data.
func renderTemplate(name, tmplText string, data TemplateData) (string, error) {
	tmpl, err := template.New(name).Parse(tmplText)
	if err != nil {
		return "", fmt.Errorf("parsing template %q: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template %q: %w", name, err)
	}
	return buf.String(), nil
}

// MarshalExample serialises a Recipe to YAML bytes (exported wrapper for cmd use).
func MarshalExample(r *Recipe) ([]byte, error) {
	return marshalYAML(r)
}

// ExampleRecipe returns a minimal but complete example recipe for documentation/init purposes.
func ExampleRecipe() *Recipe {
	return &Recipe{
		Name:        "example-recipe",
		Description: "Example recipe: lint, health-check, then run PM mode",
		Version:     "1.0.0",
		Author:      "your-name",
		GoalTemplate: `Deliver: {{.Goal}}`,
		FlowYAML: `name: example-pipeline
description: Lint, health-check, then run in PM mode
steps:
  - name: lint
    command: lint
    on_failure: continue
  - name: health
    command: doctor
    on_failure: continue
  - name: run
    command: run
    args: ["--pm"]
    if: test -f .cloop/state.db
    on_failure: abort
`,
		Hooks: hooks.Config{
			PrePlan:  `echo "Starting recipe"`,
			PostPlan: `echo "Recipe finished"`,
		},
		EnvVars: []env.Var{
			{Key: "CLOOP_RECIPE", Value: "example-recipe", Description: "Active recipe name"},
		},
	}
}
