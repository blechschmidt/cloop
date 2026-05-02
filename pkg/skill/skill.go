// Package skill implements the reusable prompt macro library.
// Skills are named prompt fragments stored in .cloop/skills/<name>.md that
// can be referenced in task descriptions and prompts as {{skill:name}}.
// Three built-in skills are always available: tdd, secure, and minimal.
package skill

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const skillsDir = ".cloop/skills"

// builtins maps skill name to content. These are always available and cannot
// be deleted, but can be overridden by a user file with the same name.
var builtins = map[string]string{
	"tdd": `## Test-Driven Development

Write tests BEFORE implementing the feature:
1. Write failing tests that define the expected behaviour.
2. Implement the minimum code to make the tests pass.
3. Refactor while keeping the tests green.

Rules:
- Every public function/method must have at least one unit test.
- Cover the happy path, edge cases, and error conditions.
- Tests must be deterministic and fast (no sleep, no external I/O unless mocked).
- Prefer table-driven tests for multiple input scenarios.
- Run the full test suite before declaring TASK_DONE.
`,

	"secure": `## Security Checklist (OWASP-aligned)

Before completing this task, verify the following:

**Input validation**
- All user-supplied input is validated and sanitised before use.
- No raw user data is interpolated into SQL queries, shell commands, or HTML.

**Authentication & authorisation**
- Access control checks are enforced on every sensitive operation.
- Secrets, API keys, and passwords are never hard-coded or logged.

**Data exposure**
- Error messages do not leak internal paths, stack traces, or sensitive data.
- Sensitive fields are masked in logs and API responses.

**Dependencies**
- No new dependency with known critical CVEs is introduced.

**Injection prevention**
- Parameterised queries are used for all database access.
- Shell commands use argument lists, not string concatenation.

Flag any unresolved security concerns explicitly before marking TASK_DONE.
`,

	"minimal": `## Minimal Implementation Principle

Avoid over-engineering. Apply these constraints:
- Implement only what the task explicitly requires — nothing more.
- Do not add features, configuration options, or abstractions for hypothetical future use.
- Do not introduce new dependencies unless strictly necessary.
- Prefer the simplest data structure that satisfies the requirement.
- Three similar lines of code is better than a premature abstraction.
- No speculative error handling for conditions that cannot occur.
- No docstrings, comments, or type annotations on code you did not change.
- If a helper is only used once, inline it.
`,
}

// Skill represents a named prompt fragment.
type Skill struct {
	Name    string
	Content string
	Builtin bool // true for built-in skills not overridden by a user file
}

// skillsPath returns the absolute path to the skills directory.
func skillsPath(workDir string) string {
	return filepath.Join(workDir, skillsDir)
}

// userSkillPath returns the path for a specific user skill file.
func userSkillPath(workDir, name string) string {
	return filepath.Join(skillsPath(workDir), name+".md")
}

// List returns all available skills (built-in + user-defined), sorted by name.
// User skills with the same name as a built-in override the built-in.
func List(workDir string) ([]Skill, error) {
	skills := make(map[string]Skill)

	// Load built-ins first.
	for name, content := range builtins {
		skills[name] = Skill{Name: name, Content: content, Builtin: true}
	}

	// Load user skills; they override built-ins with the same name.
	dir := skillsPath(workDir)
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading skills directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".md")
		data, readErr := os.ReadFile(filepath.Join(dir, e.Name()))
		if readErr != nil {
			continue
		}
		_, isBuiltin := builtins[name]
		skills[name] = Skill{
			Name:    name,
			Content: string(data),
			Builtin: isBuiltin, // still labelled built-in if it overrides one
		}
	}

	result := make([]Skill, 0, len(skills))
	for _, s := range skills {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

// Get returns the content of a skill by name. User files take precedence over
// built-ins. Returns an error if the skill does not exist.
func Get(workDir, name string) (Skill, error) {
	// Check user file first.
	path := userSkillPath(workDir, name)
	data, err := os.ReadFile(path)
	if err == nil {
		_, isBuiltin := builtins[name]
		return Skill{Name: name, Content: string(data), Builtin: isBuiltin}, nil
	}
	if !os.IsNotExist(err) {
		return Skill{}, fmt.Errorf("reading skill file: %w", err)
	}

	// Fall back to built-in.
	if content, ok := builtins[name]; ok {
		return Skill{Name: name, Content: content, Builtin: true}, nil
	}

	return Skill{}, fmt.Errorf("skill %q not found", name)
}

// Save writes skill content to .cloop/skills/<name>.md, creating the directory
// if necessary. This always saves to the user-file layer, even for built-in names.
func Save(workDir, name, content string) error {
	if err := validateName(name); err != nil {
		return err
	}
	dir := skillsPath(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating skills directory: %w", err)
	}
	path := userSkillPath(workDir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing skill file: %w", err)
	}
	return nil
}

// Delete removes a user-defined skill file. Built-in skills that have no
// corresponding user file cannot be deleted.
func Delete(workDir, name string) error {
	path := userSkillPath(workDir, name)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			// Check if it's a pure built-in with no override.
			if _, ok := builtins[name]; ok {
				return fmt.Errorf("skill %q is a built-in and cannot be deleted (create an override file to shadow it)", name)
			}
			return fmt.Errorf("skill %q not found", name)
		}
		return fmt.Errorf("deleting skill file: %w", err)
	}
	return nil
}

// skillRef matches {{skill:name}} tokens. Name may contain letters, digits,
// hyphens, and underscores only.
var skillRef = regexp.MustCompile(`\{\{skill:([a-zA-Z0-9_-]+)\}\}`)

// Expand replaces all {{skill:name}} references in prompt with the content of
// the named skill. Unknown skills are left as-is with a warning comment appended.
// Returns the expanded prompt unchanged if workDir is empty.
func Expand(workDir, prompt string) string {
	if workDir == "" {
		return prompt
	}
	return skillRef.ReplaceAllStringFunc(prompt, func(match string) string {
		sub := skillRef.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		name := sub[1]
		s, err := Get(workDir, name)
		if err != nil {
			// Leave unknown references visible so the user can diagnose.
			return match + fmt.Sprintf(" <!-- skill %q not found -->", name)
		}
		return s.Content
	})
}

// validateName checks that a skill name is non-empty and uses only safe
// characters (letters, digits, hyphens, underscores).
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("skill name must not be empty")
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("skill name %q contains invalid character %q (use letters, digits, hyphens, underscores only)", name, r)
		}
	}
	return nil
}
