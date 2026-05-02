// Package release implements semantic versioning and release automation for cloop.
// It infers the appropriate semver bump from completed task history, generates polished
// release notes combining changelog output with AI narration, creates an annotated git
// tag, and optionally pushes the tag and creates a GitHub release.
package release

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/changelog"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Release holds the computed release metadata and generated notes.
type Release struct {
	// Version is the bare semver string, e.g. "1.2.3".
	Version string
	// Tag is the full git tag name, e.g. "v1.2.3".
	Tag string
	// Bump is the semver bump that was applied: "major", "minor", or "patch".
	Bump string
	// PreviousTag is the tag this release is based on (empty if first release).
	PreviousTag string
	// Notes is the full release notes document in markdown.
	Notes string
	// TagCreated is true when an annotated git tag was actually created.
	TagCreated bool
	// TagPushed is true when the tag was pushed to the remote.
	TagPushed bool
	// GitHubURL is the URL of the created GitHub release, if any.
	GitHubURL string
}

// breakingKeywords trigger a major bump.
var breakingKeywords = []string{
	"breaking", "break", "incompatible", "remove", "removed",
	"deprecate", "deprecated", "migration required", "api change",
}

// featureKeywords trigger a minor bump.
var featureKeywords = []string{
	"feat", "feature", "add", "added", "implement", "implemented",
	"new", "introduce", "introduced", "support", "enable",
}

// InferBump analyzes completed task titles/descriptions and the git log to determine
// the appropriate semver bump level. Returns "major", "minor", or "patch".
func InferBump(tasks []*pm.Task, gitLog string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(gitLog))
	for _, t := range tasks {
		b.WriteString(" ")
		b.WriteString(strings.ToLower(t.Title))
		b.WriteString(" ")
		b.WriteString(strings.ToLower(t.Description))
	}
	combined := b.String()

	for _, kw := range breakingKeywords {
		if strings.Contains(combined, kw) {
			return "major"
		}
	}
	for _, kw := range featureKeywords {
		if strings.Contains(combined, kw) {
			return "minor"
		}
	}
	return "patch"
}

// Generate creates a full release package:
//  1. Discovers the last git tag and computes the next semver.
//  2. Generates AI-narrated release notes combining changelog output.
//  3. Creates an annotated git tag (unless dryRun is true).
//
// Pushing the tag and creating a GitHub release are handled by the caller using
// the returned Release.Tag value.
func Generate(
	ctx context.Context,
	p provider.Provider,
	model string,
	workDir string,
	tagPrefix string,
	bump string,
	dryRun bool,
) (*Release, error) {
	// ── 1. Resolve current version ───────────────────────────────────────────
	prevTag, err := lastTag(workDir, tagPrefix)
	if err != nil {
		// No existing tags — start from 0.0.0
		prevTag = ""
	}

	major, minor, patch := 0, 0, 0
	if prevTag != "" {
		major, minor, patch, err = parseVersion(prevTag, tagPrefix)
		if err != nil {
			// Unrecognised tag format; start from 0.0.0
			major, minor, patch = 0, 0, 0
		}
	}

	switch bump {
	case "major":
		major++
		minor = 0
		patch = 0
	case "minor":
		minor++
		patch = 0
	default: // "patch"
		patch++
		bump = "patch"
	}

	version := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	tag := tagPrefix + version

	rel := &Release{
		Version:     version,
		Tag:         tag,
		Bump:        bump,
		PreviousTag: prevTag,
	}

	// ── 2. Collect context for notes generation ──────────────────────────────
	s, _ := state.Load(workDir)

	// Git log since the previous tag (used for context and InferBump in auto mode).
	gitLog, _ := gitLogSince(workDir, prevTag)

	// Build the structured changelog via the existing package
	var changelogMD string
	if s != nil && s.Plan != nil {
		prompt := changelog.BuildPrompt(s, 0, "markdown")
		raw, clErr := changelog.Generate(ctx, p, prompt, model, 2*time.Minute)
		if clErr == nil {
			changelogMD = raw
		}
	}

	// ── 3. Ask AI to narrate the release ────────────────────────────────────
	notes, err := narrate(ctx, p, model, tag, bump, prevTag, gitLog, changelogMD, s)
	if err != nil {
		return nil, fmt.Errorf("release narration: %w", err)
	}
	rel.Notes = notes

	// ── 4. Create annotated git tag (unless dry-run) ─────────────────────────
	if !dryRun {
		if err := createTag(workDir, tag, notes); err != nil {
			return nil, fmt.Errorf("creating git tag %s: %w", tag, err)
		}
		rel.TagCreated = true
	}

	return rel, nil
}

// PushTag pushes the given tag to the git remote.
func PushTag(workDir, tag, remote string) error {
	if remote == "" {
		remote = "origin"
	}
	out, err := gitRun(workDir, "git", "push", remote, tag)
	if err != nil {
		return fmt.Errorf("git push %s %s: %w\n%s", remote, tag, err, out)
	}
	return nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

// semverRe matches an optional prefix then major.minor.patch.
var semverRe = regexp.MustCompile(`^.*?(\d+)\.(\d+)\.(\d+)$`)

// parseVersion extracts major, minor, patch integers from a tag like "v1.2.3".
func parseVersion(tag, prefix string) (int, int, int, error) {
	bare := strings.TrimPrefix(tag, prefix)
	m := semverRe.FindStringSubmatch(bare)
	if m == nil {
		return 0, 0, 0, fmt.Errorf("tag %q does not match semver pattern", tag)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return major, minor, patch, nil
}

// lastTag returns the most recent git tag matching tagPrefix + semver pattern.
// Falls back to "git describe --tags --abbrev=0" which returns the nearest tag.
func lastTag(workDir, tagPrefix string) (string, error) {
	// Try describe first (fastest path).
	out, err := gitRun(workDir, "git", "describe", "--tags", "--abbrev=0")
	if err == nil {
		t := strings.TrimSpace(out)
		if strings.HasPrefix(t, tagPrefix) {
			return t, nil
		}
	}

	// Fall back: list all tags, filter by prefix, sort semver-ish.
	out, err = gitRun(workDir, "git", "tag", "--list", tagPrefix+"*", "--sort=-version:refname")
	if err != nil {
		return "", fmt.Errorf("listing git tags: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, _, _, err := parseVersion(line, tagPrefix); err == nil {
			return line, nil
		}
	}
	return "", fmt.Errorf("no semver tag with prefix %q found", tagPrefix)
}

// gitLogSince returns the git log since prevTag (or all log if prevTag is empty).
func gitLogSince(workDir, prevTag string) (string, error) {
	args := []string{"git", "log", "--oneline", "--no-decorate"}
	if prevTag != "" {
		args = append(args, prevTag+"..HEAD")
	} else {
		args = append(args, "-30") // last 30 commits for first release
	}
	out, err := gitRun(workDir, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// createTag creates an annotated git tag with the release notes as the message.
func createTag(workDir, tag, message string) error {
	// Truncate message for tag annotation (git has practical limits on annotation size).
	annotation := message
	if len(annotation) > 8000 {
		annotation = annotation[:8000] + "\n\n…(truncated)"
	}
	out, err := gitRun(workDir, "git", "tag", "-a", tag, "-m", annotation)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// narrate asks the AI to write polished release notes for the given release.
func narrate(
	ctx context.Context,
	p provider.Provider,
	model string,
	tag, bump, prevTag, gitLog, changelogMD string,
	s *state.ProjectState,
) (string, error) {
	prompt := buildNarratePrompt(tag, bump, prevTag, gitLog, changelogMD, s)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Output), nil
}

// buildNarratePrompt constructs the AI prompt for release note generation.
func buildNarratePrompt(tag, bump, prevTag, gitLog, changelogMD string, s *state.ProjectState) string {
	var b strings.Builder

	b.WriteString("You are a technical writer generating release notes for a software project.\n")
	b.WriteString("Your goal is to produce polished, developer-friendly release notes in GitHub-flavoured markdown.\n\n")

	// Release metadata
	b.WriteString("## RELEASE METADATA\n")
	b.WriteString(fmt.Sprintf("- Tag: %s\n", tag))
	b.WriteString(fmt.Sprintf("- Bump type: %s\n", bump))
	if prevTag != "" {
		b.WriteString(fmt.Sprintf("- Previous tag: %s\n", prevTag))
	} else {
		b.WriteString("- First release\n")
	}
	b.WriteString(fmt.Sprintf("- Date: %s\n\n", time.Now().Format("2006-01-02")))

	// Project context
	if s != nil && s.Goal != "" {
		b.WriteString("## PROJECT GOAL\n")
		b.WriteString(s.Goal + "\n\n")
	}

	// Completed tasks
	if s != nil && s.Plan != nil {
		doneTasks := make([]*pm.Task, 0)
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				doneTasks = append(doneTasks, t)
			}
		}
		if len(doneTasks) > 0 {
			b.WriteString("## COMPLETED TASKS IN THIS RELEASE\n")
			for _, t := range doneTasks {
				b.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
				if t.Description != "" {
					b.WriteString(fmt.Sprintf("  %s\n", t.Description))
				}
			}
			b.WriteString("\n")
		}
	}

	// Git log
	if gitLog != "" {
		b.WriteString("## GIT LOG SINCE PREVIOUS TAG\n")
		if len(gitLog) > 3000 {
			gitLog = gitLog[:3000] + "\n…(truncated)"
		}
		b.WriteString(gitLog + "\n\n")
	}

	// Changelog output from previous step
	if changelogMD != "" {
		b.WriteString("## CHANGELOG DRAFT (use as input, not verbatim output)\n")
		if len(changelogMD) > 4000 {
			changelogMD = changelogMD[:4000] + "\n…(truncated)"
		}
		b.WriteString(changelogMD + "\n\n")
	}

	// Instructions
	b.WriteString("## YOUR TASK\n")
	b.WriteString("Write polished release notes for this release.\n\n")
	b.WriteString("Structure the output as follows:\n\n")
	b.WriteString("```\n")
	b.WriteString(fmt.Sprintf("## %s — YYYY-MM-DD\n\n", tag))
	b.WriteString("One-paragraph narrative summary of what this release delivers and why it matters.\n\n")
	b.WriteString("### Highlights\n")
	b.WriteString("- Key user-facing improvement 1\n")
	b.WriteString("- Key user-facing improvement 2\n\n")
	b.WriteString("### Changes\n\n")
	b.WriteString("#### Added\n- ...\n\n")
	b.WriteString("#### Changed\n- ...\n\n")
	b.WriteString("#### Fixed\n- ...\n\n")
	b.WriteString("### Upgrade Notes\n")
	b.WriteString("Any migration steps required. Omit section if none.\n")
	b.WriteString("```\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Write from the user/developer perspective — describe impact, not implementation\n")
	b.WriteString("- Keep bullet points concise (one sentence each)\n")
	b.WriteString("- Omit empty sections\n")
	b.WriteString("- Output ONLY the markdown — no preamble, no code fences around the whole document\n")
	b.WriteString("- Start directly with the `## " + tag + "` heading\n")

	return b.String()
}

// gitRun executes a git command in workDir and returns stdout+stderr output.
func gitRun(workDir string, args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", strings.Join(args[1:], " "), err)
	}
	return string(out), nil
}
