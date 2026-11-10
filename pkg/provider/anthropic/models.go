package anthropic

import (
	"strconv"
	"strings"
)

// The Messages API's request rules changed across Claude generations, and a
// request that breaks them is a 400 on every call:
//
//   - From the 4.6 models on, thinking is turned on with {type: "adaptive"}.
//     Claude Opus 4.6 and Claude Sonnet 4.6 still take the old
//     {type: "enabled", budget_tokens: N} but deprecate it. Every later model,
//     Fable, Mythos and Claude Haiku 5.5 included, refuses it.
//   - From Claude Opus 4.7 on, temperature and top_p are refused (Claude
//     Sonnet 5.5 and Claude Haiku 5.5 refuse any value but the default). Fable
//     and Mythos refuse them in every version.
//
// The rules go by generation so a model released after this list was written
// (a Fable 5.3, an Opus 6) gets the newer rules without a code change. A model
// ID that does not parse as claude-<line>-<major>[-<minor>] (the Claude 3 IDs,
// a gateway's own model names) keeps the older behaviour.

// claudeGeneration parses a model ID of the form
// claude-<line>-<major>[-<minor>][-<yyyymmdd>] into its line and version.
// A Claude Code "[1m]" suffix, a Bedrock "anthropic." prefix and a Vertex
// "@<date>" suffix are ignored. ok is false for any other shape.
func claudeGeneration(model string) (line string, major, minor int, ok bool) {
	id := strings.ToLower(strings.TrimSpace(model))
	id = strings.TrimPrefix(id, "anthropic.")
	if i := strings.IndexAny(id, "[@"); i >= 0 {
		id = id[:i]
	}
	parts := strings.Split(id, "-")
	if len(parts) < 3 || parts[0] != "claude" || !isLetters(parts[1]) {
		return "", 0, 0, false
	}
	major, ok = versionNumber(parts[2])
	if !ok {
		return "", 0, 0, false
	}
	if len(parts) > 3 {
		// An eight-digit part is a snapshot date (claude-sonnet-4-20250514),
		// not a minor version.
		if n, isNum := versionNumber(parts[3]); isNum {
			minor = n
		}
	}
	return parts[1], major, minor, true
}

// versionNumber parses a one- or two-digit version component.
func versionNumber(s string) (int, bool) {
	if len(s) == 0 || len(s) > 2 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func isLetters(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// alwaysModern reports whether a line has followed the newer request rules
// from its first release.
func alwaysModern(line string) bool {
	return line == "fable" || line == "mythos"
}

// adaptiveThinking reports whether a model turns thinking on with
// {type: "adaptive"} instead of a budget_tokens block.
func adaptiveThinking(model string) bool {
	line, major, minor, ok := claudeGeneration(model)
	if !ok {
		return false
	}
	return alwaysModern(line) || major > 4 || (major == 4 && minor >= 6)
}

// acceptsSampling reports whether a model accepts temperature and top_p.
func acceptsSampling(model string) bool {
	line, major, minor, ok := claudeGeneration(model)
	if !ok {
		return true
	}
	if alwaysModern(line) {
		return false
	}
	return major < 4 || (major == 4 && minor <= 6)
}
