// harness.go resolves which agent CLI a project's workload will need, so that
// placement can refuse an executor that does not have it.
//
// The value travels on executor.Spec.Harness and is consumed by
// pkg/executor/remote's checkHarness, whose file comment carries the reasoning
// about why the device's inventory is the right thing to check in host mode and
// the wrong thing in container mode. What belongs *here* is only the mapping
// from a project to a binary name, and that mapping lives in the UI for a
// structural reason: the provider is a property of the project's config and
// state, neither of which pkg/executor may import — it is the layer both of
// them sit above.
package ui

import (
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/state"
)

// claudeHarnessBin is the program pkg/provider/claudecode execs.
//
// Duplicated as a constant rather than imported from a symbol there because no
// such symbol exists: that package resolves the name through exec.LookPath and
// a list of fallback paths, so the string is the contract and a lookup is the
// implementation. Naming it here keeps the one place that must agree with it
// greppable from the one place that defines it.
const claudeHarnessBin = "claude"

// projectHarness returns the agent CLI a run of workDir will invoke, or "" when
// it will invoke none.
//
// Empty is the answer for every HTTP-API provider — anthropic, openai, ollama,
// mock — and it is a real answer rather than a failure to determine one: those
// providers need no binary on the executing machine, so a device that has none
// can run them perfectly well. Returning a harness name for them would refuse
// executors that are in fact correct, which is the failure mode this whole
// change exists to avoid, pointed the other way.
//
// Unreadable config is also "": this function gates a dispatch, and a project
// whose config cannot be read has bigger problems that its own error path
// reports. Guessing "claude" from a read error would turn a transient
// filesystem fault into a placement refusal naming a harness nobody asked for.
func projectHarness(workDir string) string {
	return harnessForProvider(resolveProviderName(workDir))
}

// resolveProviderName applies the same precedence as buildProjectProvider:
// the project's config, then its persisted state, then the default.
//
// Kept in step with that function deliberately — if the two disagreed, the
// placement decision would be made about a provider other than the one the run
// goes on to use, and the refusal (or the absence of one) would be about the
// wrong binary.
func resolveProviderName(workDir string) string {
	if cfg, err := config.Load(workDir); err == nil {
		if name := strings.TrimSpace(cfg.Provider); name != "" {
			return name
		}
	}
	if st, err := state.LoadLite(workDir); err == nil && st != nil {
		if name := strings.TrimSpace(st.Provider); name != "" {
			return name
		}
	}
	return claudecode.ProviderName
}

// resolveProjectModel applies buildProjectProvider's model precedence for
// providerName: the per-provider model in the project's config, then the model
// in its state.
func resolveProjectModel(workDir, providerName string, st *state.ProjectState) string {
	if cfg, err := config.Load(workDir); err == nil {
		var m string
		switch providerName {
		case "anthropic":
			m = cfg.Anthropic.Model
		case "openai":
			m = cfg.OpenAI.Model
		case "ollama":
			m = cfg.Ollama.Model
		case claudecode.ProviderName:
			m = cfg.ClaudeCode.Model
		}
		if m = strings.TrimSpace(m); m != "" {
			return m
		}
	}
	if st != nil {
		return st.Model
	}
	return ""
}

// harnessForProvider maps a provider name to the CLI it drives.
//
// A switch with one case, on purpose. claudecode is the only provider in the
// tree that execs anything — the others open an HTTP connection — and writing
// it as a lookup makes the next CLI-backed provider a one-line addition at the
// place that already has to be found, instead of an `if name == "claudecode"`
// somewhere in the dispatch path that nobody thinks to revisit.
func harnessForProvider(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case claudecode.ProviderName:
		return claudeHarnessBin
	default:
		return ""
	}
}
