package cmd

// Shared plumbing for the model calls the dashboard makes on a project's
// executor (Task 20442): the Split preview (`task decompose --dry-run --json`),
// dictation's Revise (`task revise`), the blocker analysis (`task ai-blocker
// --json`) and the plan assistant (`plan chat`). The hub dispatches them like
// any other workload — on the executor the project is bound to, with the
// caller's Claude account — and reads the framed result back (pkg/clijson).

import (
	"os"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// helperFailure is the framed payload a hub helper writes when the model call
// fails, so the hub can show the provider's own reason rather than whatever
// else shared the output stream.
type helperFailure struct {
	Error string `json:"error"`
}

// failFramed writes err as a framed failure on stdout and returns it, so the
// command still exits non-zero.
func failFramed(err error) error {
	_ = clijson.Emit(os.Stdout, helperFailure{Error: err.Error()})
	return err
}

// helperProvider builds the provider and model a hub helper calls for the
// project in workdir, resolved as `cloop suggest` resolves them: the flag,
// then config.yaml (and its CLOOP_* overrides), then the provider the project
// recorded, then whichever provider the environment can use; the model from
// the flag, the provider's section of config.yaml, then the project's.
func helperProvider(workdir string, s *state.ProjectState, flagProvider, flagModel string) (provider.Provider, string, error) {
	cfg, err := config.Load(workdir)
	if err != nil {
		return nil, "", err
	}
	applyEnvOverrides(cfg)

	name := flagProvider
	if name == "" {
		name = cfg.Provider
	}
	if name == "" && s != nil {
		name = s.Provider
	}
	if name == "" {
		name = autoSelectProvider()
	}

	model := flagModel
	if model == "" {
		switch name {
		case "anthropic":
			model = cfg.Anthropic.Model
		case "openai":
			model = cfg.OpenAI.Model
		case "ollama":
			model = cfg.Ollama.Model
		case "claudecode":
			model = cfg.ClaudeCode.Model
		}
	}
	if model == "" && s != nil {
		model = s.Model
	}

	prov, err := provider.Build(provider.ProviderConfig{
		Name:              name,
		AnthropicAPIKey:   cfg.Anthropic.APIKey,
		AnthropicBaseURL:  cfg.Anthropic.BaseURL,
		OpenAIAPIKey:      cfg.OpenAI.APIKey,
		OpenAIBaseURL:     cfg.OpenAI.BaseURL,
		OllamaBaseURL:     cfg.Ollama.BaseURL,
		MockResponsesFile: cfg.Mock.ResponsesFile,
	})
	if err != nil {
		return nil, "", err
	}
	return prov, model, nil
}
