package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/stt"
	"github.com/blechschmidt/cloop/pkg/voice"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	listenFile         string
	listenSTTProvider  string
	listenWhisperModel string
	listenGroqAPIKey   string
	listenProvider     string
	listenModel        string
	listenDryRun       bool
	listenTimeout      string
)

var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Voice/NLP task input — transcribe audio and execute natural language commands",
	Long: `Accept audio input, transcribe it via Whisper or Groq STT, parse the intent
with an AI provider, and execute the resulting cloop command.

Audio sources (in order of precedence):
  --file <path>           read from an audio file (mp3/wav/ogg/flac/m4a)
  stdin pipe              cat recording.ogg | cloop listen

STT backends:
  --stt-provider whisper  local openai-whisper CLI (default); falls back to Groq if key present
  --stt-provider groq     Groq Whisper API (requires --groq-api-key or GROQ_API_KEY env var)

Examples:
  cloop listen --file meeting.mp3
  cloop listen --file cmd.ogg --stt-provider groq --groq-api-key gsk_...
  cloop listen --file note.wav --dry-run
  cat recording.ogg | cloop listen
  cloop listen --whisper-model small --file long_recording.mp3`,
	RunE: runListen,
}

// voiceCmd is an alias for listenCmd.
var voiceCmd = &cobra.Command{
	Use:   "voice",
	Short: "Alias for 'listen' — voice/NLP task input",
	Long:  listenCmd.Long,
	RunE:  runListen,
}

func runListen(cmd *cobra.Command, args []string) error {
	headerColor := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)
	boldColor := color.New(color.Bold)
	successColor := color.New(color.FgGreen)
	warnColor := color.New(color.FgYellow)

	headerColor.Printf("\ncloop listen — voice/NLP task input\n\n")

	// ── 1. Collect audio ─────────────────────────────────────────────────────
	var audioPath string
	var tmpCleanup func()

	if listenFile != "" {
		audioPath = listenFile
	} else {
		// Try to read from stdin.
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return fmt.Errorf("no audio source: provide --file <path> or pipe audio via stdin\n  e.g. cat recording.ogg | cloop listen")
		}
		dimColor.Printf("Reading audio from stdin...\n")
		tmp, err := os.CreateTemp("", "cloop-voice-*.ogg")
		if err != nil {
			return fmt.Errorf("create tmpfile: %w", err)
		}
		audioPath = tmp.Name()
		tmpCleanup = func() { os.Remove(tmp.Name()) }
		if _, err := io.Copy(tmp, os.Stdin); err != nil {
			tmp.Close()
			return fmt.Errorf("read stdin: %w", err)
		}
		tmp.Close()
	}
	if tmpCleanup != nil {
		defer tmpCleanup()
	}

	dimColor.Printf("  Audio : %s\n", audioPath)

	// ── 2. Transcribe ────────────────────────────────────────────────────────
	sttCfg := stt.Config{
		Provider:     stt.Provider(listenSTTProvider),
		WhisperModel: listenWhisperModel,
		GroqAPIKey:   listenGroqAPIKey,
	}
	if sttCfg.GroqAPIKey == "" {
		sttCfg.GroqAPIKey = os.Getenv("GROQ_API_KEY")
	}

	dimColor.Printf("  STT   : %s (model: %s)\n\n", sttOrDefault(sttCfg.Provider), whisperModelOrDefault(sttCfg.WhisperModel))
	dimColor.Printf("Transcribing...\n")

	transcription, err := stt.Transcribe(audioPath, sttCfg)
	if err != nil {
		return fmt.Errorf("transcription failed: %w", err)
	}
	if transcription == "" {
		return fmt.Errorf("transcription returned empty text")
	}

	boldColor.Printf("\nTranscription:\n")
	fmt.Printf("  %q\n\n", transcription)

	// ── 3. Load config and build AI provider ─────────────────────────────────
	workdir, _ := os.Getwd()
	cfg, err := config.Load(workdir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	applyEnvOverrides(cfg)

	s, _ := state.Load(workdir)

	pName := listenProvider
	if pName == "" {
		pName = cfg.Provider
	}
	if pName == "" && s != nil && s.Provider != "" {
		pName = s.Provider
	}
	if pName == "" {
		pName = autoSelectProvider()
	}

	mdl := listenModel
	if mdl == "" {
		switch pName {
		case "anthropic":
			mdl = cfg.Anthropic.Model
		case "openai":
			mdl = cfg.OpenAI.Model
		case "ollama":
			mdl = cfg.Ollama.Model
		case "claudecode":
			mdl = cfg.ClaudeCode.Model
		}
	}
	if mdl == "" && s != nil {
		mdl = s.Model
	}

	timeout := 30 * time.Second
	if listenTimeout != "" {
		timeout, err = time.ParseDuration(listenTimeout)
		if err != nil {
			return fmt.Errorf("invalid --timeout: %w", err)
		}
	}

	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	prov, err := provider.Build(provCfg)
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}

	dimColor.Printf("Parsing intent with %s...\n", prov.Name())

	// ── 4. Parse intent ───────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	intent, err := voice.Parse(ctx, prov, mdl, transcription)
	if err != nil {
		return fmt.Errorf("intent parsing: %w", err)
	}

	boldColor.Printf("\nDetected intent: %s\n", intent.Action)
	if intent.Explanation != "" {
		dimColor.Printf("  %s\n", intent.Explanation)
	}

	if len(intent.CloopArgs) == 0 || intent.Action == voice.ActionUnknown {
		warnColor.Printf("\nCould not map to a cloop command. Raw transcription: %q\n", transcription)
		warnColor.Printf("Try: cloop do %q\n", transcription)
		return nil
	}

	resolvedStr := "cloop " + strings.Join(intent.CloopArgs, " ")
	boldColor.Printf("\nResolved command: %s\n\n", resolvedStr)

	if listenDryRun {
		dimColor.Printf("(dry-run — not executing)\n")
		return nil
	}

	// ── 5. Execute ────────────────────────────────────────────────────────────
	dimColor.Printf("Executing...\n\n")

	rootCmd.SetArgs(intent.CloopArgs)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("execute %s: %w", resolvedStr, err)
	}

	successColor.Printf("\nDone.\n")
	return nil
}

func sttOrDefault(p stt.Provider) string {
	if p == "" {
		return string(stt.ProviderWhisper)
	}
	return string(p)
}

func whisperModelOrDefault(m string) string {
	if m == "" {
		return "base"
	}
	return m
}

func init() {
	listenCmd.Flags().StringVar(&listenFile, "file", "", "Audio file to transcribe (mp3/wav/ogg/flac/m4a)")
	listenCmd.Flags().StringVar(&listenSTTProvider, "stt-provider", "", "STT backend: whisper (default) or groq")
	listenCmd.Flags().StringVar(&listenWhisperModel, "whisper-model", "", "Whisper model size: base (default), small, medium, large")
	listenCmd.Flags().StringVar(&listenGroqAPIKey, "groq-api-key", "", "Groq API key for STT (or set GROQ_API_KEY env var)")
	listenCmd.Flags().StringVar(&listenProvider, "provider", "", "AI provider for intent parsing (anthropic, openai, ollama, claudecode)")
	listenCmd.Flags().StringVar(&listenModel, "model", "", "Model override for intent parsing")
	listenCmd.Flags().StringVar(&listenTimeout, "timeout", "30s", "Timeout for AI intent parsing")
	listenCmd.Flags().BoolVar(&listenDryRun, "dry-run", false, "Print the resolved command without executing it")

	// voiceCmd shares the same flags.
	voiceCmd.Flags().StringVar(&listenFile, "file", "", "Audio file to transcribe (mp3/wav/ogg/flac/m4a)")
	voiceCmd.Flags().StringVar(&listenSTTProvider, "stt-provider", "", "STT backend: whisper (default) or groq")
	voiceCmd.Flags().StringVar(&listenWhisperModel, "whisper-model", "", "Whisper model size: base (default), small, medium, large")
	voiceCmd.Flags().StringVar(&listenGroqAPIKey, "groq-api-key", "", "Groq API key for STT (or set GROQ_API_KEY env var)")
	voiceCmd.Flags().StringVar(&listenProvider, "provider", "", "AI provider for intent parsing (anthropic, openai, ollama, claudecode)")
	voiceCmd.Flags().StringVar(&listenModel, "model", "", "Model override for intent parsing")
	voiceCmd.Flags().StringVar(&listenTimeout, "timeout", "30s", "Timeout for AI intent parsing")
	voiceCmd.Flags().BoolVar(&listenDryRun, "dry-run", false, "Print the resolved command without executing it")

	rootCmd.AddCommand(listenCmd)
	rootCmd.AddCommand(voiceCmd)
}
