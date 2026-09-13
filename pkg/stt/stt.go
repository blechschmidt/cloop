// Package stt provides speech-to-text transcription.
//
// The hosted request is the one the Lisa project sends, which is where this
// method comes from (Task 20238): a mono upload to the OpenAI-compatible
// /audio/transcriptions endpoint on Groq, model whisper-large-v3-turbo,
// response_format verbose_json, temperature pinned to 0 so the same utterance
// transcribes the same way twice, plus an optional language hint and decoder
// prompt. "turbo" is the distilled decoder: Lisa picked it because someone
// dictating a sentence wants the answer in about the time the local `base`
// model takes just to load its weights.
//
// # Two entry points, deliberately
//
// TranscribeHosted uploads and nothing else. TranscribeContext prefers the
// local openai-whisper CLI and only uploads when a key is configured and the
// local run failed.
//
// The split is not a convenience. The hub must never cause a program to run on
// the control-plane host, so it calls TranscribeHosted, which cannot reach the
// CLI — tests/security proves that by walking the call graph. And the CLI runs
// local-first because the alternative is that audio starts leaving a
// developer's machine the day an unrelated GROQ_API_KEY appears in their
// environment. Neither default is about speed.
package stt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const (
	// maxTranscriptionBytes caps the Groq transcription response body. Groq's
	// JSON envelope wraps the transcript text plus a few metadata fields; even
	// a multi-hour audio transcript fits in a few MB. 16 MiB is generous while
	// still bounding memory if the API ever streams something pathological.
	maxTranscriptionBytes int64 = 16 << 20

	// DefaultGroqModel is the model Lisa transcribes with. "turbo" is the
	// distilled decoder: same encoder as whisper-large-v3, a fraction of the
	// latency, and the accuracy difference does not show up on the one or two
	// spoken sentences a task title is made of.
	DefaultGroqModel = "whisper-large-v3-turbo"

	// DefaultEndpoint is Groq's OpenAI-compatible transcription route.
	DefaultEndpoint = "https://api.groq.com/openai/v1/audio/transcriptions"

	// responseFormat asks for segments alongside the text. The extra fields
	// are what let a caller tell "the wearer said nothing" from "the wearer
	// said something short" — see Result.Silent.
	responseFormat = "verbose_json"

	// defaultTimeout bounds one transcription. Dictating a task title is a
	// few seconds of audio; anything past this is a network problem, and the
	// caller is a person holding a button waiting for a reply.
	defaultTimeout = 60 * time.Second
)

// Provider selects the STT backend.
type Provider string

const (
	ProviderWhisper Provider = "whisper"
	ProviderGroq    Provider = "groq"
)

// Config holds speech-to-text configuration.
type Config struct {
	// Provider: "whisper" (local CLI, the default) or "groq" (hosted). An
	// empty value means whisper — never "groq because a key exists", which
	// would make an unrelated environment variable start uploading audio.
	// Ignored entirely by TranscribeHosted, which is always hosted.
	Provider Provider

	// Model overrides the hosted model. Defaults to DefaultGroqModel.
	Model string

	// Endpoint overrides the hosted transcription URL, for an
	// OpenAI-compatible server that is not Groq.
	Endpoint string

	// GroqAPIKey authenticates the hosted backend. Falls back to the
	// GROQ_API_KEY environment variable.
	GroqAPIKey string

	// Language is an ISO-639-1 hint ("en", "de"). Empty lets Whisper detect
	// it, which is the right default for a hub whose users may not share one.
	Language string

	// Prompt biases the decoder — Whisper's prompt field, bounded by the
	// endpoint at 224 tokens. Used to spell project and tool names the model
	// would otherwise transcribe phonetically.
	Prompt string

	// WhisperModel selects the local CLI model: "base", "small", "medium",
	// "large". Defaults to "base".
	WhisperModel string

	// Timeout bounds one hosted request. Zero means defaultTimeout.
	Timeout time.Duration
}

// Result is one transcription.
type Result struct {
	Text     string  `json:"text"`
	Language string  `json:"language,omitempty"`
	Duration float64 `json:"duration,omitempty"`
	// Backend names which path produced this, so a caller can tell the user
	// whether they are paying Groq or burning local CPU.
	Backend Provider `json:"backend,omitempty"`
}

// Silent reports whether the transcript carries no actual words.
//
// Whisper never returns "nothing". Handed a room tone, a cough, or a button
// pressed and released, it answers with an empty string, a lone "." or a
// stray "you" — its hallucination on silence. A caller that turned any of
// those into a task would leave someone a row to find and delete, so the
// check is for letters or digits rather than for a non-empty string.
func (r Result) Silent() bool {
	for _, c := range r.Text {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

// groqTranscription mirrors the verbose_json response.
type groqTranscription struct {
	Text     string  `json:"text"`
	Language string  `json:"language"`
	Duration float64 `json:"duration"`
}

// Transcribe reads audio from audioPath and returns the transcribed text.
//
// Retained for callers that only want the string (cmd/listen.go). New code
// should prefer TranscribeContext, which is cancellable and reports which
// backend answered.
func Transcribe(audioPath string, cfg Config) (string, error) {
	res, err := TranscribeContext(context.Background(), audioPath, cfg)
	return res.Text, err
}

// TranscribeHosted transcribes using the hosted endpoint only, never the local
// CLI. It is the entry point for anything serving an HTTP request.
//
// The distinction is structural, not a flag, and that is the point. cloop's
// hub is built on "an HTTP request never causes a program to run on the
// control-plane host" — tests/security walks the call graph from every handler
// to (*exec.Cmd).Run and fails the build when one connects. A runtime switch
// would not satisfy that check and, more to the point, would not satisfy the
// guarantee: the local backend is a Python process, started per request, fed
// audio supplied by the caller, running unsandboxed beside the control plane.
//
// So the two paths are two functions. The CLI, which runs on a developer's own
// machine where there is no such promise to keep, keeps the fallback through
// TranscribeContext; the hub cannot reach it from here.
func TranscribeHosted(ctx context.Context, audioPath string, cfg Config) (Result, error) {
	return transcribeGroq(ctx, audioPath, cfg.withDefaults())
}

// HostedAvailable reports whether the hosted backend is configured, and says
// what is missing when it is not. It is the gate for callers that may not use
// the local CLI — see TranscribeHosted.
func HostedAvailable(cfg Config) (bool, string) {
	if cfg.withDefaults().GroqAPIKey != "" {
		return true, ""
	}
	return false, "speech-to-text is not configured: set stt.groq_api_key (or the GROQ_API_KEY " +
		"environment variable). The hub uses hosted Whisper only — the local openai-whisper CLI " +
		"is available to 'cloop listen' but never to an HTTP request, because the hub does not " +
		"run programs on the control-plane host"
}

// TranscribeContext transcribes audioPath, honouring ctx for cancellation.
//
// audioPath must be a file on disk; the caller owns any temp cleanup.
func TranscribeContext(ctx context.Context, audioPath string, cfg Config) (Result, error) {
	cfg = cfg.withDefaults()

	switch cfg.Provider {
	case ProviderGroq:
		// An explicitly chosen backend is authoritative. Someone who passes
		// --stt-provider groq usually does so *because* the local install is
		// broken or slow, and quietly spending four minutes of CPU producing a
		// worse transcript is not a kindness.
		return transcribeGroq(ctx, audioPath, cfg)
	default:
		// Local first, hosted as the fallback. The order matters for a reason
		// that outranks latency: the fallback uploads the audio to a third
		// party, and that must be something the user opted into — by setting a
		// key *and* not pinning the local backend — rather than something that
		// starts happening the day an unrelated GROQ_API_KEY lands in their
		// environment.
		res, err := transcribeWhisper(ctx, audioPath, cfg)
		if err == nil || ctx.Err() != nil || cfg.GroqAPIKey == "" {
			return res, err
		}
		hosted, herr := transcribeGroq(ctx, audioPath, cfg)
		if herr != nil {
			// Report the local failure first: it is the backend that was
			// asked for, and "whisper CLI not found" is the actionable half.
			return Result{}, fmt.Errorf("local whisper failed (%w); hosted fallback also failed: %v", err, herr)
		}
		return hosted, nil
	}
}

// withDefaults resolves the backend and fills in the unset fields.
func (c Config) withDefaults() Config {
	if c.GroqAPIKey == "" {
		c.GroqAPIKey = strings.TrimSpace(os.Getenv("GROQ_API_KEY"))
	}
	if c.Provider == "" {
		// Local, always — never "hosted because a key happens to exist".
		// Resolving by key presence would mean an unrelated GROQ_API_KEY in
		// the environment silently starts sending a user's audio off the
		// machine, while `cloop listen`'s banner still says whisper. The hub
		// does not rely on this: it calls TranscribeHosted, which never
		// consults Provider at all.
		c.Provider = ProviderWhisper
	}
	if c.Model == "" {
		c.Model = DefaultGroqModel
	}
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	if c.WhisperModel == "" {
		c.WhisperModel = "base"
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	return c
}

// transcribeWhisper calls the local openai-whisper CLI.
func transcribeWhisper(ctx context.Context, audioPath string, cfg Config) (Result, error) {
	if _, err := exec.LookPath("whisper"); err != nil {
		return Result{}, fmt.Errorf("whisper CLI not found: install with 'pip install openai-whisper'")
	}

	tmpDir, err := os.MkdirTemp("", "cloop-stt-*")
	if err != nil {
		return Result{}, fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{audioPath,
		"--model", cfg.WhisperModel,
		"--output_format", "txt",
		"--output_dir", tmpDir,
		"--fp16", "False",
	}
	if cfg.Language != "" {
		args = append(args, "--language", cfg.Language)
	}
	// CommandContext so a cancelled request does not leave a CPU-bound
	// transcription running for minutes after nobody is waiting for it.
	cmd := exec.CommandContext(ctx, "whisper", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("whisper cancelled: %w", ctx.Err())
		}
		return Result{}, fmt.Errorf("whisper: %w\n%s", err, stderr.String())
	}

	// Whisper writes <filename>.txt in the output dir.
	base := strings.TrimSuffix(filepath.Base(audioPath), filepath.Ext(audioPath))
	txtPath := filepath.Join(tmpDir, base+".txt")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		// Fallback: list files in tmpDir and read the first .txt
		entries, _ := os.ReadDir(tmpDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".txt") {
				data, err = os.ReadFile(filepath.Join(tmpDir, e.Name()))
				break
			}
		}
		if err != nil {
			return Result{}, fmt.Errorf("reading whisper output: %w", err)
		}
	}
	return Result{
		Text:     strings.TrimSpace(string(data)),
		Language: cfg.Language,
		Backend:  ProviderWhisper,
	}, nil
}

// transcribeGroq posts to the OpenAI-compatible transcription endpoint.
func transcribeGroq(ctx context.Context, audioPath string, cfg Config) (Result, error) {
	if cfg.GroqAPIKey == "" {
		return Result{}, fmt.Errorf("groq api key required: set stt.groq_api_key or the GROQ_API_KEY env var")
	}

	f, err := os.Open(audioPath)
	if err != nil {
		return Result{}, fmt.Errorf("open audio: %w", err)
	}
	defer f.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	// The field set Lisa sends. temperature is always written, including the
	// zero: 0 is greedy decoding, which is what makes a re-recording of the
	// same sentence transcribe identically.
	fields := [][2]string{
		{"model", cfg.Model},
		{"response_format", responseFormat},
		{"temperature", "0.00"},
	}
	if cfg.Language != "" {
		fields = append(fields, [2]string{"language", cfg.Language})
	}
	if cfg.Prompt != "" {
		fields = append(fields, [2]string{"prompt", cfg.Prompt})
	}
	for _, kv := range fields {
		if err := w.WriteField(kv[0], kv[1]); err != nil {
			return Result{}, fmt.Errorf("write field %s: %w", kv[0], err)
		}
	}

	// The filename extension is load-bearing: the endpoint infers the
	// container from it, so a name without one is rejected as unsupported.
	part, err := w.CreateFormFile("file", uploadName(audioPath))
	if err != nil {
		return Result{}, fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return Result{}, fmt.Errorf("copy audio: %w", err)
	}
	if err := w.Close(); err != nil {
		return Result{}, fmt.Errorf("finalize upload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.Endpoint, &body)
	if err != nil {
		return Result{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.GroqAPIKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("groq request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := provider.ReadResponseBody(resp.Body, maxTranscriptionBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read groq response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("groq transcription status %d: %s", resp.StatusCode, truncate(string(respBody), 400))
	}

	var out groqTranscription
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Result{}, fmt.Errorf("decode groq response: %w", err)
	}
	return Result{
		Text:     strings.TrimSpace(out.Text),
		Language: out.Language,
		Duration: out.Duration,
		Backend:  ProviderGroq,
	}, nil
}

// uploadName gives the upload a filename the endpoint can read a container
// from. A temp file without an extension would otherwise be rejected.
func uploadName(audioPath string) string {
	name := filepath.Base(audioPath)
	if filepath.Ext(name) == "" {
		return name + ".wav"
	}
	return name
}

// truncate bounds an error body so a provider that answers with an HTML error
// page does not paste a whole document into a log line.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Runes, not bytes: a byte-offset cut through a multi-byte character puts
	// a replacement glyph in the operator's log line.
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
