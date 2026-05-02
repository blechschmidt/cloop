// Package stt provides speech-to-text transcription via Whisper (local) or Groq API.
package stt

import (
	"bytes"
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
)

// Provider selects the STT backend.
type Provider string

const (
	ProviderWhisper Provider = "whisper"
	ProviderGroq    Provider = "groq"
)

// Config holds speech-to-text configuration.
type Config struct {
	// Provider: "whisper" (local) or "groq" (API). Defaults to "whisper".
	Provider Provider

	// WhisperModel: "base", "small", "medium", "large". Defaults to "base".
	WhisperModel string

	// GroqAPIKey is required when Provider == "groq".
	// Falls back to GROQ_API_KEY env var.
	GroqAPIKey string
}

// groqTranscription mirrors the Groq /audio/transcriptions response.
type groqTranscription struct {
	Text string `json:"text"`
}

// Transcribe reads audio from audioPath and returns the transcribed text.
// audioPath must be a file on disk; the caller is responsible for any tmp cleanup.
func Transcribe(audioPath string, cfg Config) (string, error) {
	// Apply defaults.
	if cfg.Provider == "" {
		cfg.Provider = ProviderWhisper
	}
	if cfg.WhisperModel == "" {
		cfg.WhisperModel = "base"
	}
	if cfg.GroqAPIKey == "" {
		cfg.GroqAPIKey = os.Getenv("GROQ_API_KEY")
	}

	switch cfg.Provider {
	case ProviderGroq:
		return transcribeGroq(audioPath, cfg)
	default:
		// Whisper (local) with automatic fallback to Groq if whisper is unavailable.
		text, err := transcribeWhisper(audioPath, cfg)
		if err != nil && cfg.GroqAPIKey != "" {
			// fallback to Groq
			return transcribeGroq(audioPath, cfg)
		}
		return text, err
	}
}

// transcribeWhisper calls the local openai-whisper CLI.
func transcribeWhisper(audioPath string, cfg Config) (string, error) {
	// Check if whisper is available.
	_, err := exec.LookPath("whisper")
	if err != nil {
		return "", fmt.Errorf("whisper CLI not found: install with 'pip install openai-whisper'")
	}

	tmpDir, err := os.MkdirTemp("", "cloop-stt-*")
	if err != nil {
		return "", fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("whisper", audioPath,
		"--model", cfg.WhisperModel,
		"--output_format", "txt",
		"--output_dir", tmpDir,
		"--fp16", "False",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("whisper: %w\n%s", err, stderr.String())
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
			return "", fmt.Errorf("reading whisper output: %w", err)
		}
	}
	return strings.TrimSpace(string(data)), nil
}

// transcribeGroq calls the Groq STT API (OpenAI-compatible).
func transcribeGroq(audioPath string, cfg Config) (string, error) {
	if cfg.GroqAPIKey == "" {
		return "", fmt.Errorf("groq API key required: set --groq-api-key or GROQ_API_KEY env var")
	}

	f, err := os.Open(audioPath)
	if err != nil {
		return "", fmt.Errorf("open audio: %w", err)
	}
	defer f.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	// Model field.
	_ = w.WriteField("model", "whisper-large-v3")

	// File field.
	part, err := w.CreateFormFile("file", filepath.Base(audioPath))
	if err != nil {
		return "", fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", fmt.Errorf("copy audio: %w", err)
	}
	w.Close()

	req, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/audio/transcriptions", &body)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.GroqAPIKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("groq request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result groqTranscription
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode groq response: %w", err)
	}
	return strings.TrimSpace(result.Text), nil
}
