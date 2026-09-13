package stt

// Tests for speech-to-text (Task 20238).
//
// The point of most of these is that the request on the wire is the one the
// Lisa project sends. "Use the same method as Lisa" is only a real constraint
// if something checks the fields, because every one of them is a silent
// degradation when wrong: the plain whisper-large-v3 model is several times
// slower for the one spoken sentence a task title is made of, a missing
// response_format changes the body shape, and a non-zero temperature makes the
// same utterance transcribe differently on a retry.

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// capture is the parsed multipart request a fake endpoint received.
type capture struct {
	fields   map[string]string
	filename string
	audio    []byte
	auth     string
}

// fakeGroq stands in for the transcription endpoint and records what it got.
func fakeGroq(t *testing.T, reply string, status int) (*httptest.Server, *capture) {
	t.Helper()
	got := &capture{fields: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("bad content type: %v", err)
			w.WriteHeader(500)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("read part: %v", err)
				break
			}
			body, _ := io.ReadAll(part)
			if part.FormName() == "file" {
				got.filename = part.FileName()
				got.audio = body
			} else {
				got.fields[part.FormName()] = string(body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func tempAudio(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("fake-opus-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const verboseReply = `{"task":"transcribe","language":"English","duration":2.1,
	"text":" Add a retention policy to the audit trail.","segments":[{"id":0,"no_speech_prob":0.01}]}`

// TestGroqRequestMatchesLisa pins every field of the upload.
func TestGroqRequestMatchesLisa(t *testing.T) {
	srv, got := fakeGroq(t, verboseReply, 200)

	res, err := TranscribeContext(context.Background(), tempAudio(t, "clip.webm"), Config{
		Provider:   ProviderGroq,
		Endpoint:   srv.URL,
		GroqAPIKey: "gsk_test",
		Language:   "en",
		Prompt:     "cloop, gVisor, kubeconfig",
	})
	if err != nil {
		t.Fatalf("TranscribeContext: %v", err)
	}

	want := map[string]string{
		"model":           "whisper-large-v3-turbo",
		"response_format": "verbose_json",
		"temperature":     "0.00",
		"language":        "en",
		"prompt":          "cloop, gVisor, kubeconfig",
	}
	for k, v := range want {
		if got.fields[k] != v {
			t.Errorf("field %q = %q, want %q", k, got.fields[k], v)
		}
	}
	if got.auth != "Bearer gsk_test" {
		t.Errorf("Authorization = %q, want a bearer token", got.auth)
	}
	if string(got.audio) != "fake-opus-bytes" {
		t.Errorf("audio not forwarded verbatim: %q", got.audio)
	}
	// The extension is load-bearing — the endpoint infers the container from
	// it and rejects an upload without one.
	if filepath.Ext(got.filename) != ".webm" {
		t.Errorf("upload filename %q lost its extension", got.filename)
	}

	if res.Text != "Add a retention policy to the audit trail." {
		t.Errorf("text = %q (leading space should be trimmed)", res.Text)
	}
	if res.Backend != ProviderGroq {
		t.Errorf("backend = %q, want groq", res.Backend)
	}
	if res.Language != "English" || res.Duration != 2.1 {
		t.Errorf("metadata lost: language=%q duration=%v", res.Language, res.Duration)
	}
}

// TestGroqOmitsUnsetHints: Lisa sends no language field at all rather than an
// empty one, because an empty string is not "detect it", it is an invalid
// language code.
func TestGroqOmitsUnsetHints(t *testing.T) {
	srv, got := fakeGroq(t, verboseReply, 200)
	if _, err := TranscribeContext(context.Background(), tempAudio(t, "c.webm"), Config{
		Provider: ProviderGroq, Endpoint: srv.URL, GroqAPIKey: "k",
	}); err != nil {
		t.Fatalf("TranscribeContext: %v", err)
	}
	for _, absent := range []string{"language", "prompt"} {
		if v, ok := got.fields[absent]; ok {
			t.Errorf("unset %q was sent as %q — it should be omitted entirely", absent, v)
		}
	}
	// temperature is the exception: always sent, including the zero.
	if got.fields["temperature"] != "0.00" {
		t.Errorf("temperature = %q, want it always written as 0.00", got.fields["temperature"])
	}
}

// TestSilentDetection is what stops a mis-tap becoming a task. Whisper never
// answers "nothing" — it answers with punctuation or a hallucinated filler.
func TestSilentDetection(t *testing.T) {
	for _, s := range []string{"", "   ", ".", " . ", "...", "!?", "\n\t", "—"} {
		if !(Result{Text: s}).Silent() {
			t.Errorf("Result{%q}.Silent() = false, want true", s)
		}
	}
	for _, s := range []string{"go", "fix CI", "task 3", "ok.", "3"} {
		if (Result{Text: s}).Silent() {
			t.Errorf("Result{%q}.Silent() = true, want false", s)
		}
	}
}

// TestEnvKeyDoesNotFlipTheCLIToHosted is a privacy regression test.
//
// `cloop listen` prints "STT: whisper" for an unset provider. If the presence
// of a GROQ_API_KEY — which a user may have exported for something else
// entirely — silently reselected the hosted backend, that banner would be a
// lie about the one thing that matters: whether the audio left the machine.
func TestEnvKeyDoesNotFlipTheCLIToHosted(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	if got := (Config{}).withDefaults().Provider; got != ProviderWhisper {
		t.Errorf("with no key, provider = %q, want whisper", got)
	}

	t.Setenv("GROQ_API_KEY", "gsk_from_env")
	resolved := (Config{}).withDefaults()
	if resolved.Provider != ProviderWhisper {
		t.Errorf("an env key flipped the default backend to %q — audio would start leaving the "+
			"machine while the CLI still reports whisper", resolved.Provider)
	}
	if resolved.GroqAPIKey != "gsk_from_env" {
		t.Errorf("env key not picked up for the fallback path: %q", resolved.GroqAPIKey)
	}
	if resolved.Model != DefaultGroqModel {
		t.Errorf("default model = %q, want %q", resolved.Model, DefaultGroqModel)
	}
}

// TestExplicitGroqIsAuthoritative: someone who pins the hosted backend usually
// does so because the local install is broken or slow. Falling back to it on a
// 429 spends minutes of CPU producing a worse transcript they did not ask for.
func TestExplicitGroqIsAuthoritative(t *testing.T) {
	srv, _ := fakeGroq(t, `{"error":"rate limited"}`, http.StatusTooManyRequests)
	_, err := TranscribeContext(context.Background(), tempAudio(t, "c.webm"), Config{
		Provider: ProviderGroq, Endpoint: srv.URL, GroqAPIKey: "k", Timeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected the 429 to surface")
	}
	if strings.Contains(err.Error(), "whisper") {
		t.Errorf("an explicit --stt-provider groq fell back to the local CLI: %v", err)
	}
}

// TestContextCancellationStopsTheRequest keeps a caller who navigated away
// from continuing to pay for a transcription nobody will read.
func TestContextCancellationStopsTheRequest(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	defer srv.Close()
	defer close(blocked)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	start := time.Now()
	_, err := transcribeGroq(ctx, tempAudio(t, "c.webm"), Config{
		Provider: ProviderGroq, Endpoint: srv.URL, GroqAPIKey: "k", Timeout: 30 * time.Second,
	}.withDefaults())
	if err == nil {
		t.Fatal("expected an error from a cancelled request")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancellation took %v — the context is not reaching the HTTP client", elapsed)
	}
}

func TestMalformedResponseIsReported(t *testing.T) {
	srv, _ := fakeGroq(t, `not json at all`, 200)
	_, err := transcribeGroq(context.Background(), tempAudio(t, "c.webm"), Config{
		Provider: ProviderGroq, Endpoint: srv.URL, GroqAPIKey: "k",
	}.withDefaults())
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("a malformed body should be reported as a decode failure, got: %v", err)
	}
}

// TestUploadNameAlwaysCarriesAContainer: a temp file without an extension
// would be rejected by the endpoint.
func TestUploadNameAlwaysCarriesAContainer(t *testing.T) {
	if got := uploadName("/tmp/cloop-dictate-123"); filepath.Ext(got) != ".wav" {
		t.Errorf("uploadName without an extension = %q, want a .wav default", got)
	}
	if got := uploadName("/tmp/x.ogg"); got != "x.ogg" {
		t.Errorf("uploadName(.ogg) = %q, want it preserved", got)
	}
}

// TestVerboseJSONShapeIsWhatWeParse guards the decoder against the real
// payload recorded from the live endpoint, so a schema change is a test
// failure rather than an empty task title.
func TestVerboseJSONShapeIsWhatWeParse(t *testing.T) {
	const live = `{"task":"transcribe","language":"English","duration":2,` +
		`"text":" Add a button.","segments":[{"id":0,"seek":0,"start":0,"end":2,` +
		`"text":" Add a button.","tokens":[50365],"temperature":0,"avg_logprob":-0.29,` +
		`"compression_ratio":0.2,"no_speech_prob":0}],"x_groq":{"id":"req_01"}}`
	var out groqTranscription
	if err := json.Unmarshal([]byte(live), &out); err != nil {
		t.Fatalf("cannot parse a real verbose_json body: %v", err)
	}
	if strings.TrimSpace(out.Text) != "Add a button." {
		t.Errorf("text = %q", out.Text)
	}
}

// TestTranscribeHostedNeverFallsBackLocally is the hub's half of the
// no-host-execution guarantee. tests/security proves the call graph cannot
// reach (*exec.Cmd).Run from an HTTP handler; this proves the behaviour that
// makes the split meaningful — with no key, the hosted entry point fails and
// says so, rather than quietly starting a local Python process.
func TestTranscribeHostedNeverFallsBackLocally(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")

	_, err := TranscribeHosted(context.Background(), tempAudio(t, "c.webm"), Config{})
	if err == nil {
		t.Fatal("TranscribeHosted with no key must fail, not fall back to the local CLI")
	}
	if !strings.Contains(err.Error(), "api key") {
		t.Errorf("error should name the missing key, got: %v", err)
	}

	// Even when explicitly pinned to whisper, the hosted entry point must not
	// honour it: the caller is an HTTP handler and has no business spawning.
	_, err = TranscribeHosted(context.Background(), tempAudio(t, "c.webm"), Config{
		Provider: ProviderWhisper, WhisperModel: "base",
	})
	if err == nil {
		t.Error("TranscribeHosted honoured Provider=whisper — the hub could be configured " +
			"into spawning a process on the control plane")
	}
}

func TestHostedAvailableExplainsTheHubRule(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	ok, reason := HostedAvailable(Config{})
	if ok {
		t.Fatal("HostedAvailable with no key = true")
	}
	for _, want := range []string{"stt.groq_api_key", "GROQ_API_KEY", "control-plane host"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason should mention %q so the operator understands both the fix and\n"+
				"why the local CLI is not used here; got: %s", want, reason)
		}
	}

	t.Setenv("GROQ_API_KEY", "gsk_x")
	if ok, _ := HostedAvailable(Config{}); !ok {
		t.Error("a configured key should make hosted transcription available")
	}
}
