package ui

// Tests for the dictation credential in Settings (Task 20250).
//
// The load-bearing one is TestSTTSettings_KeyLandsWhereDictationReadsIt. Every
// other field in the Settings tab is written through /api/config/set, which
// saves to resolveWorkDir(r) — the selected project. Dictation reads the other
// way round: the dictate button and the glasses call /api/dictate and
// /api/transcribe with no project index, so sttConfig resolves entirely against
// s.WorkDir. Routing the key through the ordinary config endpoint would have
// produced a field that saves, reports success, and switches nothing on.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/stt"
)

// sttSettingsServer builds a two-project hub: WorkDir is the hub's own
// directory, and index 1 is a separate project the dashboard can select.
func sttSettingsServer(t *testing.T) (srv *Server, hub, project string) {
	t.Helper()
	hub, project = t.TempDir(), t.TempDir()
	return &Server{WorkDir: hub, Projects: []string{project}}, hub, project
}

// storedSTTKey reads the key straight out of a directory's config.yaml, so the
// assertions below check where the bytes actually landed rather than asking the
// same code path that wrote them.
func storedSTTKey(t *testing.T, dir string) string {
	t.Helper()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("load config from %s: %v", dir, err)
	}
	return cfg.STT.GroqAPIKey
}

// putSTTKey saves key, marshalling the body properly so a control character in
// key survives as a byte instead of being rejected as malformed JSON.
func putSTTKey(t *testing.T, srv *Server, target, key string) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(map[string]string{"groq_api_key": key})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, target, nil)
	req.Body = io.NopCloser(bytes.NewReader(blob))
	rec := httptest.NewRecorder()
	srv.handleSTTSettingsSave(rec, req)
	return rec
}

// TestSTTSettings_KeyLandsWhereDictationReadsIt is the property the feature
// exists for, and the bug it was written against: the key has to end up in the
// hub's config even when the caller has a project selected, because that is the
// only place dictation ever looks.
func TestSTTSettings_KeyLandsWhereDictationReadsIt(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, hub, project := sttSettingsServer(t)

	// ?project_idx=1 is the selected-project case that the ordinary config
	// endpoint would have filed the credential under.
	if rec := putSTTKey(t, srv, "/api/config/stt?project_idx=1", "gsk_hub_key"); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	if got := storedSTTKey(t, hub); got != "gsk_hub_key" {
		t.Errorf("hub config key = %q, want gsk_hub_key — dictation reads here", got)
	}
	if got := storedSTTKey(t, project); got != "" {
		t.Errorf("key leaked into the selected project's config (%q); dictation never reads there", got)
	}

	// And the capability it exists to switch on is actually on, asked exactly
	// the way the dictate button asks it: no project index.
	req := httptest.NewRequest(http.MethodGet, "/api/dictate", nil)
	if ok, reason := stt.HostedAvailable(srv.sttConfig(req)); !ok {
		t.Errorf("dictation still unavailable after saving a key: %s", reason)
	}
}

// TestSTTSettings_NeverReturnsTheKey guards both directions of the round trip:
// a settings page that echoes the credential back turns every reader of the tab
// into a holder of it, and a password field that refills itself is how a secret
// reaches a browser cache or a screenshot.
func TestSTTSettings_NeverReturnsTheKey(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, _, _ := sttSettingsServer(t)
	const secret = "gsk_super_secret_value"

	saveRec := putSTTKey(t, srv, "/api/config/stt", secret)
	getRec := httptest.NewRecorder()
	srv.handleSTTSettings(getRec, httptest.NewRequest(http.MethodGet, "/api/config/stt", nil))

	for name, body := range map[string]string{
		"PUT response": saveRec.Body.String(),
		"GET response": getRec.Body.String(),
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s contains the API key: %s", name, body)
		}
		if !strings.Contains(body, `"has_key":true`) {
			t.Errorf("%s should report has_key=true, got: %s", name, body)
		}
	}
}

// TestSTTSettings_RejectsUnusableKeys covers what would otherwise store happily
// and then fail every transcription: the key goes into an Authorization header,
// and Go's HTTP client refuses to send one containing a control byte. Caught
// here, the message names the stray newline; caught there, it names the request.
func TestSTTSettings_RejectsUnusableKeys(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, hub, _ := sttSettingsServer(t)

	for name, key := range map[string]string{
		"embedded newline": "gsk_abc\ndef",
		"carriage return":  "gsk_abc\rdef",
		"NUL byte":         "gsk_abc\x00def",
		"tab":              "gsk_abc\tdef",
		"blank":            "   ",
		"over length":      strings.Repeat("k", maxSTTKeyBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			rec := putSTTKey(t, srv, "/api/config/stt", key)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("PUT = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if got := storedSTTKey(t, hub); got != "" {
				t.Errorf("a rejected key was stored anyway: %q", got)
			}
		})
	}
}

// TestSTTSettings_ClearRemovesTheKey checks the half with no equivalent
// anywhere in the old UI: saveConfigField skips empty values, so without a
// distinct route a key could be set from the browser and never unset from it.
func TestSTTSettings_ClearRemovesTheKey(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, hub, _ := sttSettingsServer(t)
	if rec := putSTTKey(t, srv, "/api/config/stt", "gsk_to_be_removed"); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	srv.handleSTTSettingsClear(rec, httptest.NewRequest(http.MethodDelete, "/api/config/stt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := storedSTTKey(t, hub); got != "" {
		t.Errorf("key survived the clear: %q", got)
	}
	if !strings.Contains(rec.Body.String(), `"has_key":false`) {
		t.Errorf("clear should report has_key=false, got: %s", rec.Body.String())
	}
}

// TestSTTSettings_PreservesTheRestOfTheConfig is the read-modify-write check:
// the credential shares config.yaml with every other setting the hub has, and
// saving it must not be a way to lose one.
func TestSTTSettings_PreservesTheRestOfTheConfig(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, hub, _ := sttSettingsServer(t)

	cfg, err := config.Load(hub)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.Provider = "openai"
	cfg.OpenAI.APIKey = "sk-unrelated"
	cfg.STT.Language = "de"
	if err := config.Save(hub, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	if rec := putSTTKey(t, srv, "/api/config/stt", "gsk_new"); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	after, err := config.Load(hub)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Provider != "openai" || after.OpenAI.APIKey != "sk-unrelated" {
		t.Errorf("saving the dictation key disturbed the provider config: %+v", after.Provider)
	}
	if after.STT.Language != "de" {
		t.Errorf("sibling STT field was clobbered: language = %q, want de", after.STT.Language)
	}
	if after.STT.GroqAPIKey != "gsk_new" {
		t.Errorf("key = %q, want gsk_new", after.STT.GroqAPIKey)
	}
}

// TestSTTSettings_RedactsCredentialsInTheEndpoint covers the one field in this
// response a secret can ride in. stt.endpoint is operator-set and may point at
// any OpenAI-compatible server, some of which take the credential in the URL —
// and this response is readable by anyone with project read, a wider audience
// than holds the key.
func TestSTTSettings_RedactsCredentialsInTheEndpoint(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, hub, _ := sttSettingsServer(t)

	cfg, err := config.Load(hub)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.STT.Endpoint = "https://svc:hunter2@whisper.internal/v1/audio/transcriptions"
	if err := config.Save(hub, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	got := srv.hubSTTSettings()
	if strings.Contains(got.Endpoint, "hunter2") {
		t.Errorf("endpoint leaks its password: %s", got.Endpoint)
	}
	if !strings.Contains(got.Endpoint, "whisper.internal") {
		t.Errorf("redaction destroyed the useful part of the endpoint: %s", got.Endpoint)
	}

	// A plain endpoint must survive untouched — redaction that rewrites every
	// URL would quietly change what the panel claims the hub talks to.
	cfg.STT.Endpoint = "https://whisper.internal/v1/audio/transcriptions"
	if err := config.Save(hub, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := srv.hubSTTSettings(); got.Endpoint != cfg.STT.Endpoint {
		t.Errorf("endpoint = %q, want it unchanged at %q", got.Endpoint, cfg.STT.Endpoint)
	}
}

// TestSTTSettings_DistinguishesEnvFromStored keeps the Clear button honest: a
// key supplied by GROQ_API_KEY belongs to the environment, and offering to
// remove it would be a button that silently does nothing.
func TestSTTSettings_DistinguishesEnvFromStored(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "gsk_from_environment")
	srv, _, _ := sttSettingsServer(t)

	got := srv.hubSTTSettings()
	if !got.HasKey || !got.FromEnv || got.Stored {
		t.Errorf("with only an env key: %+v, want has_key+from_env with stored=false", got)
	}

	// A stored key takes precedence, and now there is something to clear.
	if rec := putSTTKey(t, srv, "/api/config/stt", "gsk_stored"); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if got := srv.hubSTTSettings(); !got.Stored || got.FromEnv {
		t.Errorf("after storing a key: %+v, want stored=true with from_env=false", got)
	}
}
