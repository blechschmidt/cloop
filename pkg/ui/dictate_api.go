package ui

// Dictated tasks (Task 20238).
//
// One endpoint, POST /api/transcribe: audio in, text out. It deliberately does
// not create anything. Task creation stays on the routes that already do it,
// which is what keeps this a transcription service rather than a second,
// subtly different way to add a task.
//
// # Why not /api/voice
//
// /api/voice exists and does more: it shells out to `cloop listen`, which
// transcribes, then asks a provider to classify the sentence into one of a
// dozen intents, then executes the resolved CLI command. That is the right
// shape for "cloop, mark task 12 done" and the wrong shape for a button whose
// only job is to fill in a title. It costs a subprocess, a second model call,
// and several seconds; and its intent classifier can decide that a dictated
// task title was actually a request to start a run.
//
// A button labelled "dictate a task" should put the words the user said into
// the task field and nothing else. So this path is transcription only — no
// subprocess, no model call, no intent.
//
// # Who may call it
//
// task.mutate, not project.read. Transcription spends money on someone else's
// API key and is the first half of creating a task, so it is gated with the
// second half rather than with reading.
//
// # Hosted only
//
// This calls stt.TranscribeHosted, which cannot reach the local openai-whisper
// CLI. pkg/stt offers both, but the fallback spawns a Python process per
// request, fed caller-supplied audio, next to the control plane — which is the
// exact thing "the hub never executes on the host" forbids, and which
// tests/security enforces by walking the call graph from every handler to
// (*exec.Cmd).Run. Keeping the two behind different functions makes that a
// property of the code rather than of a policy flag someone can flip.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/stt"
)

const (
	// maxDictationBytes bounds the upload. A dictated task title is a few
	// seconds of Opus — tens of kilobytes — and the hosted endpoint refuses
	// anything over 25 MB anyway, so this is well clear of any legitimate
	// recording while stopping a held button from spooling a gigabyte to the
	// hub's disk.
	maxDictationBytes int64 = 25 << 20

	// dictationMemoryBytes is the in-memory slice of the multipart parse; the
	// remainder spills to a temp file, which is where it is going regardless.
	dictationMemoryBytes int64 = 1 << 20

	// dictationTimeout bounds the whole transcription. Someone is holding a
	// button waiting for this, so it is short: past this the answer is no
	// longer useful even if it arrives.
	dictationTimeout = 90 * time.Second
)

// dictationStatus tells a client whether the microphone button can work at
// all, so a UI can hide a control rather than offer one that fails after the
// user has already spoken a sentence into it.
type dictationStatus struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Backend   string `json:"backend,omitempty"`

	// CanAddTasks is this caller's own task.mutate standing, resolved the
	// same way the gate on POST /api/glasses/tasks will resolve it.
	//
	// It exists for the wearable, whose credential arrives in a URL it cannot
	// read the roles out of: a read-only link must not draw a dictate row that
	// a wearer can only discover is refused by pinching it. Answering here
	// means the page asks once instead of finding out per attempt.
	CanAddTasks bool `json:"can_add_tasks"`
}

// transcribeResponse is what the button gets back.
type transcribeResponse struct {
	OK       bool   `json:"ok"`
	Text     string `json:"text"`
	Backend  string `json:"backend,omitempty"`
	Language string `json:"language,omitempty"`
}

// sttConfig resolves the speech-to-text settings for a request.
//
// The project's own config wins, then the hub's, then the environment (inside
// pkg/stt). That order lets one key configured once at the hub serve every
// project, while still letting a project that needs a different language or a
// different endpoint say so locally.
func (s *Server) sttConfig(r *http.Request) stt.Config {
	// Hub first, project second, so the project overwrites field by field.
	return s.sttConfigFrom(s.WorkDir, s.resolveWorkDir(r))
}

// sttConfigFrom resolves settings by overlaying dirs in order, later winning.
//
// Split out of sttConfig so the settings panel can ask the narrower question
// "what does the hub itself have?" — which is the one that matters, because
// dictation is only ever called without a project index. See the settings
// section at the bottom of this file.
func (s *Server) sttConfigFrom(dirs ...string) stt.Config {
	merged := config.STTConfig{}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cfg, err := config.Load(dir)
		if err != nil || cfg == nil {
			continue
		}
		overlaySTT(&merged, cfg.STT)
	}
	return stt.Config{
		Provider:     stt.Provider(merged.Provider),
		GroqAPIKey:   merged.GroqAPIKey,
		Model:        merged.Model,
		Endpoint:     merged.Endpoint,
		Language:     merged.Language,
		WhisperModel: merged.WhisperModel,
		Timeout:      dictationTimeout,
	}
}

// overlaySTT copies the set fields of src over dst. Field-by-field rather than
// whole-struct, so a project that only sets a language keeps the hub's key.
func overlaySTT(dst *config.STTConfig, src config.STTConfig) {
	for _, f := range []struct {
		to   *string
		from string
	}{
		{&dst.Provider, src.Provider},
		{&dst.GroqAPIKey, src.GroqAPIKey},
		{&dst.Model, src.Model},
		{&dst.Endpoint, src.Endpoint},
		{&dst.Language, src.Language},
		{&dst.WhisperModel, src.WhisperModel},
	} {
		if v := strings.TrimSpace(f.from); v != "" {
			*f.to = v
		}
	}
}

// dictationStatusFor reports whether dictation can work for this caller.
func (s *Server) dictationStatusFor(r *http.Request) dictationStatus {
	// HostedAvailable, not Available: the hub may not use the local CLI, so
	// asking the general question would advertise a button this handler will
	// refuse. See stt.TranscribeHosted.
	ok, reason := stt.HostedAvailable(s.sttConfig(r))
	backend := ""
	if ok {
		backend = string(stt.ProviderGroq)
	}
	return dictationStatus{
		Available:   ok,
		Reason:      reason,
		Backend:     backend,
		CanAddTasks: s.grantFor(r).decide(s.projectScope(r)).Allows(authz.PermTaskMutate),
	}
}

// handleDictateStatus serves GET /api/dictate and GET /api/glasses/dictate.
func (s *Server) handleDictateStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.dictationStatusFor(r))
}

// handleTranscribe serves POST /api/transcribe and POST /api/glasses/transcribe.
//
// Both paths run the same code: the second exists only because a display
// glasses link is pinned to the /api/glasses/ prefix (see tokenKindAdmitted),
// not because the wearable needs different behaviour.
func (s *Server) handleTranscribe(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	// Refuse before reading the body at all when nothing can transcribe it.
	// The client hides the button in that case, but a direct caller deserves
	// the same sentence — and parsing first would let a hub that cannot
	// transcribe anything still be made to spill 25 MB per concurrent request
	// into the control plane's temp directory, since ParseMultipartForm caps
	// only the in-memory portion and writes the rest to disk.
	cfg := s.sttConfig(r)
	if ok, reason := stt.HostedAvailable(cfg); !ok {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, reason))
		return
	}

	// Bound the body before parsing, for the same reason.
	r.Body = http.MaxBytesReader(w, r.Body, maxDictationBytes)
	if err := r.ParseMultipartForm(dictationMemoryBytes); err != nil {
		respondToBodyError(w, err)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, fh, err := r.FormFile("audio")
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"an 'audio' file field is required"))
		return
	}
	defer file.Close()

	tmpPath, err := spoolUpload(file, fh.Filename)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	defer os.Remove(tmpPath)

	// Tie the transcription to the request: a caller who navigates away stops
	// paying for it, and a local whisper run is killed rather than left to
	// finish on a CPU nobody is waiting for.
	ctx, cancel := context.WithTimeout(r.Context(), dictationTimeout)
	defer cancel()

	res, err := stt.TranscribeHosted(ctx, tmpPath, cfg)
	if err != nil {
		if ctx.Err() != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
				"transcription timed out — try a shorter recording"))
			return
		}
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"transcription failed: "+err.Error()))
		return
	}
	if res.Silent() {
		// Whisper answers silence with "", "." or a hallucinated "you". Saying
		// so is the difference between a user pressing the button again and a
		// user wondering why their task is called ".".
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"no speech was recognised — check the microphone and try again"))
		return
	}

	jsonOK(w, transcribeResponse{
		OK:       true,
		Text:     res.Text,
		Backend:  string(res.Backend),
		Language: res.Language,
	})
}

// spoolUpload writes the uploaded audio to a temp file and returns its path.
//
// The client's filename reaches the temp pattern only as an extension, and
// only after being checked against a fixed list. The extension matters —
// the hosted endpoint infers the container from it — but a name is attacker
// controlled, so nothing else from it is used.
func spoolUpload(src io.Reader, clientName string) (string, error) {
	tmp, err := os.CreateTemp("", "cloop-dictate-*"+audioExt(clientName))
	if err != nil {
		return "", err
	}
	path := tmp.Name()
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		os.Remove(path)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// audioExt maps a client-supplied filename to a container extension the
// transcription endpoint accepts, defaulting to .webm — what every browser
// MediaRecorder this UI drives actually produces.
func audioExt(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".webm", ".ogg", ".oga", ".wav", ".mp3", ".m4a", ".mp4", ".flac", ".mpga":
		return ext
	}
	return ".webm"
}

// ── Settings: the dictation credential (Task 20250) ──────────────────────────
//
// Until now the key dictation runs on could only be set by editing config.yaml
// or running `cloop config set stt.groq_api_key` on the hub's own host — which
// the operator of a hosted hub may well not have a shell on. These three routes
// put it in the Settings panel.
//
// # Why this is not just another /api/config/set key
//
// /api/config/set is project-scoped: it writes to resolveWorkDir(r), the
// project the dashboard currently has selected. Dictation reads the other way
// round — the front end calls /api/dictate and /api/transcribe with no project
// index at all, so sttConfig resolves both overlays against s.WorkDir.
//
// Adding "stt.groq_api_key" to applyUIConfigKey would therefore have produced
// the worst kind of working feature: the field saves, the toast says so, the
// key lands in some project's config.yaml, and the button it was meant to turn
// on stays hidden forever because nothing reads it there. So the credential
// gets its own hub-scoped routes that write where dictation actually looks, and
// the Settings tab — which labels itself "global" — keeps that promise here.

// maxSTTKeyBytes bounds a pasted credential. Groq's are ~56 characters; this
// leaves room for a longer token from an OpenAI-compatible endpoint while
// keeping a misdirected paste of something else out of config.yaml.
const maxSTTKeyBytes = 4096

// hubConfigMu serialises the load-modify-save of the hub's config.yaml.
//
// config.Save is atomic, so the file is never torn — but two writers that both
// read before either wrote would still lose one of the two edits. The window is
// tiny and the contention is nil (an operator typing into a settings form), so
// a plain mutex is the whole fix.
var hubConfigMu sync.Mutex

// sttSettings is the Settings panel's view of the dictation credential.
//
// The key itself is absent in both directions of the round trip. Returning it
// would make every reader of the settings tab a holder of the hub's credential,
// and a password field that round-trips its own value is how a secret ends up
// in a browser cache, a screenshot or a DOM dump.
type sttSettings struct {
	// HasKey is whether dictation has a key from anywhere at all.
	HasKey bool `json:"has_key"`

	// Stored is whether the hub's own config.yaml holds one. It is what makes
	// "Clear" meaningful: a key arriving from the environment is not ours to
	// remove, and a button offering to would be lying.
	Stored bool `json:"stored"`

	// FromEnv is whether GROQ_API_KEY is currently the one in force, so the
	// panel can say that saving here takes precedence over it.
	FromEnv bool `json:"from_env"`

	// Available and Reason mirror /api/dictate, so the panel can state the
	// consequence — dictation is off, and why — beside the field that fixes
	// it, rather than making the user go and find the button to discover it.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// Endpoint names what the key authenticates against. Worth showing because
	// it is overridable: a field labelled "Groq" that is in fact pointed at
	// some other OpenAI-compatible server should say so.
	Endpoint string `json:"endpoint,omitempty"`
}

// hubSTTSettings reports the dictation credential state of the hub itself.
//
// Deliberately not parameterised by the request: a caller passing ?project_idx
// would otherwise be shown a project's override as though it were what
// dictation uses, which it is not.
func (s *Server) hubSTTSettings() sttSettings {
	cfg := s.sttConfigFrom(s.WorkDir)
	stored := strings.TrimSpace(cfg.GroqAPIKey)
	fromEnv := stored == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) != ""

	available, reason := stt.HostedAvailable(cfg)
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = stt.DefaultEndpoint
	}
	return sttSettings{
		Endpoint:  redactURLUserinfo(endpoint),
		HasKey:    stored != "" || fromEnv,
		Stored:    stored != "",
		FromEnv:   fromEnv,
		Available: available,
		Reason:    reason,
	}
}

// redactURLUserinfo strips any user:password embedded in a URL.
//
// stt.endpoint is operator-set and points at any OpenAI-compatible server, and
// some of those take their credential in the URL. This response is readable by
// anyone with project read, which is a wider audience than holds the key — so
// the one field here that a secret could ride in gets it removed.
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable: return the scheme-ish prefix only rather than guess.
		return ""
	}
	if u.User == nil {
		return raw
	}
	u.User = url.User("redacted")
	return u.String()
}

// handleSTTSettings serves GET /api/config/stt.
func (s *Server) handleSTTSettings(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.hubSTTSettings())
}

// handleSTTSettingsSave serves PUT /api/config/stt.
func (s *Server) handleSTTSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroqAPIKey string `json:"groq_api_key"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	key := strings.TrimSpace(req.GroqAPIKey)
	if key == "" {
		// Not a silent no-op: a blank save is either a mis-click or an attempt
		// to clear, and the second one has its own route that says so.
		jsonErr(w, "groq_api_key is required — use DELETE /api/config/stt to remove the stored key",
			http.StatusBadRequest)
		return
	}
	if err := validateSTTKey(key); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.writeHubSTTKey(key); err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditSTTCredential(r, auditaction.ActionSTTCredentialSet)
	jsonOK(w, s.hubSTTSettings())
}

// handleSTTSettingsClear serves DELETE /api/config/stt.
func (s *Server) handleSTTSettingsClear(w http.ResponseWriter, r *http.Request) {
	if err := s.writeHubSTTKey(""); err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditSTTCredential(r, auditaction.ActionSTTCredentialCleared)
	jsonOK(w, s.hubSTTSettings())
}

// writeHubSTTKey stores key as the hub's dictation credential, or removes it
// when key is empty.
func (s *Server) writeHubSTTKey(key string) error {
	hubConfigMu.Lock()
	defer hubConfigMu.Unlock()

	cfg, err := config.Load(s.WorkDir)
	if err != nil {
		return fmt.Errorf("load hub config: %w", err)
	}
	if cfg == nil {
		return errors.New("load hub config: no configuration")
	}
	cfg.STT.GroqAPIKey = key
	if err := config.Save(s.WorkDir, cfg); err != nil {
		return fmt.Errorf("save hub config: %w", err)
	}
	return nil
}

// validateSTTKey rejects a credential that cannot work, before it is stored
// rather than after someone has spoken a sentence into a button.
//
// The length bound keeps a misdirected paste out of config.yaml. The character
// check is the one that earns its place: the key is interpolated into an
// Authorization header, and Go's HTTP client refuses to send a header value
// holding a newline or a control byte. Without this, such a key would store
// happily and then fail every transcription with an error about the request,
// pointing nowhere near the stray newline that a copy-paste put in it.
func validateSTTKey(key string) error {
	if len(key) > maxSTTKeyBytes {
		return fmt.Errorf("api key is too long (%d bytes, limit %d)", len(key), maxSTTKeyBytes)
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c < 0x20 || c == 0x7f {
			return errors.New("api key contains a control character — check for a stray newline in the pasted value")
		}
	}
	return nil
}

// auditSTTCredential records a change to the hub-wide dictation credential.
//
// The payload names no part of the key, not even a length or a prefix: the
// audit log is read by more people than hold the credential, and "which
// characters did it start with" is not a question it needs to answer.
//
// Best-effort, matching every other emitter here — a wedged journal must not
// stop an operator fixing their configuration.
func (s *Server) auditSTTCredential(r *http.Request, eventType auditaction.Action) {
	actor := s.auditActor(r)
	if actor == "" {
		actor = "anonymous"
	}
	log, err := eventlog.Open(s.WorkDir)
	if err != nil {
		if err != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "stt credential audit: open event log",
				map[string]interface{}{"error": err.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(eventType),
		EntityType: "config",
		EntityID:   "stt.groq_api_key",
		Payload:    `{"scope":"hub"}`,
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "stt credential audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}
