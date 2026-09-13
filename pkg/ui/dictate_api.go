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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
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
	merged := config.STTConfig{}
	// Hub first, project second, so the project overwrites field by field.
	for _, dir := range []string{s.WorkDir, s.resolveWorkDir(r)} {
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
