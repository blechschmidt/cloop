package ui

// Tests for dictated tasks (Task 20238).
//
// The one that matters most is TestGlassesSurface_GrantsNoMoreThanTaskMutate.
// A display-glasses link is minted with the operator role, and the only reason
// that is not a licence to spend money is that tokenKindAdmitted pins the
// token to /glasses and /api/glasses/, where no run, secret or config route
// exists. That makes the path pin load-bearing rather than belt-and-braces: a
// future endpoint added under the prefix would retroactively widen every link
// already sitting in a wearer's phone, without anyone editing this package's
// security code. The test is what turns that from a convention into a gate.

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/stt"
)

// glassesReachablePerms is what a link may exercise. project.read is the
// original read surface; task.mutate is dictation. Nothing else may appear
// under /api/glasses/ without a deliberate decision here.
var glassesReachablePerms = map[authz.Permission]bool{
	authz.PermProjectRead: true,
	authz.PermTaskMutate:  true,
	authz.PermPublic:      true,
}

func TestGlassesSurface_GrantsNoMoreThanTaskMutate(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir()}
	table := srv.routeTable()
	if len(table) == 0 {
		t.Fatal("routeTable() is empty — the discovery path broke")
	}

	seen := 0
	for _, rs := range table {
		path := patternPath(rs.Pattern)
		if !strings.HasPrefix(path, "/api/glasses/") {
			continue
		}
		seen++
		perms := []authz.Permission{rs.Perm}
		for _, p := range rs.MethodPerms {
			perms = append(perms, p)
		}
		for _, p := range perms {
			if p == "" {
				continue
			}
			if !glassesReachablePerms[p] {
				t.Errorf("route %q under /api/glasses/ requires %q.\n"+
					"A display-glasses link is minted with the operator role and confined to this\n"+
					"prefix, so every route here is reachable by a credential that lives in a URL.\n"+
					"Adding this one widens every link already issued. If that is intended, say so\n"+
					"in glassesReachablePerms and in the mint comment in glasses_api.go.",
					rs.Pattern, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no /api/glasses/ routes found — the prefix moved and this gate stopped checking anything")
	}
}

// TestGlassesRoleLadder_OperatorIsTheCeiling documents why the above matters:
// the role the link carries really does name run.start, so the path pin is the
// only thing between a leaked URL and a run.
func TestGlassesRoleLadder_OperatorIsTheCeiling(t *testing.T) {
	if got := glassesRole(true); got != authz.RoleViewer {
		t.Errorf("a read-only link must be viewer, got %q", got)
	}
	if got := glassesRole(false); got != authz.RoleOperator {
		t.Errorf("a dictation link must be operator, got %q", got)
	}

	// The role really does carry run.start. That is the whole reason the path
	// pin is load-bearing and the gate above exists; if this ever stops being
	// true the mint comment in glasses_api.go is overstating the risk and
	// should be corrected rather than left to rot.
	var hasRunStart, hasTaskMutate bool
	for _, p := range authz.RoleOperator.Permissions() {
		switch p {
		case authz.PermRunStart:
			hasRunStart = true
		case authz.PermTaskMutate:
			hasTaskMutate = true
		}
	}
	if !hasTaskMutate {
		t.Error("operator no longer carries task.mutate — a dictation link can no longer add tasks")
	}
	if !hasRunStart {
		t.Error("operator no longer carries run.start — the glasses mint comment now overstates " +
			"the risk; narrow it, and consider whether the path pin is still needed")
	}
}

// TestGlassesLinkCapability_ReadsOffTheStoredRoles is what keeps a link minted
// before dictation existed reading as read-only. Those tokens carry viewer and
// nothing else, and recomputing the answer from today's default would tell
// their holders they can dictate when the gate will refuse them.
func TestGlassesLinkCapability_ReadsOffTheStoredRoles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		roles []string
		want  bool
	}{
		{"legacy viewer link", []string{string(authz.RoleViewer)}, false},
		{"dictation link", []string{string(authz.RoleOperator)}, true},
		{"no roles", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := glassesCanAddTasks(&apitoken.Token{Roles: tc.roles})
			if got != tc.want {
				t.Errorf("glassesCanAddTasks(%v) = %v, want %v", tc.roles, got, tc.want)
			}
		})
	}
	if glassesCanAddTasks(nil) {
		t.Error("a nil token must not report the ability to add tasks")
	}
}

// multipartField builds a one-field multipart body.
func multipartField(t *testing.T, field, filename string, data []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, w.FormDataContentType()
}

// patternPath strips the optional method prefix from a ServeMux pattern.
func patternPath(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		return pattern[i+1:]
	}
	return pattern
}

// ---------------------------------------------------------------------------
// transcription
// ---------------------------------------------------------------------------

func TestTranscribe_RejectsNonPOST(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir()}
	rec := httptest.NewRecorder()
	srv.handleTranscribe(rec, httptest.NewRequest(http.MethodGet, "/api/transcribe", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/transcribe = %d, want 405", rec.Code)
	}
}

func TestTranscribe_RequiresAudioField(t *testing.T) {
	// A key, so the handler gets past the "nothing can transcribe this"
	// refusal — which is deliberately checked before the body is read — and
	// reaches the field validation this test is about.
	t.Setenv("GROQ_API_KEY", "gsk_test")

	srv := &Server{WorkDir: t.TempDir()}
	body, ctype := multipartField(t, "notaudio", "x.webm", []byte("abc"))
	req := httptest.NewRequest(http.MethodPost, "/api/transcribe", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	srv.handleTranscribe(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing audio field = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestTranscribe_SaysWhyWhenNoBackend is the "do not let someone speak into a
// dead endpoint" case: with no key and no CLI on PATH the refusal has to name
// the fix, and it has to happen before the upload is spooled to disk.
func TestTranscribe_SaysWhyWhenNoBackend(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	t.Setenv("PATH", t.TempDir()) // no `whisper` binary reachable

	if ok, _ := stt.HostedAvailable(stt.Config{}); ok {
		t.Skip("a speech backend is reachable in this environment")
	}

	srv := &Server{WorkDir: t.TempDir()}
	body, ctype := multipartField(t, "audio", "a.webm", []byte("not really audio"))
	req := httptest.NewRequest(http.MethodPost, "/api/transcribe", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	srv.handleTranscribe(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected a refusal with no backend configured, got 200")
	}
	if !strings.Contains(rec.Body.String(), "speech-to-text") {
		t.Errorf("refusal should name the missing backend, got: %s", rec.Body.String())
	}
}

// TestDictateStatus_ReportsCapability checks the two questions the wearable
// asks before drawing a control it cannot use.
func TestDictateStatus_ReportsCapability(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir()}
	rec := httptest.NewRecorder()
	srv.handleDictateStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dictate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dictate = %d, want 200", rec.Code)
	}
	for _, field := range []string{`"available"`, `"can_add_tasks"`} {
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("status response is missing %s: %s", field, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// config resolution
// ---------------------------------------------------------------------------

// TestOverlaySTT_ProjectOverridesFieldByField is the property that lets one
// key at the hub serve every project: a project setting a language must not
// blank the hub's key.
func TestOverlaySTT_ProjectOverridesFieldByField(t *testing.T) {
	merged := config.STTConfig{}
	overlaySTT(&merged, config.STTConfig{GroqAPIKey: "hub-key", Language: "en"})
	overlaySTT(&merged, config.STTConfig{Language: "de"})

	if merged.GroqAPIKey != "hub-key" {
		t.Errorf("project override cleared the hub key: %q", merged.GroqAPIKey)
	}
	if merged.Language != "de" {
		t.Errorf("project language should win, got %q", merged.Language)
	}
}

func TestAudioExt_OnlyAcceptsKnownContainers(t *testing.T) {
	cases := map[string]string{
		"dictation.webm":    ".webm",
		"dictation.ogg":     ".ogg",
		"speech.WAV":        ".wav",
		"noextension":       ".webm",
		"../../etc/passwd":  ".webm",
		"evil.sh":           ".webm",
		"a.webm\x00evil.sh": ".webm",
	}
	for in, want := range cases {
		if got := audioExt(in); got != want {
			t.Errorf("audioExt(%q) = %q, want %q", in, got, want)
		}
	}
}
