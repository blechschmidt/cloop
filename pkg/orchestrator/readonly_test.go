package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
)

func readOnlyEntries(t *testing.T) ([]executor.ReadOnlyManifestEntry, string) {
	t.Helper()
	root := t.TempDir()
	there := filepath.Join(root, "readonly", "api")
	if err := os.MkdirAll(there, 0o755); err != nil {
		t.Fatal(err)
	}
	return []executor.ReadOnlyManifestEntry{
		{Slug: "api", Project: "/srv/projects/api", Name: "API", Path: there},
		{Slug: "web", Project: "/srv/projects/web", Name: "Web", Path: filepath.Join(root, "readonly", "web")},
	}, root
}

func TestReadOnlySectionNamesOnlyTreesThatAreThere(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries}}
	got := o.readOnlySection()
	if !strings.Contains(got, "## OTHER PROJECTS YOU MAY READ") || !strings.Contains(got, entries[0].Path) ||
		!strings.Contains(got, "/srv/projects/api") || !strings.Contains(got, "read-only") {
		t.Fatalf("section does not name the project that is there:\n%s", got)
	}
	if strings.Contains(got, "/srv/projects/web") {
		t.Fatalf("section names a project whose tree never arrived:\n%s", got)
	}
	if (&Orchestrator{}).readOnlySection() != "" {
		t.Fatal("a run given no project gets a section")
	}
}

func boundaryProject(t *testing.T) *state.ProjectState {
	t.Helper()
	s, err := state.Init(t.TempDir(), "goal", 0)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.Status = "running"
	return s
}

func answer(projects ...knowledgerun.ReadOnlyStatus) func(context.Context) (*knowledgerun.ReadOnlyResponse, error) {
	return func(context.Context) (*knowledgerun.ReadOnlyResponse, error) {
		return &knowledgerun.ReadOnlyResponse{Projects: projects}, nil
	}
}

func TestReadersBoundaryCarriesOnWhileEveryProjectIsListed(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	s := boundaryProject(t)
	o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries, asked: true, check: answer(
		knowledgerun.ReadOnlyStatus{Slug: "api", Readable: true},
		knowledgerun.ReadOnlyStatus{Slug: "web", Readable: true})}}
	stop, err := o.atReadersBoundary(context.Background(), s)
	if stop || err != nil {
		t.Fatalf("atReadersBoundary = %v, %v; want the run to carry on", stop, err)
	}
	if s.Status != "running" || s.PauseReason != nil {
		t.Fatalf("state changed: %s %+v", s.Status, s.PauseReason)
	}
}

func TestReadersBoundaryEndsTheRunWhenAProjectStopsListingIt(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	for name, check := range map[string]func(context.Context) (*knowledgerun.ReadOnlyResponse, error){
		"marked unreadable": answer(knowledgerun.ReadOnlyStatus{Slug: "api", Readable: true},
			knowledgerun.ReadOnlyStatus{Slug: "web", Readable: false}),
		"left out of the answer": answer(knowledgerun.ReadOnlyStatus{Slug: "api", Readable: true}),
	} {
		t.Run(name, func(t *testing.T) {
			s := boundaryProject(t)
			o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries, check: check, asked: true}}
			before := time.Now()
			stop, err := o.atReadersBoundary(context.Background(), s)
			if !stop || err != nil {
				t.Fatalf("atReadersBoundary = %v, %v; want the run to stop", stop, err)
			}
			reloaded, err := state.Load(s.WorkDir)
			if err != nil {
				t.Fatal(err)
			}
			pr := reloaded.PauseReason
			if reloaded.Status != "paused" || pr == nil || pr.Code != pausereason.CodeReadersChanged {
				t.Fatalf("stored %s %+v, want paused readers_changed", reloaded.Status, pr)
			}
			if !strings.Contains(pr.Detail, "Web") || strings.Contains(pr.Detail, "API") {
				t.Errorf("detail %q should name only the project that stopped listing this one", pr.Detail)
			}
			if pr.ResumesAt == nil || pr.ResumesAt.Before(before.Add(-time.Second)) || !pr.AutoResumable(time.Now()) {
				t.Errorf("the pause is not one the hub resumes at once: %+v", pr)
			}
		})
	}
}

func TestReadersBoundaryEndsTheRunWhenTheHubCannotAnswer(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	for name, tc := range map[string]struct {
		err   error
		calls int32
	}{
		"hub unreachable":   {errors.New("dial tcp: connection refused"), 2},
		"hub failing":       {&knowledgerun.APIError{Status: 503, Message: "unavailable"}, 2},
		"rate limited":      {&knowledgerun.APIError{Status: 429, Message: "too often"}, 2},
		"session refused":   {&knowledgerun.APIError{Status: 401, Message: "session ended"}, 1},
		"answer not served": {&knowledgerun.APIError{Status: 404, Message: "not found"}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			s := boundaryProject(t)
			o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries, asked: true,
				check: func(context.Context) (*knowledgerun.ReadOnlyResponse, error) {
					calls.Add(1)
					return nil, tc.err
				}}}
			stop, err := o.atReadersBoundary(context.Background(), s)
			if !stop || err != nil {
				t.Fatalf("atReadersBoundary = %v, %v; want the run to stop", stop, err)
			}
			if s.PauseReason == nil || s.PauseReason.Code != pausereason.CodeReadersChanged ||
				!strings.Contains(s.PauseReason.Detail, "could not confirm") {
				t.Fatalf("pause %+v", s.PauseReason)
			}
			// Not restarted at once: a hub the run cannot reach is no
			// removal, and an immediate restart would meet the same silence.
			if s.PauseReason.AutoResumable(time.Now()) || s.PauseReason.ResumesAt == nil ||
				!s.PauseReason.AutoResumable(time.Now().Add(readersUnconfirmed+time.Second)) {
				t.Errorf("an unconfirmed boundary resumes at %v, want about %s from now", s.PauseReason.ResumesAt,
					readersUnconfirmed)
			}
			if got := calls.Load(); got != tc.calls {
				t.Errorf("asked the hub %d times, want %d", got, tc.calls)
			}
		})
	}
}

// TestReadersBoundaryIsNotAskedBeforeTheFirstTask: the hub resolved the lists
// a moment before the run started, and asking again at once would stop a run
// that cannot reach the hub before it ever ran a task.
func TestReadersBoundaryIsNotAskedBeforeTheFirstTask(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	var calls atomic.Int32
	o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries,
		check: func(context.Context) (*knowledgerun.ReadOnlyResponse, error) {
			calls.Add(1)
			return nil, errors.New("unreachable")
		}}}
	s := boundaryProject(t)
	if stop, err := o.atReadersBoundary(context.Background(), s); stop || err != nil || calls.Load() != 0 {
		t.Fatalf("the first boundary = %v, %v after %d questions; want it passed without asking", stop, err,
			calls.Load())
	}
	if stop, _ := o.atReadersBoundary(context.Background(), s); !stop || calls.Load() == 0 {
		t.Fatal("the second boundary did not ask")
	}
}

func TestReadersBoundaryWithNoSessionStopsTheRun(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	s := boundaryProject(t)
	o := &Orchestrator{readOnly: &readOnlyAccess{entries: entries, asked: true}}
	if stop, err := o.atReadersBoundary(context.Background(), s); !stop || err != nil {
		t.Fatalf("atReadersBoundary = %v, %v; want the run to stop", stop, err)
	}
	if stop, _ := (&Orchestrator{}).atReadersBoundary(context.Background(), s); stop {
		t.Fatal("a run given no project stops at a boundary")
	}
}

// TestReadOnlyAccessAsksTheHubWithTheRunsSession: the environment a run is
// dispatched with is enough to ask, and the question carries the run's token.
func TestReadOnlyAccessAsksTheHubWithTheRunsSession(t *testing.T) {
	entries, _ := readOnlyEntries(t)
	const token = knowledgerun.TokenPrefix + "abcdefabcdefabcdefabcdef.secret"
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		_ = json.NewEncoder(w).Encode(knowledgerun.ReadOnlyResponse{Projects: []knowledgerun.ReadOnlyStatus{
			{Slug: "api", Readable: true}, {Slug: "web", Readable: true}}})
	}))
	defer srv.Close()
	env := map[string]string{
		executor.EnvReadOnlyProjects: executor.EncodeReadOnlyManifest(entries),
		knowledgerun.EnvReadersURL:   srv.URL + knowledgerun.MountPath,
		knowledgerun.EnvReadersToken: token,
	}
	ro := newReadOnlyAccess(func(k string) string { return env[k] })
	if ro == nil || ro.check == nil || len(ro.entries) != 2 {
		t.Fatalf("newReadOnlyAccess = %+v", ro)
	}
	ro.asked = true
	o := &Orchestrator{readOnly: ro}
	if stop, err := o.atReadersBoundary(context.Background(), boundaryProject(t)); stop || err != nil {
		t.Fatalf("atReadersBoundary = %v, %v", stop, err)
	}
	if gotAuth != "Bearer "+token || gotPath != knowledgerun.MountPath+knowledgerun.PathReadOnly {
		t.Fatalf("hub was asked %s with %q", gotPath, gotAuth)
	}
	if newReadOnlyAccess(func(string) string { return "" }) != nil {
		t.Fatal("a run given no project has read-only access")
	}
}
