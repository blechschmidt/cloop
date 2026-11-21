package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/coder/websocket"
)

// TestEveryProjectListCarriesTheMultiProjectFlag is the hub's half of Task
// 20508. The dashboard shows a project's tabs before one is opened only while
// the hub's project list says multi_project is false, so every list the hub
// sends has to say it, and say the same: the GET, the first frame of the
// project event stream, and the pushes that follow on either stream. A push
// that left the flag out could only be read by its length, and a list of one
// is not a hub of one: a member's single shared project comes with the flag
// set (see multiProjectFor).
func TestEveryProjectListCarriesTheMultiProjectFlag(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra bool
		want  bool
	}{
		{"a hub with one project", false, false},
		{"a hub with two projects", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A registry of its own: other tests register projects in the
			// shared one, and a hub that lists them has more than one.
			t.Setenv(multiui.EnvRoot, t.TempDir())
			// Configured before the listener starts, as the browser tests do.
			srv := New(setupProjectDir(t, cloopGoal, nil), 0, "")
			if tc.extra {
				srv.Projects = []string{setupProjectDir(t, sysmonGoal, nil)}
			}
			ts := httptest.NewServer(srv.Handler())
			t.Cleanup(ts.Close)

			says := func(where string, raw []byte) {
				t.Helper()
				var body struct {
					Projects     []json.RawMessage `json:"projects"`
					MultiProject *bool             `json:"multi_project"`
				}
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("%s is not a project list: %v\n%s", where, err, raw)
				}
				if len(body.Projects) == 0 {
					t.Errorf("%s lists no project: %s", where, raw)
				}
				switch {
				case body.MultiProject == nil:
					t.Errorf("%s does not say multi_project; the dashboard can only guess from its length", where)
				case *body.MultiProject != tc.want:
					t.Errorf("%s says multi_project = %v, want %v", where, *body.MultiProject, tc.want)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// The GET.
			resp, err := http.Get(ts.URL + "/api/projects")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /api/projects: %d %v", resp.StatusCode, err)
			}
			says("GET /api/projects", raw)

			// The event stream: its first frame, then a push.
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/projects/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			sresp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer sresp.Body.Close()
			if sresp.StatusCode != http.StatusOK {
				t.Fatalf("GET /api/projects/events = %d", sresp.StatusCode)
			}
			lines := bufio.NewReader(sresp.Body)
			nextProjects := func() []byte {
				t.Helper()
				event := ""
				for {
					line, err := lines.ReadString('\n')
					if err != nil {
						t.Fatalf("the project event stream ended before a projects frame: %v", err)
					}
					line = strings.TrimRight(line, "\r\n")
					switch {
					case strings.HasPrefix(line, "event: "):
						event = strings.TrimPrefix(line, "event: ")
					case strings.HasPrefix(line, "data: ") && event == "projects":
						return []byte(strings.TrimPrefix(line, "data: "))
					case line == "":
						event = ""
					}
				}
			}
			says("the project event stream's first frame", nextProjects())

			// The socket: a hub of several is streamed with no project, a hub of
			// one with its own, as the dashboard asks for them.
			wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/ws"
			if tc.want {
				wsURL += "?scope=global"
			}
			ws, _, err := websocket.Dial(ctx, wsURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			ws.SetReadLimit(16 << 20)
			// A push reaches the sockets the hub has registered; the handshake
			// returns before this one is.
			deadline := time.Now().Add(10 * time.Second)
			for hubClientCount(srv) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("the socket was never registered with the hub")
				}
				time.Sleep(10 * time.Millisecond)
			}

			srv.broadcastProjectsUpdate()
			says("a projects push on the event stream", nextProjects())
			for {
				_, frame, err := ws.Read(ctx)
				if err != nil {
					t.Fatalf("the socket ended before the projects push: %v", err)
				}
				var m wsMessage
				if json.Unmarshal(frame, &m) == nil && m.Type == "projects" {
					says("a projects push on the socket", m.Data)
					break
				}
			}
		})
	}
}

// hubClientCount is how many dashboard sockets the hub has registered, in any
// room.
func hubClientCount(s *Server) int {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	n := 0
	for _, clients := range s.hubClients {
		n += len(clients)
	}
	return n
}
