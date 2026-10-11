package hubclient

// The calls `cloop remote` and `cloop whoami` make. Each is one of the
// dashboard's own routes, so each is authorised exactly as the dashboard's
// button is: the session's role on the project, decided by the hub.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/coder/websocket"
)

// Me returns the hub's /api/me for this credential: who the session is, its
// role and permissions, and its clocks.
func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.Do(ctx, http.MethodGet, "/api/me", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Logout ends this credential's session at the hub. ended is false when there
// was no live session left to end — revoked, expired, or signed out already —
// which is not an error: the credential is dead either way.
func (c *Client) Logout(ctx context.Context) (ended bool, err error) {
	var out struct {
		Ended bool `json:"ended"`
	}
	if err := c.Do(ctx, http.MethodPost, "/auth/logout", nil, nil, &out); err != nil {
		return false, err
	}
	return out.Ended, nil
}

// Project is one project the session can see, with the index the hub
// addresses it by.
type Project struct {
	Idx         int    `json:"idx"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Status      string `json:"status"`
	Goal        string `json:"goal"`
	Running     bool   `json:"running"`
	TotalTasks  int    `json:"total_tasks"`
	DoneTasks   int    `json:"done_tasks"`
	FailedTasks int    `json:"failed_tasks"`
	ActiveTasks int    `json:"active_tasks"`
	Hidden      bool   `json:"hidden"`
}

// Projects lists the projects this session can see, in index order.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project      `json:"projects"`
		Indices  map[string]int `json:"indices"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/projects", url.Values{"indices": {"1"}}, nil, &out); err != nil {
		return nil, err
	}
	if out.Indices == nil {
		return nil, errors.New("this hub does not report project indices: it predates `cloop remote` — " +
			"upgrade it, or use the dashboard")
	}
	projects := make([]Project, 0, len(out.Projects))
	for _, p := range out.Projects {
		idx, ok := out.Indices[p.Path]
		if !ok {
			// Listed but not addressable by this session: nothing it could
			// act on, so not offered.
			continue
		}
		p.Idx = idx
		projects = append(projects, p)
	}
	sort.SliceStable(projects, func(i, j int) bool { return projects[i].Idx < projects[j].Idx })
	return projects, nil
}

// ResolveProject finds the project ref names: its index, its name (exact,
// then case-insensitive) or its path. An ambiguous name is an error naming
// the candidates, never a guess.
func (c *Client) ResolveProject(ctx context.Context, ref string) (Project, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Project{}, errors.New("name a project: its name, its index, or its path (see `cloop remote projects`)")
	}
	projects, err := c.Projects(ctx)
	if err != nil {
		return Project{}, err
	}
	if n, err := strconv.Atoi(ref); err == nil {
		for _, p := range projects {
			if p.Idx == n {
				return p, nil
			}
		}
		return Project{}, fmt.Errorf("no project has index %d here (see `cloop remote projects`)", n)
	}
	var exact, folded []Project
	for _, p := range projects {
		switch {
		case p.Name == ref || p.Path == ref:
			exact = append(exact, p)
		case strings.EqualFold(p.Name, ref):
			folded = append(folded, p)
		}
	}
	for _, set := range [][]Project{exact, folded} {
		switch len(set) {
		case 0:
			continue
		case 1:
			return set[0], nil
		default:
			names := make([]string, 0, len(set))
			for _, p := range set {
				names = append(names, fmt.Sprintf("%d (%s)", p.Idx, p.Path))
			}
			return Project{}, fmt.Errorf("%q names %d projects — use an index or a path: %s",
				ref, len(set), strings.Join(names, ", "))
		}
	}
	return Project{}, fmt.Errorf("no project called %q that this session can see (see `cloop remote projects`)", ref)
}

// Task is one task as the hub lists it.
type Task struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Priority    int    `json:"priority"`
}

// Tasks lists a project's tasks.
func (c *Client) Tasks(ctx context.Context, idx int) ([]Task, error) {
	var out struct {
		Tasks []Task `json:"tasks"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/tasks", projectQuery(idx), nil, &out); err != nil {
		return nil, err
	}
	return out.Tasks, nil
}

// AddTask adds a task to a project and returns it.
func (c *Client) AddTask(ctx context.Context, idx int, title, description string) (Task, error) {
	var out struct {
		Task Task `json:"task"`
	}
	err := c.Do(ctx, http.MethodPost, "/api/tasks", projectQuery(idx),
		map[string]any{"title": title, "description": description}, &out)
	if err != nil {
		return Task{}, err
	}
	return out.Task, nil
}

// Run starts a project's run — the dashboard's Start button — and returns the
// hub's message.
func (c *Client) Run(ctx context.Context, idx int) (string, error) {
	var out struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := c.Do(ctx, http.MethodPost, "/api/run", projectQuery(idx), map[string]any{}, &out); err != nil {
		return "", err
	}
	return out.Message, nil
}

// Stop stops a project's run — the dashboard's Stop button — and reports
// whether there was one to stop.
func (c *Client) Stop(ctx context.Context, idx int) (bool, string, error) {
	var out struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := c.Do(ctx, http.MethodPost, "/api/stop", projectQuery(idx), map[string]any{}, &out); err != nil {
		return false, "", err
	}
	return out.OK, out.Message, nil
}

// LiveLog returns what the hub holds of a project's current run output, and
// whether a run is going.
func (c *Client) LiveLog(ctx context.Context, idx int) (lines []string, running bool, err error) {
	var out struct {
		Running bool     `json:"running"`
		Lines   []string `json:"lines"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/livelog", projectQuery(idx), nil, &out); err != nil {
		return nil, false, err
	}
	return out.Lines, out.Running, nil
}

// ErrStreamEnded is FollowLogs ending because the hub closed the stream on
// the session's account: it was revoked or expired, or access to the project
// was withdrawn. The message says which.
var ErrStreamEnded = errors.New("the hub closed the log stream")

// LogEvents receives what FollowLogs reads besides output.
type LogEvents struct {
	// RunState is told each time the hub reports the run started or stopped.
	RunState func(running bool)
}

// FollowLogs streams a project's run output to w over the dashboard's own
// WebSocket, from the backlog the hub replays on connect onwards, until ctx
// ends or the hub closes the stream. A stream the hub closes because the
// session ended returns an error wrapping ErrStreamEnded.
func (c *Client) FollowLogs(ctx context.Context, idx int, w io.Writer, ev LogEvents) error {
	u, err := url.Parse(c.Base)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = "/api/ws"
	q := projectQuery(idx)
	q.Set("name", "cloop remote logs")
	u.RawQuery = q.Encode()

	hdr := http.Header{}
	hdr.Set("User-Agent", UserAgent())
	if c.Credential != "" {
		hdr.Set("Authorization", "Bearer "+c.Credential)
	}
	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: hdr, HTTPClient: c.http})
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			_ = resp.Body.Close()
			if resp.StatusCode >= 400 {
				return parseError(resp.StatusCode, body)
			}
		}
		return fmt.Errorf("open the log stream: %w", err)
	}
	defer conn.CloseNow()
	// The connect burst is a full state snapshot, which can run to megabytes
	// on a large project.
	conn.SetReadLimit(64 << 20)

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				if ce.Code == websocket.StatusNormalClosure {
					return nil
				}
				return fmt.Errorf("%w (%d %s)", ErrStreamEnded, ce.Code, ce.Reason)
			}
			return fmt.Errorf("log stream: %w", err)
		}
		var msg struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "step_output":
			var d struct {
				Chunk string `json:"chunk"`
			}
			if json.Unmarshal(msg.Data, &d) == nil && d.Chunk != "" {
				if _, err := io.WriteString(w, d.Chunk); err != nil {
					return err
				}
			}
		case "run_state":
			var d struct {
				Running bool `json:"running"`
			}
			if json.Unmarshal(msg.Data, &d) == nil && ev.RunState != nil {
				ev.RunState(d.Running)
			}
		case "credential_ended", "access_withdrawn":
			var d struct {
				Message string `json:"message"`
				Reason  string `json:"reason"`
			}
			_ = json.Unmarshal(msg.Data, &d)
			text := d.Message
			if text == "" {
				text = d.Reason
			}
			return fmt.Errorf("%w: %s", ErrStreamEnded, text)
		}
	}
}

func projectQuery(idx int) url.Values {
	return url.Values{"project_idx": {strconv.Itoa(idx)}}
}
