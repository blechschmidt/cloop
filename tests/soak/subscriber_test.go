package soak

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// subscriber is one live WebSocket client, owned by one tenant.
//
// Ownership is the whole point: every frame this connection receives is
// attributed to the tenant that opened it, so a frame carrying another
// tenant's canary is cross-tenant bleed by definition rather than by
// inference.
type subscriber struct {
	tenant *tenant
	// scope names what this connection asked for, for failure messages:
	// either a project ("alpha-proj0") or "global".
	scope string
	// project is the project this subscriber is subscribed to, nil for a
	// global-scope connection.
	project *project

	conn   *websocket.Conn
	cancel context.CancelFunc

	mu sync.Mutex
	// frames counts everything received, so a subscriber that silently
	// received nothing is distinguishable from one that received only clean
	// traffic. A soak where every stream was empty would otherwise report
	// zero bleed and mean nothing.
	frames int
	// ownCanaries counts frames carrying a canary this subscriber's tenant
	// owns — the positive control.
	ownCanaries int
	// leaks holds every frame carrying material this tenant does not own.
	leaks []leak
	// running is the last run_state seen. A project-scoped connection only
	// ever hears about its own project, so it needs no key.
	running  bool
	sawState bool
	// runsEnded counts true→false transitions — completed runs.
	//
	// Counted rather than sampled, because sampling cannot see a run that
	// started and finished between two polls. The driver originally waited
	// for `running` to go true and then false, and under concurrency both
	// frames routinely arrive inside one poll interval: the wait then never
	// latched and every task sat out its full timeout. An edge count is
	// immune to that, because classify sees every frame.
	runsEnded int
	closed    bool
	closeErr  error
}

// leak is one frame that reached the wrong tenant.
type leak struct {
	// recipient is the tenant that should never have seen this.
	recipient string
	// scope is the recipient stream that carried it.
	scope string
	// owner and ownerTask name where the material came from.
	owner     string
	ownerTask string
	// kind distinguishes a leaked log line from a leaked credential.
	kind string
	// frameType is the wsMessage envelope type ("step_output", "state_diff"…).
	frameType string
	// frame is the offending payload, truncated.
	frame string
	at    time.Time
}

func (l leak) String() string {
	return fmt.Sprintf("%s material %q (task %s) reached tenant %q on stream %q in a %q frame at %s:\n      %s",
		l.kind, l.owner, l.ownerTask, l.recipient, l.scope, l.frameType,
		l.at.Format(time.RFC3339Nano), l.frame)
}

// openSubscribers connects one WebSocket per project plus one global-scope
// connection per tenant.
//
// The global connection is not redundant. Fleet-wide broadcasts (projects,
// executor_update, audit_append) walk every room including the one that
// belongs to no project, and that room is reachable by a path
// broadcastToProject cannot take — so a payload that leaks there leaks past
// the per-project scoping this suite's other connections test.
func (w *world) openSubscribers(t *testing.T) {
	t.Helper()
	for _, tn := range w.tenants {
		for _, p := range tn.projects {
			w.dial(t, tn, p, fmt.Sprintf("/api/ws?project_idx=%d", p.idx), p.name, p)
		}
		w.dial(t, tn, nil, "/api/ws?scope=global", "global", nil)
	}
	// Let every connection register in the hub's room map before the first
	// dispatch. A subscriber that joins mid-run would miss frames, and
	// "missed" and "correctly withheld" are indistinguishable afterwards.
	w.waitForSubscribers(t)
}

func (w *world) dial(t *testing.T, tn *tenant, p *project, path, scope string, proj *project) {
	t.Helper()
	sub := &subscriber{tenant: tn, scope: scope, project: proj}

	// The URL helper always appends project_idx; a global-scope stream
	// declares itself with ?scope=global, which resolveStreamScope honours
	// ahead of any index.
	idx := 0
	if p != nil {
		idx = p.idx
	}
	wsURL := "ws" + strings.TrimPrefix(w.url(path, tn, idx), "http")

	ctx, cancel := context.WithCancel(context.Background())
	sub.cancel = cancel

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		cancel()
		t.Fatalf("tenant %s: dial %s: %v", tn.name, scope, err)
	}
	// The hub replays a project's buffered log on connect and can batch a
	// large chunk; the default read limit would drop the connection on a
	// frame this suite specifically wants to inspect.
	conn.SetReadLimit(-1)
	sub.conn = conn

	tn.subs = append(tn.subs, sub)
	t.Cleanup(func() {
		cancel()
		_ = conn.Close(websocket.StatusNormalClosure, "")
	})

	go sub.pump(ctx, w)
}

// pump reads frames until the connection closes, classifying each one as it
// arrives.
//
// Classification happens here rather than in a post-run sweep so the offending
// frame is captured with its arrival time and before any truncation or
// buffering could lose it — and so the suite never has to hold every frame of
// a twenty-container soak in memory to answer a question about three of them.
func (s *subscriber) pump(ctx context.Context, w *world) {
	for {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			s.mu.Lock()
			s.closed = true
			s.closeErr = err
			s.mu.Unlock()
			return
		}
		s.classify(w, string(data))
	}
}

// classify records one frame.
func (s *subscriber) classify(w *world, raw string) {
	var env struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal([]byte(raw), &env)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames++

	// run_state is how the driver learns a dispatch finished. Only meaningful
	// on a project-scoped stream, which is the only kind that receives it.
	if env.Type == "run_state" && s.project != nil {
		var rs struct {
			Running bool `json:"running"`
		}
		if json.Unmarshal(env.Data, &rs) == nil {
			if s.sawState && s.running && !rs.Running {
				s.runsEnded++
			}
			s.running = rs.Running
			s.sawState = true
		}
	}

	for _, p := range w.projects {
		ownedByRecipient := p.tenant == s.tenant

		// A canary is scoped to a project, and its prefix is stable across
		// that project's tasks, so one Contains answers "did any of this
		// project's output reach here" without knowing the sequence number.
		if prefix := canaryPrefix(p); strings.Contains(raw, prefix) {
			if ownedByRecipient {
				s.ownCanaries++
			} else {
				s.leaks = append(s.leaks, leak{
					recipient: s.tenant.name,
					scope:     s.scope,
					owner:     p.name,
					ownerTask: extractTask(raw, prefix),
					kind:      "log",
					frameType: env.Type,
					frame:     truncate(raw, 400),
					at:        time.Now(),
				})
			}
		}

		// A credential must never appear on any stream, including its own
		// owner's: the hub redacts leased values out of harness output, and
		// the workload is written not to print them. Either failing is a
		// finding, so this one is not conditioned on ownership.
		if strings.Contains(raw, p.secretSentinel) {
			s.leaks = append(s.leaks, leak{
				recipient: s.tenant.name,
				scope:     s.scope,
				owner:     p.name,
				ownerTask: "n/a",
				kind:      "credential",
				frameType: env.Type,
				frame:     truncate(raw, 400),
				at:        time.Now(),
			})
		}
	}
}

// canaryPrefix is the tenant+project-stable part of a canary, without the
// per-task sequence.
func canaryPrefix(p *project) string {
	return fmt.Sprintf("CLOOPSOAK~%s~%s~", p.tenant.name, p.name)
}

// extractTask pulls the task segment out of a canary occurrence so a failure
// names the task and not only the project.
func extractTask(raw, prefix string) string {
	i := strings.Index(raw, prefix)
	if i < 0 {
		return "unknown"
	}
	rest := raw[i+len(prefix):]
	if j := strings.Index(rest, "~"); j >= 0 {
		return rest[:j]
	}
	return "unknown"
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("… (%d bytes total)", len(s))
}

// isRunning reports the last run_state this subscriber saw.
func (s *subscriber) isRunning() (running, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.sawState
}

// completedRuns returns how many runs this subscriber has watched end.
func (s *subscriber) completedRuns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runsEnded
}

// snapshot returns this subscriber's counters and leaks.
func (s *subscriber) snapshot() (frames, own int, leaks []leak) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames, s.ownCanaries, append([]leak(nil), s.leaks...)
}

// subscriberFor returns the project-scoped subscriber watching p.
func (w *world) subscriberFor(p *project) *subscriber {
	for _, sub := range p.tenant.subs {
		if sub.project == p {
			return sub
		}
	}
	return nil
}

// waitForSubscribers blocks until every connection has received at least one
// frame, so no dispatch starts against a stream the hub has not registered yet.
func (w *world) waitForSubscribers(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		pending := 0
		var lagging string
		for _, tn := range w.tenants {
			for _, sub := range tn.subs {
				sub.mu.Lock()
				n := sub.frames
				sub.mu.Unlock()
				if n == 0 {
					pending++
					lagging = tn.name + "/" + sub.scope
				}
			}
		}
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscriber(s) never received a frame (e.g. %s); "+
				"the hub is not delivering to them and no bleed assertion below would mean anything",
				pending, lagging)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
