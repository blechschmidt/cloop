package ciworkflow_test

// A job's relay session outlives the hub restarting under it (Task 20390).
//
// A GitHub Actions job federates once and then relays through the hub for the
// rest of the job, which can be hours. The hub restarts — a nightly deploy, a
// rolling update — and the job's next call must still be served: Claude Code
// answers a 401 by retrying for about three minutes and then failing the job
// with "Not logged in", and the job cannot federate again, because its OIDC
// token has been spent.
//
// These run the guide's workflow on the played runner with a step added after
// federation that waits while the test restarts the hub process in place —
// same directory, same port — and calls before and after it.

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	beforeRestartStep = "Call the API before the restart"
	pauseStep         = "Wait while the hub restarts"
	afterRestartStep  = "Call the API after the restart"
)

// sdkCall is a relay call the way an SDK makes it, as TestPublishedWorkflow's
// added step does. With a status file it records the HTTP status there and
// succeeds whatever it was; without one it fails the step on any refusal.
func sdkCall(name, statusFile string) workflowStep {
	call := `"$ANTHROPIC_BASE_URL/v1/messages" \
  -H "x-api-key: $ANTHROPIC_AUTH_TOKEN" -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,"messages":[{"role":"user","content":"ping"}]}'`
	if statusFile != "" {
		return workflowStep{
			Name: name, Shell: "bash",
			Run: `curl -sS -o /dev/null -w '%{http_code}' ` + call + ` > "` + statusFile + `"`,
		}
	}
	return workflowStep{Name: name, Shell: "bash", Run: `curl -sS --fail-with-body ` + call + ` | jq -er '.content[0].text'`}
}

// pause is a step that tells the test it is waiting, then waits for the test
// to let it go — bounded, so a test that dies early does not hang the job.
func pause() workflowStep {
	return workflowStep{
		Name: pauseStep, Shell: "bash",
		Run: `touch "$RUNNER_TEMP/paused"
for i in $(seq 1 1800); do
  [ -e "$RUNNER_TEMP/resume" ] && exit 0
  sleep 0.1
done
echo "the test never let the job go on" >&2
exit 1`,
	}
}

// insertBefore returns steps with extra inserted before the step named name.
func insertBefore(t *testing.T, steps []workflowStep, name string, extra ...workflowStep) []workflowStep {
	t.Helper()
	for i, s := range steps {
		if s.Name == name {
			out := append([]workflowStep(nil), steps[:i]...)
			out = append(out, extra...)
			return append(out, steps[i:]...)
		}
	}
	t.Fatalf("the published workflow has no step %q", name)
	return nil
}

// runAcrossRestart runs job on r and, once its pause step is reached, calls
// whileWaiting — where the test restarts the hub — and then lets it go on.
func runAcrossRestart(t *testing.T, r *runner, job workflowJob, whileWaiting func()) *jobResult {
	t.Helper()
	done := make(chan *jobResult, 1)
	go func() { done <- r.run(job) }()
	paused := filepath.Join(r.temp, "paused")
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := os.Stat(paused); err == nil {
			break
		}
		select {
		case res := <-done:
			t.Fatalf("the job ended before it reached %q:\n%s", pauseStep, res.Log)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job never reached %q", pauseStep)
		}
		time.Sleep(50 * time.Millisecond)
	}
	whileWaiting()
	if err := os.WriteFile(filepath.Join(r.temp, "resume"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		return res
	case <-time.After(5 * time.Minute):
		t.Fatal("the job did not finish within 5 minutes of the restart")
		return nil
	}
}

// TestRelaySessionSurvivesAHubRestart: the hub is stopped — gracefully, and
// killed outright — and started again between two of a job's relay calls. The
// job's next call, Claude Code's included, is served with the session it
// already holds: no new token exchange, the restored session counting on from
// what it had spent.
func TestRelaySessionSurvivesAHubRestart(t *testing.T) {
	t.Parallel()
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		sig := sig
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.hub.addRule(t, reviewRule)
			job := w.publishedJob(t)
			r := newRunner(t, w.github, w.pki, w.claude)
			job.Steps = insertBefore(t, job.Steps, agentStep, sdkCall(beforeRestartStep, ""), pause())
			job.Steps = append(job.Steps, sdkCall(afterRestartStep, ""))

			seenBefore := 0
			res := runAcrossRestart(t, r, job, func() {
				if w.up != nil {
					seenBefore = len(w.up.seen())
				}
				w.hub.restart(t, sig)
			})
			t.Logf("job log:\n%s", res.Log)
			if res.Failed() {
				t.Fatalf("the job failed across the restart; hub output:\n%s", w.hub.tail())
			}

			if n := len(w.github.idTokenRequests()); n != 1 {
				t.Errorf("the job asked GitHub for %d ID tokens, want 1", n)
			}
			ex := w.hub.exchanges(t)
			if len(ex) != 1 || !ex[0].Accepted {
				t.Fatalf("exchanges = %+v, want the job's one: no new exchange after the restart", ex)
			}
			restored := w.hub.auditEvents(t, "ci.session.restored")
			if len(restored) != 1 || restored[0]["entity_id"] != ex[0].SessionID {
				t.Fatalf("ci.session.restored events = %v, want one for session %s", restored, ex[0].SessionID)
			}
			if sig == syscall.SIGTERM {
				if n := len(w.hub.auditEvents(t, "ci.session.suspended")); n != 1 {
					t.Errorf("ci.session.suspended events = %d, want the graceful stop's one", n)
				}
				// The suspension wrote the session's spend, so the restored
				// session's meter agrees with everything the API saw.
				w.waitSettled(t, ex[0].SessionID, w.relayedAll(3))
			} else if w.up != nil {
				// Killed: what the stopped process spent since its last
				// checkpoint may be lost, never what the new one spent.
				after := int64(len(w.up.seen()) - seenBefore)
				w.waitSettled(t, ex[0].SessionID, func(s ciSession) bool { return s.Usage.Requests >= after })
			}
			// Every API call the job made was served. (Claude Code also sends
			// a HEAD /api/hello without a credential, which the relay refuses
			// before any session is involved; that is not one of them.)
			for _, kind := range []string{"ci.relay.denied", "ci.rejected"} {
				for _, e := range w.hub.auditEvents(t, kind) {
					if p := fmt.Sprint(e["payload"]); strings.Contains(p, `"path":"/v1/`) {
						t.Errorf("a call of the job was refused: %s %s", kind, p)
					}
				}
			}
		})
	}
}

// TestRelayRefusesASessionWhoseRuleWasDisabled: the session's rule is
// disabled while the job is between calls — through the API once the
// restarted hub is up, or behind its back while no hub process runs — and the
// job's next call is refused with the 401 it would have got, and the session
// ends.
func TestRelayRefusesASessionWhoseRuleWasDisabled(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		disable func(t *testing.T, w *world, ruleID string)
	}{
		{"through the API after the restart", func(t *testing.T, w *world, ruleID string) {
			w.hub.restart(t, syscall.SIGTERM)
			rule := map[string]any{}
			for k, v := range reviewRule {
				rule[k] = v
			}
			rule["enabled"] = false
			w.hub.mustAPI(t, http.MethodPut, "/api/ci/rules/"+ruleID, rule, nil)
		}},
		{"while no hub process runs", func(t *testing.T, w *world, ruleID string) {
			w.hub.halt(t, syscall.SIGKILL)
			db, err := sql.Open("sqlite", "file:"+filepath.Join(w.hub.dir, ".cloop", "state.db")+"?_pragma=busy_timeout(5000)")
			if err != nil {
				t.Fatal(err)
			}
			res, err := db.Exec(`UPDATE ci_pipeline_rules SET enabled = 0 WHERE id = ?`, ruleID)
			_ = db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				t.Fatalf("disabled %d rules, want 1", n)
			}
			w.hub.launch(t)
		}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			ruleID := w.hub.addRule(t, reviewRule)
			job := w.publishedJob(t)
			r := newRunner(t, w.github, w.pki, w.claude)
			status := filepath.Join(r.temp, "status-after")
			// No agent step: Claude Code answers a 401 by retrying for three
			// minutes. The call after the pause records its status instead.
			var steps []workflowStep
			for _, s := range job.Steps {
				if s.Name == agentStep {
					break
				}
				steps = append(steps, s)
			}
			job.Steps = append(steps, sdkCall(beforeRestartStep, ""), pause(), sdkCall(afterRestartStep, status))

			res := runAcrossRestart(t, r, job, func() { tc.disable(t, w, ruleID) })
			t.Logf("job log:\n%s", res.Log)
			if res.Failed() {
				t.Fatalf("the job failed; hub output:\n%s", w.hub.tail())
			}
			raw, err := os.ReadFile(status)
			if err != nil {
				t.Fatal(err)
			}
			if code, _ := strconv.Atoi(strings.TrimSpace(string(raw))); code != http.StatusUnauthorized {
				t.Fatalf("the call after the rule was disabled = HTTP %s, want 401", raw)
			}
			ex := w.hub.exchanges(t)
			if len(ex) != 1 {
				t.Fatalf("exchanges = %+v, want the job's one", ex)
			}
			if n := len(w.hub.auditEvents(t, "ci.session.restored")); n != 0 {
				t.Errorf("a session whose rule was disabled was restored (%d events)", n)
			}
			var ended bool
			for _, e := range w.hub.auditEvents(t, "ci.session.closed") {
				if e["entity_id"] == ex[0].SessionID {
					ended = true
				}
			}
			if !ended {
				t.Errorf("no ci.session.closed event ended session %s", ex[0].SessionID)
			}
			for _, s := range w.hub.sessions(t) {
				if s.ID == ex[0].SessionID {
					t.Errorf("the hub still lists session %s: %+v", s.ID, s)
				}
			}
		})
	}
}
