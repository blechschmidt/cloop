package cmd

// Copilot on a hub with single sign-on acts for the person, end to end (Task
// 20449): a hub in this process (internal/ssohubtest) runs a copilot project
// on its own host and dispatches its runs and model calls to this test binary
// acting as cloop — the real `cloop run`, the real subcommands, the real
// copilot provider — and a stand-in `copilot` first on PATH records what each
// call signed in with and where it kept its state.
//
// The hub's own environment carries a Copilot token, GitHub tokens and a
// GitHub host, as a service's might for something else. Before Task 20449
// every person's run, model call and resume inherited them, and the stand-in
// would have recorded the hub's token for everyone; a person with no
// credential of their own was served on it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/copilotauth"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// copilotCallFields are what the stand-in records of each call, in order.
var copilotCallFields = []string{"PWD", "COPILOT_GITHUB_TOKEN", "COPILOT_HOME", "GH_CONFIG_DIR", "GH_TOKEN",
	"GITHUB_TOKEN", "GH_HOST", "COPILOT_API_URL", "CLOOP_COPILOT_HOME"}

// hubCopilotAmbient is the hub process's own environment: what a call made
// for a person must never sign in with or send a token to.
var hubCopilotAmbient = map[string]string{
	"COPILOT_GITHUB_TOKEN": "hub-own-copilot-token",
	"GH_TOKEN":             "hub-own-gh-token",
	"GITHUB_TOKEN":         "hub-own-github-token",
	"GH_HOST":              "ghe.hub-own.example",
	"COPILOT_API_URL":      "https://collector.hub-own.example",
}

// copilotStandIn writes the stand-in `copilot`: it records the environment
// fields above, one line per call, and answers each prompt the way a model
// would.
func copilotStandIn(t *testing.T) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "copilot-calls.log")
	var rec []string
	for _, f := range copilotCallFields {
		rec = append(rec, "${"+f+"-<unset>}")
	}
	script := `#!/bin/sh
prompt=$(cat)
echo "` + strings.Join(rec, "|") + `" >> ` + quoteArg(log) + `
case "$prompt" in
*"recursively decomposed into concrete sub-tasks"*)
  echo '[{"title":"First part","description":"a"},{"title":"Second part","description":"b"}]' ;;
*"diagnosing why a software task is stuck"*)
  echo '{"root_cause":"a failed dependency","actions":["retry it","split it","ask"],"recommendation":"skip"}' ;;
*"You are editing the details of a single task"*)
  echo 'Move every table, and the indexes.' ;;
*TASK_DONE*)
  printf 'Did the task.\nTASK_DONE\n' ;;
*)
  echo 'Task 1 comes first.' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "copilot"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// copilotCall is one line of the stand-in's log, by field.
type copilotCall map[string]string

func copilotCalls(t *testing.T, log string) []copilotCall {
	t.Helper()
	raw, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []copilotCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) != len(copilotCallFields) {
			t.Fatalf("unreadable stand-in log line %q", line)
		}
		c := copilotCall{}
		for i, f := range copilotCallFields {
			c[f] = parts[i]
		}
		out = append(out, c)
	}
	return out
}

// copilotPAT is a fine-grained GitHub token shaped as the dashboard's paste
// classifier recognises one, distinct per six-character tag; built at run
// time so no realistic-looking token sits in the source.
func copilotPAT(tag string) string {
	return "github" + "_pat_" + "11AB2CD3" + strings.Repeat(tag, 12)
}

func TestHubCopilotActsForThePersonEndToEnd(t *testing.T) {
	log := copilotStandIn(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}})
	for k, v := range hubCopilotAmbient {
		t.Setenv(k, v)
	}

	ps, err := state.Load(hub.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending, Priority: 1},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hub.Dir, ".cloop", "config.yaml"), []byte("provider: copilot\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const alice, bob, carol = "alice@example.com", "bob@example.com", "carol@example.com"
	browsers := map[string]*http.Client{
		alice: hub.SignIn(t, alice, ssohubtest.GroupOperators),
		bob:   hub.SignIn(t, bob, ssohubtest.GroupOperators),
		carol: hub.SignIn(t, carol, ssohubtest.GroupOperators),
	}
	tokens := map[string]string{alice: copilotPAT("aL1cE2"), bob: copilotPAT("bO3bB4")}

	// The last call must have signed in as who, in who's own Copilot home, in
	// dir (when one is named), with nothing of the hub's and nothing of the
	// other's.
	var ranIn func(t *testing.T, who, what, dir string)
	ranFor := func(t *testing.T, who, what string) {
		t.Helper()
		ranIn(t, who, what, hub.Dir)
	}
	ranIn = func(t *testing.T, who, what, dir string) {
		t.Helper()
		calls := copilotCalls(t, log)
		if len(calls) == 0 {
			t.Fatalf("%s for %s: the Copilot CLI never ran", what, who)
		}
		got := calls[len(calls)-1]
		home, err := copilotauth.HomePath(who)
		if err != nil {
			t.Fatal(err)
		}
		if got["COPILOT_GITHUB_TOKEN"] != tokens[who] {
			t.Errorf("%s for %s signed in with %.30q…, want %s's own token", what, who, got["COPILOT_GITHUB_TOKEN"], who)
		}
		if got["COPILOT_HOME"] != home || got["GH_CONFIG_DIR"] != filepath.Join(home, "gh") {
			t.Errorf("%s for %s kept its state in %q (gh %q), want %s's own %q", what, who, got["COPILOT_HOME"],
				got["GH_CONFIG_DIR"], who, home)
		}
		for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "COPILOT_API_URL", "CLOOP_COPILOT_HOME"} {
			if got[k] != "<unset>" {
				t.Errorf("%s for %s: the CLI inherited %s=%q", what, who, k, got[k])
			}
		}
		if dir != "" && got["PWD"] != dir {
			t.Errorf("%s for %s ran in %q, want the project %q", what, who, got["PWD"], dir)
		}
	}
	// No call ever: the hub's own credentials, or one person's in another's.
	defer func() {
		for _, c := range copilotCalls(t, log) {
			for k, v := range c {
				for _, ambient := range hubCopilotAmbient {
					if v == ambient {
						t.Errorf("a call carried the hub's own %s", k)
					}
				}
			}
		}
	}()
	refused := func(t *testing.T, who, method, path string, body any, what string) {
		t.Helper()
		before := len(copilotCalls(t, log))
		code, raw := hub.Call(t, browsers[who], method, path, body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if code != http.StatusConflict || out["code"] != "harness_credential_missing" || out["per_person"] != true {
			t.Errorf("%s for %s with no credential = %d %s, want the 409 the dialog opens on", what, who, code, raw)
		}
		if after := len(copilotCalls(t, log)); after != before {
			t.Errorf("%s for %s with no credential ran the Copilot CLI %d time(s) — on the hub's own sign-in",
				what, who, after-before)
		}
	}

	// Nobody has a credential yet: refused, never served by the hub's.
	refused(t, carol, http.MethodPost, "/api/tasks/1/decompose", map[string]any{}, "the split preview")
	refused(t, carol, http.MethodPost, "/api/run?project_idx=0", map[string]any{}, "a run")

	grants := map[string]string{}
	for _, who := range []string{alice, bob} {
		code, raw := hub.Call(t, browsers[who], http.MethodPost, "/api/projects/0/harness-credential",
			map[string]any{"token": tokens[who]})
		var out struct {
			Granted struct {
				GrantID string `json:"grant_id"`
			} `json:"granted"`
			PerPerson bool `json:"per_person"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Granted.GrantID == "" || !out.PerPerson {
			t.Fatalf("%s grants a Copilot credential = %d %s", who, code, raw)
		}
		grants[who] = out.Granted.GrantID
		if strings.Contains(string(raw), tokens[who]) {
			t.Fatal("the grant's answer repeated the token")
		}
	}

	// The four dashboard model calls, each on the caller's own credential.
	for _, who := range []string{alice, bob} {
		b := browsers[who]
		t.Run("model calls/"+who, func(t *testing.T) {
			code, raw := hub.Call(t, b, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
			if code != http.StatusOK || !strings.Contains(string(raw), `"title":"Second part"`) {
				t.Fatalf("split preview = %d %s", code, raw)
			}
			ranFor(t, who, "the split preview")
			code, raw = hub.Call(t, b, http.MethodPost, "/api/tasks/1/revise",
				map[string]any{"instruction": "and the indexes", "description": "Move every table."})
			if code != http.StatusOK || !strings.Contains(string(raw), "Move every table, and the indexes.") {
				t.Fatalf("revise = %d %s", code, raw)
			}
			ranFor(t, who, "revise")
			code, raw = hub.Call(t, b, http.MethodPost, "/api/tasks/1/blocker", map[string]any{})
			if code != http.StatusOK || !strings.Contains(string(raw), `"recommendation":"skip"`) {
				t.Fatalf("blocker analysis = %d %s", code, raw)
			}
			ranFor(t, who, "the blocker analysis")
			code, raw = hub.Call(t, b, http.MethodPost, "/api/chat/plan", map[string]any{"message": "What is next?"})
			// The CLI's words stream as it writes them, newline and all.
			if answer, _ := sseTokens(t, raw); code != http.StatusOK || strings.TrimSpace(answer) != "Task 1 comes first." {
				t.Fatalf("plan chat = %d, answer %q: %s", code, answer, raw)
			}
			ranFor(t, who, "the plan assistant")
		})
	}

	// The inline replay runs the provider in the hub's own process, and is
	// pinned all the same: bob replays a call of alice's on his own.
	code, raw := hub.Call(t, browsers[bob], http.MethodGet, "/api/provider-calls?limit=50", nil)
	var list struct {
		Calls []struct {
			ID       int64  `json:"id"`
			Provider string `json:"provider"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(raw, &list); code != http.StatusOK || err != nil || len(list.Calls) == 0 ||
		list.Calls[0].Provider != "copilot" {
		t.Fatalf("provider calls = %d %s (%v)", code, raw, err)
	}
	replay := fmt.Sprintf("/api/provider-calls/%d/replay", list.Calls[0].ID)
	refused(t, carol, http.MethodPost, replay, map[string]any{}, "a provider-call replay")
	code, raw = hub.Call(t, browsers[bob], http.MethodPost, replay,
		map[string]any{"prompt": "You are editing the details of a single task"})
	if code != http.StatusOK || !strings.Contains(string(raw), "Move every table, and the indexes.") {
		t.Fatalf("bob's replay = %d %s", code, raw)
	}
	ranFor(t, bob, "the provider-call replay")

	// alice's run: the real `cloop run`, on her credential.
	if code, raw := hub.Call(t, browsers[alice], http.MethodPost, "/api/run?project_idx=0", map[string]any{}); code != http.StatusOK {
		t.Fatalf("alice's run = %d %s", code, raw)
	}
	awaitTaskDone(t, hub.Dir, 1)
	ranFor(t, alice, "alice's run")

	// The inline task replay runs the provider in the hub's own process too,
	// here with the target spelled as a person might type it: the factory
	// reads provider names without regard to case, and so does the pin. (It
	// gives the provider no working directory, so its directory is not
	// checked.)
	replayRun := map[string]any{"task_id": 1, "provider": "Copilot", "model": "stub-model"}
	refused(t, carol, http.MethodPost, "/api/replay-runs", replayRun, "an inline task replay")
	if code, raw := hub.Call(t, browsers[bob], http.MethodPost, "/api/replay-runs", replayRun); code != http.StatusOK {
		t.Fatalf("bob's task replay = %d %s", code, raw)
	}
	ranIn(t, bob, "bob's inline task replay", "")

	// It pauses at a usage cap with work left; the automatic resume acts for
	// alice, who started it — not for bob, and not for the hub.
	capPauseWithWork(t, hub.Dir, 2)
	resumeOnce(t, hub, log)
	awaitTaskDone(t, hub.Dir, 2)
	ranFor(t, alice, "the resume of alice's run")

	// Without her credential the resume is held for a person rather than
	// carried on on anyone else's.
	if code, raw := hub.Call(t, browsers[alice], http.MethodDelete, "/api/grants/"+grants[alice], nil); code != http.StatusOK {
		t.Fatalf("alice revokes her grant = %d %s", code, raw)
	}
	capPauseWithWork(t, hub.Dir, 3)
	before := len(copilotCalls(t, log))
	// The sweep skips a project it still sees executing, and the run that
	// finished task 2 may not have been let go of yet — under -race on a busy
	// machine it was not: sweep until the resume is decided, as resumeOnce
	// does.
	var st *state.ProjectState
	for deadline := time.Now().Add(60 * time.Second); ; {
		hub.Server.SweepAutoResume(context.Background())
		var err error
		if st, err = state.LoadLite(hub.Dir); err != nil {
			t.Fatal(err)
		}
		if (st.PauseReason != nil && st.PauseReason.Code == pausereason.CodeStarterUnavailable) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if after := len(copilotCalls(t, log)); after != before {
		t.Fatalf("a resume of alice's run with no credential of hers ran the Copilot CLI %d time(s)", after-before)
	}
	if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeStarterUnavailable ||
		!strings.Contains(st.PauseReason.Detail, alice) {
		t.Fatalf("the project is %s %+v, want paused starter_unavailable naming alice", st.Status, st.PauseReason)
	}
}

// awaitTaskDone waits for the project's run to finish task id and the project
// to stop running.
func awaitTaskDone(t *testing.T, dir string, id int) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := state.LoadLite(dir); err == nil && st != nil && st.Plan != nil && st.Status != "running" {
			for _, task := range st.Plan.Tasks {
				if task.ID == id && task.Status == pm.TaskDone {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	st, _ := state.LoadLite(dir)
	var tasks []string
	if st != nil && st.Plan != nil {
		for _, task := range st.Plan.Tasks {
			tasks = append(tasks, fmt.Sprintf("%d=%s", task.ID, task.Status))
		}
	}
	t.Fatalf("task %d never finished: status %v, tasks %v", id, st.Status, tasks)
}

// capPauseWithWork adds a pending task id and parks the project on a usage cap
// whose window reopened an hour ago.
func capPauseWithWork(t *testing.T, dir string, id int) {
	t.Helper()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, &pm.Task{ID: id, Title: fmt.Sprintf("Follow-up %d", id),
		Description: "More of the work.", Status: pm.TaskPending, Priority: id})
	ps.SetPaused(pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour window exhausted", time.Now().Add(-time.Hour)))
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
}

// resumeOnce sweeps until the hub has let go of the last run and resumed the
// paused one — the sweep skips a project it still sees executing — and the
// resumed run has called the CLI.
func resumeOnce(t *testing.T, hub *ssohubtest.Hub, log string) {
	t.Helper()
	before := len(copilotCalls(t, log))
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := state.LoadLite(hub.Dir); err == nil && st.Status == "paused" {
			hub.Server.SweepAutoResume(context.Background())
		}
		if len(copilotCalls(t, log)) > before {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	st, _ := state.LoadLite(hub.Dir)
	t.Fatalf("the paused run was never resumed: status %s, pause %+v", st.Status, st.PauseReason)
}
