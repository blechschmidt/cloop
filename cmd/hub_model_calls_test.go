package cmd

// The dashboard's model calls, end to end (Task 20442): a hub with single sign-on
// in this process (internal/ssohubtest) dispatches the Split preview, Revise,
// the blocker analysis and the plan assistant to this test binary acting as
// cloop — the real subcommands, with the real claudecode provider — and a
// stand-in `claude` first on PATH records whose account each call ran on.
//
// The hub's own environment carries a Claude token, as :8888's did through its
// dotfiles. Before Task 20442 each of these calls ran in the hub, spent that
// token or the hub's own login for whoever asked, and the stand-in would have
// recorded the same account for everyone.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// modelCallClaude writes the stand-in `claude`: it records the directory it
// ran in, its CLAUDE_CONFIG_DIR and the two ambient credentials, one line per
// call, and answers each feature's prompt the way a model would.
func modelCallClaude(t *testing.T) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "claude-calls.log")
	script := `#!/bin/sh
prompt=$(cat)
echo "$PWD|${CLAUDE_CONFIG_DIR-<unset>}|${CLAUDE_CODE_OAUTH_TOKEN-<unset>}|${ANTHROPIC_API_KEY-<unset>}" >> ` + quoteArg(log) + `
case "$prompt" in
*"recursively decomposed into concrete sub-tasks"*)
  echo '[{"title":"First part","description":"a"},{"title":"Second part","description":"b"}]' ;;
*"diagnosing why a software task is stuck"*)
  echo '{"root_cause":"a failed dependency","actions":["retry it","split it","ask"],"recommendation":"skip"}' ;;
*"You are editing the details of a single task"*)
  echo 'Move every table, and the indexes.' ;;
*)
  echo 'Task 1 comes first.' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// claudeCall is one line of the stand-in's log.
type claudeCall struct{ dir, configDir, oauthToken, apiKey string }

func claudeCalls(t *testing.T, log string) []claudeCall {
	t.Helper()
	raw, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []claudeCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 4 {
			t.Fatalf("unreadable stand-in log line %q", line)
		}
		out = append(out, claudeCall{f[0], f[1], f[2], f[3]})
	}
	return out
}

// hubCall makes one request as browser and returns the status and body.
func hubCall(t *testing.T, hub *ssohubtest.Hub, browser *http.Client, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, hub.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// sseTokens reads the plan assistant's answer out of its event stream.
func sseTokens(t *testing.T, raw []byte) (answer string, events []string) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(raw))
	name := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
			events = append(events, name)
		case strings.HasPrefix(line, "data: ") && name == "token":
			var d struct{ Token string }
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d); err != nil {
				t.Fatalf("token %q: %v", line, err)
			}
			answer += d.Token
		}
	}
	return answer, events
}

func TestHubModelCallsRunOnTheCallersClaudeAccount(t *testing.T) {
	log := modelCallClaude(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{SelfExe: cliSelfExe(t), AdminEmails: []string{rootEmail}})
	// The hub's ambient credentials, which no call made for a user may spend.
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "ambient-hub-token")
	t.Setenv("ANTHROPIC_API_KEY", "ambient-hub-key")

	ps, err := state.Load(hub.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate the database", Description: "Move every table.", Status: pm.TaskPending, Priority: 1},
		{ID: 2, Title: "Ship it", Status: pm.TaskPending, Priority: 2, DependsOn: []int{1}},
	}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hub.Dir, ".cloop", "config.yaml"), []byte("provider: claudecode\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const alice, bob = "alice@example.com", "bob@example.com"
	browsers := map[string]*http.Client{
		alice: hub.SignIn(t, alice, ssohubtest.GroupOperators),
		bob:   hub.SignIn(t, bob, ssohubtest.GroupOperators),
	}
	// The last call must have run in the project, on who's account and on
	// nothing ambient.
	ranFor := func(t *testing.T, who, what string) {
		t.Helper()
		calls := claudeCalls(t, log)
		if len(calls) == 0 {
			t.Fatalf("%s for %s: claude never ran", what, who)
		}
		got := calls[len(calls)-1]
		home, err := claudecodeauth.HomeFor(who)
		if err != nil {
			t.Fatal(err)
		}
		if got.configDir != home {
			t.Errorf("%s for %s ran on CLAUDE_CONFIG_DIR %q, want %s's own %q", what, who, got.configDir, who, home)
		}
		if got.oauthToken != "" || got.apiKey != "" {
			t.Errorf("%s for %s carried an ambient credential: token %q, key %q", what, who, got.oauthToken, got.apiKey)
		}
		if got.dir != hub.Dir {
			t.Errorf("%s for %s ran in %q, want the project %q", what, who, got.dir, hub.Dir)
		}
	}

	for _, who := range []string{alice, bob} {
		b := browsers[who]
		t.Run(who, func(t *testing.T) {
			code, raw := hubCall(t, hub, b, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
			if code != http.StatusOK || !strings.Contains(string(raw), `"title":"Second part"`) {
				t.Fatalf("split preview = %d %s", code, raw)
			}
			ranFor(t, who, "the split preview")

			code, raw = hubCall(t, hub, b, http.MethodPost, "/api/tasks/1/revise",
				map[string]any{"instruction": "and the indexes", "description": "Move every table."})
			if code != http.StatusOK || !strings.Contains(string(raw), "Move every table, and the indexes.") {
				t.Fatalf("revise = %d %s", code, raw)
			}
			ranFor(t, who, "revise")

			code, raw = hubCall(t, hub, b, http.MethodPost, "/api/tasks/2/blocker", map[string]any{})
			if code != http.StatusOK || !strings.Contains(string(raw), `"recommendation":"skip"`) {
				t.Fatalf("blocker analysis = %d %s", code, raw)
			}
			ranFor(t, who, "the blocker analysis")

			code, raw = hubCall(t, hub, b, http.MethodPost, "/api/chat/plan", map[string]any{"message": "What is next?"})
			answer, events := sseTokens(t, raw)
			if code != http.StatusOK || answer != "Task 1 comes first." || events[len(events)-1] != "done" {
				t.Fatalf("plan chat = %d, answer %q, events %v: %s", code, answer, events, raw)
			}
			ranFor(t, who, "the plan assistant")
		})
	}

	// The inline replay calls the provider in the hub's own process, and is
	// pinned to the caller's account all the same: bob replays a call alice's
	// revise made.
	code, raw := hubCall(t, hub, browsers[bob], http.MethodGet, "/api/provider-calls?limit=50", nil)
	var list struct {
		Calls []struct {
			ID       int64  `json:"id"`
			Provider string `json:"provider"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(raw, &list); code != http.StatusOK || err != nil || len(list.Calls) == 0 {
		t.Fatalf("provider calls = %d %s (%v)", code, raw, err)
	}
	before := len(claudeCalls(t, log))
	code, raw = hubCall(t, hub, browsers[bob], http.MethodPost,
		fmt.Sprintf("/api/provider-calls/%d/replay", list.Calls[0].ID), map[string]any{"prompt": "You are editing the details of a single task"})
	if code != http.StatusOK || !strings.Contains(string(raw), "Move every table, and the indexes.") {
		t.Fatalf("replay = %d %s", code, raw)
	}
	if len(claudeCalls(t, log)) != before+1 {
		t.Fatal("the replay did not run claude")
	}
	ranFor(t, bob, "the provider-call replay")

	// A viewer reads what blocks a task and cannot have one analysed.
	viewer := hub.SignIn(t, vicEmail, ssohubtest.GroupViewers)
	before = len(claudeCalls(t, log))
	if code, raw := hubCall(t, hub, viewer, http.MethodPost, "/api/tasks/2/blocker", map[string]any{}); code != http.StatusForbidden {
		t.Errorf("a viewer's analysis = %d %s, want 403", code, raw)
	}
	if after := len(claudeCalls(t, log)); after != before {
		t.Errorf("a viewer's request made %d model call(s)", after-before)
	}
}
