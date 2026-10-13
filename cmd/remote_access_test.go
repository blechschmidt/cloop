package cmd

// `cloop remote executors`, `repos`, `grants` and `features` against an
// in-process hub with single sign-on (Task 20417). Each command is the
// dashboard's own call made with a terminal's session, so each test checks
// what it does for someone allowed, and that someone the dashboard would
// refuse is refused by the hub with the permission named.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
)

// rootProject creates, as root, a project from a checkout of acme/widgets
// with that repository granted through root's own token, and returns its
// path.
func rootProject(t *testing.T, w *remoteWorld) string {
	t.Helper()
	w.as(t, rootEmail)
	storeSecret(t, w, "root-pat", "github_pat", patPayload, true)
	checkoutOf(t, "git@github.com:acme/widgets.git")
	out, err := runRemoteCLI(t, "init", "--goal", "Ship the widgets API", "--repo-secret", "root-pat", "--json")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	return decodeInit(t, out).Project.Path
}

// share gives identity role on the project at path, as root does from the
// project's Members card.
func share(t *testing.T, w *remoteWorld, path, identity, role string) {
	t.Helper()
	root := w.browser(t, rootEmail)
	idx := projectIdxFor(t, w, root, path)
	status, body := w.hub.Call(t, root, http.MethodPost, fmt.Sprintf("/api/projects/%d/members", idx),
		map[string]string{"identity": identity, "role": role})
	if status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("share %s with %s as %s = %d %s", path, identity, role, status, body)
	}
}

// projectIdxFor is path's index in browser's project list.
func projectIdxFor(t *testing.T, w *remoteWorld, browser *http.Client, path string) int {
	t.Helper()
	status, body := w.hub.Call(t, browser, http.MethodGet, "/api/projects?indices=1", nil)
	var list struct {
		Indices map[string]int `json:"indices"`
	}
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK {
		t.Fatalf("GET /api/projects = %d %s", status, body)
	}
	idx, ok := list.Indices[path]
	if !ok {
		t.Fatalf("%s is not in the list: %s", path, body)
	}
	return idx
}

// sameRefusal asserts the terminal's error carries exactly the refusal the
// dashboard's own call gets, and renders it without raw structure.
func sameRefusal(t *testing.T, err error, status int, body []byte) {
	t.Helper()
	var ae *hubclient.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("the refusal %v does not carry the hub's answer", err)
	}
	var dash struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if jerr := json.Unmarshal(body, &dash); jerr != nil {
		t.Fatalf("the dashboard's answer %s: %v", body, jerr)
	}
	if ae.Status != status || ae.Code != dash.Error.Code || ae.Message != dash.Error.Message {
		t.Fatalf("the terminal was refused with %d %s %q; the dashboard with %d %s %q",
			ae.Status, ae.Code, ae.Message, status, dash.Error.Code, dash.Error.Message)
	}
	for k, v := range dash.Error.Details {
		if ae.Detail(k) != fmt.Sprint(v) {
			t.Errorf("detail %s: terminal %q, dashboard %v", k, ae.Detail(k), v)
		}
	}
	msg := err.Error()
	if perm, _ := dash.Error.Details["required_permission"].(string); perm != "" && !strings.Contains(msg, "needs:      "+perm) {
		t.Errorf("the terminal's refusal does not name %s:\n%s", perm, msg)
	}
	if !strings.Contains(msg, "to get it:") {
		t.Errorf("the terminal's refusal does not say how to get the permission:\n%s", msg)
	}
	for _, raw := range []string{"{", "map[", "[object"} {
		if strings.Contains(msg, raw) {
			t.Errorf("the terminal's refusal carries raw structure (%q):\n%s", raw, msg)
		}
	}
}

func TestRemoteExecutorsOffersOnlyWhatTheUserMayUse(t *testing.T) {
	w := newRemoteWorld(t)
	w.hub.AddExecutor(t, &ssohubtest.StubExecutor{IDValue: "open-box"}, "Open box")
	w.hub.AddExecutor(t, &ssohubtest.StubExecutor{IDValue: "locked-box"}, "Locked box")
	w.hub.RestrictExecutor(t, "locked-box", "platform")

	ids := func(out string) map[string]bool {
		t.Helper()
		var v executorsView
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("executors --json printed %q: %v", out, err)
		}
		got := map[string]bool{}
		for _, e := range v.Executors {
			got[e.ID] = true
		}
		return got
	}

	// Outside the access list: not offered.
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	out, err := runRemoteCLI(t, "executors", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(out); !got["open-box"] || got["locked-box"] {
		t.Fatalf("a maintainer outside the access list was offered %v", got)
	}
	// On it: offered, and marked as restricted.
	w.as(t, "pat@example.com", ssohubtest.GroupMaintainers, "platform")
	out, err = runRemoteCLI(t, "executors", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(out); !got["open-box"] || !got["locked-box"] {
		t.Fatalf("a member of the access list was offered %v", got)
	}
	out, err = runRemoteCLI(t, "executors")
	if err != nil || !strings.Contains(out, "locked-box") || !strings.Contains(out, "restricted; you are on its access list") {
		t.Fatalf("executors (table) = %v\n%s", err, out)
	}
	// A viewer may read the fleet, as the dashboard lets them, and is
	// offered the same.
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	out, err = runRemoteCLI(t, "executors", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(out); !got["open-box"] || got["locked-box"] {
		t.Fatalf("a viewer was offered %v", got)
	}
}

func TestRemoteReposListAddRemove(t *testing.T) {
	w := newRemoteWorld(t)
	path := rootProject(t, w)

	out, err := runRemoteCLI(t, "repos", "list", "widgets")
	if err != nil || !strings.Contains(out, "acme/widgets") || !strings.Contains(out, "root-pat") ||
		!strings.Contains(out, "runs no git proxy") {
		t.Fatalf("repos list = %v\n%s", err, out)
	}

	out, err = runRemoteCLI(t, "repos", "add", "widgets", "acme/docs", "acme/site", "--secret", "root-pat", "--access", "write")
	if err != nil || !strings.Contains(out, "Granted acme/docs, acme/site (write) through root-pat") {
		t.Fatalf("repos add = %v\n%s", err, out)
	}
	// Adding what it already reaches changes nothing.
	out, err = runRemoteCLI(t, "repos", "add", "widgets", "acme/docs", "--secret", "root-pat", "--json")
	if err != nil {
		t.Fatalf("repos add again: %v\n%s", err, out)
	}
	var res repoAttachResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Assigned) != 0 || len(res.Already) != 1 {
		t.Fatalf("repos add of a reachable repository = %+v (%v)", res, err)
	}

	// Withdrawing one of two narrows the grant; withdrawing the last revokes it.
	out, err = runRemoteCLI(t, "repos", "remove", "widgets", "acme/docs")
	if err != nil || !strings.Contains(out, "Withdrew acme/docs") || !strings.Contains(out, "which keeps acme/site") {
		t.Fatalf("repos remove of one of two = %v\n%s", err, out)
	}
	out, err = runRemoteCLI(t, "repos", "list", "widgets", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var panel hubclient.ProjectRepositories
	if err := json.Unmarshal([]byte(out), &panel); err != nil {
		t.Fatal(err)
	}
	var reached []string
	for _, a := range panel.Assignments {
		reached = append(reached, a.Repos...)
	}
	if strings.Join(reached, ",") != "acme/widgets,acme/site" && strings.Join(reached, ",") != "acme/site,acme/widgets" {
		t.Fatalf("after withdrawing acme/docs the project reaches %v", reached)
	}
	out, err = runRemoteCLI(t, "repos", "remove", "widgets", "acme/site")
	if err != nil || !strings.Contains(out, "Withdrew grant") {
		t.Fatalf("repos remove of the last = %v\n%s", err, out)
	}
	if _, err := runRemoteCLI(t, "repos", "remove", "widgets", "acme/nothing"); err == nil ||
		!strings.Contains(err.Error(), "cannot reach acme/nothing") {
		t.Fatalf("removing a repository it cannot reach = %v", err)
	}

	// A viewer of the project may read the list and not change it: the
	// grant is refused as the Repositories panel's Grant button is, and a
	// viewer cannot ask for one instead.
	share(t, w, path, vicEmail, "viewer")
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	// The list names no colleague's personal credential, root's token
	// included: the hub withholds those from everyone but their owner.
	if out, err := runRemoteCLI(t, "repos", "list", "widgets"); err != nil || strings.Contains(out, "root-pat") {
		t.Fatalf("a viewer's repos list = %v\n%s", err, out)
	}
	_, err = runRemoteCLI(t, "repos", "add", "widgets", "acme/evil", "--secret", "root-pat", "--justification", "please")
	if err == nil {
		t.Fatal("a viewer granted a repository")
	}
	vic := w.browser(t, vicEmail, ssohubtest.GroupViewers)
	status, body := w.hub.Call(t, vic, http.MethodPost,
		fmt.Sprintf("/api/projects/%d/repositories", projectIdxFor(t, w, vic, path)),
		map[string]any{"secret": "root-pat", "repos": []string{"acme/evil"}, "access": "read"})
	sameRefusal(t, err, status, body)
	if !strings.Contains(err.Error(), "secret.grant") {
		t.Errorf("the refusal does not name secret.grant: %v", err)
	}
}

func TestRemoteGrantsRequestListWithdraw(t *testing.T) {
	w := newRemoteWorld(t)
	path := rootProject(t, w)
	// The organisation's token, which only someone with secret.grant hands out.
	storeSecret(t, w, "org-token", "github_pat", patPayload, false)
	share(t, w, path, oliveEmail, "operator")

	// An operator asks for it.
	w.as(t, oliveEmail, ssohubtest.GroupOperators)
	out, err := runRemoteCLI(t, "grants", "request", "org-token", "--project", "widgets", "--repo", "acme/widgets",
		"--access", "write", "--justification", "Push the rate-limiting branch (API-412)")
	if err != nil {
		t.Fatalf("grants request: %v\n%s", err, out)
	}
	for _, want := range []string{"Requested org-token", "for project:" + path, "request req_", "Who can approve it:",
		rootEmail + " (admin)", "members of group " + ssohubtest.GroupMaintainers + " (maintainer)"} {
		if !strings.Contains(out, want) {
			t.Errorf("grants request printed no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, oliveEmail+" (") {
		t.Errorf("the requester is offered as their own approver:\n%s", out)
	}

	out, err = runRemoteCLI(t, "grants", "list", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var list hubclient.GrantRequestList
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Requests) != 1 {
		t.Fatalf("grants list = %+v (%v)", list, err)
	}
	req := list.Requests[0]
	if req.State != "pending" || !req.Mine || len(req.Approvers) == 0 || req.Subject != "project:"+path {
		t.Fatalf("the request reads %+v", req)
	}
	out, err = runRemoteCLI(t, "grants", "list")
	if err != nil || !strings.Contains(out, req.ID) || !strings.Contains(out, "can be approved by: "+rootEmail) {
		t.Fatalf("grants list (table) = %v\n%s", err, out)
	}

	// `repos add` through the organisation's token turns into a request too.
	out, err = runRemoteCLI(t, "repos", "add", "widgets", "acme/docs", "--secret", "org-token",
		"--justification", "Docs for the rate limiter")
	if err != nil || !strings.Contains(out, "Requested org-token") || !strings.Contains(out, "Who can approve it:") {
		t.Fatalf("repos add through a shared token as an operator = %v\n%s", err, out)
	}

	out, err = runRemoteCLI(t, "grants", "withdraw", req.ID)
	if err != nil || !strings.Contains(out, "Withdrew request "+req.ID) {
		t.Fatalf("grants withdraw = %v\n%s", err, out)
	}
	if _, err := runRemoteCLI(t, "grants", "withdraw", req.ID); err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("withdrawing it twice = %v", err)
	}

	// A viewer may not ask at all, and is told what asking takes.
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	_, err = runRemoteCLI(t, "grants", "request", "org-token", "--subject", "project:"+path, "--repo", "acme/widgets",
		"--justification", "curious")
	if err == nil {
		t.Fatal("a viewer filed a request")
	}
	status, body := w.hub.Call(t, w.browser(t, vicEmail, ssohubtest.GroupViewers), http.MethodPost, "/api/grant-requests",
		map[string]any{"secret_ref": "org-token", "subject": "project:" + path, "repos": []string{"acme/widgets"},
			"justification": "curious"})
	sameRefusal(t, err, status, body)
	if !strings.Contains(err.Error(), "operator role") {
		t.Errorf("the refusal does not say which role asking takes:\n%v", err)
	}
}

// gitProject makes a git-backed project on the hub owned by root, as a
// project checked out on the hub's own disk is, and returns its path.
func gitProject(t *testing.T, w *remoteWorld, name string) string {
	t.Helper()
	dir := filepath.Join(w.hub.Home, "projects", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "README.md")
	gitIn(t, dir, "commit", "-q", "-m", "init")
	if _, err := state.Init(dir, "Parallel work on "+name, 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".cloop/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore cloop state")
	if err := multiui.AddPathsOwned([]string{dir}, rootEmail); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRemoteFeaturesStartListPR(t *testing.T) {
	w := newRemoteWorld(t)
	path := gitProject(t, w, "app")
	w.as(t, rootEmail)

	out, err := runRemoteCLI(t, "features", "start", "app", "Rate limiting", "--task", "Add a token bucket",
		"--task", "Return 429 with Retry-After", "--json")
	if err != nil {
		t.Fatalf("features start: %v\n%s", err, out)
	}
	var started hubclient.StartedFeature
	if err := json.Unmarshal([]byte(out), &started); err != nil || started.Slug != "rate-limiting" || started.Idx < 0 {
		t.Fatalf("features start printed %+v (%v)\n%s", started, err, out)
	}

	out, err = runRemoteCLI(t, "features", "list", "app")
	if err != nil || !strings.Contains(out, "rate-limiting") || !strings.Contains(out, started.Branch) {
		t.Fatalf("features list = %v\n%s", err, out)
	}
	out, err = runRemoteCLI(t, "features", "list", "app", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var list hubclient.FeatureList
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Features) != 1 || list.Features[0].TotalTasks != 2 {
		t.Fatalf("features list --json = %+v (%v)", list, err)
	}

	// The project has no GitHub remote to propose into: the hub's refusal
	// comes back with its code, readable.
	_, err = runRemoteCLI(t, "features", "pr", "app", "rate-limiting")
	if err == nil {
		t.Fatal("features pr opened a pull request with no forge")
	}
	ae, ok := hubclient.AsAPIError(errors.Unwrap(err))
	if !ok {
		ae, ok = hubclient.AsAPIError(err)
	}
	if !ok || ae.Code == "" || !strings.Contains(err.Error(), ae.Code) || strings.Contains(err.Error(), "{") {
		t.Fatalf("features pr refused with %v (%+v)", err, ae)
	}

	// A viewer of the project is refused as the Features panel's button is.
	share(t, w, path, vicEmail, "viewer")
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	if out, err := runRemoteCLI(t, "features", "list", "app"); err != nil || !strings.Contains(out, "rate-limiting") {
		t.Fatalf("a viewer's features list = %v\n%s", err, out)
	}
	_, err = runRemoteCLI(t, "features", "start", "app", "Sneaky")
	if err == nil {
		t.Fatal("a viewer started a feature")
	}
	vic := w.browser(t, vicEmail, ssohubtest.GroupViewers)
	status, body := w.hub.Call(t, vic, http.MethodPost, fmt.Sprintf("/api/projects/%d/features", projectIdxFor(t, w, vic, path)),
		map[string]any{"name": "Sneaky"})
	sameRefusal(t, err, status, body)
	for _, want := range []string{"needs:      project.write on project", "your role:  viewer", "share it with you as maintainer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
	if _, err := runRemoteCLI(t, "features", "pr", "app", "rate-limiting"); err == nil || !strings.Contains(err.Error(), "project.write") {
		t.Fatalf("a viewer's features pr = %v", err)
	}
}

// TestRemoteCommandsAllSpeakJSON: every command under `cloop remote` that
// prints something takes --json.
func TestRemoteCommandsAllSpeakJSON(t *testing.T) {
	for _, c := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"init", remoteInitCmd}, {"executors", remoteExecutorsCmd},
		{"repos list", remoteReposListCmd}, {"repos add", remoteReposAddCmd}, {"repos remove", remoteReposRemoveCmd},
		{"grants request", remoteGrantsRequestCmd}, {"grants list", remoteGrantsListCmd}, {"grants withdraw", remoteGrantsWithdrawCmd},
		{"features start", remoteFeaturesStartCmd}, {"features list", remoteFeaturesListCmd}, {"features pr", remoteFeaturesPRCmd},
		{"approvals list", remoteApprovalsListCmd}, {"approvals approve", remoteApprovalsApproveCmd}, {"approvals deny", remoteApprovalsDenyCmd},
	} {
		if c.cmd.Flags().Lookup("json") == nil {
			t.Errorf("cloop remote %s has no --json", c.name)
		}
	}
}

func TestExplainRefusalRendersEveryDialectReadably(t *testing.T) {
	for name, tc := range map[string]struct {
		ae   hubclient.APIError
		want []string
	}{
		"a missing permission": {
			ae: hubclient.APIError{Status: 403, Code: "FORBIDDEN", Message: "your role does not permit this action",
				Details: map[string]any{"required_permission": "task.mutate", "role": "viewer", "scope": "project=api"}},
			want: []string{"needs:      task.mutate on project api", "your role:  viewer on project api",
				"ask a maintainer of api to share it with you as operator"},
		},
		"claims too old": {
			ae: hubclient.APIError{Status: 403, Code: "FORBIDDEN", Message: "claims are too old",
				Details: map[string]any{"required_permission": "project.write", "reason": "stale", "renewable": true}},
			want: []string{"cloop login https://hub.example.com", "approved too long ago"},
		},
		"the dashboard's own dialect": {
			ae: hubclient.APIError{Status: 409, Code: "host_execution_denied", Message: "host execution is disabled",
				Remediation: "bind the project to an isolated executor",
				Details:     map[string]any{"alternatives": []any{"sandbox-1", "edge-2"}, "nested": map[string]any{"b": 2, "a": "x"}}},
			want: []string{"host execution is disabled (HTTP 409, host_execution_denied) — bind the project to an isolated executor",
				"alternatives: sandbox-1, edge-2", "nested: a=x, b=2"},
		},
		"a refusal that names the permission only in its prose": {
			ae:   hubclient.APIError{Status: 403, Code: "FORBIDDEN", Message: "this is a shared secret: granting it requires secret.grant."},
			want: []string{"needs:      secret.grant", "cloop remote grants request"},
		},
	} {
		ae := tc.ae
		got := (&remoteError{hub: "https://hub.example.com", ae: &ae}).Error()
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q does not say %q", name, got, want)
			}
		}
		for _, raw := range []string{"map[", "[object", "{\""} {
			if strings.Contains(got, raw) {
				t.Errorf("%s: %q carries raw structure", name, got)
			}
		}
	}
}

// TestRemoteFlagUsageHasNoBackticks: pflag reads a backticked word in a
// flag's usage as the flag's value name, so `cloop login` in --hub's text
// rendered as "--hub cloop login" in every `cloop remote` help page.
func TestRemoteFlagUsageHasNoBackticks(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			if strings.Contains(f.Usage, "`") {
				t.Errorf("%s --%s: usage %q has a backtick, which pflag prints as the value name", c.CommandPath(), f.Name, f.Usage)
			}
		}
		c.LocalFlags().VisitAll(check)
		c.PersistentFlags().VisitAll(check)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(remoteCmd)
}
